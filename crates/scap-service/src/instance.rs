//! Allocate or select a compute identity, then permanently consume it at startup.
//!
//! The same object backend used for database authority owns this record. It is
//! neither a lease nor a database ownership grant. Per-ID records are never
//! deleted, renewed, overwritten or adopted, even after clean exit. The separate
//! allocator counter only advances and never substitutes for a per-ID claim.

use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::Failure;

const PREFIX: &str = "scap-worker/v1/instances/";
const MAGIC: &[u8] = b"SCAP-WORKER-INSTANCE-v1\0";
const ALLOCATOR: &str = "scap-worker/v1/allocator";
const ALLOCATOR_MAGIC: &[u8] = b"SCAP-WORKER-ALLOCATOR-v1\0";
const MAX_ALLOCATION_ATTEMPTS: usize = 16;

/// Only the startup that receives an unambiguous create acknowledgment and
/// verifies that exact immutable record may expose its configured identity.
/// In particular, an existing identical record is NOT idempotent success.
pub(crate) fn claim(objects: &dyn Objects, worker: u64, deadline: Instant) -> Result<(), Failure> {
    if worker == 0 {
        return Err(Failure::new("CONFIG"));
    }
    let key = format!("{PREFIX}{worker}");
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&worker.to_be_bytes());
    create_verified(objects, &key, &bytes, "INSTANCE_REUSED", deadline)
}

/// An explicit administrative bootstrap, never an automatic missing-state
/// recovery. The operator must prove that every historically issued identity
/// is at or below this floor, and must preserve this record thereafter.
pub(crate) fn initialize(
    objects: &dyn Objects,
    high_water: u64,
    deadline: Instant,
) -> Result<(), Failure> {
    create_verified(
        objects,
        ALLOCATOR,
        &counter_bytes(high_water),
        "INSTANCE_ALLOCATOR_EXISTS",
        deadline,
    )
}

/// Reserve a new number using the exact observed counter ETag, then consume
/// its permanent marker. A definite conflict starts a different candidate;
/// ambiguity never reads, refreshes an ETag, retries, or starts the service.
pub(crate) fn allocate(objects: &dyn Objects, deadline: Instant) -> Result<u64, Failure> {
    let mut previous_candidate = 0;
    for _ in 0..MAX_ALLOCATION_ATTEMPTS {
        remaining(deadline)?;
        let stored = objects
            .get(ALLOCATOR, ALLOCATOR_MAGIC.len() + 8, deadline)
            .map_err(|error| match error {
                StoreError::Missing => Failure::new("INSTANCE_ALLOCATOR_MISSING"),
                StoreError::Limit | StoreError::Corrupt => Failure::new("INSTANCE_CORRUPT"),
                _ => Failure::new("INSTANCE_UNKNOWN"),
            })?;
        remaining(deadline)?;
        if stored.etag.is_empty()
            || stored.bytes.len() != ALLOCATOR_MAGIC.len() + 8
            || !stored.bytes.starts_with(ALLOCATOR_MAGIC)
        {
            return Err(Failure::new("INSTANCE_CORRUPT"));
        }
        let high_water = u64::from_be_bytes(
            stored.bytes[ALLOCATOR_MAGIC.len()..]
                .try_into()
                .expect("checked allocator body length"),
        );
        let candidate = high_water
            .checked_add(1)
            .ok_or_else(|| Failure::new("INSTANCE_EXHAUSTED"))?;
        if candidate < previous_candidate {
            return Err(Failure::new("INSTANCE_CORRUPT"));
        }
        if candidate == previous_candidate {
            // A definite rejection did not yield a new counter observation.
            // Do not replay the same candidate, even under a changed ETag.
            return Err(Failure::new("INSTANCE_ALLOCATION_BUSY"));
        }
        previous_candidate = candidate;
        let published = objects.put(
            ALLOCATOR,
            &counter_bytes(candidate),
            Condition::Match(&stored.etag),
            deadline,
        );
        remaining(deadline)?;
        match published {
            Ok(etag) => {
                if etag.is_empty() {
                    return Err(Failure::new("INSTANCE_UNKNOWN"));
                }
            }
            Err(StoreError::Conflict) => continue,
            Err(_) => return Err(Failure::new("INSTANCE_UNKNOWN")),
        }
        // Another allocator may already advance the mutable counter. Its PUT
        // acknowledgment reserves this candidate; only the immutable marker
        // is read back. The reservation is never rolled back on later failure.
        match claim(objects, candidate, deadline) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.code == "INSTANCE_REUSED" => continue,
            Err(error) => return Err(error),
        }
    }
    Err(Failure::new("INSTANCE_ALLOCATION_BUSY"))
}

fn counter_bytes(high_water: u64) -> Vec<u8> {
    let mut bytes = ALLOCATOR_MAGIC.to_vec();
    bytes.extend_from_slice(&high_water.to_be_bytes());
    bytes
}

fn create_verified(
    objects: &dyn Objects,
    key: &str,
    bytes: &[u8],
    conflict: &'static str,
    deadline: Instant,
) -> Result<(), Failure> {
    remaining(deadline)?;
    let etag = objects
        .put(key, bytes, Condition::Absent, deadline)
        .map_err(|error| match error {
            StoreError::Conflict => Failure::new(conflict),
            _ => Failure::new("INSTANCE_UNKNOWN"),
        })?;
    if etag.is_empty() {
        return Err(Failure::new("INSTANCE_UNKNOWN"));
    }
    remaining(deadline)?;
    let stored = objects
        .get(key, bytes.len(), deadline)
        .map_err(|error| match error {
            StoreError::Missing | StoreError::Limit | StoreError::Corrupt => {
                Failure::new("INSTANCE_CORRUPT")
            }
            _ => Failure::new("INSTANCE_UNKNOWN"),
        })?;
    remaining(deadline)?;
    if stored.bytes != bytes || stored.etag != etag {
        return Err(Failure::new("INSTANCE_CORRUPT"));
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<(), Failure> {
    if Instant::now() >= deadline {
        return Err(Failure::new("INSTANCE_UNKNOWN"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
