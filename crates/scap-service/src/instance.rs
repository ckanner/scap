//! Permanently consume an explicitly configured compute identity at startup.
//!
//! The same object backend used for database authority owns this record. It is
//! neither a lease nor a database ownership grant. Records are never deleted,
//! renewed, overwritten or adopted by another startup, even after clean exit.

use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::Failure;

const PREFIX: &str = "scap-worker/v1/instances/";
const MAGIC: &[u8] = b"SCAP-WORKER-INSTANCE-v1\0";

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
    remaining(deadline)?;
    let etag = objects
        .put(&key, &bytes, Condition::Absent, deadline)
        .map_err(|error| match error {
            StoreError::Conflict => Failure::new("INSTANCE_REUSED"),
            _ => Failure::new("INSTANCE_UNKNOWN"),
        })?;
    if etag.is_empty() {
        return Err(Failure::new("INSTANCE_UNKNOWN"));
    }
    remaining(deadline)?;
    let stored = objects
        .get(&key, bytes.len(), deadline)
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
