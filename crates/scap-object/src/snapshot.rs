//! Explicit retained roots. Permanent metadata never grants historical ACKs.

use crate::data_tree;
use crate::format::*;
use crate::head_publication::PreparedHead;
use crate::object_context::ObjectContext;
use crate::snapshot_format::{cleanup_room, gross_bytes};
pub use crate::snapshot_records::PrepareSnapshotInput;
use crate::snapshot_records::{self, SnapshotDescriptor, SnapshotProof, MAX_DESCRIPTOR, MAX_PROOF};
use crate::{Database, Error, Snapshot};
use scap_object_store::{Condition, Objects, StoreError, Stored};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSnapshot {
    pub scope: Scope,
    pub input: PrepareSnapshotInput,
    pub reference: SnapshotRef,
    pub point: SnapshotPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotState {
    Prepared,
    Retained,
    ReleasedObserved,
    Fenced,
}

/// `state` is a current observation, not a receipt for a past Unknown call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotObservation {
    pub head: Head,
    pub prepared: PreparedSnapshot,
    pub state: SnapshotState,
    pub accepted: Option<SnapshotEntry>,
}

/// Only this module constructs snapshot-changing publication capabilities.
pub(super) struct VerifiedSnapshotTransition {
    base: Snapshot,
    next: Head,
}

impl VerifiedSnapshotTransition {
    pub(super) fn into_parts(self) -> (Snapshot, Head) {
        (self.base, self.next)
    }
}

struct SnapshotMeter {
    objects: Arc<dyn Objects>,
    remaining: AtomicUsize,
    deadline: Instant,
    now: fn() -> Instant,
}

impl SnapshotMeter {
    fn check(&self, deadline: Instant) -> Result<Instant, StoreError> {
        let deadline = deadline.min(self.deadline);
        if (self.now)() >= deadline {
            return Err(StoreError::Unknown);
        }
        self.remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .map_err(|_| StoreError::Budget)?;
        Ok(deadline)
    }
}

impl Objects for SnapshotMeter {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        self.objects.get(key, maximum, self.check(deadline)?)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        self.objects
            .put(key, bytes, condition, self.check(deadline)?)
    }
}

fn prepared(descriptor: &SnapshotDescriptor) -> PreparedSnapshot {
    PreparedSnapshot {
        scope: descriptor.scope.clone(),
        input: descriptor.input.clone(),
        reference: descriptor.reference(),
        point: descriptor.point.clone(),
    }
}

fn entries(head: &Head) -> &[SnapshotEntry] {
    head.snapshots.as_deref().unwrap_or(&[])
}

impl Database {
    fn snapshot_budget(&self, deadline: Instant) -> Self {
        let mut database = self.clone();
        // New prepare uses eight I/Os including the one manifest GET. Extra
        // stable/error probes remain bounded and use the same absolute deadline.
        database.objects = Arc::new(SnapshotMeter {
            objects: self.objects.clone(),
            remaining: AtomicUsize::new(12),
            deadline,
            now: Instant::now,
        });
        database
    }

    fn snapshot_head(
        &self,
        principal: u64,
        read: bool,
        deadline: Instant,
    ) -> Result<Snapshot, Error> {
        let base = self.read_head(deadline)?;
        Self::permission(&base.head, principal, read, false, true)?;
        if base.head.lifecycle == Lifecycle::Provisioning {
            return Err(Error::Lifecycle);
        }
        Ok(base)
    }

    fn snapshot_barrier(
        &self,
        principal: u64,
        read: bool,
        base: &Snapshot,
        deadline: Instant,
    ) -> Result<(), Error> {
        let current = self.snapshot_head(principal, read, deadline)?;
        if current.head != base.head || current.etag != base.etag {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn snapshot_decode(
        &self,
        identity: &SnapshotIdentity,
        stored: Result<Stored, StoreError>,
    ) -> Result<Option<SnapshotDescriptor>, Error> {
        let stored = match stored {
            Ok(stored) => stored,
            Err(StoreError::Missing) => return Ok(None),
            Err(error) => return Err(Error::Store(error)),
        };
        let descriptor =
            SnapshotDescriptor::decode(&stored.bytes).map_err(|_| self.observe(Error::Corrupt))?;
        if stored.etag.is_empty()
            || descriptor.scope != self.scope
            || descriptor.input.identity() != *identity
        {
            return Err(self.observe(Error::Corrupt));
        }
        Ok(Some(descriptor))
    }

    fn snapshot_proof(
        &self,
        descriptor: &SnapshotDescriptor,
        stored: Result<Stored, StoreError>,
    ) -> Result<Option<SnapshotProof>, Error> {
        let stored = match stored {
            Ok(stored) => stored,
            Err(StoreError::Missing) => return Ok(None),
            Err(error) => return Err(Error::Store(error)),
        };
        let proof =
            SnapshotProof::decode(&stored.bytes).map_err(|_| self.observe(Error::Corrupt))?;
        if stored.etag.is_empty() || proof.scope != self.scope || proof.entry != descriptor.entry()
        {
            return Err(self.observe(Error::Corrupt));
        }
        Ok(Some(proof))
    }

    fn snapshot_entry(
        &self,
        base: &Head,
        descriptor: &SnapshotDescriptor,
    ) -> Result<Option<SnapshotEntry>, Error> {
        let actual = entries(base)
            .iter()
            .find(|entry| entry.reference.identity() == descriptor.input.identity());
        if actual.is_some_and(|entry| *entry != descriptor.entry()) {
            return Err(self.observe(Error::Corrupt));
        }
        Ok(actual.cloned())
    }

    fn snapshot_observation(
        &self,
        base: &Snapshot,
        descriptor: &SnapshotDescriptor,
        proof: Option<SnapshotProof>,
    ) -> Result<SnapshotObservation, Error> {
        let accepted = self.snapshot_entry(&base.head, descriptor)?;
        let (state, accepted) = if accepted.is_some() {
            (SnapshotState::Retained, accepted)
        } else if let Some(proof) = proof {
            if base.head.head_serial <= descriptor.reference().capture_serial
                || descriptor.point.source_revision > base.head.revision
                || descriptor.point.sequence > base.head.sequence
            {
                return Err(self.observe(Error::Corrupt));
            }
            (SnapshotState::ReleasedObserved, Some(proof.entry))
        } else if descriptor.matches(base) {
            (SnapshotState::Prepared, None)
        } else {
            (SnapshotState::Fenced, None)
        };
        Ok(SnapshotObservation {
            head: base.head.clone(),
            prepared: prepared(descriptor),
            state,
            accepted,
        })
    }

    pub(crate) fn snapshot_view(
        &self,
        principal: u64,
        identity: &SnapshotIdentity,
        read: bool,
        deadline: Instant,
    ) -> Result<(Snapshot, SnapshotDescriptor, SnapshotObservation), Error> {
        let base = self.snapshot_head(principal, read, deadline)?;
        let descriptor = self.objects.get(
            &snapshot_records::key(&self.scope, identity, false),
            MAX_DESCRIPTOR,
            deadline,
        );
        let proof = self.objects.get(
            &snapshot_records::key(&self.scope, identity, true),
            MAX_PROOF,
            deadline,
        );
        // Buffer every raw result. No Missing, malformed proof, input mismatch
        // or transport result may hide a later revocation or changing HEAD.
        self.snapshot_barrier(principal, read, &base, deadline)?;
        let descriptor = self.snapshot_decode(identity, descriptor)?;
        let descriptor = match descriptor {
            Some(descriptor) => descriptor,
            None => {
                if proof.is_ok()
                    || entries(&base.head)
                        .iter()
                        .any(|entry| entry.reference.identity() == *identity)
                {
                    return Err(self.observe(Error::Corrupt));
                }
                // The Present case was rejected above. Preserve every exact
                // error, including Missing and Unknown, without a fallback.
                return Err(Error::Store(proof.expect_err("present proof rejected")));
            }
        };
        let proof = self.snapshot_proof(&descriptor, proof)?;
        let observation = self.snapshot_observation(&base, &descriptor, proof)?;
        Ok((base, descriptor, observation))
    }

    fn snapshot_idle(head: &Head) -> Result<(), Error> {
        Self::no_pending_owner(head)?;
        if head.storage.plan.is_some()
            || head.storage.sweep.is_some()
            || head.storage.terminal.is_some()
        {
            return Err(Error::Fenced);
        }
        Ok(())
    }

    fn snapshot_capture_head(base: &Head, descriptor: &SnapshotDescriptor) -> Result<Head, Error> {
        Self::ready(base)?;
        Self::snapshot_idle(base)?;
        let mut next = base.clone();
        next.format = 9;
        next.head_serial = base.head_serial.checked_add(1).ok_or(Error::Limit)?;
        next.snapshots
            .get_or_insert_with(Vec::new)
            .push(descriptor.entry());
        next.snapshot_limits = Some(descriptor.limits.clone());
        next.restore_origin.get_or_insert(None);
        descriptor
            .limits
            .fits(entries(&next))
            .map_err(|_| Error::Limit)?;
        if !cleanup_room(&next) {
            return Err(Error::Limit);
        }
        next.validate().map_err(Error::Format)?;
        Ok(next)
    }

    fn snapshot_publish(&self, base: Snapshot, next: Head, deadline: Instant) -> Result<(), Error> {
        if !cleanup_room(&next) {
            return Err(Error::Limit);
        }
        let candidate = VerifiedSnapshotTransition { base, next };
        let publication = PreparedHead::snapshot(self, candidate, deadline)?;
        self.publish_healthy(publication)
    }

    pub fn snapshot_prepare(
        &self,
        principal: u64,
        input: &PrepareSnapshotInput,
        deadline: Instant,
    ) -> Result<PreparedSnapshot, Error> {
        input.validate().map_err(Error::Format)?;
        let deadline = self.options.deadline(deadline, false);
        let database = self.snapshot_budget(deadline);
        let identity = input.identity();
        let key = snapshot_records::key(&self.scope, &identity, false);
        let mut stored = database.objects.get(&key, MAX_DESCRIPTOR, deadline);
        let base = database.snapshot_head(principal, true, deadline)?;
        if matches!(stored, Err(StoreError::Missing)) {
            stored = database.objects.get(&key, MAX_DESCRIPTOR, deadline);
        }
        database.snapshot_barrier(principal, true, &base, deadline)?;
        if let Some(descriptor) = database.snapshot_decode(&identity, stored)? {
            if descriptor.input != *input {
                return Err(Error::Conflict);
            }
            database.snapshot_entry(&base.head, &descriptor)?;
            return Ok(prepared(&descriptor));
        }
        if entries(&base.head)
            .iter()
            .any(|entry| entry.reference.identity() == identity)
        {
            return Err(database.observe(Error::Corrupt));
        }
        match database.objects.get(
            &snapshot_records::key(&self.scope, &identity, true),
            MAX_PROOF,
            deadline,
        ) {
            Err(StoreError::Missing) => {}
            Ok(_) => {
                database.snapshot_barrier(principal, true, &base, deadline)?;
                return Err(database.observe(Error::Corrupt));
            }
            Err(error) => return Err(Error::Store(error)),
        }
        if input.creator != principal {
            return Err(Error::Denied);
        }
        if input.expected_revision != base.head.revision
            || input.expected_head_serial != base.head.head_serial
        {
            return Err(Error::Conflict);
        }
        Self::ready(&base.head)?;
        Self::snapshot_idle(&base.head)?;
        let limits = base
            .head
            .snapshot_limits
            .clone()
            .unwrap_or_else(|| self.options.snapshot_limits.clone());
        if entries(&base.head).len() >= limits.max_points as usize {
            return Err(Error::Limit);
        }
        if entries(&base.head)
            .iter()
            .any(|entry| entry.label == input.label)
        {
            return Err(Error::Conflict);
        }
        let objects = ObjectContext::from_snapshot(&database, &base, deadline)?;
        let manifest = data_tree::manifest(&objects, &base.head.data_root, deadline)
            .map_err(|error| objects.observe(error))?;
        let bytes = gross_bytes(entries(&base.head)).expect("decoded HEAD bounds the point count")
            + manifest.page_count as u64 * PAGE_SIZE as u64;
        if bytes > limits.max_logical_bytes {
            return Err(Error::Limit);
        }
        let descriptor = SnapshotDescriptor::new(&base, input, manifest.page_count, limits)
            .map_err(Error::Format)?;
        Self::snapshot_capture_head(&base.head, &descriptor)?;
        let bytes = descriptor
            .bytes()
            .expect("new bounded snapshot descriptor is valid");
        match database
            .objects
            .put(&key, &bytes, Condition::Absent, deadline)
        {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(Error::Store(error)),
        }
        let stored = database.objects.get(&key, MAX_DESCRIPTOR, deadline);
        let exact = stored.as_ref().is_ok_and(|value| value.bytes == bytes);
        let durable = database
            .snapshot_decode(&identity, stored)?
            .ok_or_else(|| database.observe(Error::Corrupt))?;
        if durable != descriptor {
            return Err(Error::Conflict);
        }
        if !exact {
            return Err(database.observe(Error::Corrupt));
        }
        Ok(prepared(&durable))
    }

    pub fn snapshot_inspect(
        &self,
        principal: u64,
        identity: &SnapshotIdentity,
        deadline: Instant,
    ) -> Result<SnapshotObservation, Error> {
        identity.validate().map_err(Error::Format)?;
        let deadline = self.options.deadline(deadline, false);
        let (_, _, observation) = self
            .snapshot_budget(deadline)
            .snapshot_view(principal, identity, false, deadline)?;
        Ok(observation)
    }

    pub fn snapshot_list(&self, principal: u64, deadline: Instant) -> Result<Head, Error> {
        let deadline = self.options.deadline(deadline, false);
        Ok(self
            .snapshot_budget(deadline)
            .snapshot_head(principal, false, deadline)?
            .head)
    }

    pub fn snapshot_capture(
        &self,
        principal: u64,
        reference: &SnapshotRef,
        deadline: Instant,
    ) -> Result<SnapshotObservation, Error> {
        reference.validate().map_err(Error::Format)?;
        let deadline = self.options.deadline(deadline, false);
        let database = self.snapshot_budget(deadline);
        let (base, descriptor, observed) =
            database.snapshot_view(principal, &reference.identity(), true, deadline)?;
        if descriptor.reference() != *reference {
            return Err(Error::Conflict);
        }
        Self::ready(&base.head)?;
        Self::snapshot_idle(&base.head)?;
        if observed.state != SnapshotState::Prepared {
            return Ok(observed);
        }
        let objects = ObjectContext::from_snapshot(&database, &base, deadline)?;
        let manifest = data_tree::manifest(&objects, &base.head.data_root, deadline)
            .map_err(|error| objects.observe(error))?;
        if manifest.page_count != descriptor.point.page_count {
            return Err(objects.observe(Error::Corrupt));
        }
        let next = Self::snapshot_capture_head(&base.head, &descriptor)?;
        database.snapshot_publish(base, next.clone(), deadline)?;
        Ok(SnapshotObservation {
            head: next,
            prepared: prepared(&descriptor),
            state: SnapshotState::Retained,
            accepted: Some(descriptor.entry()),
        })
    }

    pub fn snapshot_release(
        &self,
        principal: u64,
        reference: &SnapshotRef,
        deadline: Instant,
    ) -> Result<SnapshotObservation, Error> {
        reference.validate().map_err(Error::Format)?;
        let deadline = self.options.deadline(deadline, false);
        let database = self.snapshot_budget(deadline);
        let (base, descriptor, observed) =
            database.snapshot_view(principal, &reference.identity(), false, deadline)?;
        if descriptor.reference() != *reference {
            return Err(Error::Conflict);
        }
        if observed.state != SnapshotState::Retained {
            return Ok(observed);
        }
        Self::snapshot_idle(&base.head)?;
        let proof = SnapshotProof {
            version: 1,
            scope: self.scope.clone(),
            entry: descriptor.entry(),
        };
        // A validated descriptor yields a validated entry; its bounded label,
        // fixed-width identities and hashes fit strictly below MAX_PROOF.
        let bytes = proof
            .bytes()
            .expect("validated descriptor yields a bounded proof");
        let key = snapshot_records::key(&self.scope, &reference.identity(), true);
        match database
            .objects
            .put(&key, &bytes, Condition::Absent, deadline)
        {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(Error::Store(error)),
        }
        let stored = database.objects.get(&key, MAX_PROOF, deadline);
        database.snapshot_barrier(principal, false, &base, deadline)?;
        let stored = stored.map_err(Error::Store)?;
        if stored.etag.is_empty() || stored.bytes != bytes {
            return Err(database.observe(Error::Corrupt));
        }
        let mut next = base.head.clone();
        next.head_serial = next
            .head_serial
            .checked_add(1)
            .expect("HEAD9 reserves each retained point's release");
        next.snapshots
            .as_mut()
            .expect("a retained point belongs to HEAD9")
            .retain(|entry| entry.reference != *reference);
        database.snapshot_publish(base, next.clone(), deadline)?;
        Ok(SnapshotObservation {
            head: next,
            prepared: prepared(&descriptor),
            state: SnapshotState::ReleasedObserved,
            accepted: Some(proof.entry),
        })
    }

    pub fn set_snapshot_limits(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        limits: SnapshotLimits,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let deadline = self.options.deadline(deadline, false);
        let database = self.snapshot_budget(deadline);
        let base = database.snapshot_head(principal, false, deadline)?;
        if base.head.revision != expected_revision {
            return Err(Error::Conflict);
        }
        if !matches!(
            base.head.lifecycle,
            Lifecycle::Ready | Lifecycle::Maintenance
        ) {
            return Err(Error::Lifecycle);
        }
        Self::snapshot_idle(&base.head)?;
        limits.validate().map_err(Error::Format)?;
        limits.fits(entries(&base.head)).map_err(|_| Error::Limit)?;
        let mut next = Self::next(&base.head, nonce)?;
        next.format = 9;
        next.snapshots.get_or_insert_with(Vec::new);
        next.snapshot_limits = Some(limits);
        next.restore_origin.get_or_insert(None);
        database.snapshot_publish(base, next.clone(), deadline)?;
        Ok(next)
    }
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
