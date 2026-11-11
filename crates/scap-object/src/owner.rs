//! Restartable owner plans. Each invocation owns one bounded metadata prefix;
//! each HEAD replacement keeps its original body, ETag and absolute deadline.

use crate::format::*;
use crate::head_publication::PreparedHead;
use crate::object_context::ObjectContext;
use crate::owner_format::{self, OwnerDescriptor, OwnerProof, MAX_DESCRIPTOR, MAX_PROOF};
pub use crate::owner_format::{
    OwnerIdentity, OwnerMode, OwnerNonces, OwnerPlanRef, PrepareOwnerInput,
};
use crate::{Database, Error, Session, Snapshot};
use scap_object_store::{Condition, Objects, StoreError, Stored};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOwner {
    pub scope: Scope,
    pub input: PrepareOwnerInput,
    pub reference: OwnerPlanRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerPreparation {
    Prepared(PreparedOwner),
    Pending(OwnerPlanRef),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerState {
    Prepared,
    Claimed,
    Cancelling,
    Active,
    Aborted,
    Fenced,
}

/// Historical acceptance is not the previous caller's ACK, today's writer
/// authority or a native Session. `head` is a separate current observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerObservation {
    pub head: Head,
    pub prepared: PreparedOwner,
    pub state: OwnerState,
    pub accepted: Option<OwnerPlan>,
}

/// Only this module grants an owner-plan-changing publication capability.
pub(super) struct VerifiedOwnerTransition {
    base: Snapshot,
    next: Head,
}

impl VerifiedOwnerTransition {
    pub(super) fn into_parts(self) -> (Snapshot, Head) {
        (self.base, self.next)
    }
}

struct OwnerMeter {
    objects: Arc<dyn Objects>,
    head: String,
    prefix: String,
    remaining: AtomicUsize,
    deadline: Instant,
    payload_gets: u64,
    payload_bytes: u64,
    used: Mutex<PayloadUsage>,
    now: fn() -> Instant,
}

#[derive(Default)]
struct PayloadUsage {
    gets: u64,
    bytes: u64,
}

impl OwnerMeter {
    fn check(&self, key: &str, deadline: Instant) -> Result<Instant, StoreError> {
        let deadline = deadline.min(self.deadline);
        if (self.now)() >= deadline {
            return Err(StoreError::Unknown);
        }
        if key == self.head || key.starts_with(&self.prefix) {
            self.remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                    left.checked_sub(1)
                })
                .map_err(|_| StoreError::Budget)?;
        }
        Ok(deadline)
    }
}

impl Objects for OwnerMeter {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let deadline = self.check(key, deadline)?;
        if key == self.head || key.starts_with(&self.prefix) {
            return self.objects.get(key, maximum, deadline);
        }
        let allowance = {
            let mut used = self.used.lock().expect("private owner recovery accounting");
            let remaining = self.payload_bytes - used.bytes;
            if used.gets == self.payload_gets || remaining == 0 {
                return Err(StoreError::Budget);
            }
            used.gets += 1;
            let allowance = (maximum as u64).min(remaining) as usize;
            used.bytes += allowance as u64;
            allowance
        };
        let mut result = self.objects.get(key, allowance, deadline);
        if matches!(result, Err(StoreError::Limit)) && allowance < maximum {
            // A locally shortened allowance is not corrupt source content.
            result = Err(StoreError::Budget);
        }
        let actual = result
            .as_ref()
            .map_or(allowance, |stored| stored.bytes.len());
        if actual > allowance {
            return Err(StoreError::Corrupt);
        }
        if (self.now)() >= deadline {
            return Err(StoreError::Unknown);
        }
        self.used
            .lock()
            .expect("private owner recovery accounting")
            .bytes -= (allowance - actual) as u64;
        result
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        let deadline = self.check(key, deadline)?;
        self.objects.put(key, bytes, condition, deadline)
    }
}

fn prepared(descriptor: &OwnerDescriptor) -> PreparedOwner {
    PreparedOwner {
        scope: descriptor.scope.clone(),
        input: descriptor.input.clone(),
        reference: descriptor.reference(),
    }
}

fn observation(
    head: Head,
    descriptor: &OwnerDescriptor,
    accepted: Option<OwnerPlan>,
    claimable: bool,
) -> OwnerObservation {
    let state = match accepted.as_ref().map(|plan| plan.phase.kind) {
        Some(OwnerPhaseKind::Claimed) => OwnerState::Claimed,
        Some(OwnerPhaseKind::Cancelling) => OwnerState::Cancelling,
        Some(OwnerPhaseKind::Active) => OwnerState::Active,
        Some(OwnerPhaseKind::Aborted) => OwnerState::Aborted,
        None if claimable => OwnerState::Prepared,
        None => OwnerState::Fenced,
    };
    OwnerObservation {
        head,
        prepared: prepared(descriptor),
        state,
        accepted,
    }
}

impl Database {
    fn owner_budget(&self, deadline: Instant) -> Self {
        let mut database = self.clone();
        database.objects = Arc::new(OwnerMeter {
            objects: self.objects.clone(),
            head: head_key(&self.scope),
            prefix: owner_format::prefix(&self.scope),
            remaining: AtomicUsize::new(8),
            deadline,
            payload_gets: self.options.owner_recovery_gets,
            payload_bytes: self.options.owner_recovery_bytes,
            used: Mutex::new(PayloadUsage::default()),
            now: Instant::now,
        });
        database
    }

    fn owner_head(&self, principal: u64, deadline: Instant) -> Result<Snapshot, Error> {
        let base = self.read_head(deadline)?;
        Self::permission(&base.head, principal, false, false, true)?;
        Ok(base)
    }

    fn owner_descriptor(
        &self,
        identity: &OwnerIdentity,
        deadline: Instant,
    ) -> Result<Option<OwnerDescriptor>, Error> {
        let key = owner_format::key(&self.scope, identity, false);
        self.owner_decode_descriptor(identity, self.objects.get(&key, MAX_DESCRIPTOR, deadline))
    }

    fn owner_decode_descriptor(
        &self,
        identity: &OwnerIdentity,
        stored: Result<Stored, StoreError>,
    ) -> Result<Option<OwnerDescriptor>, Error> {
        let stored = match stored {
            Ok(stored) => stored,
            Err(StoreError::Missing) => return Ok(None),
            Err(error) => return Err(Error::Store(error)),
        };
        let descriptor =
            OwnerDescriptor::decode(&stored.bytes).map_err(|_| self.observe(Error::Corrupt))?;
        if stored.etag.is_empty()
            || descriptor.scope != self.scope
            || descriptor.input.identity() != *identity
        {
            return Err(self.observe(Error::Corrupt));
        }
        Ok(Some(descriptor))
    }

    fn owner_reference(
        &self,
        reference: &OwnerPlanRef,
        deadline: Instant,
    ) -> Result<OwnerDescriptor, Error> {
        reference.validate().map_err(Error::Format)?;
        let descriptor = self
            .owner_descriptor(&reference.identity(), deadline)?
            .ok_or(Error::Store(StoreError::Missing))?;
        if descriptor.reference() != *reference {
            return Err(Error::Conflict);
        }
        Ok(descriptor)
    }

    fn owner_marker(&self, descriptor: &OwnerDescriptor, marker: &OwnerPlan) -> Result<(), Error> {
        descriptor
            .marker(marker)
            .map_err(|_| self.observe(Error::Corrupt))
    }

    fn owner_admission(head: &Head) -> Result<(), Error> {
        Self::ready(head)?;
        Self::no_pending_owner(head)?;
        if head.storage.plan.is_some()
            || head.storage.sweep.is_some()
            || head.storage.terminal.is_some()
        {
            return Err(Error::Fenced);
        }
        head.revision.checked_add(2).ok_or(Error::Limit)?;
        head.head_serial.checked_add(2).ok_or(Error::Limit)?;
        Ok(())
    }

    fn owner_mode(head: &Head, input: &PrepareOwnerInput) -> Result<(), Error> {
        match input.mode {
            OwnerMode::Takeover => {
                head.owner_epoch.checked_add(1).ok_or(Error::Limit)?;
            }
            OwnerMode::Activate => {
                if head.active || head.owner_instance != input.target_worker {
                    return Err(Error::Fenced);
                }
            }
        }
        Ok(())
    }

    /// Fixed caller input makes a lost prepare response recoverable without a
    /// known descriptor hash. An existing record is never rebuilt at a new base.
    pub fn owner_prepare(
        &self,
        principal: u64,
        input: &PrepareOwnerInput,
        deadline: Instant,
    ) -> Result<OwnerPreparation, Error> {
        input.validate().map_err(Error::Format)?;
        let deadline = self.options.deadline(deadline, false);
        let database = self.owner_budget(deadline);
        let identity = input.identity();
        let key = owner_format::key(&self.scope, &identity, false);
        // Hold the raw result until the subsequent fresh HEAD authorizes the
        // caller. A slow descriptor GET must not preserve an old ADMIN grant.
        let mut stored = database.objects.get(&key, MAX_DESCRIPTOR, deadline);
        let base = database.owner_head(principal, deadline)?;
        if matches!(stored, Err(StoreError::Missing)) {
            // Missing was observed before this HEAD. Another caller may have
            // created and admitted the descriptor in between those reads.
            // Re-read after HEAD1, then authorize/stabilize HEAD2 before
            // interpreting the dependency, input conflict or transport error.
            stored = database.objects.get(&key, MAX_DESCRIPTOR, deadline);
            database.owner_barrier(principal, &base, deadline)?;
        }
        if let Some(descriptor) = database.owner_decode_descriptor(&identity, stored)? {
            if descriptor.input != *input {
                return Err(Error::Conflict);
            }
            if let Some(marker) = base
                .head
                .owner_plan
                .as_ref()
                .filter(|marker| marker.reference.identity() == identity)
            {
                database.owner_marker(&descriptor, marker)?;
            }
            return Ok(OwnerPreparation::Prepared(prepared(&descriptor)));
        }
        if base
            .head
            .owner_plan
            .as_ref()
            .is_some_and(|marker| marker.reference.identity() == identity)
        {
            return Err(database.observe(Error::Corrupt));
        }
        if let Some(marker) = base
            .head
            .owner_plan
            .as_ref()
            .filter(|marker| marker.pending())
        {
            return Ok(OwnerPreparation::Pending(marker.reference.clone()));
        }
        if input.creator != principal {
            return Err(Error::Denied);
        }
        if input.expected_revision != base.head.revision
            || input.expected_head_serial != base.head.head_serial
        {
            return Err(Error::Conflict);
        }
        Self::owner_admission(&base.head)?;
        Self::owner_mode(&base.head, input)?;
        // A proof is permanent evidence that this absent descriptor was once
        // authoritative. Do not conceal a missing dependency by recreating it.
        let proof_key = owner_format::key(&self.scope, &identity, true);
        match database.objects.get(&proof_key, MAX_PROOF, deadline) {
            Err(StoreError::Missing) => {}
            Ok(_) => {
                // A competing admission and replacement may have created this
                // proof after our absence observation. Only an unchanged HEAD
                // can turn that observation into a missing dependency.
                database.owner_barrier(principal, &base, deadline)?;
                return Err(database.observe(Error::Corrupt));
            }
            Err(error) => return Err(Error::Store(error)),
        }
        let descriptor = OwnerDescriptor::new(&base, input).map_err(Error::Format)?;
        // No mutation follows new's strict validation. Its fixed-width fields
        // and 1,024-byte ASCII ETag (even doubled by JSON escapes) have a
        // strict total bound below the 16 KiB record ceiling.
        let bytes = descriptor.bytes().expect("new bounded descriptor is valid");
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
            .owner_decode_descriptor(&identity, stored)?
            .ok_or_else(|| database.observe(Error::Corrupt))?;
        if durable != descriptor {
            return Err(Error::Conflict);
        }
        if !exact {
            return Err(database.observe(Error::Corrupt));
        }
        Ok(OwnerPreparation::Prepared(prepared(&durable)))
    }

    fn owner_barrier(
        &self,
        principal: u64,
        base: &Snapshot,
        deadline: Instant,
    ) -> Result<(), Error> {
        let current = self.owner_head(principal, deadline)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn owner_observe(
        &self,
        principal: u64,
        base: Snapshot,
        descriptor: &OwnerDescriptor,
        deadline: Instant,
    ) -> Result<OwnerObservation, Error> {
        let accepted = if let Some(marker) = base
            .head
            .owner_plan
            .as_ref()
            .filter(|marker| marker.reference.identity() == descriptor.input.identity())
        {
            if marker.reference != descriptor.reference() {
                // One immutable identity cannot name two first-persisted
                // descriptors. Establish the stable observation before latching.
                self.owner_barrier(principal, &base, deadline)?;
                return Err(self.observe(Error::Corrupt));
            }
            self.owner_marker(descriptor, marker)?;
            Some(marker.clone())
        } else {
            let key = owner_format::key(&self.scope, &descriptor.input.identity(), true);
            match self.objects.get(&key, MAX_PROOF, deadline) {
                Ok(stored) => {
                    let proof = OwnerProof::decode(&stored.bytes)
                        .map_err(|_| self.observe(Error::Corrupt))?;
                    if stored.etag.is_empty() || proof.scope != self.scope {
                        return Err(self.observe(Error::Corrupt));
                    }
                    self.owner_marker(descriptor, &proof.marker)?;
                    let earlier = base.head.owner_plan.as_ref().is_some_and(|current| {
                        proof.marker.phase.revision < current.admission.revision
                            && proof.marker.phase.head_serial < current.admission.head_serial
                    });
                    if !earlier {
                        // It may have appeared after HEAD1. A changing final
                        // HEAD is a conflict, not a forged historical record.
                        self.owner_barrier(principal, &base, deadline)?;
                        return Err(self.observe(Error::Corrupt));
                    }
                    Some(proof.marker)
                }
                Err(StoreError::Missing) => None,
                Err(error) => return Err(Error::Store(error)),
            }
        };
        self.owner_barrier(principal, &base, deadline)?;
        let claimable = descriptor.matches(&base);
        Ok(observation(base.head, descriptor, accepted, claimable))
    }

    /// No hash is required to find the first persisted operation after a lost
    /// prepare response. Callers compare its actual input with their saved input.
    pub fn owner_inspect(
        &self,
        principal: u64,
        identity: &OwnerIdentity,
        deadline: Instant,
    ) -> Result<OwnerObservation, Error> {
        identity.validate().map_err(Error::Format)?;
        let deadline = self.options.deadline(deadline, false);
        let database = self.owner_budget(deadline);
        let base = database.owner_head(principal, deadline)?;
        let descriptor = database
            .owner_descriptor(identity, deadline)?
            .ok_or(Error::Store(StoreError::Missing))?;
        database.owner_observe(principal, base, &descriptor, deadline)
    }

    fn owner_preserve(&self, base: &Head, deadline: Instant) -> Result<(), Error> {
        let Some(marker) = &base.owner_plan else {
            return Ok(());
        };
        let descriptor = self
            .owner_descriptor(&marker.reference.identity(), deadline)?
            .ok_or_else(|| self.observe(Error::Corrupt))?;
        self.owner_marker(&descriptor, marker)?;
        let proof = OwnerProof {
            version: 1,
            scope: self.scope.clone(),
            marker: marker.clone(),
        };
        let bytes = proof.bytes().map_err(Error::Format)?;
        let key = owner_format::key(&self.scope, &marker.reference.identity(), true);
        match self.objects.put(&key, &bytes, Condition::Absent, deadline) {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(Error::Store(error)),
        }
        let durable = self
            .objects
            .get(&key, MAX_PROOF, deadline)
            .map_err(Error::Store)?;
        if durable.etag.is_empty() || durable.bytes != bytes {
            return Err(self.observe(Error::Corrupt));
        }
        Ok(())
    }

    fn owner_publish(
        &self,
        base: Snapshot,
        next: Head,
        descriptor: &OwnerDescriptor,
        deadline: Instant,
    ) -> Result<OwnerObservation, Error> {
        let marker = next
            .owner_plan
            .as_ref()
            .expect("owner transition installs a marker");
        self.owner_marker(descriptor, marker)?;
        self.healthy_in(base.head.storage.active_generation)?;
        let accepted = Some(marker.clone());
        let candidate = VerifiedOwnerTransition {
            base,
            next: next.clone(),
        };
        let publication = PreparedHead::owner(self, candidate, deadline)?;
        self.publish_healthy(publication)?;
        Ok(observation(next, descriptor, accepted, false))
    }

    fn owner_start(
        &self,
        base: Snapshot,
        descriptor: &OwnerDescriptor,
        kind: OwnerAdmissionKind,
        deadline: Instant,
    ) -> Result<OwnerObservation, Error> {
        Self::owner_admission(&base.head)?;
        Self::owner_mode(&base.head, &descriptor.input)?;
        self.owner_preserve(&base.head, deadline)?;
        let (phase, nonce) = match kind {
            OwnerAdmissionKind::Claim => (OwnerPhaseKind::Claimed, descriptor.input.nonces.claim),
            OwnerAdmissionKind::Cancel => {
                (OwnerPhaseKind::Cancelling, descriptor.input.nonces.cancel)
            }
        };
        // The same immutable base passed owner_admission's +2 reservation.
        let mut next = Self::next(&base.head, nonce).expect("owner admission reserved counters");
        next.format = 8;
        next.active = false;
        if kind == OwnerAdmissionKind::Claim && descriptor.input.mode == OwnerMode::Takeover {
            next.owner_epoch += 1; // owner_admission/mode and exact descriptor checked above.
            next.owner_instance = descriptor.input.target_worker;
        }
        next.owner_plan = Some(OwnerPlan {
            reference: descriptor.reference(),
            admission: OwnerAdmission {
                kind,
                revision: next.revision,
                head_serial: next.head_serial,
            },
            phase: OwnerPhase {
                kind: phase,
                revision: next.revision,
                head_serial: next.head_serial,
                nonce,
                owner_epoch: next.owner_epoch,
                owner_instance: next.owner_instance,
            },
        });
        self.owner_publish(base, next, descriptor, deadline)
    }

    pub fn owner_claim(
        &self,
        principal: u64,
        reference: &OwnerPlanRef,
        deadline: Instant,
    ) -> Result<OwnerObservation, Error> {
        let deadline = self.options.deadline(deadline, false);
        let database = self.owner_budget(deadline);
        let base = database.owner_head(principal, deadline)?;
        let descriptor = database.owner_reference(reference, deadline)?;
        if self.worker != descriptor.input.target_worker {
            return Err(Error::Fenced);
        }
        if !descriptor.matches(&base) {
            return database.owner_observe(principal, base, &descriptor, deadline);
        }
        database.owner_start(base, &descriptor, OwnerAdmissionKind::Claim, deadline)
    }

    /// At most one HEAD CAS: an unaccepted plan first installs Cancelling;
    /// a later invocation can finish Aborted after a crash or lost response.
    pub fn owner_abort(
        &self,
        principal: u64,
        reference: &OwnerPlanRef,
        deadline: Instant,
    ) -> Result<OwnerObservation, Error> {
        let deadline = self.options.deadline(deadline, false);
        let database = self.owner_budget(deadline);
        let base = database.owner_head(principal, deadline)?;
        let descriptor = database.owner_reference(reference, deadline)?;
        if let Some(marker) = base
            .head
            .owner_plan
            .as_ref()
            .filter(|m| m.reference == *reference)
        {
            database.owner_marker(&descriptor, marker)?;
            if marker.pending() {
                let next = terminal(
                    &base.head,
                    OwnerPhaseKind::Aborted,
                    descriptor.input.nonces.abort,
                )
                .expect("validated pending HEAD reserves its terminal counters");
                return database.owner_publish(base, next, &descriptor, deadline);
            }
        }
        if descriptor.matches(&base) {
            return database.owner_start(base, &descriptor, OwnerAdmissionKind::Cancel, deadline);
        }
        database.owner_observe(principal, base, &descriptor, deadline)
    }

    /// Some(Session) belongs only to this invocation's complete recovery and
    /// accepted Active CAS. Observing an old terminal result yields None.
    pub fn owner_resume(
        &self,
        principal: u64,
        reference: &OwnerPlanRef,
        directory: &Path,
        deadline: Instant,
    ) -> Result<(OwnerObservation, Option<Session>), Error> {
        let deadline = self.options.deadline(deadline, true);
        let database = self.owner_budget(deadline);
        let base = database.owner_head(principal, deadline)?;
        let descriptor = database.owner_reference(reference, deadline)?;
        if self.worker != descriptor.input.target_worker {
            return Err(Error::Fenced);
        }
        let claimed = base.head.owner_plan.as_ref().filter(|marker| {
            marker.reference == *reference && marker.phase.kind == OwnerPhaseKind::Claimed
        });
        let Some(marker) = claimed else {
            return database
                .owner_observe(principal, base, &descriptor, deadline)
                .map(|o| (o, None));
        };
        database.owner_marker(&descriptor, marker)?;
        let objects = ObjectContext::from_snapshot(&database, &base, deadline)?;
        // Keep the native gate on the original shared-lineage Database. The
        // bounded operation meter belongs only to this recovery's object reads.
        let mut session = self.restore(&objects, &base, directory, deadline)?;
        database.verify_results(&objects, &base.head, deadline)?;
        session.history_verified = true;
        database.owner_barrier(principal, &base, deadline)?;
        let next = terminal(
            &base.head,
            OwnerPhaseKind::Active,
            descriptor.input.nonces.activate,
        )
        .expect("validated pending HEAD reserves its terminal counters");
        let observation = database.owner_publish(base, next, &descriptor, deadline)?;
        Ok((observation, Some(session)))
    }
}

fn terminal(base: &Head, kind: OwnerPhaseKind, nonce: u64) -> Result<Head, Error> {
    let mut next = Database::next(base, nonce)?;
    next.active = kind == OwnerPhaseKind::Active;
    let marker = next
        .owner_plan
        .as_mut()
        .expect("current validated owner plan");
    marker.phase.kind = kind;
    marker.phase.revision = next.revision;
    marker.phase.head_serial = next.head_serial;
    marker.phase.nonce = nonce;
    Ok(next)
}

#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
