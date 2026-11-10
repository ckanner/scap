//! Explicit administrator compaction and bounded, restartable retired-key sweep.
//! Ordinary readers have no durable pins. This module admits no retained roots.

use crate::format::*;
use crate::head_publication::PreparedHead;
use crate::object_context::ObjectContext;
use crate::{closure, Database, Error, Snapshot};
use scap_object_store::{
    DeleteOutcome, Garbage, GcCandidate, ListEnd, ListKind, ListMode, ListRequest, Listings,
};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepReport {
    pub head: Head,
    pub generation: u64,
    pub scanned: u32,
    /// An exclusive lowercase content-hash frontier within this exact generation.
    pub next_after: Option<String>,
    pub exhausted: bool,
}

/// Only this module constructs storage-changing candidates. Ordinary business
/// publication still requires storage equality in PreparedHead::new.
pub(super) struct TechnicalHead {
    base: Snapshot,
    next: Head,
}
impl TechnicalHead {
    pub(super) fn into_parts(self) -> (Snapshot, Head) {
        (self.base, self.next)
    }
}

fn technical_next(base: &Head) -> Result<Head, Error> {
    let mut next = base.clone();
    next.head_serial = base.head_serial.checked_add(1).ok_or(Error::Limit)?;
    Ok(next)
}

fn plan(head: &Head, serial: u64) -> Result<&CopyPlan, Error> {
    head.storage
        .plan
        .as_ref()
        .filter(|plan| serial != 0 && plan.serial == serial)
        .ok_or(Error::Conflict)
}

fn prefix(scope: &Scope, generation: u64) -> String {
    object_key(scope, generation, "")
}

/// A complete prefix is private to this call. Cancellation/deadline failure
/// drops the cursor, even after its last frame, without granting a seal.
fn copy_closure(
    source: &ObjectContext,
    target: &ObjectContext,
    original: &Snapshot,
    plan: &CopyPlan,
    deadline: Instant,
    stop: &dyn Fn() -> bool,
) -> Result<(), Error> {
    let mut cursor = closure::Cursor::for_copy(source, original, plan, deadline, stop)?;
    loop {
        match cursor.advance(closure::StepBudget::default(), &mut |visit| {
            target.save_raw(visit.hash, visit.bytes, deadline)
        })? {
            closure::Step::Pending(next) => cursor = next,
            closure::Step::Complete(proof) => {
                proof.finish(original)?;
                return Ok(());
            }
        }
    }
}

impl Database {
    fn maintenance_base(&self, principal: u64, deadline: Instant) -> Result<Snapshot, Error> {
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, false, false, true)?;
        Self::ready(&base.head)?;
        Ok(base)
    }

    fn publish_technical(
        &self,
        base: &Snapshot,
        next: &Head,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.healthy_in(base.head.storage.active_generation)?;
        let candidate = TechnicalHead {
            base: base.clone(),
            next: next.clone(),
        };
        let publication = PreparedHead::technical(self, candidate, deadline)?;
        self.publish_healthy(publication)
    }

    pub fn compact_begin(
        &self,
        principal: u64,
        expected_head_serial: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.maintenance_base(principal, deadline)?;
        if expected_head_serial != base.head.head_serial
            || base.head.storage.plan.is_some()
            || base.head.storage.sweep.is_some()
        {
            return Err(Error::Conflict);
        }
        let mut next = technical_next(&base.head)?;
        // Valid HEAD has M <= serial; technical_next already proved serial + 1.
        let target = next.storage.allocated_through + 1;
        next.storage.allocated_through = target;
        next.storage.plan = Some(CopyPlan {
            serial: next.head_serial,
            source: next.storage.active_generation,
            target,
            phase: CopyPhase::Copying,
            basis: CopyBasis::capture(&base.head),
        });
        next.active = false;
        self.publish_technical(&base, &next, deadline)?;
        Ok(next)
    }

    /// A restart revalidates the same complete plan from its roots. No disk
    /// cursor or previous process prefix is accepted as a completion proof.
    pub fn compact_copy(
        &self,
        principal: u64,
        plan_serial: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let deadline = self.options.deadline(deadline, true);
        let base = self.maintenance_base(principal, deadline)?;
        let original = plan(&base.head, plan_serial)?.clone();
        if original.phase == CopyPhase::Sealed {
            return Ok(base.head);
        }
        let source = ObjectContext::from_snapshot(self, &base, deadline);
        let target = ObjectContext::target(self, &base, &original, deadline)
            .expect("plan cloned from this immutable, validated original HEAD");
        source.healthy()?;
        target.healthy()?;
        copy_closure(&source, &target, &base, &original, deadline, &|| false)?;
        source.healthy()?;
        target.healthy()?;
        // Current ACL is checked again. Policy changes do not replace the
        // frozen closure or restore an obsolete policy from the copy basis.
        let current = self.maintenance_base(principal, deadline)?;
        let current_plan = plan(&current.head, plan_serial)?;
        if current_plan.source != original.source
            || current_plan.target != original.target
            || current_plan.basis != original.basis
        {
            return Err(Error::Conflict);
        }
        if current_plan.phase == CopyPhase::Sealed {
            return Ok(current.head);
        }
        let mut next = technical_next(&current.head)?;
        next.storage
            .plan
            .as_mut()
            .expect("validated current plan")
            .phase = CopyPhase::Sealed;
        self.publish_technical(&current, &next, deadline)?;
        Ok(next)
    }

    pub fn compact_promote(
        &self,
        principal: u64,
        plan_serial: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.maintenance_base(principal, deadline)?;
        let current = plan(&base.head, plan_serial)?;
        if current.phase != CopyPhase::Sealed {
            return Err(Error::Conflict);
        }
        self.healthy_in(current.target)?;
        let mut next = technical_next(&base.head)?;
        next.storage.active_generation = current.target;
        next.storage.plan = None;
        next.active = false;
        self.publish_technical(&base, &next, deadline)?;
        Ok(next)
    }

    pub fn compact_abort(
        &self,
        principal: u64,
        plan_serial: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.maintenance_base(principal, deadline)?;
        plan(&base.head, plan_serial)?;
        let mut next = technical_next(&base.head)?;
        next.storage.plan = None;
        next.active = false;
        self.publish_technical(&base, &next, deadline)?;
        Ok(next)
    }

    /// Discover at most one page. LIST is only a candidate source: every
    /// persisted ETag comes from the dedicated exact, typed GC GET.
    #[allow(clippy::too_many_arguments)]
    pub fn gc_prepare(
        &self,
        principal: u64,
        expected_head_serial: u64,
        generation: u64,
        after: Option<&str>,
        listings: &dyn Listings,
        garbage: &dyn Garbage,
        deadline: Instant,
    ) -> Result<SweepReport, Error> {
        let base = self.maintenance_base(principal, deadline)?;
        if base.head.head_serial != expected_head_serial
            || base.head.storage.plan.is_some()
            || base.head.storage.sweep.is_some()
        {
            return Err(Error::Conflict);
        }
        if !base.head.storage.retired(generation) {
            return Err(Error::Fenced);
        }
        if after.is_some_and(|hash| !hash_valid(hash)) {
            return Err(Error::Format(FormatError::Invalid));
        }
        let prefix = prefix(&self.scope, generation);
        let frontier = after.map(|hash| format!("{prefix}{hash}"));
        let page = listings
            .list_page(
                &ListRequest {
                    prefix: &prefix,
                    mode: ListMode::Keys,
                    after: frontier.as_deref(),
                },
                deadline,
            )
            .map_err(list_error)?;
        if page.entries.len() > MAX_SWEEP_ENTRIES {
            return Err(Error::Corrupt);
        }
        let scanned = page.entries.len() as u32;
        let mut entries = Vec::new();
        let mut previous = frontier.as_deref();
        for entry in &page.entries {
            let hash = entry
                .key
                .strip_prefix(&prefix)
                .filter(|hash| hash_valid(hash))
                .ok_or(Error::Corrupt)?;
            if entry.kind != ListKind::Object
                || previous.is_some_and(|old| old >= entry.key.as_str())
            {
                return Err(Error::Corrupt);
            }
            previous = Some(&entry.key);
            if let GcCandidate::Present { etag } = garbage
                .inspect(&prefix, hash, deadline)
                .map_err(Error::Gc)?
            {
                entries.push(SweepEntry {
                    key: entry.key.clone(),
                    hash: hash.into(),
                    etag,
                    disposition: SweepDisposition::Pending,
                });
            }
        }
        let (next_after, exhausted) = match &page.end {
            ListEnd::Exhausted => (None, true),
            ListEnd::More { after } => {
                if page.entries.last().is_none_or(|entry| &entry.key != after) {
                    return Err(Error::Corrupt);
                }
                (
                    // This is exactly the last key whose prefix/hash passed above.
                    Some(after[prefix.len()..].into()),
                    false,
                )
            }
        };
        if entries.is_empty() {
            return Ok(SweepReport {
                head: base.head,
                generation,
                scanned,
                next_after,
                exhausted,
            });
        }
        let mut next = technical_next(&base.head)?;
        next.storage.sweep = Some(SweepCheckpoint {
            serial: next.head_serial,
            generation,
            next_after: next_after.clone(),
            exhausted,
            entries,
        });
        self.publish_technical(&base, &next, deadline)?;
        Ok(SweepReport {
            head: next,
            generation,
            scanned,
            next_after,
            exhausted,
        })
    }

    /// Resume only an exactly observed current batch. A lost response is never
    /// translated into an Applied disposition, nor an ETag replacement.
    pub fn gc_resume(
        &self,
        principal: u64,
        batch_serial: u64,
        garbage: &dyn Garbage,
        deadline: Instant,
    ) -> Result<SweepReport, Error> {
        let mut base = self.maintenance_base(principal, deadline)?;
        let checkpoint = base
            .head
            .storage
            .sweep
            .as_ref()
            .filter(|batch| batch_serial != 0 && batch.serial == batch_serial)
            .ok_or(Error::Conflict)?
            .clone();
        // decode_head has proved this checkpoint's generation permanently retired.
        let prefix = prefix(&self.scope, checkpoint.generation);
        let mut disposed = checkpoint.clone();
        for entry in &mut disposed.entries {
            if entry.disposition != SweepDisposition::Pending {
                continue;
            }
            entry.disposition = match garbage
                .inspect(&prefix, &entry.hash, deadline)
                .map_err(Error::Gc)?
            {
                GcCandidate::Missing => SweepDisposition::ObservedAbsent,
                GcCandidate::Present { .. } => match garbage
                    .delete(&prefix, &entry.hash, &entry.etag, deadline)
                    .map_err(Error::Gc)?
                {
                    DeleteOutcome::Applied => SweepDisposition::Applied,
                    DeleteOutcome::Missing => SweepDisposition::ObservedAbsent,
                    DeleteOutcome::Conflict => SweepDisposition::ConditionMismatch,
                },
            };
        }
        if disposed != checkpoint {
            let mut next = technical_next(&base.head)?;
            next.storage.sweep = Some(disposed.clone());
            self.publish_technical(&base, &next, deadline)?;
            base = self.maintenance_base(principal, deadline)?;
            if base.head.storage.sweep.as_ref() != Some(&disposed) {
                return Err(Error::Conflict);
            }
        }
        // Every Pending entry either received a terminal typed outcome above or
        // returned an error. Exact observation has confirmed this settled batch.
        let mut next = technical_next(&base.head)?;
        next.storage.sweep = None;
        self.publish_technical(&base, &next, deadline)?;
        let current = self.maintenance_base(principal, deadline)?;
        if current.head.head_serial < next.head_serial || current.head.storage.sweep.is_some() {
            return Err(Error::Conflict);
        }
        Ok(SweepReport {
            head: current.head,
            generation: checkpoint.generation,
            scanned: checkpoint.entries.len() as u32,
            next_after: checkpoint.next_after,
            exhausted: checkpoint.exhausted,
        })
    }
}

fn list_error(error: scap_object_store::ListError) -> Error {
    use scap_object_store::ListError;
    match error {
        ListError::Invalid => Error::Format(FormatError::Invalid),
        ListError::Limit => Error::Limit,
        ListError::Corrupt => Error::Corrupt,
        ListError::Denied => Error::Denied,
        ListError::Unknown => Error::Unknown,
    }
}

#[cfg(test)]
#[path = "reclamation_tests.rs"]
mod tests;
