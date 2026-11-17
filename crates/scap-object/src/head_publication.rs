//! One metadata-only replacement of an originally observed authority body.
//!
//! This private primitive grants no permission or immutable-read protection.
//! Business publication retains its own manifest, quota and health checks.
//! Storage transitions enter only through the sealed reclamation candidate;
//! their admission and complete-copy checks remain in that owning module.

use std::sync::Arc;
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::format::{encode_head, head_key, FormatError, Head, Lifecycle, NamedDeletionKind};
use crate::{Database, Error, Snapshot};

/// The encoded candidate, original condition and deadline cannot be rebound
/// after preparation. A PUT response is deliberately not a usable Snapshot.
pub(super) struct PreparedHead {
    objects: Arc<dyn Objects>,
    key: String,
    bytes: Vec<u8>,
    etag: String,
    deadline: Instant,
    domain: PublicationDomain,
}

#[derive(Clone, Copy)]
pub(super) enum PublicationDomain {
    Live(u64),
    TerminalMetadata,
}

impl PublicationDomain {
    pub(super) fn original(head: &Head) -> Self {
        if head.storage.terminal.is_some() {
            Self::TerminalMetadata
        } else {
            Self::Live(head.storage.active_generation)
        }
    }
}

impl PreparedHead {
    pub(super) fn new(
        database: &Database,
        base: &Snapshot,
        next: &Head,
        deadline: Instant,
    ) -> Result<Self, Error> {
        if next.storage != base.head.storage
            || base.head.storage.terminal.is_some()
            || next.owner_plan != base.head.owner_plan
            || next.format != base.head.format
            || next.snapshots != base.head.snapshots
            || next.snapshot_limits != base.head.snapshot_limits
            || next.restore_origin != base.head.restore_origin
        {
            return Err(Error::Format(FormatError::Invalid));
        }
        if base.head.owner_plan.is_some() {
            if next.owner_instance != base.head.owner_instance || (!base.head.active && next.active)
            {
                return Err(Error::Format(FormatError::Invalid));
            }
            if next.owner_epoch != base.head.owner_epoch {
                let named_delete = base.head.lifecycle != Lifecycle::Deleted
                    && next.lifecycle == Lifecycle::Deleted
                    && next.creation.is_some()
                    && next
                        .deletion
                        .as_ref()
                        .is_some_and(|deletion| deletion.kind == NamedDeletionKind::Delete)
                    && base.head.owner_epoch.checked_add(1) == Some(next.owner_epoch);
                if !named_delete {
                    return Err(Error::Format(FormatError::Invalid));
                }
            }
        }
        if base
            .head
            .owner_plan
            .as_ref()
            .is_some_and(|plan| plan.pending())
        {
            Database::owner_metadata_room(&base.head)?;
            let mut allowed = base.head.clone();
            allowed.revision = next.revision;
            allowed.head_serial = next.head_serial;
            allowed.transition = next.transition.clone();
            allowed.policy = next.policy.clone();
            allowed.auth_epoch = next.auth_epoch;
            allowed.quota = next.quota.clone();
            if allowed != *next {
                return Err(Error::Format(FormatError::Invalid));
            }
        }
        Self::bound(database, base, next, deadline)
    }

    pub(super) fn owner(
        database: &Database,
        candidate: crate::owner::VerifiedOwnerTransition,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let (base, next) = candidate.into_parts();
        Self::bound(database, &base, &next, deadline)
    }

    pub(super) fn technical(
        database: &Database,
        candidate: crate::reclamation::TechnicalHead,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let (base, next) = candidate.into_parts();
        Self::bound(database, &base, &next, deadline)
    }

    pub(super) fn snapshot(
        database: &Database,
        candidate: crate::snapshot::VerifiedSnapshotTransition,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let (base, next) = candidate.into_parts();
        Self::bound(database, &base, &next, deadline)
    }

    pub(super) fn domain(&self) -> PublicationDomain {
        self.domain
    }

    pub(super) fn restore(
        database: &Database,
        candidate: crate::catalogue::VerifiedRestoreTransition,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let (base, next) = candidate.into_parts();
        Self::bound(database, &base, &next, deadline)
    }

    fn bound(
        database: &Database,
        base: &Snapshot,
        next: &Head,
        deadline: Instant,
    ) -> Result<Self, Error> {
        base.head.validate().map_err(Error::Format)?;
        if base.head.scope != database.scope
            || next.scope != base.head.scope
            || base.etag.is_empty()
        {
            return Err(Error::Format(FormatError::Invalid));
        }
        let serial = base.head.head_serial.checked_add(1).ok_or(Error::Limit)?;
        if next.head_serial != serial {
            return Err(Error::Format(FormatError::Invalid));
        }
        if !crate::snapshot_format::cleanup_room(next) {
            return Err(Error::Limit);
        }
        let bytes = encode_head(next).map_err(Error::Format)?;
        Ok(Self {
            objects: database.objects.clone(),
            key: head_key(&base.head.scope),
            bytes,
            etag: base.etag.clone(),
            deadline,
            domain: PublicationDomain::original(&base.head),
        })
    }

    pub(super) fn publish(self) -> Result<(), Error> {
        match self.objects.put(
            &self.key,
            &self.bytes,
            Condition::Match(&self.etag),
            self.deadline,
        ) {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict) => Err(Error::Conflict),
            Err(error) => Err(Error::Store(error)),
        }
    }
}

#[cfg(test)]
#[path = "head_publication_tests.rs"]
mod tests;
