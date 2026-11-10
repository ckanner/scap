//! One metadata-only replacement of an originally observed authority body.
//!
//! This private primitive grants no permission or immutable-read protection.
//! Business publication retains its own manifest, quota and health checks.
//! Storage transitions enter only through the sealed reclamation candidate;
//! their admission and complete-copy checks remain in that owning module.

use std::sync::Arc;
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::format::{encode_head, head_key, FormatError, Head};
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
        if next.storage != base.head.storage || base.head.storage.terminal.is_some() {
            return Err(Error::Format(FormatError::Invalid));
        }
        Self::bound(database, base, next, deadline)
    }

    pub(super) fn technical(
        database: &Database,
        candidate: crate::reclamation::TechnicalHead,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let (base, next) = candidate.into_parts();
        Self::bound(database, &base, &next, deadline)
    }

    pub(super) fn domain(&self) -> PublicationDomain {
        self.domain
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
