//! One metadata-only replacement of an originally observed authority body.
//!
//! This private primitive grants no permission or immutable-read protection.
//! Business publication retains its own manifest, quota and health checks.
//! Future technical transitions must supply their complete admission protocol
//! before using it; the current decoder rejects pins and migration states.

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
}

impl PreparedHead {
    pub(super) fn new(
        database: &Database,
        base: &Snapshot,
        next: &Head,
        deadline: Instant,
    ) -> Result<Self, Error> {
        if base.head.scope != database.scope
            || next.scope != base.head.scope
            || next.storage != base.head.storage
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
