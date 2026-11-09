//! Immutable object addressing captured for one observed HEAD or bootstrap.
//!
//! The physical storage generation is captured from one validated HEAD.
//! Keeping that choice in this value prevents object algorithms from consulting
//! mutable authority partway through an attempt. This is not a pin or
//! reclamation authorization; format 5 currently admits generation one only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::data_tree::DataObjects;
use crate::format::{
    digest, encode_object, object_key, Envelope, Head, Payload, Scope, ValidatedFrame,
    INITIAL_STORAGE_GENERATION, MAX_OBJECT_BYTES,
};
use crate::{Database, Error};

pub(super) struct ObjectContext {
    objects: Arc<dyn Objects>,
    scope: Scope,
    storage_generation: u64,
    quarantined: Arc<AtomicBool>,
}

impl ObjectContext {
    /// The private caller has already validated and authorized this exact HEAD.
    /// Capturing its namespace does not re-read HEAD or extend the deadline.
    pub(super) fn capture(database: &Database, head: &Head) -> Self {
        Self::new(database, &head.scope, head.storage.active_generation)
    }

    /// Explicit creation is the only production path without an existing HEAD.
    /// Its immutable dependencies can become orphans if HEAD creation loses.
    pub(super) fn bootstrap(database: &Database) -> Self {
        Self::new(database, &database.scope, INITIAL_STORAGE_GENERATION)
    }

    fn new(database: &Database, scope: &Scope, storage_generation: u64) -> Self {
        Self {
            objects: database.objects.clone(),
            scope: scope.clone(),
            storage_generation,
            quarantined: database.quarantined.clone(),
        }
    }

    pub(super) fn matches(&self, head: &Head) -> bool {
        self.scope == head.scope && self.storage_generation == head.storage.active_generation
    }

    pub(super) fn observe(&self, error: Error) -> Error {
        observe(&self.quarantined, error)
    }

    /// The callback borrows the one original GET buffer. Only source GET/frame
    /// failures are observed here; a callback's later target error must not
    /// quarantine the source namespace.
    pub(super) fn with_raw<T>(
        &self,
        hash: &str,
        deadline: Instant,
        callback: impl FnOnce(&str, ValidatedFrame<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let key = object_key(&self.scope, self.storage_generation, hash);
        let stored = self
            .objects
            .get(&key, MAX_OBJECT_BYTES, deadline)
            .map_err(|error| self.observe(Error::Store(error)))?;
        let frame = ValidatedFrame::parse(&stored.bytes, &self.scope, hash)
            .map_err(|error| self.observe(Error::Format(error)))?;
        callback(&key, frame)
    }
}

pub(super) fn observe(quarantined: &AtomicBool, error: Error) -> Error {
    if matches!(
        error,
        Error::Corrupt
            | Error::Format(_)
            | Error::Store(StoreError::Missing | StoreError::Corrupt | StoreError::Limit)
            | Error::Engine(scap_object_sqlite::Error::InvalidImage)
    ) {
        quarantined.store(true, Ordering::Release);
    }
    error
}

impl DataObjects for ObjectContext {
    fn load(&self, root: &str, deadline: Instant) -> Result<Payload, Error> {
        self.with_raw(root, deadline, |_, frame| Ok(frame.into_envelope().payload))
    }

    fn save(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
        let envelope = Envelope {
            format: 2,
            scope: self.scope.clone(),
            payload,
        };
        let bytes = encode_object(&envelope).map_err(Error::Format)?;
        let root = digest(&bytes);
        let key = object_key(&self.scope, self.storage_generation, &root);
        match self.objects.put(&key, &bytes, Condition::Absent, deadline) {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(Error::Store(error)),
        }
        // Immutable-key collisions are accepted only after exact read-back.
        let stored = self
            .objects
            .get(&key, MAX_OBJECT_BYTES, deadline)
            .map_err(|error| observe(&self.quarantined, Error::Store(error)))?;
        if stored.bytes != bytes {
            return Err(observe(&self.quarantined, Error::Corrupt));
        }
        Ok(root)
    }
}
