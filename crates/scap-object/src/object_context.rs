//! Immutable object addressing captured for one observed HEAD or bootstrap.
//!
//! Format 4 has one physical namespace per logical Scope. Keeping that choice
//! in this value prevents object algorithms from consulting Database again
//! partway through an attempt. This is not a pin or reclamation authorization.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::data_tree::DataObjects;
use crate::format::{
    decode_object, digest, encode_object, object_key, Envelope, Head, Payload, Scope,
    MAX_OBJECT_BYTES,
};
use crate::{Database, Error};

pub(super) struct ObjectContext {
    objects: Arc<dyn Objects>,
    scope: Scope,
    quarantined: Arc<AtomicBool>,
}

impl ObjectContext {
    /// The private caller has already validated and authorized this exact HEAD.
    /// Capturing its namespace does not re-read HEAD or extend the deadline.
    pub(super) fn capture(database: &Database, head: &Head) -> Self {
        Self::new(database, &head.scope)
    }

    /// Explicit creation is the only production path without an existing HEAD.
    /// Its immutable dependencies can become orphans if HEAD creation loses.
    pub(super) fn bootstrap(database: &Database) -> Self {
        Self::new(database, &database.scope)
    }

    fn new(database: &Database, scope: &Scope) -> Self {
        Self {
            objects: database.objects.clone(),
            scope: scope.clone(),
            quarantined: database.quarantined.clone(),
        }
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
        let stored = self
            .objects
            .get(&object_key(&self.scope, root), MAX_OBJECT_BYTES, deadline)
            .map_err(|error| observe(&self.quarantined, Error::Store(error)))?;
        Ok(decode_object(&stored.bytes, &self.scope, root)
            .map_err(|error| observe(&self.quarantined, Error::Format(error)))?
            .payload)
    }

    fn save(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
        let envelope = Envelope {
            format: 2,
            scope: self.scope.clone(),
            payload,
        };
        let bytes = encode_object(&envelope).map_err(Error::Format)?;
        let root = digest(&bytes);
        let key = object_key(&self.scope, &root);
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
