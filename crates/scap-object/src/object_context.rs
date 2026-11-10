//! One immutable namespace and one non-resumable operation prefix.
//! Diagnostics use the same backend/meter, Scope and original deadline.

use crate::data_tree::DataObjects;
use crate::format::{
    decode_head, digest, encode_object, head_key, object_key, CopyPlan, Envelope, Head, Payload,
    Scope, ValidatedFrame, INITIAL_STORAGE_GENERATION, MAX_HEAD_BYTES, MAX_OBJECT_BYTES,
};
use crate::{Database, Error, Snapshot};
use scap_object_store::{Condition, Objects, StoreError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

const MAX_CONTEXTS: usize = 64;

#[derive(Default)]
pub(super) struct Knowledge {
    slots: Mutex<Vec<Slot>>,
}
struct Slot {
    generation: u64,
    references: usize,
    incident: bool,
    retired: bool,
}

struct AuthorityBasis {
    serial: u64,
    active: u64,
    allocated: u64,
    etag: String,
    fingerprint: String,
}
fn head_fingerprint(head: &Head) -> String {
    digest(&serde_json::to_vec(head).expect("HEAD values serialize"))
}

impl Knowledge {
    fn acquire(&self, generation: u64) -> bool {
        let mut slots = self.slots.lock().expect("private lineage knowledge");
        if slots.iter().map(|slot| slot.references).sum::<usize>() >= MAX_CONTEXTS {
            return false;
        }
        if let Some(slot) = slots.iter_mut().find(|slot| slot.generation == generation) {
            slot.references += 1;
        } else {
            if slots.len() == MAX_CONTEXTS {
                return false;
            }
            slots.push(Slot {
                generation,
                references: 1,
                incident: false,
                retired: false,
            });
        }
        true
    }

    fn release(&self, generation: u64) {
        let mut slots = self.slots.lock().expect("private lineage knowledge");
        let slot = slots
            .iter_mut()
            .find(|slot| slot.generation == generation)
            .expect("owned lineage slot");
        slot.references -= 1;
        slots.retain(|slot| slot.references != 0 || (slot.incident && !slot.retired));
    }

    fn incident(&self, generation: u64, retired: bool) {
        let mut slots = self.slots.lock().expect("private lineage knowledge");
        let slot = slots
            .iter_mut()
            .find(|slot| slot.generation == generation)
            .expect("owned lineage slot");
        slot.incident = true;
        slot.retired |= retired;
    }

    pub(super) fn blocked(&self, generation: Option<u64>) -> bool {
        self.slots
            .lock()
            .expect("private lineage knowledge")
            .iter()
            .any(|slot| slot.incident && generation.is_none_or(|g| g == slot.generation))
    }
}

pub(super) struct ObjectContext {
    objects: Arc<dyn Objects>,
    scope: Scope,
    storage_generation: u64,
    basis: Option<AuthorityBasis>,
    quarantined: Arc<AtomicBool>,
    knowledge: Arc<Knowledge>,
    registered: bool,
    failed: AtomicBool,
    deadline: OnceLock<Instant>,
}

impl ObjectContext {
    pub(super) fn from_snapshot(
        database: &Database,
        snapshot: &Snapshot,
        deadline: Instant,
    ) -> Result<Self, Error> {
        Self::bound(
            database,
            snapshot,
            snapshot.head.storage.active_generation,
            deadline,
        )
    }

    fn bound(
        database: &Database,
        snapshot: &Snapshot,
        generation: u64,
        deadline: Instant,
    ) -> Result<Self, Error> {
        if snapshot.head.storage.terminal.is_some() {
            return Err(Error::Lifecycle);
        }
        let context = Self::new(
            database,
            &snapshot.head.scope,
            generation,
            Some(AuthorityBasis {
                serial: snapshot.head.head_serial,
                active: snapshot.head.storage.active_generation,
                allocated: snapshot.head.storage.allocated_through,
                etag: snapshot.etag.clone(),
                fingerprint: head_fingerprint(&snapshot.head),
            }),
        );
        context
            .deadline
            .set(deadline)
            .expect("new context deadline");
        Ok(context)
    }

    #[cfg(test)]
    pub(super) fn capture(database: &Database, head: &Head) -> Result<Self, Error> {
        if head.storage.terminal.is_some() {
            return Err(Error::Lifecycle);
        }
        Ok(Self::new(
            database,
            &head.scope,
            head.storage.active_generation,
            None,
        ))
    }

    pub(super) fn target(
        database: &Database,
        snapshot: &Snapshot,
        plan: &CopyPlan,
        deadline: Instant,
    ) -> Result<Self, Error> {
        if snapshot.head.storage.plan.as_ref() != Some(plan) || !plan.basis.matches(&snapshot.head)
        {
            return Err(Error::Conflict);
        }
        Self::bound(database, snapshot, plan.target, deadline)
    }

    pub(super) fn bootstrap(database: &Database) -> Self {
        Self::new(database, &database.scope, INITIAL_STORAGE_GENERATION, None)
    }

    pub(super) fn bootstrap_at(database: &Database, deadline: Instant) -> Self {
        let context = Self::bootstrap(database);
        context
            .deadline
            .set(deadline)
            .expect("new bootstrap deadline");
        context
    }

    fn new(
        database: &Database,
        scope: &Scope,
        storage_generation: u64,
        basis: Option<AuthorityBasis>,
    ) -> Self {
        Self {
            objects: database.objects.clone(),
            scope: scope.clone(),
            storage_generation,
            basis,
            quarantined: database.quarantined.clone(),
            knowledge: database.knowledge.clone(),
            registered: database.knowledge.acquire(storage_generation),
            failed: AtomicBool::new(false),
            deadline: OnceLock::new(),
        }
    }

    pub(super) fn matches(&self, head: &Head) -> bool {
        head.storage.terminal.is_none()
            && self.scope == head.scope
            && self.storage_generation == head.storage.active_generation
    }

    fn check(&self, deadline: Instant) -> Result<Instant, Error> {
        if !self.registered {
            return Err(Error::Store(StoreError::Budget));
        }
        let deadline = deadline.min(*self.deadline.get_or_init(|| deadline));
        if self.failed.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Error::Unknown);
        }
        Ok(deadline)
    }

    pub(super) fn healthy(&self) -> Result<(), Error> {
        if !self.registered {
            return Err(Error::Store(StoreError::Budget));
        }
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Unknown);
        }
        if self.quarantined.load(Ordering::Acquire)
            || self.knowledge.blocked(Some(self.storage_generation))
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    pub(super) fn observe(&self, error: Error) -> Error {
        if self.failed.swap(true, Ordering::AcqRel) {
            error
        } else {
            observe(&self.quarantined, error)
        }
    }

    fn physical(&self, error: Error, deadline: Instant) -> Error {
        if self.failed.swap(true, Ordering::AcqRel) {
            return error;
        }
        self.knowledge.incident(self.storage_generation, false);
        if Instant::now() >= deadline {
            return error;
        }
        // No recursive failure classification, fresh authorization or Snapshot output.
        let Ok(stored) = self
            .objects
            .get(&head_key(&self.scope), MAX_HEAD_BYTES, deadline)
        else {
            return error;
        };
        let head = match decode_head(&stored.bytes, &self.scope) {
            Ok(head) if !stored.etag.is_empty() => head,
            _ => {
                self.quarantined.store(true, Ordering::Release);
                return error;
            }
        };
        if let Some(basis) = &self.basis {
            if head.head_serial < basis.serial
                || head.storage.active_generation < basis.active
                || head.storage.allocated_through < basis.allocated
                || (head.head_serial == basis.serial
                    && (stored.etag != basis.etag || head_fingerprint(&head) != basis.fingerprint))
                || (head.head_serial > basis.serial && stored.etag == basis.etag)
                || head
                    .storage
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| terminal.serial <= basis.serial)
            {
                self.quarantined.store(true, Ordering::Release);
                return error;
            }
            // The original active/copy generation was protected. Same-serial
            // body equality above therefore cannot prove retirement; a valid
            // retirement observation necessarily has a strictly newer serial.
        }
        if head.storage.retired(self.storage_generation) {
            self.knowledge.incident(self.storage_generation, true);
            Error::SnapshotExpired
        } else {
            error
        }
    }

    fn source_error(&self, error: StoreError, deadline: Instant) -> Error {
        if matches!(
            error,
            StoreError::Missing | StoreError::Corrupt | StoreError::Limit
        ) {
            self.physical(Error::Store(error), deadline)
        } else {
            self.failed.store(true, Ordering::Release);
            Error::Store(error)
        }
    }

    /// A visitor's target/local failure closes the prefix without poisoning source.
    pub(super) fn with_raw<T>(
        &self,
        hash: &str,
        deadline: Instant,
        callback: impl FnOnce(&str, ValidatedFrame<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let deadline = self.check(deadline)?;
        let key = object_key(&self.scope, self.storage_generation, hash);
        let stored = self
            .objects
            .get(&key, MAX_OBJECT_BYTES, deadline)
            .map_err(|error| self.source_error(error, deadline))?;
        if stored.bytes.len() > MAX_OBJECT_BYTES || digest(&stored.bytes) != hash {
            return Err(self.physical(Error::Format(crate::format::FormatError::Corrupt), deadline));
        }
        // Hash-valid malformed structure/type/Scope is a content-semantic fault.
        let frame = ValidatedFrame::parse(&stored.bytes, &self.scope, hash)
            .map_err(|error| self.observe(Error::Format(error)))?;
        callback(&key, frame).inspect_err(|_| {
            self.failed.store(true, Ordering::Release);
        })
    }

    pub(super) fn save_raw(
        &self,
        hash: &str,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), Error> {
        let deadline = self.check(deadline)?;
        let key = object_key(&self.scope, self.storage_generation, hash);
        match self.objects.put(&key, bytes, Condition::Absent, deadline) {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                return Err(Error::Store(error));
            }
        }
        let stored = self
            .objects
            .get(&key, MAX_OBJECT_BYTES, deadline)
            .map_err(|error| self.source_error(error, deadline))?;
        if stored.bytes != bytes {
            if digest(&stored.bytes) != hash {
                return Err(self.physical(Error::Corrupt, deadline));
            }
            return Err(self.observe(Error::Corrupt));
        }
        Ok(())
    }
}

impl Drop for ObjectContext {
    fn drop(&mut self) {
        if self.registered {
            self.knowledge.release(self.storage_generation);
        }
    }
}

/// Authority/content semantics only. Captured contexts own physical failures.
pub(super) fn observe(quarantined: &AtomicBool, error: Error) -> Error {
    if matches!(
        error,
        Error::Corrupt | Error::Format(_) | Error::Engine(scap_object_sqlite::Error::InvalidImage)
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
        self.save_raw(&root, &bytes, deadline)?;
        Ok(root)
    }
}
