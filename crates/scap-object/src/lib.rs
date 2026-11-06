//! Object-authoritative SQLite. Local files never establish committed state.

pub mod format;

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use format::*;
use scap_object_sqlite::{CommitGate, GateDecision, PageBatch, SqliteWriter, WriterLimits};
use scap_object_store::{Condition, Objects, StoreError};
use scap_sql::{SqlLimits, Statement, TransactionResult};

#[derive(Debug)]
pub enum Error {
    Format(FormatError),
    Store(StoreError),
    Sql(scap_sql::SqlError),
    Engine(scap_object_sqlite::Error),
    Denied,
    Lifecycle,
    Fenced,
    Conflict,
    RequestConflict,
    WindowFull,
    Closed,
    Retired,
    Unknown,
    Limit,
    Corrupt,
    CommittedButUnavailable(Box<Receipt>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub scope: Scope,
    pub request: Request,
    pub sequence: u64,
    pub transition: Transition,
    pub data_root: String,
    pub result_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Committed { receipt: Receipt, bytes: Vec<u8> },
    Cancelled { transition: Transition },
    Unknown,
    Closed,
    Retired,
}

#[derive(Clone)]
struct Snapshot {
    head: Head,
    etag: String,
}

/// This is an internal trusted service boundary. `principal` must be supplied
/// by authenticated admission, never copied from an unauthenticated request.
/// The object credentials must not be made available to database clients.
#[derive(Clone)]
pub struct Database {
    objects: Arc<dyn Objects>,
    scope: Scope,
    worker: u64,
}

pub fn sql_limits() -> SqlLimits {
    SqlLimits {
        max_statements: 32,
        max_sql_bytes: 16384,
        max_parameters: 128,
        max_columns: 64,
        max_rows: 1024,
        max_result_bytes: MAX_RESULT_BYTES as u32,
        max_value_bytes: 16384,
    }
}

fn engine_limits() -> WriterLimits {
    WriterLimits {
        sql: sql_limits(),
        max_vm_steps: 1_000_000,
        max_database_pages: MAX_PAGES as u32,
        max_changed_pages: MAX_PAGES as u32,
    }
}

pub fn request(
    epoch: u64,
    id: u64,
    principal: u64,
    statements: &[Statement],
) -> Result<Request, Error> {
    let hash = scap_sql::request_fingerprint(statements, sql_limits()).map_err(Error::Sql)?;
    let fingerprint = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    let request = Request {
        epoch,
        id,
        principal,
        fingerprint,
    };
    request.validate().map_err(Error::Format)?;
    Ok(request)
}

impl Database {
    pub fn new(objects: Arc<dyn Objects>, scope: Scope, worker: u64) -> Result<Self, Error> {
        scope.validate().map_err(Error::Format)?;
        if worker == 0 {
            return Err(Error::Fenced);
        }
        Ok(Self {
            objects,
            scope,
            worker,
        })
    }

    fn read_head(&self, deadline: Instant) -> Result<Snapshot, Error> {
        let object = self
            .objects
            .get(&head_key(&self.scope), MAX_HEAD_BYTES, deadline)
            .map_err(Error::Store)?;
        let head = decode_head(&object.bytes, &self.scope).map_err(Error::Format)?;
        if object.etag.is_empty() {
            return Err(Error::Corrupt);
        }
        Ok(Snapshot {
            head,
            etag: object.etag,
        })
    }

    fn authorize(
        head: &Head,
        principal: u64,
        read: bool,
        write: bool,
        admin: bool,
    ) -> Result<(), Error> {
        if head.lifecycle == Lifecycle::Deleted {
            return Err(Error::Lifecycle);
        }
        let policy = head
            .policy
            .iter()
            .find(|entry| entry.principal == principal)
            .ok_or(Error::Denied)?;
        if (read && !policy.read) || (write && !policy.write) || (admin && !policy.admin) {
            return Err(Error::Denied);
        }
        Ok(())
    }

    fn ready(head: &Head) -> Result<(), Error> {
        if head.lifecycle != Lifecycle::Ready {
            return Err(Error::Lifecycle);
        }
        Ok(())
    }

    fn writer(&self, head: &Head) -> Result<(), Error> {
        Self::ready(head)?;
        if !head.active || head.owner_instance != self.worker {
            return Err(Error::Fenced);
        }
        Ok(())
    }

    fn load(&self, root: &str, deadline: Instant) -> Result<Payload, Error> {
        let stored = self
            .objects
            .get(&object_key(&self.scope, root), MAX_OBJECT_BYTES, deadline)
            .map_err(Error::Store)?;
        Ok(decode_object(&stored.bytes, &self.scope, root)
            .map_err(Error::Format)?
            .payload)
    }

    fn upload(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
        let envelope = Envelope {
            format: 1,
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
            .map_err(Error::Store)?;
        if stored.bytes != bytes {
            return Err(Error::Corrupt);
        }
        Ok(root)
    }

    fn publish(&self, base: &Snapshot, head: &Head, deadline: Instant) -> Result<(), Error> {
        let bytes = encode_head(head).map_err(Error::Format)?;
        self.verify_closure(head, deadline)?;
        match self.objects.put(
            &head_key(&self.scope),
            &bytes,
            Condition::Match(&base.etag),
            deadline,
        ) {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict) => Err(Error::Conflict),
            Err(error) => Err(Error::Store(error)),
        }
    }

    fn next(base: &Head, nonce: u64) -> Result<Head, Error> {
        let mut head = base.clone();
        head.revision = head.revision.checked_add(1).ok_or(Error::Limit)?;
        head.transition = Transition {
            revision: head.revision,
            nonce,
        };
        Ok(head)
    }

    /// Explicit provisioning only. A missing HEAD on every other path is an
    /// error. Reusing a database ID is rejected by conditional creation.
    pub fn create(&self, principal: u64, nonce: u64, deadline: Instant) -> Result<Head, Error> {
        let data_root = self.upload(
            Payload::Manifest(Manifest {
                pages: Vec::new(),
                image_hash: digest(&[]),
            }),
            deadline,
        )?;
        let index = self.upload(Payload::Index(Vec::new()), deadline)?;
        let head = Head {
            format: 1,
            scope: self.scope.clone(),
            revision: 1,
            transition: Transition { revision: 1, nonce },
            sequence: 0,
            owner_epoch: 1,
            owner_instance: self.worker,
            active: false,
            auth_epoch: 1,
            policy: vec![Permission {
                principal,
                read: true,
                write: true,
                admin: true,
            }],
            lifecycle: Lifecycle::Ready,
            data_root,
            request_epoch: 1,
            windows: vec![Window {
                epoch: 1,
                root: index,
                count: 0,
            }],
        };
        let bytes = encode_head(&head).map_err(Error::Format)?;
        self.objects
            .put(&head_key(&self.scope), &bytes, Condition::Absent, deadline)
            .map_err(Error::Store)?;
        Ok(head)
    }

    pub fn status(&self, principal: u64, deadline: Instant) -> Result<Head, Error> {
        let snapshot = self.read_head(deadline)?;
        Self::authorize(&snapshot.head, principal, true, false, false)?;
        Ok(snapshot.head)
    }

    fn manifest(&self, head: &Head, deadline: Instant) -> Result<Manifest, Error> {
        match self.load(&head.data_root, deadline)? {
            Payload::Manifest(manifest) => Ok(manifest),
            _ => Err(Error::Corrupt),
        }
    }

    fn image(&self, head: &Head, deadline: Instant) -> Result<Vec<u8>, Error> {
        let manifest = self.manifest(head, deadline)?;
        let mut bytes = Vec::with_capacity(manifest.pages.len() * PAGE_SIZE);
        for root in manifest.pages {
            match self.load(&root, deadline)? {
                Payload::Page(page) => bytes.extend(page),
                _ => return Err(Error::Corrupt),
            }
        }
        if digest(&bytes) != manifest.image_hash {
            return Err(Error::Corrupt);
        }
        Ok(bytes)
    }

    fn verify_closure(&self, head: &Head, deadline: Instant) -> Result<(), Error> {
        self.image(head, deadline)?;
        for window in &head.windows {
            for entry in self.index(window, deadline)? {
                self.resolve_entry(head, &entry.request, &entry.outcome, deadline)?;
            }
        }
        Ok(())
    }

    fn index(&self, window: &Window, deadline: Instant) -> Result<Vec<Entry>, Error> {
        let entries = match self.load(&window.root, deadline)? {
            Payload::Index(entries) => entries,
            _ => return Err(Error::Corrupt),
        };
        if entries.len() != window.count as usize
            || entries
                .iter()
                .any(|entry| entry.request.epoch != window.epoch)
        {
            return Err(Error::Corrupt);
        }
        Ok(entries)
    }

    fn resolve(
        &self,
        head: &Head,
        request: &Request,
        deadline: Instant,
    ) -> Result<Resolution, Error> {
        request.validate().map_err(Error::Format)?;
        if request.epoch > head.request_epoch {
            return Err(Error::RequestConflict);
        }
        let Some(window) = head
            .windows
            .iter()
            .find(|window| window.epoch == request.epoch)
        else {
            return Ok(Resolution::Retired);
        };
        let entries = self.index(window, deadline)?;
        let Some(entry) = entries
            .into_iter()
            .find(|entry| entry.request.id == request.id)
        else {
            return Ok(if request.epoch == head.request_epoch {
                Resolution::Unknown
            } else {
                Resolution::Closed
            });
        };
        if entry.request != *request {
            return Err(Error::RequestConflict);
        }
        self.resolve_entry(head, request, &entry.outcome, deadline)
    }

    fn resolve_entry(
        &self,
        head: &Head,
        request: &Request,
        outcome: &OutcomeRef,
        deadline: Instant,
    ) -> Result<Resolution, Error> {
        match outcome {
            OutcomeRef::Cancelled { transition } => {
                if transition.revision > head.revision {
                    return Err(Error::Corrupt);
                }
                Ok(Resolution::Cancelled {
                    transition: transition.clone(),
                })
            }
            OutcomeRef::Committed { result } => {
                let stored = match self.load(result, deadline)? {
                    Payload::Result(stored) => stored,
                    _ => return Err(Error::Corrupt),
                };
                if stored.request != *request
                    || stored.sequence > head.sequence
                    || stored.transition.revision > head.revision
                {
                    return Err(Error::Corrupt);
                }
                let receipt = Receipt {
                    scope: self.scope.clone(),
                    request: request.clone(),
                    sequence: stored.sequence,
                    transition: stored.transition,
                    data_root: stored.data_root,
                    result_hash: result.clone(),
                };
                Ok(Resolution::Committed {
                    receipt,
                    bytes: stored.bytes,
                })
            }
        }
    }

    pub fn lookup(
        &self,
        principal: u64,
        request: &Request,
        deadline: Instant,
    ) -> Result<Resolution, Error> {
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, true, false, false)?;
        if request.principal != principal {
            return Err(Error::Denied);
        }
        self.resolve(&base.head, request, deadline)
    }

    fn control(
        &self,
        principal: u64,
        expected_revision: u64,
        deadline: Instant,
    ) -> Result<Snapshot, Error> {
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, false, false, true)?;
        if base.head.revision != expected_revision {
            return Err(Error::Conflict);
        }
        Ok(base)
    }

    pub fn takeover(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.control(principal, expected_revision, deadline)?;
        Self::ready(&base.head)?;
        let mut head = Self::next(&base.head, nonce)?;
        head.owner_epoch = head.owner_epoch.checked_add(1).ok_or(Error::Limit)?;
        head.owner_instance = self.worker;
        head.active = false;
        self.publish(&base, &head, deadline)?;
        Ok(head)
    }

    pub fn activate(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.control(principal, expected_revision, deadline)?;
        Self::ready(&base.head)?;
        if base.head.owner_instance != self.worker || base.head.active {
            return Err(Error::Fenced);
        }
        self.verify_closure(&base.head, deadline)?;
        let current = self.read_head(deadline)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(Error::Conflict);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.active = true;
        self.publish(&base, &head, deadline)?;
        Ok(head)
    }

    pub fn set_policy(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        policy: Vec<Permission>,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.control(principal, expected_revision, deadline)?;
        let mut head = Self::next(&base.head, nonce)?;
        head.auth_epoch = head.auth_epoch.checked_add(1).ok_or(Error::Limit)?;
        head.policy = policy;
        self.publish(&base, &head, deadline)?;
        Ok(head)
    }

    pub fn set_lifecycle(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        lifecycle: Lifecycle,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.control(principal, expected_revision, deadline)?;
        let mut head = Self::next(&base.head, nonce)?;
        head.lifecycle = lifecycle;
        self.publish(&base, &head, deadline)?;
        Ok(head)
    }

    /// Trusted coordinator operation; no tenant-controlled arbitrary rotation.
    /// It closes only a full epoch and retains two complete closed epochs.
    pub fn close_full(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.control(principal, expected_revision, deadline)?;
        if base.head.windows[0].count as usize != MAX_REQUESTS {
            return Err(Error::WindowFull);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.request_epoch = head.request_epoch.checked_add(1).ok_or(Error::Limit)?;
        let root = self.upload(Payload::Index(Vec::new()), deadline)?;
        head.windows.insert(
            0,
            Window {
                epoch: head.request_epoch,
                root,
                count: 0,
            },
        );
        head.windows.truncate(3);
        self.publish(&base, &head, deadline)?;
        Ok(head)
    }

    fn append(&self, head: &mut Head, entry: Entry, deadline: Instant) -> Result<(), Error> {
        let mut entries = self.index(&head.windows[0], deadline)?;
        if entries.len() == MAX_REQUESTS {
            return Err(Error::WindowFull);
        }
        if entries.iter().any(|old| old.request.id == entry.request.id) {
            return Err(Error::RequestConflict);
        }
        entries.push(entry);
        head.windows[0].count = entries.len() as u32;
        head.windows[0].root = self.upload(Payload::Index(entries), deadline)?;
        Ok(())
    }

    pub fn cancel(
        &self,
        principal: u64,
        request: &Request,
        deadline: Instant,
    ) -> Result<Resolution, Error> {
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, true, true, false)?;
        if principal != request.principal {
            return Err(Error::Denied);
        }
        let resolution = self.resolve(&base.head, request, deadline)?;
        if resolution != Resolution::Unknown {
            return Ok(resolution);
        }
        let mut head = Self::next(&base.head, request.id)?;
        let transition = head.transition.clone();
        self.append(
            &mut head,
            Entry {
                request: request.clone(),
                outcome: OutcomeRef::Cancelled {
                    transition: transition.clone(),
                },
            },
            deadline,
        )?;
        self.publish(&base, &head, deadline)?;
        Ok(Resolution::Cancelled { transition })
    }

    fn commit(
        &self,
        base: &Snapshot,
        request: &Request,
        batch: &PageBatch,
        result: &[u8],
        deadline: Instant,
    ) -> Result<Receipt, Error> {
        self.writer(&base.head)?;
        let mut manifest = self.manifest(&base.head, deadline)?;
        let mut image = self.image(&base.head, deadline)?;
        if batch.size_after as usize > MAX_PAGES {
            return Err(Error::Limit);
        }
        image.resize(batch.size_after as usize * PAGE_SIZE, 0);
        manifest
            .pages
            .resize(batch.size_after as usize, String::new());
        let mut seen = std::collections::BTreeSet::new();
        for change in &batch.pages {
            if change.number == 0
                || change.number > batch.size_after
                || change.bytes.len() != PAGE_SIZE
                || !seen.insert(change.number)
            {
                return Err(Error::Corrupt);
            }
            let index = change.number as usize - 1;
            image[index * PAGE_SIZE..(index + 1) * PAGE_SIZE].copy_from_slice(&change.bytes);
            manifest.pages[index] = self.upload(Payload::Page(change.bytes.clone()), deadline)?;
        }
        if manifest.pages.iter().any(|root| root.is_empty()) {
            return Err(Error::Corrupt);
        }
        manifest.image_hash = digest(&image);
        let mut head = Self::next(&base.head, request.id)?;
        head.sequence = head.sequence.checked_add(1).ok_or(Error::Limit)?;
        head.data_root = self.upload(Payload::Manifest(manifest), deadline)?;
        let stored = StoredResult {
            request: request.clone(),
            sequence: head.sequence,
            transition: head.transition.clone(),
            data_root: head.data_root.clone(),
            bytes: result.to_vec(),
        };
        let result_hash = self.upload(Payload::Result(stored), deadline)?;
        self.append(
            &mut head,
            Entry {
                request: request.clone(),
                outcome: OutcomeRef::Committed {
                    result: result_hash.clone(),
                },
            },
            deadline,
        )?;
        self.publish(base, &head, deadline)?;
        Ok(Receipt {
            scope: self.scope.clone(),
            request: request.clone(),
            sequence: head.sequence,
            transition: head.transition,
            data_root: head.data_root,
            result_hash,
        })
    }

    /// One fresh submission, with no automatic SQL or CAS retry. After an
    /// ambiguous result the caller must retain identity and use lookup/cancel.
    pub fn execute(
        &self,
        principal: u64,
        identity: &Request,
        statements: &[Statement],
        directory: &Path,
        deadline: Instant,
    ) -> Result<(Receipt, TransactionResult), Error> {
        if request(identity.epoch, identity.id, principal, statements)? != *identity {
            return Err(Error::RequestConflict);
        }
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, true, true, false)?;
        match self.resolve(&base.head, identity, deadline)? {
            Resolution::Committed { receipt, bytes } => {
                return Ok((
                    receipt,
                    scap_sql::decode_result(&bytes, sql_limits()).map_err(Error::Sql)?,
                ))
            }
            Resolution::Cancelled { .. } => return Err(Error::Closed),
            Resolution::Closed => return Err(Error::Closed),
            Resolution::Retired => return Err(Error::Retired),
            Resolution::Unknown => {}
        }
        self.writer(&base.head)?;
        if base.head.windows[0].count as usize == MAX_REQUESTS {
            return Err(Error::WindowFull);
        }
        let image = self.image(&base.head, deadline)?;
        let decision = Rc::new(RefCell::new(None));
        let gate = PublishGate {
            database: self.clone(),
            base,
            request: identity.clone(),
            deadline,
            decision: decision.clone(),
        };
        let mut writer = SqliteWriter::create_new(directory, image, engine_limits(), gate)
            .map_err(Error::Engine)?;
        let executed = writer.execute(statements);
        let outcome = decision.borrow_mut().take();
        Self::finish(outcome, executed)
    }

    fn finish(
        outcome: Option<Result<Receipt, Error>>,
        executed: Result<TransactionResult, scap_object_sqlite::Error>,
    ) -> Result<(Receipt, TransactionResult), Error> {
        match outcome {
            Some(Ok(receipt)) => match executed {
                Ok(result) => Ok((receipt, result)),
                Err(_) => Err(Error::CommittedButUnavailable(Box::new(receipt))),
            },
            Some(Err(error)) => Err(error),
            None => match executed {
                Err(error) => Err(Error::Engine(error)),
                Ok(_) => Err(Error::Unknown),
            },
        }
    }

    pub fn query(
        &self,
        principal: u64,
        statements: &[Statement],
        directory: &Path,
        deadline: Instant,
    ) -> Result<TransactionResult, Error> {
        let snapshot = self.read_head(deadline)?;
        Self::authorize(&snapshot.head, principal, true, false, false)?;
        let image = self.image(&snapshot.head, deadline)?;
        let mut writer = SqliteWriter::create_new(directory, image, engine_limits(), ReadOnly)
            .map_err(Error::Engine)?;
        writer
            .query(statements, Arc::new(move || Instant::now() >= deadline))
            .map_err(Error::Engine)
    }
}

struct PublishGate {
    database: Database,
    base: Snapshot,
    request: Request,
    deadline: Instant,
    decision: Rc<RefCell<Option<Result<Receipt, Error>>>>,
}

impl CommitGate for PublishGate {
    fn publish(&mut self, batch: &PageBatch, result: &[u8]) -> GateDecision {
        let result = self
            .database
            .commit(&self.base, &self.request, batch, result, self.deadline);
        let decision = match &result {
            Ok(_) => GateDecision::Accepted,
            Err(_) => GateDecision::Unknown,
        };
        *self.decision.borrow_mut() = Some(result);
        decision
    }
}

struct ReadOnly;
impl CommitGate for ReadOnly {
    fn publish(&mut self, _: &PageBatch, _: &[u8]) -> GateDecision {
        GateDecision::Rejected
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod review_tests;
