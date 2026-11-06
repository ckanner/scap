//! Object-authoritative SQLite. Local files never establish committed state.

pub mod format;
pub mod options;

mod data_tree;

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use format::*;
use scap_object_sqlite::{CommitGate, GateDecision, ImageBuilder, PageBatch, SqliteWriter};
use scap_object_store::{Condition, Objects, StoreError};
use scap_sql::{SqlLimits, Statement, TransactionResult};

pub use options::Options;
use options::{durable_sql_limits, input_budget, MAX_REQUEST_BYTES};

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
    StaleSnapshot,
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
    options: Options,
    quarantined: Arc<AtomicBool>,
}

pub fn sql_limits() -> SqlLimits {
    Options::default().sql
}

pub fn request(
    epoch: u64,
    id: u64,
    principal: u64,
    statements: &[Statement],
) -> Result<Request, Error> {
    input_budget(statements, MAX_REQUEST_BYTES)?;
    let hash =
        scap_sql::request_fingerprint(statements, durable_sql_limits()).map_err(Error::Sql)?;
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
        Self::with_options(objects, scope, worker, Options::default())
    }

    pub fn with_options(
        objects: Arc<dyn Objects>,
        scope: Scope,
        worker: u64,
        options: Options,
    ) -> Result<Self, Error> {
        scope.validate().map_err(Error::Format)?;
        options.validate()?;
        if worker == 0 {
            return Err(Error::Fenced);
        }
        Ok(Self {
            objects,
            scope,
            worker,
            options,
            quarantined: Arc::new(AtomicBool::new(false)),
        })
    }

    fn observe(&self, error: Error) -> Error {
        if matches!(
            error,
            Error::Corrupt
                | Error::Format(_)
                | Error::Store(StoreError::Missing | StoreError::Corrupt | StoreError::Limit)
                | Error::Engine(scap_object_sqlite::Error::InvalidImage)
        ) {
            self.quarantined.store(true, Ordering::Release);
        }
        error
    }

    fn healthy(&self) -> Result<(), Error> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn read_head(&self, deadline: Instant) -> Result<Snapshot, Error> {
        let object = self
            .objects
            .get(&head_key(&self.scope), MAX_HEAD_BYTES, deadline)
            .map_err(Error::Store)?;
        let head = decode_head(&object.bytes, &self.scope)
            .map_err(|error| self.observe(Error::Format(error)))?;
        if object.etag.is_empty() {
            return Err(self.observe(Error::Corrupt));
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
        self.healthy()?;
        if !head.active || head.owner_instance != self.worker {
            return Err(Error::Fenced);
        }
        Ok(())
    }

    fn load(&self, root: &str, deadline: Instant) -> Result<Payload, Error> {
        let stored = self
            .objects
            .get(&object_key(&self.scope, root), MAX_OBJECT_BYTES, deadline)
            .map_err(|error| self.observe(Error::Store(error)))?;
        Ok(decode_object(&stored.bytes, &self.scope, root)
            .map_err(|error| self.observe(Error::Format(error)))?
            .payload)
    }

    fn upload(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
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
            .map_err(|error| self.observe(Error::Store(error)))?;
        if stored.bytes != bytes {
            return Err(self.observe(Error::Corrupt));
        }
        Ok(root)
    }

    fn publish(&self, base: &Snapshot, head: &Head, deadline: Instant) -> Result<(), Error> {
        self.healthy()?;
        let maximum = head.quota.max_pages().map_err(Error::Format)?;
        let bytes = encode_head(head).map_err(Error::Format)?;
        let manifest = data_tree::manifest(self, &head.data_root, deadline)
            .map_err(|error| self.observe(error))?;
        if manifest.page_count > maximum {
            return Err(Error::Limit);
        }
        // New dependencies were conditionally created and exactly read back.
        // Unchanged references inherit the prior HEAD's immutable closure;
        // protocol participants never delete reachable objects (GC is disabled).
        // Cold activation and the first session write verify retained history.
        self.healthy()?;
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
        let data_root = data_tree::empty(self, deadline)?;
        let index = self.upload(Payload::Index(Vec::new()), deadline)?;
        let head = Head {
            format: 2,
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
            quota: self.options.quota.clone(),
            retention: self.options.retention.clone(),
            data_root,
            request_epoch: 1,
            windows: vec![Window {
                epoch: 1,
                root: index,
                count: 0,
                result_bytes: 0,
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

    fn verify_closure(&self, head: &Head, deadline: Instant) -> Result<(), Error> {
        let manifest = data_tree::manifest(self, &head.data_root, deadline)
            .map_err(|error| self.observe(error))?;
        if manifest.page_count > head.quota.max_pages().map_err(Error::Format)? {
            return Err(Error::Limit);
        }
        data_tree::walk(self, &manifest, deadline, |_, _| Ok(()))
            .map_err(|error| self.observe(error))?;
        self.verify_results(head, deadline)
    }

    fn verify_results(&self, head: &Head, deadline: Instant) -> Result<(), Error> {
        for window in &head.windows {
            let mut bytes = 0_u64;
            for entry in self.index(window, deadline)? {
                if let Resolution::Committed { bytes: result, .. } =
                    self.resolve_entry(head, &entry.request, &entry.outcome, deadline)?
                {
                    // A window has at most 65,536 independently bounded 64 MiB
                    // results, so its exact aggregate fits in u64.
                    bytes += result.len() as u64;
                }
            }
            if bytes != window.result_bytes {
                return Err(self.observe(Error::Corrupt));
            }
        }
        Ok(())
    }

    fn index(&self, window: &Window, deadline: Instant) -> Result<Vec<Entry>, Error> {
        let entries = match self.load(&window.root, deadline)? {
            Payload::Index(entries) => entries,
            _ => return Err(self.observe(Error::Corrupt)),
        };
        if entries.len() != window.count as usize
            || entries
                .iter()
                .any(|entry| entry.request.epoch != window.epoch)
        {
            return Err(self.observe(Error::Corrupt));
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
                    return Err(self.observe(Error::Corrupt));
                }
                Ok(Resolution::Cancelled {
                    transition: transition.clone(),
                })
            }
            OutcomeRef::Committed { result } => {
                let stored = match self.load(result, deadline)? {
                    Payload::Result(stored) => stored,
                    _ => return Err(self.observe(Error::Corrupt)),
                };
                if stored.request != *request
                    || stored.sequence > head.sequence
                    || stored.transition.revision > head.revision
                {
                    return Err(self.observe(Error::Corrupt));
                }
                // Object integrity and request binding do not imply that the
                // retained SQL result can be decoded. All lookup and recovery
                // paths share this check; do not allocate a decoded row graph
                // or apply the current (possibly lower) SQL admission limits.
                scap_sql::validate_result(&stored.bytes, durable_sql_limits())
                    .map_err(|_| self.observe(Error::Corrupt))?;
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

    /// Change the persisted logical file quota in the same ordering domain as
    /// writes. None removes SCAP's business quota, not SQLite's page-number limit.
    pub fn set_quota(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        quota: DatabaseQuota,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let base = self.control(principal, expected_revision, deadline)?;
        let maximum = quota.max_pages().map_err(Error::Format)?;
        let manifest = data_tree::manifest(self, &base.head.data_root, deadline)
            .map_err(|error| self.observe(error))?;
        if manifest.page_count > maximum {
            return Err(Error::Limit);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.quota = quota;
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
        if !base.head.windows[0].full(&base.head.retention) {
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
                result_bytes: 0,
            },
        );
        head.windows.truncate(3);
        self.publish(&base, &head, deadline)?;
        Ok(head)
    }

    fn append(
        &self,
        head: &mut Head,
        entry: Entry,
        result_bytes: u64,
        deadline: Instant,
    ) -> Result<(), Error> {
        let mut entries = self.index(&head.windows[0], deadline)?;
        if entries.len() == head.retention.max_entries as usize {
            return Err(Error::WindowFull);
        }
        let bytes = head.windows[0]
            .result_bytes
            .checked_add(result_bytes)
            .ok_or(Error::Limit)?;
        if bytes > head.retention.max_result_bytes {
            return Err(Error::WindowFull);
        }
        if entries.iter().any(|old| old.request.id == entry.request.id) {
            return Err(Error::RequestConflict);
        }
        entries.push(entry);
        head.windows[0].count = entries.len() as u32;
        head.windows[0].result_bytes = bytes;
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
            0,
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
        if base.head.windows[0].full(&base.head.retention) {
            return Err(Error::WindowFull);
        }
        let mut head = Self::next(&base.head, request.id)?;
        head.sequence = head.sequence.checked_add(1).ok_or(Error::Limit)?;
        head.data_root = data_tree::update(
            self,
            &base.head.data_root,
            batch,
            base.head.quota.max_pages().map_err(Error::Format)?,
            deadline,
        )?;
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
            result.len() as u64,
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
        let deadline = self.options.deadline(deadline, false);
        match self.admit(principal, identity, statements, deadline)? {
            Admission::Existing(receipt, result) => Ok((receipt, result)),
            Admission::Fresh(base) => {
                let mut session = self.restore(&base, directory, deadline)?;
                session.execute_prepared(base, identity, statements, deadline)
            }
        }
    }

    // Keep materialization as a defensive boundary as well as the allocation-
    // free closure check. This helper accepts untrusted bytes independently;
    // decoder changes must not turn a historical replay into a fresh write.
    fn decode_retained_result(&self, bytes: &[u8]) -> Result<TransactionResult, Error> {
        scap_sql::decode_result(bytes, durable_sql_limits())
            .map_err(|_| self.observe(Error::Corrupt))
    }

    fn admit(
        &self,
        principal: u64,
        identity: &Request,
        statements: &[Statement],
        deadline: Instant,
    ) -> Result<Admission, Error> {
        if request(identity.epoch, identity.id, principal, statements)? != *identity {
            return Err(Error::RequestConflict);
        }
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, true, true, false)?;
        match self.resolve(&base.head, identity, deadline)? {
            Resolution::Committed { receipt, bytes } => {
                return Ok(Admission::Existing(
                    receipt,
                    self.decode_retained_result(&bytes)?,
                ))
            }
            Resolution::Cancelled { .. } => return Err(Error::Closed),
            Resolution::Closed => return Err(Error::Closed),
            Resolution::Retired => return Err(Error::Retired),
            Resolution::Unknown => {}
        }
        self.writer(&base.head)?;
        if base.head.windows[0].full(&base.head.retention) {
            return Err(Error::WindowFull);
        }
        input_budget(statements, self.options.max_input_bytes)?;
        scap_sql::validate_statements(statements, self.options.sql).map_err(Error::Sql)?;
        Ok(Admission::Fresh(base))
    }

    /// Restore one authenticated immutable root into an owned private file.
    /// The recovery deadline is separate from subsequent operation deadlines.
    pub fn session(
        &self,
        principal: u64,
        directory: &Path,
        deadline: Instant,
    ) -> Result<Session, Error> {
        let deadline = self.options.deadline(deadline, true);
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, true, false, false)?;
        let mut session = self.restore(&base, directory, deadline)?;
        // Prepare retained history within the recovery budget, so the first
        // hot SQL operation does not hide a full historical result scan.
        self.verify_results(&base.head, deadline)?;
        session.history_verified = true;
        Ok(session)
    }

    fn restore(
        &self,
        base: &Snapshot,
        directory: &Path,
        deadline: Instant,
    ) -> Result<Session, Error> {
        let manifest = data_tree::manifest(self, &base.head.data_root, deadline)
            .map_err(|error| self.observe(error))?;
        let limits = self.options.writer(&base.head.quota)?;
        let mut image =
            ImageBuilder::create_new(directory, manifest.page_count, limits.max_database_pages)
                .map_err(Error::Engine)?;
        data_tree::walk(self, &manifest, deadline, |page, bytes| {
            image.append_pages(page, bytes).map_err(Error::Engine)
        })
        .map_err(|error| self.observe(error))?;
        let image = image.finish().map_err(Error::Engine)?;
        let state = Rc::new(RefCell::new(Publication::default()));
        let gate = PublishGate {
            database: self.clone(),
            state: state.clone(),
        };
        let writer = SqliteWriter::open(
            image,
            limits,
            gate,
            Arc::new(move || Instant::now() >= deadline),
        )
        .map_err(|error| self.observe(Error::Engine(error)))?;
        Ok(Session {
            database: self.clone(),
            writer,
            state,
            data_root: base.head.data_root.clone(),
            quota: base.head.quota.clone(),
            owner_epoch: base.head.owner_epoch,
            invalidated: false,
            history_verified: false,
        })
    }

    /// Cold activation can retain its freshly verified local file for future
    /// operations, avoiding a second whole-database download after recovery.
    pub fn activate_session(
        &self,
        principal: u64,
        expected_revision: u64,
        nonce: u64,
        directory: &Path,
        deadline: Instant,
    ) -> Result<(Head, Session), Error> {
        let deadline = self.options.deadline(deadline, true);
        let base = self.control(principal, expected_revision, deadline)?;
        Self::ready(&base.head)?;
        if base.head.owner_instance != self.worker || base.head.active {
            return Err(Error::Fenced);
        }
        let mut session = self.restore(&base, directory, deadline)?;
        self.verify_results(&base.head, deadline)?;
        session.history_verified = true;
        let current = self.read_head(deadline)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(Error::Conflict);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.active = true;
        self.publish(&base, &head, deadline)?;
        Ok((head, session))
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
        let deadline = self.options.deadline(deadline, false);
        let snapshot = self.read_head(deadline)?;
        Self::authorize(&snapshot.head, principal, true, false, false)?;
        input_budget(statements, self.options.max_input_bytes)?;
        scap_sql::validate_statements(statements, self.options.sql).map_err(Error::Sql)?;
        let mut session = self.restore(&snapshot, directory, deadline)?;
        session
            .writer
            .query(statements, Arc::new(move || Instant::now() >= deadline))
            .map_err(Error::Engine)
    }
}

impl data_tree::DataObjects for Database {
    fn load(&self, hash: &str, deadline: Instant) -> Result<Payload, Error> {
        Self::load(self, hash, deadline)
    }

    fn save(&self, payload: Payload, deadline: Instant) -> Result<String, Error> {
        self.upload(payload, deadline)
    }
}

enum Admission {
    Existing(Receipt, TransactionResult),
    Fresh(Snapshot),
}

struct AttemptContext {
    base: Snapshot,
    request: Request,
    deadline: Instant,
}

#[derive(Default)]
struct Publication {
    context: Option<AttemptContext>,
    outcome: Option<Result<Receipt, Error>>,
}

struct PublishGate {
    database: Database,
    state: Rc<RefCell<Publication>>,
}

impl CommitGate for PublishGate {
    fn publish(&mut self, batch: &PageBatch, result: &[u8]) -> GateDecision {
        let context = self.state.borrow_mut().context.take();
        let result = match context {
            Some(context) => self.database.commit(
                &context.base,
                &context.request,
                batch,
                result,
                context.deadline,
            ),
            None => Err(Error::Corrupt),
        };
        let result = result.map_err(|error| self.database.observe(error));
        let decision = match &result {
            Ok(_) => GateDecision::Accepted,
            Err(_) => GateDecision::Unknown,
        };
        self.state.borrow_mut().outcome = Some(result);
        decision
    }
}

/// A verified local SQLite cache, never an authorization lease. Every public
/// operation re-reads HEAD. A different root or quota requires a new session;
/// an ambiguous/native failure cannot replay SQL through the stopped writer.
pub struct Session {
    database: Database,
    writer: SqliteWriter<PublishGate>,
    state: Rc<RefCell<Publication>>,
    data_root: String,
    quota: DatabaseQuota,
    owner_epoch: u64,
    invalidated: bool,
    history_verified: bool,
}

impl Session {
    pub fn page_count(&self) -> u32 {
        self.writer.page_count()
    }

    fn align(&mut self, head: &Head, writing: bool) -> Result<(), Error> {
        if self.invalidated
            || self.writer.is_stopped()
            || self.data_root != head.data_root
            || self.quota != head.quota
            || (writing && self.owner_epoch != head.owner_epoch)
        {
            self.invalidated = true;
            return Err(Error::StaleSnapshot);
        }
        Ok(())
    }

    pub fn execute(
        &mut self,
        principal: u64,
        identity: &Request,
        statements: &[Statement],
        deadline: Instant,
    ) -> Result<(Receipt, TransactionResult), Error> {
        let deadline = self.database.options.deadline(deadline, false);
        match self
            .database
            .admit(principal, identity, statements, deadline)?
        {
            Admission::Existing(receipt, result) => Ok((receipt, result)),
            Admission::Fresh(base) => self.execute_prepared(base, identity, statements, deadline),
        }
    }

    fn execute_prepared(
        &mut self,
        base: Snapshot,
        identity: &Request,
        statements: &[Statement],
        deadline: Instant,
    ) -> Result<(Receipt, TransactionResult), Error> {
        self.align(&base.head, true)?;
        if !self.history_verified {
            self.database.verify_results(&base.head, deadline)?;
            self.history_verified = true;
        }
        *self.state.borrow_mut() = Publication {
            context: Some(AttemptContext {
                base,
                request: identity.clone(),
                deadline,
            }),
            outcome: None,
        };
        let executed = self
            .writer
            .execute(statements, Arc::new(move || Instant::now() >= deadline));
        let mut state = self.state.borrow_mut();
        state.context = None;
        let outcome = state.outcome.take();
        let result = Database::finish(outcome, executed)?;
        self.data_root = result.0.data_root.clone();
        Ok(result)
    }

    pub fn query(
        &mut self,
        principal: u64,
        statements: &[Statement],
        deadline: Instant,
    ) -> Result<TransactionResult, Error> {
        let deadline = self.database.options.deadline(deadline, false);
        let snapshot = self.database.read_head(deadline)?;
        Database::authorize(&snapshot.head, principal, true, false, false)?;
        self.align(&snapshot.head, false)?;
        input_budget(statements, self.database.options.max_input_bytes)?;
        self.writer
            .query(statements, Arc::new(move || Instant::now() >= deadline))
            .map_err(Error::Engine)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod review_tests;

#[cfg(test)]
mod session_tests;

#[cfg(test)]
mod quarantine_tests;

#[cfg(test)]
mod result_validation_tests;
