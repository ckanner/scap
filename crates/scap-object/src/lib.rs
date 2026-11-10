//! Object-authoritative SQLite. Local files never establish committed state.

pub mod catalogue;
pub mod format;
pub mod options;

mod closure;
mod data_tree;
mod head_publication;
mod object_context;
mod reclamation;
mod request_index;
pub use reclamation::SweepReport;

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use data_tree::DataObjects;
use format::*;
use head_publication::{PreparedHead, PublicationDomain};
use object_context::ObjectContext;
use scap_object_sqlite::{CommitGate, GateDecision, ImageBuilder, PageBatch, SqliteWriter};
use scap_object_store::{Condition, Objects, StoreError};
use scap_sql::{SqlLimits, Statement, TransactionResult};

pub use options::Options;
use options::{durable_sql_limits, input_budget, MAX_REQUEST_BYTES};

#[derive(Debug)]
pub enum Error {
    Format(FormatError),
    Store(StoreError),
    Gc(scap_object_store::GcError),
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
    SnapshotExpired,
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
    knowledge: Arc<object_context::Knowledge>,
}

/// A closed set of management changes which preserves every immutable
/// reference, lifecycle and identity field from the original authority.
enum MetadataUpdate {
    Takeover,
    Policy(Vec<Permission>),
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

fn check_cancelled(head: &Head, request_id: u64, transition: &Transition) -> Result<(), Error> {
    if transition.revision > head.revision || transition.nonce != request_id {
        Err(Error::Corrupt)
    } else {
        Ok(())
    }
}

/// Shared owned/borrowed retained-result checks. `raw` is the original result
/// payload, never a newly decoded row graph or re-encoded replacement.
fn check_retained_result(
    head: &Head,
    request: &Request,
    stored: &StoredResult,
    raw: &[u8],
) -> Result<(), Error> {
    if stored.request != *request
        || stored.sequence > head.sequence
        || stored.transition.revision > head.revision
        || stored.transition.nonce != request.id
    {
        return Err(Error::Corrupt);
    }
    scap_sql::validate_result(raw, durable_sql_limits()).map_err(|_| Error::Corrupt)
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
            knowledge: Arc::new(object_context::Knowledge::default()),
        })
    }

    fn observe(&self, error: Error) -> Error {
        object_context::observe(&self.quarantined, error)
    }

    #[cfg(test)]
    fn healthy(&self) -> Result<(), Error> {
        if self.quarantined.load(Ordering::Acquire) || self.knowledge.blocked(None) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn healthy_in(&self, generation: u64) -> Result<(), Error> {
        if self.quarantined.load(Ordering::Acquire) || self.knowledge.blocked(Some(generation)) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn healthy_domain(&self, domain: PublicationDomain) -> Result<(), Error> {
        match domain {
            PublicationDomain::Live(generation) => self.healthy_in(generation),
            PublicationDomain::TerminalMetadata => {
                // Historical physical-generation incidents stay recorded, but
                // none of those namespaces is protected after a permanent seal.
                // Never clear the shared authority/content-semantic latch.
                if self.quarantined.load(Ordering::Acquire) {
                    Err(Error::Corrupt)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn no_copy(head: &Head) -> Result<(), Error> {
        if head.storage.plan.is_some() {
            Err(Error::Fenced)
        } else {
            Ok(())
        }
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
        if matches!(head.lifecycle, Lifecycle::Deleted | Lifecycle::Provisioning) {
            return Err(Error::Lifecycle);
        }
        Self::permission(head, principal, read, write, admin)
    }

    fn permission(
        head: &Head,
        principal: u64,
        read: bool,
        write: bool,
        admin: bool,
    ) -> Result<(), Error> {
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
        Self::no_copy(head)?;
        self.healthy_in(head.storage.active_generation)?;
        if !head.active || head.owner_instance != self.worker {
            return Err(Error::Fenced);
        }
        Ok(())
    }

    fn publish(&self, base: &Snapshot, head: &Head, deadline: Instant) -> Result<(), Error> {
        let objects = ObjectContext::from_snapshot(self, base, deadline)?;
        self.publish_in(&objects, base, head, deadline)
    }

    /// Acknowledges only the management HEAD. No arbitrary candidate can enter
    /// this path; activation and all dependency-changing operations retain
    /// their existing immutable verification.
    fn publish_metadata(
        &self,
        base: &Snapshot,
        nonce: u64,
        update: MetadataUpdate,
        deadline: Instant,
    ) -> Result<Head, Error> {
        let mut head = Self::next(&base.head, nonce)?;
        match update {
            MetadataUpdate::Takeover => {
                Self::no_copy(&base.head)?;
                head.owner_epoch = head.owner_epoch.checked_add(1).ok_or(Error::Limit)?;
                head.owner_instance = self.worker;
                head.active = false;
            }
            MetadataUpdate::Policy(policy) => {
                head.auth_epoch = head.auth_epoch.checked_add(1).ok_or(Error::Limit)?;
                head.policy = policy;
            }
        }
        self.healthy_in(base.head.storage.active_generation)?;
        let publication = PreparedHead::new(self, base, &head, deadline)?;
        self.publish_healthy(publication)?;
        Ok(head)
    }

    fn publish_healthy(&self, publication: PreparedHead) -> Result<(), Error> {
        self.healthy_domain(publication.domain())?;
        publication.publish()
    }

    fn publish_in(
        &self,
        objects: &ObjectContext,
        base: &Snapshot,
        head: &Head,
        deadline: Instant,
    ) -> Result<(), Error> {
        objects.healthy()?;
        let maximum = head.quota.max_pages().map_err(Error::Format)?;
        let publication = PreparedHead::new(self, base, head, deadline)?;
        let manifest = data_tree::manifest(objects, &head.data_root, deadline)
            .map_err(|error| objects.observe(error))?;
        if manifest.page_count > maximum {
            return Err(Error::Limit);
        }
        // New dependencies were conditionally created and exactly read back.
        // Unchanged references inherit the prior HEAD's immutable closure;
        // protocol participants never delete reachable objects (GC is disabled).
        // Cold activation and the first session write verify retained history.
        self.publish_healthy(publication)
    }

    fn next(base: &Head, nonce: u64) -> Result<Head, Error> {
        let mut head = base.clone();
        head.revision = head.revision.checked_add(1).ok_or(Error::Limit)?;
        head.head_serial = head.head_serial.checked_add(1).ok_or(Error::Limit)?;
        head.transition = Transition {
            revision: head.revision,
            nonce,
        };
        Ok(head)
    }

    /// Explicit provisioning only. A missing HEAD on every other path is an
    /// error. Reusing a database ID is rejected by conditional creation.
    pub fn create(&self, principal: u64, nonce: u64, deadline: Instant) -> Result<Head, Error> {
        let head = self.initial_head(principal, nonce, deadline)?;
        self.create_head(&head, deadline)?;
        Ok(head)
    }

    fn initial_head(&self, principal: u64, nonce: u64, deadline: Instant) -> Result<Head, Error> {
        let objects = ObjectContext::bootstrap_at(self, deadline);
        let data_root = data_tree::empty(&objects, deadline)?;
        let index = request_index::empty(&objects, 1, deadline)?;
        let head = Head {
            format: 6,
            scope: self.scope.clone(),
            head_serial: 1,
            storage: Storage {
                active_generation: INITIAL_STORAGE_GENERATION,
                allocated_through: INITIAL_STORAGE_GENERATION,
                plan: None,
                sweep: None,
                terminal: None,
            },
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
            creation: None,
            deletion: None,
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
        Ok(head)
    }

    fn create_head(&self, head: &Head, deadline: Instant) -> Result<(), Error> {
        if head.scope != self.scope || head.revision != 1 || head.head_serial != 1 {
            return Err(Error::Format(FormatError::Invalid));
        }
        let bytes = encode_head(head).map_err(Error::Format)?;
        self.objects
            .put(&head_key(&self.scope), &bytes, Condition::Absent, deadline)
            .map_err(Error::Store)?;
        Ok(())
    }

    pub fn status(&self, principal: u64, deadline: Instant) -> Result<Head, Error> {
        let snapshot = self.read_head(deadline)?;
        Self::authorize(&snapshot.head, principal, true, false, false)?;
        Ok(snapshot.head)
    }

    fn verify_closure(
        &self,
        objects: &ObjectContext,
        base: &Snapshot,
        deadline: Instant,
    ) -> Result<(), Error> {
        let stop = || false;
        let mut cursor = closure::Cursor::new(objects, base, deadline, &stop)?;
        loop {
            match cursor.advance(closure::StepBudget::default(), &mut |_| Ok(()))? {
                closure::Step::Pending(next) => cursor = next,
                closure::Step::Complete(proof) => return proof.finish(base).map(|_| ()),
            }
        }
    }

    fn verify_results(
        &self,
        objects: &ObjectContext,
        head: &Head,
        deadline: Instant,
    ) -> Result<(), Error> {
        for window in &head.windows {
            request_index::walk(objects, window, deadline, |entry| {
                self.resolve_index_entry(objects, head, &entry, deadline)
                    .map(|_| ())
            })
            .map_err(|error| objects.observe(error))?;
        }
        Ok(())
    }

    fn resolve(
        &self,
        objects: &ObjectContext,
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
        let Some(entry) = request_index::lookup(objects, window, request.id, deadline)
            .map_err(|error| objects.observe(error))?
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
        self.resolve_index_entry(objects, head, &entry, deadline)
    }

    fn resolve_index_entry(
        &self,
        objects: &ObjectContext,
        head: &Head,
        entry: &Entry,
        deadline: Instant,
    ) -> Result<Resolution, Error> {
        let resolution =
            self.resolve_entry(objects, head, &entry.request, &entry.outcome, deadline)?;
        if let Resolution::Committed { bytes, .. } = &resolution {
            if bytes.len() as u64 != entry.result_bytes {
                return Err(self.observe(Error::Corrupt));
            }
        }
        Ok(resolution)
    }

    fn resolve_entry(
        &self,
        objects: &ObjectContext,
        head: &Head,
        request: &Request,
        outcome: &OutcomeRef,
        deadline: Instant,
    ) -> Result<Resolution, Error> {
        match outcome {
            OutcomeRef::Cancelled { transition } => {
                check_cancelled(head, request.id, transition)
                    .map_err(|error| objects.observe(error))?;
                Ok(Resolution::Cancelled {
                    transition: transition.clone(),
                })
            }
            OutcomeRef::Committed { result } => {
                let stored = match objects.load(result, deadline)? {
                    Payload::Result(stored) => stored,
                    _ => return Err(self.observe(Error::Corrupt)),
                };
                check_retained_result(head, request, &stored, &stored.bytes)
                    .map_err(|error| objects.observe(error))?;
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
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        self.resolve(&objects, &base.head, request, deadline)
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
        Self::no_copy(&base.head)?;
        self.publish_metadata(&base, nonce, MetadataUpdate::Takeover, deadline)
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
        Self::no_copy(&base.head)?;
        if base.head.owner_instance != self.worker || base.head.active {
            return Err(Error::Fenced);
        }
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        self.verify_closure(&objects, &base, deadline)?;
        let current = self.read_head(deadline)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(Error::Conflict);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.active = true;
        self.publish_in(&objects, &base, &head, deadline)?;
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
        self.publish_metadata(&base, nonce, MetadataUpdate::Policy(policy), deadline)
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
        Self::no_copy(&base.head)?;
        if base.head.storage.sweep.is_some() {
            return Err(Error::Fenced);
        }
        if lifecycle == Lifecycle::Provisioning
            || (base.head.creation.is_some() && lifecycle == Lifecycle::Deleted)
        {
            return Err(Error::Lifecycle);
        }
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
        Self::no_copy(&base.head)?;
        let maximum = quota.max_pages().map_err(Error::Format)?;
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        let manifest = data_tree::manifest(&objects, &base.head.data_root, deadline)
            .map_err(|error| objects.observe(error))?;
        if manifest.page_count > maximum {
            return Err(Error::Limit);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.quota = quota;
        self.publish_in(&objects, &base, &head, deadline)?;
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
        Self::no_copy(&base.head)?;
        if !base.head.windows[0].full(&base.head.retention) {
            return Err(Error::WindowFull);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.request_epoch = head.request_epoch.checked_add(1).ok_or(Error::Limit)?;
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        let root = request_index::empty(&objects, head.request_epoch, deadline)?;
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
        self.publish_in(&objects, &base, &head, deadline)?;
        Ok(head)
    }

    fn append(
        &self,
        objects: &ObjectContext,
        head: &mut Head,
        entry: Entry,
        deadline: Instant,
    ) -> Result<(), Error> {
        if head.windows[0].count == head.retention.max_entries {
            return Err(Error::WindowFull);
        }
        let bytes = head.windows[0]
            .result_bytes
            .checked_add(entry.result_bytes)
            .ok_or(Error::Limit)?;
        if bytes > head.retention.max_result_bytes {
            return Err(Error::WindowFull);
        }
        head.windows[0] = request_index::insert(objects, &head.windows[0], entry, deadline)
            .map_err(|error| objects.observe(error))?;
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
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        let resolution = self.resolve(&objects, &base.head, request, deadline)?;
        if resolution != Resolution::Unknown {
            return Ok(resolution);
        }
        Self::no_copy(&base.head)?;
        let mut head = Self::next(&base.head, request.id)?;
        let transition = head.transition.clone();
        self.append(
            &objects,
            &mut head,
            Entry {
                request: request.clone(),
                outcome: OutcomeRef::Cancelled {
                    transition: transition.clone(),
                },
                result_bytes: 0,
            },
            deadline,
        )?;
        self.publish_in(&objects, &base, &head, deadline)?;
        Ok(Resolution::Cancelled { transition })
    }

    fn commit(
        &self,
        context: &AttemptContext,
        batch: &PageBatch,
        result: &[u8],
    ) -> Result<Receipt, Error> {
        let base = &context.base;
        let request = &context.request;
        let objects = &context.objects;
        let deadline = context.deadline;
        self.writer(&base.head)?;
        if base.head.windows[0].full(&base.head.retention) {
            return Err(Error::WindowFull);
        }
        let mut head = Self::next(&base.head, request.id)?;
        head.sequence = head.sequence.checked_add(1).ok_or(Error::Limit)?;
        head.data_root = data_tree::update(
            objects,
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
        let result_hash = objects.save(Payload::Result(stored), deadline)?;
        self.append(
            objects,
            &mut head,
            Entry {
                request: request.clone(),
                outcome: OutcomeRef::Committed {
                    result: result_hash.clone(),
                },
                result_bytes: result.len() as u64,
            },
            deadline,
        )?;
        self.publish_in(objects, base, &head, deadline)?;
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
            Admission::Fresh(context) => {
                let mut session =
                    self.restore(&context.objects, &context.base, directory, deadline)?;
                session.execute_prepared(context, statements)
            }
        }
    }

    // Keep materialization as a defensive boundary as well as the allocation-
    // free closure check. This helper accepts untrusted bytes independently;
    // decoder changes must not turn a historical replay into a fresh write.
    fn decode_retained_admission(
        &self,
        receipt: Receipt,
        bytes: &[u8],
    ) -> Result<Admission, Error> {
        // Validate independently before applying local materialization limits.
        // Lower memory budgets cannot turn a valid, already committed result
        // into corruption, invalidate its receipt, or cause SQL re-execution.
        let result = scap_sql::decode_result_with_memory_limit(
            bytes,
            durable_sql_limits(),
            self.options.result_memory_bytes,
        )
        .map_err(|error| match error {
            scap_sql::SqlError::ResourceExhausted => {
                Error::CommittedButUnavailable(Box::new(receipt.clone()))
            }
            _ => self.observe(Error::Corrupt),
        })?;
        Ok(Admission::Existing(receipt, result))
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
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        match self.resolve(&objects, &base.head, identity, deadline)? {
            Resolution::Committed { receipt, bytes } => {
                return self.decode_retained_admission(receipt, &bytes);
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
        Ok(Admission::Fresh(Box::new(AttemptContext {
            base,
            objects,
            request: identity.clone(),
            deadline,
        })))
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
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        let mut session = self.restore(&objects, &base, directory, deadline)?;
        // Prepare retained history within the recovery budget, so the first
        // hot SQL operation does not hide a full historical result scan.
        self.verify_results(&objects, &base.head, deadline)?;
        session.history_verified = true;
        Ok(session)
    }

    fn restore(
        &self,
        objects: &ObjectContext,
        base: &Snapshot,
        directory: &Path,
        deadline: Instant,
    ) -> Result<Session, Error> {
        let manifest = data_tree::manifest(objects, &base.head.data_root, deadline)
            .map_err(|error| objects.observe(error))?;
        let limits = self.options.writer(&base.head.quota)?;
        let mut image =
            ImageBuilder::create_new(directory, manifest.page_count, limits.max_database_pages)
                .map_err(Error::Engine)?;
        data_tree::walk(objects, &manifest, deadline, |page, bytes| {
            image.append_pages(page, bytes).map_err(Error::Engine)
        })
        .map_err(|error| objects.observe(error))?;
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
        Self::no_copy(&base.head)?;
        if base.head.owner_instance != self.worker || base.head.active {
            return Err(Error::Fenced);
        }
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        let mut session = self.restore(&objects, &base, directory, deadline)?;
        self.verify_results(&objects, &base.head, deadline)?;
        session.history_verified = true;
        let current = self.read_head(deadline)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(Error::Conflict);
        }
        let mut head = Self::next(&base.head, nonce)?;
        head.active = true;
        self.publish_in(&objects, &base, &head, deadline)?;
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
        let objects = ObjectContext::from_snapshot(self, &snapshot, deadline)?;
        let mut session = self.restore(&objects, &snapshot, directory, deadline)?;
        // Direct cold queries, like Open, validate the entire retained history.
        // Warm Session::query remains a fresh HEAD plus local SQLite operation.
        self.verify_results(&objects, &snapshot.head, deadline)?;
        session
            .writer
            .query(statements, Arc::new(move || Instant::now() >= deadline))
            .map_err(Error::Engine)
    }
}

enum Admission {
    Existing(Receipt, TransactionResult),
    Fresh(Box<AttemptContext>),
}

struct AttemptContext {
    base: Snapshot,
    objects: ObjectContext,
    request: Request,
    deadline: Instant,
}

#[derive(Default)]
struct Publication {
    context: Option<Box<AttemptContext>>,
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
            Some(context) => self
                .database
                .commit(&context, batch, result)
                .map_err(|error| context.objects.observe(error)),
            None => Err(self.database.observe(Error::Corrupt)),
        };
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
            Admission::Fresh(context) => self.execute_prepared(context, statements),
        }
    }

    fn execute_prepared(
        &mut self,
        context: Box<AttemptContext>,
        statements: &[Statement],
    ) -> Result<(Receipt, TransactionResult), Error> {
        self.align(&context.base.head, true)?;
        if !self.history_verified {
            self.database
                .verify_results(&context.objects, &context.base.head, context.deadline)?;
            self.history_verified = true;
        }
        let deadline = context.deadline;
        *self.state.borrow_mut() = Publication {
            context: Some(context),
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

#[cfg(test)]
mod object_context_tests;
