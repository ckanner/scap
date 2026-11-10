//! Deployment-root recovery of every required permanent slot, one at a time.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_object_store::{Listings, Objects};
use scap_sql::{Statement, TransactionResult};

use super::recovery_budget::RecoveryMeter;
use super::*;
use crate::object_context::ObjectContext;
use crate::Session;

/// Trusted configuration selects a READ principal for each discovered tenant.
/// This mapping never selects the scan denominator and never implies READ.
pub trait TenantReaders: Send + Sync {
    fn principal(&self, deployment: u64, tenant: u64) -> Option<u64>;
}

#[cfg(test)]
#[path = "recovery_job_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStop {
    Invalid,
    Busy,
    Limit,
    PermissionBlocked,
    StorageDenied,
    Conflict,
    Unknown,
    Corrupt,
    Local,
    SnapshotExpired,
}

impl From<DiscoveryError> for RecoveryStop {
    fn from(value: DiscoveryError) -> Self {
        match value {
            DiscoveryError::Invalid => Self::Invalid,
            DiscoveryError::Denied => Self::StorageDenied,
            DiscoveryError::Limit => Self::Limit,
            DiscoveryError::Conflict => Self::Conflict,
            DiscoveryError::Unknown => Self::Unknown,
            DiscoveryError::Corrupt => Self::Corrupt,
            DiscoveryError::SnapshotExpired => Self::SnapshotExpired,
        }
    }
}

fn recovery_error(error: Error) -> RecoveryStop {
    match error {
        Error::Denied => RecoveryStop::PermissionBlocked,
        Error::Conflict | Error::Store(StoreError::Conflict) => RecoveryStop::Conflict,
        Error::Unknown
        | Error::Store(StoreError::Unknown)
        | Error::Engine(scap_object_sqlite::Error::Interrupted) => RecoveryStop::Unknown,
        Error::Limit | Error::Store(StoreError::Limit | StoreError::Budget) => RecoveryStop::Limit,
        Error::SnapshotExpired => RecoveryStop::SnapshotExpired,
        Error::Engine(scap_object_sqlite::Error::Io(_)) => RecoveryStop::Local,
        _ => RecoveryStop::Corrupt,
    }
}

/// This profile verifies Ready and Maintenance databases without activating or
/// taking ownership. Other states retain their exact metadata classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCompletion {
    pub traversal_exhausted: bool,
    pub preexisting_slots_covered: bool,
    pub metadata_classified: u64,
    pub heads_classified: u64,
    pub data_verified: u64,
    pub data_not_required: u64,
    pub pending_scope: Option<Scope>,
    pub permission_blocked: bool,
    pub recovery_complete: bool,
}

/// At most one metadata observation and one verified native image are returned
/// per step. A repeated pending observation is not a newly discovered slot.
pub struct RecoveryStep {
    pub metadata: Option<DiscoveredRecord>,
    pub recovered: Option<RecoveredDatabase>,
    pub completion: RecoveryCompletion,
    pub usage: RecoveryUsage,
    pub stopped: Option<RecoveryStop>,
}

struct ImageLease(Arc<AtomicBool>);

impl Drop for ImageLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// One verified, disposable cache. It has no write/activate method; each query
/// checks the fixed trusted principal's current READ on a fresh exact HEAD.
/// Drop it before the next job step. The Session drops before its image lease.
pub struct RecoveredDatabase {
    session: Session,
    head: Head,
    principal: u64,
    deadline: Instant,
    _lease: ImageLease,
}

impl RecoveredDatabase {
    pub fn head(&self) -> &Head {
        &self.head
    }

    pub fn query(
        &mut self,
        statements: &[Statement],
        deadline: Instant,
    ) -> Result<TransactionResult, Error> {
        self.session
            .query(self.principal, statements, deadline.min(self.deadline))
    }
}

/// Stateful, bounded coordination, not a stateless client continuation token.
/// The private checkpoint is one inventory frontier plus one pending Scope;
/// totals/deadline survive every step. Losing the process starts a new root scan.
pub struct RecoveryJob {
    inventory: RecoveryInventory,
    cursor: InventoryCursor,
    meter: Arc<RecoveryMeter>,
    readers: Arc<dyn TenantReaders>,
    deployment: u64,
    worker: u64,
    options: Options,
    pending: Option<Scope>,
    classified: u64,
    exhausted: bool,
    heads: u64,
    verified: u64,
    not_required: u64,
    finished: bool,
    image: Arc<AtomicBool>,
}

impl RecoveryJob {
    pub fn new(
        objects: Arc<dyn Objects>,
        listings: Arc<dyn Listings>,
        capability: RecoveryCapability,
        readers: Arc<dyn TenantReaders>,
        options: Options,
        budget: RecoveryBudget,
        deadline: Instant,
    ) -> Result<Self, RecoveryStop> {
        Self::with_clock(
            objects,
            listings,
            capability,
            readers,
            options,
            budget,
            (deadline, Instant::now),
        )
    }

    fn with_clock(
        objects: Arc<dyn Objects>,
        listings: Arc<dyn Listings>,
        capability: RecoveryCapability,
        readers: Arc<dyn TenantReaders>,
        options: Options,
        budget: RecoveryBudget,
        time: (Instant, fn() -> Instant),
    ) -> Result<Self, RecoveryStop> {
        let (deadline, now) = time;
        let deadline = deadline.min(now() + Duration::from_secs(3600));
        let meter = RecoveryMeter::new(objects, listings, budget.validate()?, deadline, now);
        meter.check(deadline)?;
        let deployment = capability.deployment;
        let worker = capability.worker;
        let mut inventory =
            RecoveryInventory::new(meter.clone(), meter.clone(), capability, options.clone())?;
        inventory.now = now;
        let cursor = inventory.begin();
        Ok(Self {
            inventory,
            cursor,
            meter,
            readers,
            deployment,
            worker,
            options,
            pending: None,
            classified: 0,
            exhausted: false,
            heads: 0,
            verified: 0,
            not_required: 0,
            finished: false,
            image: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn step(
        &mut self,
        directory: &Path,
        deadline: Instant,
    ) -> Result<RecoveryStep, RecoveryStop> {
        if self.image.load(Ordering::Acquire) {
            return Err(RecoveryStop::Busy);
        }
        let mut metadata = None;
        let mut recovered = None;
        let stopped = self
            .advance(directory, deadline, &mut metadata, &mut recovered)
            .err()
            .map(|error| self.meter.failure(error));
        self.finished = self.exhausted
            && self.pending.is_none()
            && stopped.is_none()
            && self.heads == self.verified + self.not_required;
        let completion = RecoveryCompletion {
            traversal_exhausted: self.exhausted,
            preexisting_slots_covered: self.exhausted,
            metadata_classified: self.classified,
            heads_classified: self.heads,
            data_verified: self.verified,
            data_not_required: self.not_required,
            pending_scope: self.pending.clone(),
            permission_blocked: stopped == Some(RecoveryStop::PermissionBlocked),
            recovery_complete: self.finished,
        };
        Ok(RecoveryStep {
            metadata,
            recovered,
            completion,
            usage: self.meter.usage(),
            stopped,
        })
    }

    fn advance(
        &mut self,
        directory: &Path,
        deadline: Instant,
        metadata: &mut Option<DiscoveredRecord>,
        recovered: &mut Option<RecoveredDatabase>,
    ) -> Result<(), RecoveryStop> {
        if self.finished {
            return Ok(());
        }
        let deadline = deadline.min(self.meter.deadline);
        self.meter.check(deadline)?;
        let mut later = None;
        if self.pending.is_some() {
            self.meter.retry_candidate()?;
        } else {
            let budget = self.meter.discovery_budget();
            let page = self.inventory.page(self.cursor.clone(), budget, deadline)?;
            self.meter.counted_candidates(page.usage.candidates);
            self.cursor = page.cursor;
            self.classified = page.completion.metadata_classified;
            self.exhausted = page.completion.traversal_exhausted;
            *metadata = page.records.into_iter().next();
            if let Some(record) = metadata.as_ref() {
                self.accept_metadata(record);
            }
            later = match page.stopped {
                Some(DiscoveryError::Limit) if budget.candidates != 0 => None,
                other => other.map(RecoveryStop::from),
            };
        }
        if let Some(scope) = self.pending.clone() {
            let (record, snapshot) = self.snapshot(&scope, deadline)?;
            *metadata = Some(record);
            let image = if matches!(
                snapshot.head.lifecycle,
                Lifecycle::Ready | Lifecycle::Maintenance
            ) {
                Some(self.restore(snapshot, directory, deadline)?)
            } else {
                None
            };
            self.meter.check(deadline)?;
            if image.is_some() {
                self.verified += 1;
            } else {
                self.not_required += 1;
            }
            *recovered = image;
            self.pending = None;
        } else {
            self.meter.check(deadline)?;
        }
        match later {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn accept_metadata(&mut self, record: &DiscoveredRecord) {
        if record.kind == RecordKind::Head {
            // This private input is produced only by discover_slot, which has
            // already decoded the complete actual Scope. A missing Scope is a
            // programming invariant violation, never a malformed wire record
            // to skip. The classifier rejects malformed wire bytes first.
            self.pending = Some(
                record
                    .scope
                    .clone()
                    .expect("classified physical HEAD contains its actual Scope"),
            );
            self.heads += 1;
        }
    }

    fn snapshot(
        &self,
        scope: &Scope,
        deadline: Instant,
    ) -> Result<(DiscoveredRecord, Snapshot), RecoveryStop> {
        let catalogue = Catalogue {
            objects: self.meter.clone(),
            deployment: self.deployment,
            tenant: scope.tenant,
            worker: self.worker,
            options: self.options.clone(),
        };
        let first = catalogue
            .read_slot(scope, deadline)
            .map_err(DiscoveryError::from)?
            .ok_or(RecoveryStop::Corrupt)?;
        let (creation, binding_revision, snapshot) = if let Some(origin) = &first.head.creation {
            let source =
                authority(catalogue.read_descriptor(origin.creator, origin.operation, deadline))
                    .map_err(DiscoveryError::from)?;
            let view = catalogue
                .view(&source, deadline)
                .map_err(DiscoveryError::from)?;
            catalogue
                .metadata_state(&source, &view, deadline)
                .map_err(DiscoveryError::from)?;
            let (binding_revision, _) = Catalogue::revisions(&source, &view);
            let current = view.head.ok_or(RecoveryStop::Corrupt)?;
            require(Catalogue::own(&source, &current.head)).map_err(DiscoveryError::from)?;
            (Some(source.creation.clone()), binding_revision, current)
        } else {
            (None, None, first)
        };
        if snapshot.head.scope != *scope {
            return Err(RecoveryStop::Corrupt);
        }
        let state = match snapshot.head.lifecycle {
            Lifecycle::Ready => MetadataState::Ready,
            Lifecycle::Maintenance => MetadataState::Maintenance,
            Lifecycle::Provisioning => MetadataState::Provisioning,
            Lifecycle::Deleted => MetadataState::Deleted,
        };
        let record = DiscoveredRecord {
            key: format::head_key(scope),
            kind: RecordKind::Head,
            state,
            creation,
            scope: Some(scope.clone()),
            binding_revision,
            head_revision: Some(snapshot.head.revision),
            control: None,
        };
        Ok((record, snapshot))
    }

    fn restore(
        &self,
        snapshot: Snapshot,
        directory: &Path,
        deadline: Instant,
    ) -> Result<RecoveredDatabase, RecoveryStop> {
        let scope = &snapshot.head.scope;
        let principal = self
            .readers
            .principal(self.deployment, scope.tenant)
            .ok_or(RecoveryStop::PermissionBlocked)?;
        if principal == 0 {
            return Err(RecoveryStop::Invalid);
        }
        Database::authorize(&snapshot.head, principal, true, false, false)
            .map_err(recovery_error)?;
        // Scope and options have already been validated by the exact slot read
        // and constructor. No public caller can inject an unclassified Scope.
        let database = Database {
            objects: self.meter.clone(),
            scope: scope.clone(),
            worker: self.worker,
            options: self.options.clone(),
            quarantined: Arc::new(AtomicBool::new(false)),
            knowledge: Arc::new(crate::object_context::Knowledge::default()),
        };
        let deadline = self.options.deadline(deadline, true);
        self.meter.check(deadline)?;
        // authorize() rejected Deleted, so this strict snapshot is nonterminal.
        // The local Database above has fresh empty Knowledge and no other clone
        // or context; its first context cannot exhaust the admission allowance.
        let objects = ObjectContext::from_snapshot(&database, &snapshot, deadline)
            .expect("authorized nonterminal authority and a fresh unshared lineage");
        let mut session = database
            .restore(&objects, &snapshot, directory, deadline)
            .map_err(recovery_error)?;
        self.meter.check(deadline)?;
        database
            .verify_results(&objects, &snapshot.head, deadline)
            .map_err(recovery_error)?;
        self.meter.check(deadline)?;
        session.history_verified = true;
        let current = database.read_head(deadline).map_err(recovery_error)?;
        if current.etag != snapshot.etag || current.head != snapshot.head {
            return Err(RecoveryStop::Conflict);
        }
        self.meter.check(deadline)?;
        self.image.store(true, Ordering::Release);
        Ok(RecoveredDatabase {
            session,
            head: snapshot.head,
            principal,
            deadline: self.meter.deadline,
            _lease: ImageLease(self.image.clone()),
        })
    }
}
