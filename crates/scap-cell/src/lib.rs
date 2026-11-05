//! Bounded deterministic cell metadata and physical-transaction acceptance.
//!
//! Admission identities must come from a trusted credential verifier and be
//! bound to the actual request before proposal. This module rechecks current
//! replicated policy; it does not authenticate callers, perform I/O, publish
//! SQLite pages, or provide a transport. Reads require a fresh Raft read barrier
//! and `decode_bound` against the same durable Store view before using this API.
//! Request records are retained until explicit acknowledgement and an ordered
//! epoch rotation replace them with a permanent fence. Administrative receipts
//! remain retained. Capacity exhaustion never silently evicts a fence.
//! The cell bootstrap administrator is immutable in this G0 format; credential
//! rotation, cell-admin rotation and a production admission service are absent.

use std::collections::BTreeMap;
use std::fmt::{self, Display};

use raft::eraftpb::{Entry, EntryType};
use scap_core::{physical, CommitReceipt, CommitTicket, PreparedWrite};
use scap_raft_driver::{Application, AppliedBatch};
use sha2::{Digest, Sha256};

mod codec;

pub use scap_core::{CellIdentity, DatabaseIdentity};

pub const READ: u8 = 1;
pub const WRITE: u8 = 2;
pub const ADMIN: u8 = 4;

/// Bound for the versioned per-entry result, excluding the retained SQL result.
/// A tracked result is meaningful only from the matching durable driver attempt.
pub const MAX_APPLIED_OUTCOME_BYTES: u32 = 512;
const RESERVED_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub term: u64,
    pub index: u64,
}

/// Replicated limits: changing the local limits cannot silently change apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_state_bytes: u32,
    pub max_command_bytes: u32,
    pub max_databases: u32,
    pub max_policy_grants: u32,
    pub max_admin_operations: u32,
    pub max_requests_per_database: u32,
    pub max_transaction_bytes: u32,
    pub max_result_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub principal_id: u128,
    pub credential_id: u128,
    pub admission_id: u128,
    pub auth_epoch: u64,
    /// Original request namespace. Legacy wire/state records always mean 1;
    /// credential refresh must never silently refresh this value on a retry.
    pub request_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub principal_id: u128,
    pub permissions: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerToken {
    pub epoch: u64,
    pub worker_instance_id: u128,
}

/// Immutable, content-addressed physical recovery archive. The cell remains
/// authoritative for permissions, ownership, request results and cancellations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveRef {
    pub source: Position,
    pub revision: u64,
    pub commit_hash: [u8; 32],
    pub object_digest: [u8; 32],
    pub object_bytes: u32,
    pub metadata_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub cell: CellIdentity,
    pub database: DatabaseIdentity,
    pub admission: Admission,
    pub kind: CommandKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandKind {
    Create {
        operation_id: u128,
        policy: Vec<Grant>,
    },
    ClaimOwner {
        operation_id: u128,
        expected_epoch: u64,
        worker_instance_id: u128,
    },
    ActivateOwner {
        operation_id: u128,
        token: OwnerToken,
        restored_revision: u64,
        restored_hash: [u8; 32],
    },
    AuthFence {
        operation_id: u128,
        expected_epoch: u64,
        policy: Vec<Grant>,
    },
    Commit {
        write: PreparedWrite,
        request_fingerprint: [u8; 32],
        result: Vec<u8>,
    },
    ResolveOrCancel {
        request_id: u128,
        request_fingerprint: [u8; 32],
    },
    AcknowledgeRequest {
        request_id: u128,
        request_fingerprint: [u8; 32],
        expected: RequestTerminal,
    },
    RotateRequests {
        expected_epoch: u64,
    },
    SuspendDb {
        operation_id: u128,
        token: OwnerToken,
        expected_revision: u64,
    },
    PublishArchive {
        operation_id: u128,
        expected_owner: OwnerToken,
        expected_previous: Option<[u8; 32]>,
        archive: ArchiveRef,
    },
    PruneArchive {
        operation_id: u128,
        expected_owner: OwnerToken,
        archive_digest: [u8; 32],
    },
    HydrateArchive {
        operation_id: u128,
        archive: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Invalid,
    Fenced,
    Unauthorized,
    NotFound,
    Exists,
    Conflict,
    Cancelled,
    Capacity,
    TooLarge,
    Exhausted,
    Cold,
    Retired,
}

/// The caller explicitly relinquishes this exact terminal result. An unknown
/// request cannot be acknowledged, and an acknowledgement does not cancel SQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestTerminal {
    Committed { sequence: u64 },
    Cancelled { position: Position },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Malformed(&'static str),
    Binding,
    Position,
    Limit,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminResult {
    Created,
    OwnerClaimed(OwnerToken),
    OwnerActivated,
    AuthChanged(u64),
    Suspended(u64),
    ArchivePublished([u8; 32]),
    ArchivePruned([u8; 32]),
    ArchiveHydrated([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitResult {
    pub receipt: CommitReceipt,
    pub position: Position,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Administrative(AdminResult),
    AlreadyApplied(AdminResult),
    Accepted(CommitResult),
    AlreadyCommitted(CommitResult),
    Cancelled,
    AlreadyCancelled,
    Rejected(Reject),
    RequestAcknowledged,
    RequestsRotated { epoch: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedOutcome {
    pub position: Position,
    pub outcome: Outcome,
}

/// Result of one exact, durably applied internal history-format activation.
/// This is a separate protocol from business command outcomes. A rejected
/// activation leaves the legacy format and all recovery bytes intact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryActivationOutcome {
    pub cell: CellIdentity,
    pub position: Position,
    pub result: Result<(), Reject>,
}

/// Exact durable result of the separate v4 request-retention activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionActivationOutcome {
    pub cell: CellIdentity,
    pub position: Position,
    pub result: Result<(), Reject>,
}

enum ActivationOutcome {
    History(HistoryActivationOutcome),
    Retention(RetentionActivationOutcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedTransaction {
    pub admission: Admission,
    pub request_fingerprint: [u8; 32],
    pub commit: CommitResult,
    pub physical_changes: Vec<u8>,
    pub result: Vec<u8>,
    pub commit_hash: [u8; 32],
}

/// A verified physical baseline, published only with the same durable cell
/// application that retires its covered physical deltas. Logical receipts,
/// original results and cancellation fences remain in the cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBase {
    pub source: Position,
    pub revision: u64,
    pub commit_hash: [u8; 32],
    pub image_digest: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Trusted recovery source from one bound cell view. The tail begins exactly
/// after the optional base; it is never a complete history from revision zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverySource<'a> {
    pub base: Option<&'a RecoveryBase>,
    pub tail: &'a [AcceptedTransaction],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// No record at this view. A later or delayed proposal may still commit.
    Unknown,
    Committed {
        commit: CommitResult,
        result: Vec<u8>,
        acknowledged: bool,
    },
    Cancelled {
        position: Position,
        acknowledged: bool,
    },
    /// The old namespace cannot execute again; its result was relinquished.
    /// This is neither Unknown nor evidence that SQL was cancelled.
    Retired { current_epoch: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseView {
    pub identity: DatabaseIdentity,
    pub auth_epoch: u64,
    pub owner: OwnerToken,
    pub active: bool,
    pub revision: u64,
    pub commit_hash: [u8; 32],
    pub suspended: bool,
    pub cold: bool,
    pub archive: Option<ArchiveRef>,
    pub base_revision: u64,
    pub tail_entries: u64,
    pub tail_bytes: u64,
    pub request_epoch: u64,
    pub retained_requests: u64,
    pub unacknowledged_requests: u64,
    pub retired_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadView {
    pub cell: CellIdentity,
    pub database: DatabaseView,
    pub admission: Admission,
    pub position: Position,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RequestRecord {
    Accepted(u64),
    Cancelled {
        admission: Admission,
        fingerprint: [u8; 32],
        position: Position,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetiredPrefix {
    revision: u64,
    commit_hash: [u8; 32],
    source: Position,
}

impl RetiredPrefix {
    const EMPTY: Self = Self {
        revision: 0,
        commit_hash: [0; 32],
        source: Position { term: 0, index: 0 },
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Database {
    identity: DatabaseIdentity,
    auth_epoch: u64,
    owner: OwnerToken,
    active: bool,
    policy: Vec<Grant>,
    transactions: Vec<AcceptedTransaction>,
    requests: BTreeMap<u128, RequestRecord>,
    suspended: bool,
    cold: bool,
    archive: Option<ArchiveRef>,
    base: Option<RecoveryBase>,
    request_epoch: u64,
    retired: RetiredPrefix,
    retirement_position: Option<Position>,
    acknowledged: BTreeMap<u128, Position>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdminRecord {
    admission: Admission,
    database: DatabaseIdentity,
    digest: [u8; 32],
    result: AdminResult,
    position: Position,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellState {
    identity: CellIdentity,
    bootstrap_admin: u128,
    physical_history_version: u8,
    limits: Limits,
    position: Position,
    databases: BTreeMap<u128, Database>,
    administration: BTreeMap<u128, AdminRecord>,
    last_outcome: Option<AppliedOutcome>,
}

pub struct CellApplication {
    identity: CellIdentity,
    limits: Limits,
}

enum AdminAction<'a> {
    Create(&'a [Grant]),
    Claim {
        expected_epoch: u64,
        worker_instance_id: u128,
    },
    Activate {
        token: OwnerToken,
        restored_revision: u64,
        restored_hash: [u8; 32],
    },
    Fence {
        expected_epoch: u64,
        policy: &'a [Grant],
    },
    Suspend {
        token: OwnerToken,
        expected_revision: u64,
    },
    Publish {
        expected_owner: OwnerToken,
        expected_previous: Option<[u8; 32]>,
        archive: ArchiveRef,
    },
    Prune(OwnerToken, [u8; 32]),
    Hydrate(&'a [u8]),
}

pub fn payload_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn encode_command(command: &Command, limits: Limits) -> Result<Vec<u8>, Error> {
    codec::encode_command(command, limits)
}

pub fn encode_applied_outcome(outcome: &AppliedOutcome) -> Vec<u8> {
    codec::encode_applied_outcome(outcome)
}

pub fn decode_applied_outcome(bytes: &[u8], expected: Position) -> Result<AppliedOutcome, Error> {
    codec::decode_applied_outcome(bytes, expected)
}

/// Trusted catalogue control only, never tenant HTTP input. The replicated
/// bootstrap administrator and cell scope are checked again during apply.
pub fn encode_history_activation(cell: CellIdentity, bootstrap_administrator: u128) -> Vec<u8> {
    codec::encode_history_activation(cell, bootstrap_administrator)
}

/// Bind the internal result to the exact tracked driver attempt, then perform
/// a fresh read before opening business admission for the active format.
pub fn decode_history_activation_outcome(
    bytes: &[u8],
    expected_cell: CellIdentity,
    expected: Position,
) -> Result<HistoryActivationOutcome, Error> {
    codec::decode_history_activation_outcome(bytes, expected_cell, expected)
}

/// Activate request-retention semantics only after the older history activation
/// and every preceding legacy log entry have been durably applied.
pub fn encode_retention_activation(cell: CellIdentity, bootstrap_administrator: u128) -> Vec<u8> {
    codec::encode_retention_activation(cell, bootstrap_administrator)
}

pub fn decode_retention_activation_outcome(
    bytes: &[u8],
    expected_cell: CellIdentity,
    expected: Position,
) -> Result<RetentionActivationOutcome, Error> {
    codec::decode_retention_activation_outcome(bytes, expected_cell, expected)
}

impl CellState {
    /// Only explicit authorized new-group bootstrap may call this constructor.
    /// Genesis must equal the enclosing Store's durable application position.
    pub fn bootstrap(
        identity: CellIdentity,
        bootstrap_admin: u128,
        genesis: Position,
        limits: Limits,
    ) -> Result<Self, Error> {
        validate_config(identity, limits)?;
        if bootstrap_admin == 0 || genesis.term == 0 || genesis.index == 0 {
            return Err(Error::Invalid(
                "bootstrap identity and position must be nonzero",
            ));
        }
        Ok(Self {
            identity,
            bootstrap_admin,
            physical_history_version: 3,
            limits,
            position: genesis,
            databases: BTreeMap::new(),
            administration: BTreeMap::new(),
            last_outcome: None,
        })
    }

    /// Fixed pre-activation genesis for a service group or a fresh learner
    /// which may replay a legacy log prefix. This constructor must never be
    /// used to replace an existing replica's durable application state.
    pub fn bootstrap_legacy(
        identity: CellIdentity,
        bootstrap_admin: u128,
        genesis: Position,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut state = Self::bootstrap(identity, bootstrap_admin, genesis, limits)?;
        state.physical_history_version = 2;
        Ok(state)
    }

    pub fn encode(&self) -> Vec<u8> {
        codec::encode_state(self, true)
    }

    /// Also required after snapshot-only installation: Application::apply is not
    /// invoked by the driver on that path. Never authorize a stale inner image
    /// using a newer outer Store applied index.
    pub fn decode_bound(
        bytes: &[u8],
        identity: CellIdentity,
        position: Position,
        limits: Limits,
    ) -> Result<Self, Error> {
        let state = codec::decode_state(bytes, identity, limits)?;
        if state.position != position {
            return Err(Error::Position);
        }
        Ok(state)
    }

    pub fn identity(&self) -> CellIdentity {
        self.identity
    }

    /// Immutable administrator retained in every durable application snapshot.
    /// Startup uses this to reject local genesis-configuration drift.
    pub fn bootstrap_administrator(&self) -> u128 {
        self.bootstrap_admin
    }

    /// Legacy snapshots keep their version 2/3 semantics until the respective
    /// ordered activation succeeds. Fresh generic groups start at version 3;
    /// version 4 additionally supports acknowledged request retirement.
    pub fn physical_history_version(&self) -> u8 {
        self.physical_history_version
    }

    pub fn position(&self) -> Position {
        self.position
    }

    pub fn last_outcome(&self) -> Option<&AppliedOutcome> {
        self.last_outcome.as_ref()
    }

    /// Trusted internal inspection; this is not a user-facing authorization API.
    pub fn database(&self, database_id: u128) -> Option<DatabaseView> {
        self.databases.get(&database_id).map(Database::view)
    }

    /// Use only after matching a fresh Safe ReadIndex to this durable view.
    pub fn authorize_read(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
        owner: OwnerToken,
    ) -> Result<ReadView, Reject> {
        let db = self.authorized(identity, admission, READ)?;
        if !db.active || db.owner != owner {
            return Err(Reject::Fenced);
        }
        Ok(ReadView {
            cell: self.identity,
            database: db.view(),
            admission,
            position: self.position,
        })
    }

    /// Transaction preflight on a fresh, bound read view. The transaction API
    /// needs both permissions, an active owner and the writer's exact head.
    /// Commit checks these again in the ordered state machine after SQL runs.
    pub fn authorize_write(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
        owner: OwnerToken,
        predecessor: u64,
    ) -> Result<ReadView, Reject> {
        let view = self.authorize_read(identity, admission, owner)?;
        self.authorized(identity, admission, WRITE)?;
        if view.database.revision != predecessor {
            return Err(Reject::Conflict);
        }
        Ok(view)
    }

    pub fn lookup(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
        request_id: u128,
        fingerprint: [u8; 32],
    ) -> Result<Lookup, Reject> {
        let db = self.authorized(identity, admission, READ)?;
        if admission.request_epoch < db.request_epoch {
            return Ok(Lookup::Retired {
                current_epoch: db.request_epoch,
            });
        }
        db.check_request_epoch(admission.request_epoch)?;
        let acknowledged = db.acknowledged.contains_key(&request_id);
        match db.resolve(admission.principal_id, request_id, fingerprint)? {
            Some(RequestRecord::Accepted(sequence)) => {
                let tx = db.transaction(*sequence);
                Ok(Lookup::Committed {
                    commit: tx.commit.clone(),
                    result: tx.result.clone(),
                    acknowledged,
                })
            }
            Some(RequestRecord::Cancelled { position, .. }) => Ok(Lookup::Cancelled {
                position: *position,
                acknowledged,
            }),
            None => Ok(Lookup::Unknown),
        }
    }

    /// Trusted internal recovery only, never a public READ endpoint. This exposes
    /// the verified physical base and its contiguous tail. The tail may include
    /// other principals' original results. Bind a validated recovery worker;
    /// it must not export these records based only on user READ permission.
    /// Consumers also validate position/identity and the engine's physical format
    /// before rebuilding an isolated SQLite instance.
    pub fn recovery_source(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
    ) -> Result<RecoverySource<'_>, Reject> {
        let database = self.authorized(identity, admission, READ)?;
        if database.cold {
            return Err(Reject::Cold);
        }
        Ok(RecoverySource {
            base: database.base.as_ref(),
            tail: &database.transactions[database.tail_start()..],
        })
    }

    /// Trusted archiver only, after a fresh bound ReadIndex. The exact bytes must
    /// be uploaded and read back successfully before proposing PublishArchive.
    /// This does not grant publication or permit truncating shared Raft logs.
    pub fn archive_snapshot(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
    ) -> Result<(ArchiveRef, Vec<u8>), Reject> {
        let database = self.authorized(identity, admission, ADMIN)?;
        if database.cold {
            return Err(Reject::Cold);
        }
        let bytes = codec::encode_archive(
            self.identity,
            database,
            self.position,
            self.physical_history_version,
        );
        // A future hydration must fit one bounded ordered command. Oversized
        // databases remain hot until a separately verified chunk protocol exists.
        if bytes.len().saturating_add(192) > self.limits.max_command_bytes as usize {
            return Err(Reject::TooLarge);
        }
        let view = database.view();
        Ok((
            ArchiveRef {
                source: self.position,
                revision: view.revision,
                commit_hash: view.commit_hash,
                object_digest: payload_digest(&bytes),
                object_bytes: bytes.len() as u32,
                metadata_digest: codec::archive_metadata(database),
            },
            bytes,
        ))
    }

    /// Trusted lifecycle inspection with current administrative permission.
    /// The caller must bind this state to a fresh Safe ReadIndex.
    pub fn archive_status(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
    ) -> Result<DatabaseView, Reject> {
        Ok(self.authorized(identity, admission, ADMIN)?.view())
    }

    /// Finite metadata only, with current READ permission and a fresh bound
    /// ReadIndex. Suspended/cold databases need no active execution owner.
    pub fn metadata(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
    ) -> Result<DatabaseView, Reject> {
        Ok(self.authorized(identity, admission, READ)?.view())
    }

    fn authorized(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
        permission: u8,
    ) -> Result<&Database, Reject> {
        validate_admission(admission)?;
        let db = self
            .databases
            .get(&identity.database_id)
            .ok_or(Reject::NotFound)?;
        if db.identity != identity {
            return Err(Reject::Fenced);
        }
        if admission.auth_epoch != db.auth_epoch || !db.permits(admission.principal_id, permission)
        {
            return Err(Reject::Unauthorized);
        }
        Ok(db)
    }

    fn advance(&mut self, entry: &Entry) -> Result<Option<ActivationOutcome>, Error> {
        let position = Position {
            term: entry.term,
            index: entry.index,
        };
        if self.position.index.checked_add(1) != Some(position.index)
            || position.term < self.position.term
        {
            return Err(Error::Position);
        }
        if entry.get_entry_type() != EntryType::EntryNormal || entry.data.is_empty() {
            self.position = position;
            return Ok(None);
        }
        if codec::is_history_activation(&entry.data) {
            let result = self.activate_history(&entry.data);
            self.position = position;
            return Ok(Some(ActivationOutcome::History(HistoryActivationOutcome {
                cell: self.identity,
                position,
                result,
            })));
        }
        if codec::is_retention_activation(&entry.data) {
            let result = self.activate_retention(&entry.data);
            self.position = position;
            return Ok(Some(ActivationOutcome::Retention(
                RetentionActivationOutcome {
                    cell: self.identity,
                    position,
                    result,
                },
            )));
        }
        let outcome = if entry.data.len() > self.limits.max_command_bytes as usize {
            Outcome::Rejected(Reject::TooLarge)
        } else {
            let command = codec::decode_command(&entry.data, self.limits)?;
            let mut candidate = self.clone();
            match candidate.execute(&command, position) {
                Ok(outcome) => {
                    if candidate.fits() {
                        *self = candidate;
                        outcome
                    } else {
                        Outcome::Rejected(Reject::Capacity)
                    }
                }
                Err(reason) => Outcome::Rejected(reason),
            }
        };
        self.position = position;
        self.last_outcome = Some(AppliedOutcome { position, outcome });
        Ok(None)
    }

    fn activate_history(&mut self, bytes: &[u8]) -> Result<(), Reject> {
        if bytes.len() > self.limits.max_command_bytes as usize {
            return Err(Reject::TooLarge);
        }
        let (cell, administrator) =
            codec::decode_history_activation(bytes).map_err(|_| Reject::Invalid)?;
        if cell != self.identity {
            return Err(Reject::Fenced);
        }
        if administrator != self.bootstrap_admin {
            return Err(Reject::Unauthorized);
        }
        if self.physical_history_version >= 3 {
            return Ok(());
        }
        let mut candidate = self.clone();
        for database in candidate.databases.values_mut() {
            if !database.cold {
                database.migrate_legacy(self.identity, self.limits)?;
            }
        }
        candidate.physical_history_version = 3;
        if !candidate.fits() {
            return Err(Reject::Capacity);
        }
        *self = candidate;
        Ok(())
    }

    fn activate_retention(&mut self, bytes: &[u8]) -> Result<(), Reject> {
        if bytes.len() > self.limits.max_command_bytes as usize {
            return Err(Reject::TooLarge);
        }
        let (cell, administrator) =
            codec::decode_retention_activation(bytes).map_err(|_| Reject::Invalid)?;
        if cell != self.identity {
            return Err(Reject::Fenced);
        }
        if administrator != self.bootstrap_admin {
            return Err(Reject::Unauthorized);
        }
        if self.physical_history_version < 3 {
            return Err(Reject::Conflict);
        }
        if self.physical_history_version == 4 {
            return Ok(());
        }
        let mut candidate = self.clone();
        candidate.physical_history_version = 4;
        if !candidate.fits() {
            return Err(Reject::Capacity);
        }
        *self = candidate;
        Ok(())
    }

    fn fits(&self) -> bool {
        // Each unacknowledged retained request must already fund its future
        // (u128 request id, term/index) acknowledgement. Otherwise a full window
        // could accept SQL yet never make room for the confirmations to retire it.
        let acknowledgements = if self.physical_history_version >= 4 {
            self.databases.values().fold(0usize, |bytes, database| {
                bytes.saturating_add(
                    database
                        .requests
                        .len()
                        .saturating_sub(database.acknowledged.len())
                        .saturating_mul(32),
                )
            })
        } else {
            0
        };
        codec::encode_state(self, false)
            .len()
            .saturating_add(acknowledgements)
            .saturating_add(RESERVED_BYTES)
            <= self.limits.max_state_bytes as usize
    }

    fn execute(&mut self, command: &Command, position: Position) -> Result<Outcome, Reject> {
        if command.cell != self.identity || !valid_database_identity(command.database) {
            return Err(Reject::Fenced);
        }
        validate_admission(command.admission)?;
        if self.physical_history_version < 4 && command.admission.request_epoch != 1 {
            return Err(Reject::Conflict);
        }
        match &command.kind {
            CommandKind::Commit {
                write,
                request_fingerprint,
                result,
            } => self.commit(command, write, *request_fingerprint, result, position),
            CommandKind::ResolveOrCancel {
                request_id,
                request_fingerprint,
            } => self.cancel(command, *request_id, *request_fingerprint, position),
            CommandKind::AcknowledgeRequest {
                request_id,
                request_fingerprint,
                expected,
            } => self.acknowledge(
                command,
                *request_id,
                *request_fingerprint,
                *expected,
                position,
            ),
            CommandKind::RotateRequests { expected_epoch } => {
                self.rotate_requests(command, *expected_epoch, position)
            }
            CommandKind::Create {
                operation_id,
                policy,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Create(policy),
            ),
            CommandKind::ClaimOwner {
                operation_id,
                expected_epoch,
                worker_instance_id,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Claim {
                    expected_epoch: *expected_epoch,
                    worker_instance_id: *worker_instance_id,
                },
            ),
            CommandKind::ActivateOwner {
                operation_id,
                token,
                restored_revision,
                restored_hash,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Activate {
                    token: *token,
                    restored_revision: *restored_revision,
                    restored_hash: *restored_hash,
                },
            ),
            CommandKind::AuthFence {
                operation_id,
                expected_epoch,
                policy,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Fence {
                    expected_epoch: *expected_epoch,
                    policy,
                },
            ),
            CommandKind::SuspendDb {
                operation_id,
                token,
                expected_revision,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Suspend {
                    token: *token,
                    expected_revision: *expected_revision,
                },
            ),
            CommandKind::PublishArchive {
                operation_id,
                expected_owner,
                expected_previous,
                archive,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Publish {
                    expected_owner: *expected_owner,
                    expected_previous: *expected_previous,
                    archive: *archive,
                },
            ),
            CommandKind::PruneArchive {
                operation_id,
                expected_owner,
                archive_digest,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Prune(*expected_owner, *archive_digest),
            ),
            CommandKind::HydrateArchive {
                operation_id,
                archive,
            } => self.administer(
                command,
                position,
                *operation_id,
                AdminAction::Hydrate(archive),
            ),
        }
    }

    fn administer(
        &mut self,
        command: &Command,
        position: Position,
        operation_id: u128,
        action: AdminAction<'_>,
    ) -> Result<Outcome, Reject> {
        if operation_id == 0 {
            return Err(Reject::Invalid);
        }
        if matches!(action, AdminAction::Create(_)) {
            if command.admission.principal_id != self.bootstrap_admin
                || command.admission.auth_epoch != 1
            {
                return Err(Reject::Unauthorized);
            }
        } else {
            self.authorized(command.database, command.admission, ADMIN)?;
        }
        // Credential/admission identifiers and the refreshed auth epoch are not
        // the administrative intent. Replay still requires current permission.
        let digest = codec::admin_digest(command);
        if let Some(record) = self.administration.get(&operation_id) {
            if record.admission.principal_id != command.admission.principal_id
                || record.database != command.database
                || record.digest != digest
            {
                return Err(Reject::Conflict);
            }
            return Ok(Outcome::AlreadyApplied(record.result.clone()));
        }
        if self.administration.len() >= self.limits.max_admin_operations as usize {
            return Err(Reject::Capacity);
        }
        let result = match action {
            AdminAction::Create(policy) => {
                validate_policy(policy, self.limits)?;
                if self.databases.contains_key(&command.database.database_id) {
                    return Err(Reject::Exists);
                }
                if self.databases.len() >= self.limits.max_databases as usize {
                    return Err(Reject::Capacity);
                }
                self.databases.insert(
                    command.database.database_id,
                    Database {
                        identity: command.database,
                        auth_epoch: 1,
                        owner: OwnerToken {
                            epoch: 0,
                            worker_instance_id: 0,
                        },
                        active: false,
                        policy: policy.to_vec(),
                        transactions: Vec::new(),
                        requests: BTreeMap::new(),
                        suspended: true,
                        cold: false,
                        archive: None,
                        base: None,
                        request_epoch: 1,
                        retired: RetiredPrefix::EMPTY,
                        retirement_position: None,
                        acknowledged: BTreeMap::new(),
                    },
                );
                AdminResult::Created
            }
            AdminAction::Claim {
                expected_epoch,
                worker_instance_id,
            } => {
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                if db.cold {
                    return Err(Reject::Cold);
                }
                if db.owner.epoch != expected_epoch || worker_instance_id == 0 {
                    return Err(Reject::Fenced);
                }
                let epoch = expected_epoch.checked_add(1).ok_or(Reject::Exhausted)?;
                db.owner = OwnerToken {
                    epoch,
                    worker_instance_id,
                };
                db.active = false;
                db.suspended = false;
                AdminResult::OwnerClaimed(db.owner)
            }
            AdminAction::Activate {
                token,
                restored_revision,
                restored_hash,
            } => {
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                if db.cold {
                    return Err(Reject::Cold);
                }
                if token.epoch == 0 || db.owner != token || db.suspended {
                    return Err(Reject::Fenced);
                }
                let view = db.view();
                if view.revision != restored_revision || view.commit_hash != restored_hash {
                    return Err(Reject::Conflict);
                }
                db.active = true;
                AdminResult::OwnerActivated
            }
            AdminAction::Fence {
                expected_epoch,
                policy,
            } => {
                validate_policy(policy, self.limits)?;
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                if db.auth_epoch != expected_epoch {
                    return Err(Reject::Conflict);
                }
                db.auth_epoch = expected_epoch.checked_add(1).ok_or(Reject::Exhausted)?;
                db.policy = policy.to_vec();
                AdminResult::AuthChanged(db.auth_epoch)
            }
            AdminAction::Suspend {
                token,
                expected_revision,
            } => {
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                if db.owner != token {
                    return Err(Reject::Fenced);
                }
                if db.view().revision != expected_revision {
                    return Err(Reject::Conflict);
                }
                // A never-claimed legacy database has no owner to revoke.
                // Otherwise advance the epoch; old activate/commit requests fail.
                if !db.suspended && db.owner.epoch != 0 {
                    db.owner.epoch = db.owner.epoch.checked_add(1).ok_or(Reject::Exhausted)?;
                }
                db.active = false;
                db.suspended = true;
                AdminResult::Suspended(db.owner.epoch)
            }
            AdminAction::Publish {
                expected_owner,
                expected_previous,
                archive,
            } => {
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                if db.cold || db.active || !db.suspended || db.owner != expected_owner {
                    return Err(Reject::Fenced);
                }
                let previous = db.archive.map(|value| value.object_digest);
                let view = db.view();
                if previous != expected_previous
                    || archive.revision != view.revision
                    || archive.commit_hash != view.commit_hash
                    || !position_within(archive.source, self.position)
                    || db
                        .retirement_position
                        .is_some_and(|retired| !position_within(retired, archive.source))
                    || db
                        .transactions
                        .last()
                        .is_some_and(|tx| !position_within(tx.commit.position, archive.source))
                {
                    return Err(Reject::Conflict);
                }
                let expected = codec::encode_archive(
                    self.identity,
                    db,
                    archive.source,
                    self.physical_history_version,
                );
                if archive.object_bytes as usize != expected.len()
                    || archive.object_digest != payload_digest(&expected)
                    || archive.metadata_digest != codec::archive_metadata(db)
                    || expected.len().saturating_add(192) > self.limits.max_command_bytes as usize
                {
                    return Err(Reject::Invalid);
                }
                db.archive = Some(archive);
                AdminResult::ArchivePublished(archive.object_digest)
            }
            AdminAction::Prune(expected_owner, digest) => {
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                let archive = db.archive.ok_or(Reject::NotFound)?;
                let view = db.view();
                if db.active || !db.suspended || db.owner != expected_owner {
                    return Err(Reject::Fenced);
                }
                if archive.object_digest != digest
                    || archive.revision != view.revision
                    || archive.commit_hash != view.commit_hash
                {
                    return Err(Reject::Conflict);
                }
                for transaction in &mut db.transactions {
                    transaction.physical_changes.clear();
                }
                if let Some(base) = &mut db.base {
                    base.bytes.clear();
                }
                db.cold = true;
                AdminResult::ArchivePruned(digest)
            }
            AdminAction::Hydrate(bytes) => {
                let db = self
                    .databases
                    .get_mut(&command.database.database_id)
                    .unwrap();
                let archive = db.archive.ok_or(Reject::NotFound)?;
                if db.active || !db.suspended {
                    return Err(Reject::Fenced);
                }
                if bytes.len() != archive.object_bytes as usize
                    || payload_digest(bytes) != archive.object_digest
                {
                    return Err(Reject::Invalid);
                }
                let restored = codec::decode_archive(
                    bytes,
                    self.identity,
                    db,
                    archive,
                    self.limits,
                    self.physical_history_version,
                )
                .map_err(|_| Reject::Invalid)?;
                // Only missing physical bytes are copied; current metadata,
                // results, request identities, policy and fences are preserved.
                for (target, source) in db.transactions.iter_mut().zip(restored.transactions) {
                    target.physical_changes = source.physical_changes;
                }
                db.base = restored.base;
                db.cold = false;
                AdminResult::ArchiveHydrated(archive.object_digest)
            }
        };
        self.administration.insert(
            operation_id,
            AdminRecord {
                admission: command.admission,
                database: command.database,
                digest,
                result: result.clone(),
                position,
            },
        );
        Ok(Outcome::Administrative(result))
    }

    fn commit(
        &mut self,
        command: &Command,
        write: &PreparedWrite,
        fingerprint: [u8; 32],
        result: &[u8],
        position: Position,
    ) -> Result<Outcome, Reject> {
        let db = self.authorized(command.database, command.admission, WRITE)?;
        db.check_request_epoch(command.admission.request_epoch)?;
        let ticket = &write.ticket;
        if ticket.cell_id != self.identity.cell_id
            || ticket.cell_incarnation != self.identity.cell_incarnation
            || ticket.database_id != command.database.database_id
            || ticket.incarnation != command.database.incarnation
            || ticket.placement_generation != command.database.placement_generation
            || ticket.auth_epoch != command.admission.auth_epoch
        {
            return Err(Reject::Fenced);
        }
        match db.resolve(
            command.admission.principal_id,
            ticket.request_id,
            fingerprint,
        )? {
            Some(RequestRecord::Accepted(sequence)) => {
                return Ok(Outcome::AlreadyCommitted(
                    db.transaction(*sequence).commit.clone(),
                ));
            }
            Some(RequestRecord::Cancelled { .. }) => return Err(Reject::Cancelled),
            None => {}
        }
        if db.cold
            || !db.active
            || db.owner.epoch != ticket.owner_epoch
            || db.owner.worker_instance_id != ticket.worker_instance_id
        {
            return Err(Reject::Fenced);
        }
        let previous = db.view();
        if ticket.predecessor != previous.revision {
            return Err(Reject::Conflict);
        }
        if write.physical_changes.is_empty()
            || payload_digest(&write.physical_changes) != ticket.payload_digest
        {
            return Err(Reject::Invalid);
        }
        if write.physical_changes.len() > self.limits.max_transaction_bytes as usize
            || result.len() > self.limits.max_result_bytes as usize
        {
            return Err(Reject::TooLarge);
        }
        if db.requests.len() >= self.limits.max_requests_per_database as usize {
            return Err(Reject::Capacity);
        }
        let sequence = previous.revision.checked_add(1).ok_or(Reject::Exhausted)?;
        let commit = CommitResult {
            receipt: CommitReceipt {
                ticket: ticket.clone(),
                sequence,
            },
            position,
        };
        let mut tx = AcceptedTransaction {
            admission: command.admission,
            request_fingerprint: fingerprint,
            commit: commit.clone(),
            physical_changes: write.physical_changes.clone(),
            result: result.to_vec(),
            commit_hash: [0; 32],
        };
        tx.commit_hash = codec::transaction_hash(previous.commit_hash, &tx);
        let db = self
            .databases
            .get_mut(&command.database.database_id)
            .unwrap();
        db.transactions.push(tx);
        db.requests
            .insert(ticket.request_id, RequestRecord::Accepted(sequence));
        if self.physical_history_version >= 3 {
            db.compact(self.identity, self.limits)?;
        }
        Ok(Outcome::Accepted(commit))
    }

    fn cancel(
        &mut self,
        command: &Command,
        request_id: u128,
        fingerprint: [u8; 32],
        position: Position,
    ) -> Result<Outcome, Reject> {
        let db = self.authorized(command.database, command.admission, WRITE)?;
        db.check_request_epoch(command.admission.request_epoch)?;
        match db.resolve(command.admission.principal_id, request_id, fingerprint)? {
            Some(RequestRecord::Accepted(sequence)) => {
                return Ok(Outcome::AlreadyCommitted(
                    db.transaction(*sequence).commit.clone(),
                ));
            }
            Some(RequestRecord::Cancelled { .. }) => return Ok(Outcome::AlreadyCancelled),
            None => {}
        }
        if db.requests.len() >= self.limits.max_requests_per_database as usize {
            return Err(Reject::Capacity);
        }
        self.databases
            .get_mut(&command.database.database_id)
            .unwrap()
            .requests
            .insert(
                request_id,
                RequestRecord::Cancelled {
                    admission: command.admission,
                    fingerprint,
                    position,
                },
            );
        Ok(Outcome::Cancelled)
    }

    fn acknowledge(
        &mut self,
        command: &Command,
        request_id: u128,
        fingerprint: [u8; 32],
        expected: RequestTerminal,
        position: Position,
    ) -> Result<Outcome, Reject> {
        let db = self.authorized(command.database, command.admission, WRITE)?;
        db.check_request_epoch(command.admission.request_epoch)?;
        if self.physical_history_version < 4 {
            return Err(Reject::Conflict);
        }
        let record = db
            .resolve(command.admission.principal_id, request_id, fingerprint)?
            .ok_or(Reject::NotFound)?;
        let actual = match record {
            RequestRecord::Accepted(sequence) => RequestTerminal::Committed {
                sequence: *sequence,
            },
            RequestRecord::Cancelled { position, .. } => RequestTerminal::Cancelled {
                position: *position,
            },
        };
        if actual != expected {
            return Err(Reject::Conflict);
        }
        self.databases
            .get_mut(&command.database.database_id)
            .unwrap()
            .acknowledged
            .entry(request_id)
            .or_insert(position);
        Ok(Outcome::RequestAcknowledged)
    }

    fn rotate_requests(
        &mut self,
        command: &Command,
        expected_epoch: u64,
        position: Position,
    ) -> Result<Outcome, Reject> {
        let db = self.authorized(command.database, command.admission, ADMIN)?;
        if self.physical_history_version < 4 {
            return Err(Reject::Conflict);
        }
        db.check_request_epoch(command.admission.request_epoch)?;
        db.check_request_epoch(expected_epoch)?;
        if db.cold {
            return Err(Reject::Cold);
        }
        if db.requests.is_empty() || db.acknowledged.len() != db.requests.len() {
            return Err(Reject::Conflict);
        }
        let epoch = db.request_epoch.checked_add(1).ok_or(Reject::Exhausted)?;
        let db = self
            .databases
            .get_mut(&command.database.database_id)
            .unwrap();
        // Materialize the exact head before releasing any metadata. A failed
        // fold leaves the entire candidate unpublished, including the fence.
        db.fold(self.identity, self.limits)?;
        if let Some(base) = &db.base {
            db.retired = RetiredPrefix {
                revision: base.revision,
                commit_hash: base.commit_hash,
                source: base.source,
            };
        }
        db.transactions.clear();
        db.requests.clear();
        db.acknowledged.clear();
        db.request_epoch = epoch;
        db.retirement_position = Some(position);
        // An old archive has a different logical prefix/namespace. It remains
        // immutable in S3 but is no longer a live prune or hydrate authority.
        db.archive = None;
        Ok(Outcome::RequestsRotated { epoch })
    }
}

impl Database {
    fn transaction(&self, sequence: u64) -> &AcceptedTransaction {
        &self.transactions[(sequence - self.retired.revision - 1) as usize]
    }

    fn tail_start(&self) -> usize {
        (self.base_revision() - self.retired.revision) as usize
    }

    fn check_request_epoch(&self, epoch: u64) -> Result<(), Reject> {
        if epoch < self.request_epoch {
            return Err(Reject::Retired);
        }
        if epoch > self.request_epoch {
            return Err(Reject::Conflict);
        }
        Ok(())
    }

    fn base_revision(&self) -> u64 {
        self.base.as_ref().map_or(0, |base| base.revision)
    }

    fn tail_bytes(&self) -> u64 {
        self.transactions
            .iter()
            .skip(self.tail_start())
            .map(|transaction| transaction.physical_changes.len() as u64)
            .sum()
    }

    fn compaction_due(&self, limits: Limits) -> bool {
        let count = (self.transactions.len() - self.tail_start()) as u64;
        physical_tail_due(count, self.tail_bytes(), limits)
    }

    fn view(&self) -> DatabaseView {
        DatabaseView {
            identity: self.identity,
            auth_epoch: self.auth_epoch,
            owner: self.owner,
            active: self.active,
            revision: self.retired.revision + self.transactions.len() as u64,
            commit_hash: self
                .transactions
                .last()
                .map_or(self.retired.commit_hash, |tx| tx.commit_hash),
            suspended: self.suspended,
            cold: self.cold,
            archive: self.archive,
            base_revision: self.base_revision(),
            tail_entries: if self.cold {
                0
            } else {
                (self.transactions.len() - self.tail_start()) as u64
            },
            tail_bytes: self.tail_bytes(),
            request_epoch: self.request_epoch,
            retained_requests: self.requests.len() as u64,
            unacknowledged_requests: (self.requests.len() - self.acknowledged.len()) as u64,
            retired_revision: self.retired.revision,
        }
    }

    /// The limits and thresholds are derived exclusively from the replicated
    /// cell limits and the v3 format. No worker-local setting changes apply.
    fn compact(&mut self, cell: CellIdentity, limits: Limits) -> Result<(), Reject> {
        if !self.compaction_due(limits) {
            return Ok(());
        }
        self.fold(cell, limits)
    }

    fn fold(&mut self, cell: CellIdentity, limits: Limits) -> Result<(), Reject> {
        let start = self.tail_start();
        if start == self.transactions.len() {
            return Ok(());
        }
        let identity = physical::EngineIdentity {
            cell,
            database: self.identity,
        };
        let limits = physical_limits(limits);
        let mut image = if let Some(base) = &self.base {
            physical::Image::from_snapshot(
                physical::Snapshot {
                    head: physical::Head {
                        identity,
                        revision: base.revision,
                        image_digest: base.image_digest,
                    },
                    bytes: base.bytes.clone(),
                },
                limits,
            )
        } else {
            physical::Image::empty(identity, limits)
        }
        .map_err(physical_rejection)?;
        for transaction in &self.transactions[start..] {
            image = image
                .replay(&transaction.commit.receipt, &transaction.physical_changes)
                .map_err(physical_rejection)?;
        }
        let transaction = self.transactions.last().expect("nonempty physical tail");
        self.base = Some(recovery_base(transaction, &image));
        for transaction in &mut self.transactions {
            transaction.physical_changes.clear();
        }
        Ok(())
    }

    /// Called only by an ordered format activation or by hydration of an old
    /// archive after activation, never by legacy snapshot decoding or restart.
    /// Reproduce every v3 fold boundary to keep the physical representation
    /// independent of a replica's earlier applied prefix. Validate the remaining
    /// tail too; legacy opaque data is not a SQLite recovery source merely
    /// because it has not yet reached a fold boundary.
    fn migrate_legacy(&mut self, cell: CellIdentity, limits: Limits) -> Result<(), Reject> {
        if self.transactions.is_empty() {
            return Ok(());
        }
        let mut image = physical::Image::empty(
            physical::EngineIdentity {
                cell,
                database: self.identity,
            },
            physical_limits(limits),
        )
        .map_err(physical_rejection)?;
        let mut base = None;
        let mut entries = 0;
        let mut bytes = 0;
        for transaction in &self.transactions {
            image = image
                .replay(&transaction.commit.receipt, &transaction.physical_changes)
                .map_err(physical_rejection)?;
            entries += 1;
            bytes += transaction.physical_changes.len() as u64;
            if physical_tail_due(entries, bytes, limits) {
                base = Some(recovery_base(transaction, &image));
                entries = 0;
                bytes = 0;
            }
        }
        let covered = base.as_ref().map_or(0, |base| base.revision as usize);
        self.base = base;
        for transaction in &mut self.transactions[..covered] {
            transaction.physical_changes.clear();
        }
        Ok(())
    }

    fn permits(&self, principal: u128, permission: u8) -> bool {
        self.policy
            .iter()
            .any(|grant| grant.principal_id == principal && grant.permissions & permission != 0)
    }

    fn resolve(
        &self,
        principal: u128,
        request_id: u128,
        fingerprint: [u8; 32],
    ) -> Result<Option<&RequestRecord>, Reject> {
        if request_id == 0 {
            return Err(Reject::Invalid);
        }
        let record = self.requests.get(&request_id);
        let binding = match record {
            Some(RequestRecord::Accepted(sequence)) => {
                let tx = self.transaction(*sequence);
                Some((tx.admission.principal_id, tx.request_fingerprint))
            }
            Some(RequestRecord::Cancelled {
                admission,
                fingerprint,
                ..
            }) => Some((admission.principal_id, *fingerprint)),
            None => None,
        };
        if let Some((original_principal, original_fingerprint)) = binding {
            if original_principal != principal {
                return Err(Reject::Unauthorized);
            }
            if original_fingerprint != fingerprint {
                return Err(Reject::Conflict);
            }
        }
        Ok(record)
    }
}

fn physical_tail_due(entries: u64, bytes: u64, limits: Limits) -> bool {
    let threshold =
        u64::from(limits.max_state_bytes / 4).min(u64::from(limits.max_transaction_bytes) * 4);
    entries >= 8 || bytes >= threshold
}

fn recovery_base(transaction: &AcceptedTransaction, image: &physical::Image) -> RecoveryBase {
    RecoveryBase {
        source: transaction.commit.position,
        revision: transaction.commit.receipt.sequence,
        commit_hash: transaction.commit_hash,
        image_digest: image.head().image_digest,
        bytes: image.bytes().to_vec(),
    }
}

fn physical_limits(limits: Limits) -> physical::Limits {
    let pages =
        (limits.max_state_bytes / physical::PAGE_SIZE as u32).min(physical::MAX_DATABASE_PAGES);
    physical::Limits {
        max_database_pages: pages,
        max_changed_pages: pages,
        max_transaction_bytes: limits.max_transaction_bytes,
    }
}

fn physical_rejection(error: physical::Error) -> Reject {
    match error {
        physical::Error::Limits => Reject::Capacity,
        physical::Error::TooLarge => Reject::TooLarge,
        _ => Reject::Invalid,
    }
}

impl CellApplication {
    pub fn new(identity: CellIdentity, limits: Limits) -> Result<Self, Error> {
        validate_config(identity, limits)?;
        Ok(Self { identity, limits })
    }
}

impl Application for CellApplication {
    type Error = Error;

    fn apply(&mut self, previous: &[u8], committed: &[Entry]) -> Result<Vec<u8>, Error> {
        let mut state = codec::decode_state(previous, self.identity, self.limits)?;
        for entry in committed {
            state.advance(entry)?;
        }
        Ok(state.encode())
    }

    fn apply_with_results(
        &mut self,
        previous: &[u8],
        committed: &[Entry],
        requested: &[u64],
    ) -> Result<AppliedBatch, Error> {
        let mut state = codec::decode_state(previous, self.identity, self.limits)?;
        let mut results = Vec::new();
        for entry in committed {
            let activation = state.advance(entry)?;
            if requested.get(results.len()) == Some(&entry.index) {
                if let Some(activation) = activation {
                    results.push(match activation {
                        ActivationOutcome::History(value) => {
                            codec::encode_history_activation_outcome(&value)
                        }
                        ActivationOutcome::Retention(value) => {
                            codec::encode_retention_activation_outcome(&value)
                        }
                    });
                } else {
                    let outcome = state.last_outcome.as_ref().ok_or(Error::Position)?;
                    if outcome.position != state.position {
                        return Err(Error::Position);
                    }
                    results.push(encode_applied_outcome(outcome));
                }
            }
        }
        if results.len() != requested.len() {
            return Err(Error::Position);
        }
        Ok(AppliedBatch {
            state: state.encode(),
            results,
        })
    }
}

fn valid_database_identity(identity: DatabaseIdentity) -> bool {
    identity.database_id != 0 && identity.incarnation != 0 && identity.placement_generation != 0
}

fn validate_admission(admission: Admission) -> Result<(), Reject> {
    if admission.principal_id == 0
        || admission.credential_id == 0
        || admission.admission_id == 0
        || admission.auth_epoch == 0
        || admission.request_epoch == 0
    {
        return Err(Reject::Unauthorized);
    }
    Ok(())
}

fn validate_policy(policy: &[Grant], limits: Limits) -> Result<(), Reject> {
    if policy.is_empty() || policy.len() > limits.max_policy_grants as usize {
        return Err(Reject::Invalid);
    }
    let mut previous = 0;
    let mut administrator = false;
    for grant in policy {
        if grant.principal_id <= previous
            || grant.permissions == 0
            || grant.permissions & !(READ | WRITE | ADMIN) != 0
        {
            return Err(Reject::Invalid);
        }
        previous = grant.principal_id;
        administrator |= grant.permissions & ADMIN != 0;
    }
    if !administrator {
        return Err(Reject::Invalid);
    }
    Ok(())
}

fn validate_config(identity: CellIdentity, limits: Limits) -> Result<(), Error> {
    if identity.cell_id == 0 || identity.cell_incarnation == 0 {
        return Err(Error::Invalid("cell identity must be nonzero"));
    }
    if limits.max_state_bytes < 1024
        || limits.max_command_bytes == 0
        || limits.max_databases == 0
        || limits.max_policy_grants == 0
        || limits.max_admin_operations == 0
        || limits.max_requests_per_database == 0
        || limits.max_transaction_bytes == 0
        || limits.max_result_bytes == 0
    {
        return Err(Error::Invalid(
            "bounded nonzero limits and rejection reserve required",
        ));
    }
    Ok(())
}

fn position_within(position: Position, bound: Position) -> bool {
    position.term != 0
        && position.index != 0
        && position.index <= bound.index
        && position.term <= bound.term
        && (position.index != bound.index || position.term == bound.term)
}

fn validate_state(state: &CellState) -> Result<(), Error> {
    if state.bootstrap_admin == 0 || !position_within(state.position, state.position) {
        return Err(Error::Malformed("invalid state identity or position"));
    }
    for database in state.databases.values() {
        // Decoder constructs map keys from the identity; private transitions
        // preserve that relationship without a second unreachable key check.
        if !valid_database_identity(database.identity)
            || database.auth_epoch == 0
            || (database.owner.epoch == 0) != (database.owner.worker_instance_id == 0)
            || (database.active && database.owner.epoch == 0)
        {
            return Err(Error::Malformed("invalid database metadata"));
        }
        if (database.suspended && database.active) || (database.cold && !database.suspended) {
            return Err(Error::Malformed("invalid cold lifecycle"));
        }
        validate_retirement(database, state.position)?;
        validate_base(database, state.identity, state.position, state.limits)?;
        if let Some(archive) = database.archive {
            let view = database.view();
            if !position_within(archive.source, state.position)
                || archive.revision < database.retired.revision
                || archive.revision > view.revision
                || archive.object_bytes == 0
                || (archive.object_bytes as usize).saturating_add(192)
                    > state.limits.max_command_bytes as usize
                || archive.object_digest == [0; 32]
                || (archive.revision == view.revision && archive.commit_hash != view.commit_hash)
            {
                return Err(Error::Malformed("invalid archive reference"));
            }
            let archived_hash = if archive.revision == database.retired.revision {
                database.retired.commit_hash
            } else {
                let transaction = database.transaction(archive.revision);
                if !position_within(transaction.commit.position, archive.source) {
                    return Err(Error::Malformed("archive source precedes accepted history"));
                }
                transaction.commit_hash
            };
            if archive.commit_hash != archived_hash {
                return Err(Error::Malformed(
                    "archive hash does not match retained history",
                ));
            }
            if database.cold
                && (archive.revision != view.revision
                    || archive.metadata_digest != codec::archive_metadata(database))
            {
                return Err(Error::Malformed("cold archive does not cover metadata"));
            }
        } else if database.cold {
            return Err(Error::Malformed("cold database has no archive"));
        }
        validate_policy(&database.policy, state.limits)
            .map_err(|_| Error::Malformed("invalid stored policy"))?;
        let mut previous_hash = database.retired.commit_hash;
        let mut previous_position = database.retired.source;
        for (index, transaction) in database.transactions.iter().enumerate() {
            let sequence = database.retired.revision + index as u64 + 1;
            let ticket = &transaction.commit.receipt.ticket;
            let position = transaction.commit.position;
            if ticket.cell_id != state.identity.cell_id
                || ticket.cell_incarnation != state.identity.cell_incarnation
                || ticket.database_id != database.identity.database_id
                || ticket.incarnation != database.identity.incarnation
                || ticket.placement_generation != database.identity.placement_generation
                || ticket.auth_epoch == 0
                || ticket.auth_epoch > database.auth_epoch
                || ticket.owner_epoch == 0
                || ticket.owner_epoch > database.owner.epoch
                || ticket.worker_instance_id == 0
                || ticket.request_id == 0
                || ticket.predecessor != sequence - 1
                || transaction.commit.receipt.sequence != sequence
                || validate_admission(transaction.admission).is_err()
                || transaction.admission.auth_epoch != ticket.auth_epoch
                || transaction.admission.request_epoch != database.request_epoch
                || !position_within(position, state.position)
                || position.index <= previous_position.index
                || position.term < previous_position.term
                || database.retirement_position.is_some_and(|retired| {
                    !position_within(retired, position) || position.index == retired.index
                })
            {
                return Err(Error::Malformed("invalid accepted transaction identity"));
            }
            if database.cold || sequence <= database.base_revision() {
                if !transaction.physical_changes.is_empty() {
                    return Err(Error::Malformed(
                        "retired history retained partial physical data",
                    ));
                }
            } else if transaction.physical_changes.is_empty()
                || payload_digest(&transaction.physical_changes) != ticket.payload_digest
                || codec::transaction_hash(previous_hash, transaction) != transaction.commit_hash
            {
                return Err(Error::Malformed("invalid accepted transaction integrity"));
            }
            if database.requests.get(&ticket.request_id) != Some(&RequestRecord::Accepted(sequence))
            {
                return Err(Error::Malformed(
                    "accepted transaction has no matching request",
                ));
            }
            previous_hash = transaction.commit_hash;
            previous_position = position;
        }
        for (&request_id, record) in &database.requests {
            if request_id == 0 {
                return Err(Error::Malformed("zero request identity"));
            }
            match record {
                RequestRecord::Accepted(sequence) => {
                    if *sequence <= database.retired.revision
                        || *sequence > database.view().revision
                    {
                        return Err(Error::Malformed(
                            "request points outside transaction history",
                        ));
                    }
                    if database
                        .transaction(*sequence)
                        .commit
                        .receipt
                        .ticket
                        .request_id
                        != request_id
                    {
                        return Err(Error::Malformed("request points to a different request"));
                    }
                }
                RequestRecord::Cancelled {
                    admission,
                    position,
                    ..
                } => {
                    if validate_admission(*admission).is_err()
                        || admission.auth_epoch > database.auth_epoch
                        || admission.request_epoch != database.request_epoch
                        || !position_within(*position, state.position)
                        || database.retirement_position.is_some_and(|retired| {
                            !position_within(retired, *position) || position.index == retired.index
                        })
                    {
                        return Err(Error::Malformed("invalid cancellation fence"));
                    }
                }
            }
        }
        for (&request_id, &position) in &database.acknowledged {
            let terminal = match database.requests.get(&request_id) {
                Some(RequestRecord::Accepted(sequence)) => {
                    database.transaction(*sequence).commit.position
                }
                Some(RequestRecord::Cancelled { position, .. }) => *position,
                None => return Err(Error::Malformed("acknowledgement without request")),
            };
            if !position_within(position, state.position)
                || !position_within(terminal, position)
                || terminal.index == position.index
            {
                return Err(Error::Malformed("invalid request acknowledgement position"));
            }
        }
    }
    for (&operation_id, record) in &state.administration {
        if operation_id == 0
            || validate_admission(record.admission).is_err()
            || !position_within(record.position, state.position)
        {
            return Err(Error::Malformed("invalid administrative receipt"));
        }
        let database = state
            .databases
            .get(&record.database.database_id)
            .ok_or(Error::Malformed("administrative database absent"))?;
        if database.identity != record.database || record.admission.auth_epoch > database.auth_epoch
        {
            return Err(Error::Malformed("administrative database binding mismatch"));
        }
        match &record.result {
            AdminResult::Created => {}
            AdminResult::OwnerClaimed(token) => {
                if token.epoch == 0
                    || token.epoch > database.owner.epoch
                    || token.worker_instance_id == 0
                {
                    return Err(Error::Malformed("invalid historical owner token"));
                }
            }
            AdminResult::OwnerActivated => {
                if database.owner.epoch == 0 {
                    return Err(Error::Malformed("activation without an owner"));
                }
            }
            AdminResult::AuthChanged(epoch) => {
                if *epoch < 2 || *epoch > database.auth_epoch {
                    return Err(Error::Malformed("invalid historical auth epoch"));
                }
            }
            AdminResult::Suspended(epoch) => {
                if *epoch > database.owner.epoch {
                    return Err(Error::Malformed("invalid historical suspend epoch"));
                }
            }
            AdminResult::ArchivePublished(digest)
            | AdminResult::ArchivePruned(digest)
            | AdminResult::ArchiveHydrated(digest) => {
                if *digest == [0; 32] {
                    return Err(Error::Malformed("invalid historical archive digest"));
                }
            }
        }
    }
    if let Some(last) = &state.last_outcome {
        if !position_within(last.position, state.position) {
            return Err(Error::Malformed("invalid outcome position"));
        }
        let matches = match &last.outcome {
            Outcome::Accepted(commit) | Outcome::AlreadyCommitted(commit) => {
                let tx = state
                    .databases
                    .get(&commit.receipt.ticket.database_id)
                    .and_then(|db| db.transactions.iter().find(|tx| tx.commit == *commit));
                tx.is_some()
                    && position_within(commit.position, last.position)
                    && (!matches!(last.outcome, Outcome::Accepted(_))
                        || commit.position == last.position)
            }
            Outcome::Administrative(result) | Outcome::AlreadyApplied(result) => {
                state.administration.values().any(|record| {
                    record.result == *result
                        && position_within(record.position, last.position)
                        && (!matches!(last.outcome, Outcome::Administrative(_))
                            || record.position == last.position)
                })
            }
            Outcome::Cancelled | Outcome::AlreadyCancelled => state.databases.values().any(|db| {
                db.requests.values().any(|record| {
                    if let RequestRecord::Cancelled { position, .. } = record {
                        position_within(*position, last.position)
                            && (!matches!(last.outcome, Outcome::Cancelled)
                                || *position == last.position)
                    } else {
                        false
                    }
                })
            }),
            Outcome::Rejected(_) => true,
            Outcome::RequestAcknowledged => state.databases.values().any(|db| {
                db.acknowledged
                    .values()
                    .any(|position| position_within(*position, last.position))
            }),
            Outcome::RequestsRotated { epoch } => state.databases.values().any(|db| {
                db.request_epoch == *epoch && db.retirement_position == Some(last.position)
            }),
        };
        if !matches {
            return Err(Error::Malformed("outcome has no matching durable record"));
        }
    } else if !state.databases.is_empty() {
        return Err(Error::Malformed("non-genesis state lost its outcome"));
    }
    Ok(())
}

fn validate_retirement(database: &Database, position: Position) -> Result<(), Error> {
    if database.request_epoch == 0
        || database
            .retired
            .revision
            .checked_add(database.transactions.len() as u64)
            .is_none()
        || database.acknowledged.len() > database.requests.len()
    {
        return Err(Error::Malformed("invalid request retirement bounds"));
    }
    if database.retired.revision == 0 {
        if database.retired != RetiredPrefix::EMPTY {
            return Err(Error::Malformed("nonempty zero retired prefix"));
        }
    } else if !position_within(database.retired.source, position)
        || database
            .base
            .as_ref()
            .is_none_or(|base| base.revision < database.retired.revision)
    {
        return Err(Error::Malformed("retired prefix has no recoverable base"));
    }
    match database.retirement_position {
        Some(retirement) => {
            if database.request_epoch == 1
                || !position_within(retirement, position)
                || (database.retired.revision != 0
                    && (!position_within(database.retired.source, retirement)
                        || database.retired.source.index == retirement.index))
                || database
                    .archive
                    .is_some_and(|archive| !position_within(retirement, archive.source))
            {
                return Err(Error::Malformed("invalid namespace retirement position"));
            }
        }
        None => {
            if database.request_epoch != 1 || database.retired != RetiredPrefix::EMPTY {
                return Err(Error::Malformed("request epoch lost retirement fence"));
            }
        }
    }
    Ok(())
}

fn validate_base(
    database: &Database,
    cell: CellIdentity,
    position: Position,
    limits: Limits,
) -> Result<(), Error> {
    let Some(base) = &database.base else {
        return Ok(());
    };
    if base.revision == 0
        || base.revision < database.retired.revision
        || base.revision > database.retired.revision + database.transactions.len() as u64
        || !position_within(base.source, position)
    {
        return Err(Error::Malformed("invalid recovery base position"));
    }
    let (source, hash) = if base.revision == database.retired.revision {
        (database.retired.source, database.retired.commit_hash)
    } else {
        let transaction = database.transaction(base.revision);
        (transaction.commit.position, transaction.commit_hash)
    };
    if base.source != source || base.commit_hash != hash {
        return Err(Error::Malformed(
            "recovery base does not cover its logical prefix",
        ));
    }
    if database.cold {
        if !base.bytes.is_empty() {
            return Err(Error::Malformed("cold state retained a physical base"));
        }
    } else {
        physical::Image::from_snapshot(
            physical::Snapshot {
                head: physical::Head {
                    identity: physical::EngineIdentity {
                        cell,
                        database: database.identity,
                    },
                    revision: base.revision,
                    image_digest: base.image_digest,
                },
                bytes: base.bytes.clone(),
            },
            physical_limits(limits),
        )
        .map_err(|_| Error::Malformed("invalid recovery base image"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
