//! Bounded deterministic cell metadata and physical-transaction acceptance.
//!
//! Admission identities must come from a trusted credential verifier and be
//! bound to the actual request before proposal. This module rechecks current
//! replicated policy; it does not authenticate callers, perform I/O, publish
//! SQLite pages, or provide a transport. Reads require a fresh Raft read barrier
//! and `decode_bound` against the same durable Store view before using this API.
//! All accepted transactions, cancellation fences and administrative receipts
//! are retained. Capacity exhaustion rejects new work; it never evicts a fence.
//! The cell bootstrap administrator is immutable in this G0 format; credential
//! rotation, cell-admin rotation and a production admission service are absent.

use std::collections::BTreeMap;
use std::fmt::{self, Display};

use raft::eraftpb::{Entry, EntryType};
use scap_core::{CommitReceipt, CommitTicket, PreparedWrite};
use scap_raft_driver::{Application, AppliedBatch};
use sha2::{Digest, Sha256};

mod codec;

pub const READ: u8 = 1;
pub const WRITE: u8 = 2;
pub const ADMIN: u8 = 4;

/// Bound for the versioned per-entry result, excluding the retained SQL result.
/// A tracked result is meaningful only from the matching durable driver attempt.
pub const MAX_APPLIED_OUTCOME_BYTES: u32 = 512;
const RESERVED_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellIdentity {
    pub cell_id: u128,
    pub cell_incarnation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub term: u64,
    pub index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseIdentity {
    pub database_id: u128,
    pub incarnation: u64,
    pub placement_generation: u64,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedOutcome {
    pub position: Position,
    pub outcome: Outcome,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// No record at this view. A later or delayed proposal may still commit.
    Unknown,
    Committed {
        commit: CommitResult,
        result: Vec<u8>,
    },
    Cancelled {
        position: Position,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseView {
    pub identity: DatabaseIdentity,
    pub auth_epoch: u64,
    pub owner: OwnerToken,
    pub active: bool,
    pub revision: u64,
    pub commit_hash: [u8; 32],
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct Database {
    identity: DatabaseIdentity,
    auth_epoch: u64,
    owner: OwnerToken,
    active: bool,
    policy: Vec<Grant>,
    transactions: Vec<AcceptedTransaction>,
    requests: BTreeMap<u128, RequestRecord>,
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
            limits,
            position: genesis,
            databases: BTreeMap::new(),
            administration: BTreeMap::new(),
            last_outcome: None,
        })
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
        match db.resolve(admission.principal_id, request_id, fingerprint)? {
            Some(RequestRecord::Accepted(sequence)) => {
                let tx = &db.transactions[*sequence as usize - 1];
                Ok(Lookup::Committed {
                    commit: tx.commit.clone(),
                    result: tx.result.clone(),
                })
            }
            Some(RequestRecord::Cancelled { position, .. }) => Ok(Lookup::Cancelled {
                position: *position,
            }),
            None => Ok(Lookup::Unknown),
        }
    }

    /// Trusted internal recovery only, never a public READ endpoint. This exposes
    /// all retained physical transactions and original results, including those
    /// from other principals. The caller must bind a validated recovery worker;
    /// it must not export these records based only on user READ permission.
    /// Consumers also validate position/identity and the engine's physical format
    /// before rebuilding an isolated SQLite instance.
    pub fn recovery_transactions(
        &self,
        identity: DatabaseIdentity,
        admission: Admission,
    ) -> Result<&[AcceptedTransaction], Reject> {
        Ok(&self.authorized(identity, admission, READ)?.transactions)
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

    fn advance(&mut self, entry: &Entry) -> Result<(), Error> {
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
            return Ok(());
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
        Ok(())
    }

    fn fits(&self) -> bool {
        codec::encode_state(self, false)
            .len()
            .saturating_add(RESERVED_BYTES)
            <= self.limits.max_state_bytes as usize
    }

    fn execute(&mut self, command: &Command, position: Position) -> Result<Outcome, Reject> {
        if command.cell != self.identity || !valid_database_identity(command.database) {
            return Err(Reject::Fenced);
        }
        validate_admission(command.admission)?;
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
                if db.owner.epoch != expected_epoch || worker_instance_id == 0 {
                    return Err(Reject::Fenced);
                }
                let epoch = expected_epoch.checked_add(1).ok_or(Reject::Exhausted)?;
                db.owner = OwnerToken {
                    epoch,
                    worker_instance_id,
                };
                db.active = false;
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
                if token.epoch == 0 || db.owner != token {
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
                    db.transactions[*sequence as usize - 1].commit.clone(),
                ));
            }
            Some(RequestRecord::Cancelled { .. }) => return Err(Reject::Cancelled),
            None => {}
        }
        if !db.active
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
        // The retained transaction count is bounded by the u32 request limit.
        let sequence = previous.revision + 1;
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
        match db.resolve(command.admission.principal_id, request_id, fingerprint)? {
            Some(RequestRecord::Accepted(sequence)) => {
                return Ok(Outcome::AlreadyCommitted(
                    db.transactions[*sequence as usize - 1].commit.clone(),
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
}

impl Database {
    fn view(&self) -> DatabaseView {
        DatabaseView {
            identity: self.identity,
            auth_epoch: self.auth_epoch,
            owner: self.owner,
            active: self.active,
            revision: self.transactions.len() as u64,
            commit_hash: self
                .transactions
                .last()
                .map_or([0; 32], |tx| tx.commit_hash),
        }
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
                let tx = &self.transactions[*sequence as usize - 1];
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
            state.advance(entry)?;
            if requested.get(results.len()) == Some(&entry.index) {
                let outcome = state.last_outcome.as_ref().ok_or(Error::Position)?;
                if outcome.position != state.position {
                    return Err(Error::Position);
                }
                results.push(encode_applied_outcome(outcome));
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
        validate_policy(&database.policy, state.limits)
            .map_err(|_| Error::Malformed("invalid stored policy"))?;
        let mut previous_hash = [0; 32];
        let mut previous_position = Position { term: 0, index: 0 };
        for (index, transaction) in database.transactions.iter().enumerate() {
            let sequence = index as u64 + 1;
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
                || ticket.predecessor != index as u64
                || transaction.commit.receipt.sequence != sequence
                || validate_admission(transaction.admission).is_err()
                || transaction.admission.auth_epoch != ticket.auth_epoch
                || !position_within(position, state.position)
                || position.index <= previous_position.index
                || position.term < previous_position.term
            {
                return Err(Error::Malformed("invalid accepted transaction identity"));
            }
            if transaction.physical_changes.is_empty()
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
                    if *sequence == 0 || *sequence > database.transactions.len() as u64 {
                        return Err(Error::Malformed(
                            "request points outside transaction history",
                        ));
                    }
                    if database.transactions[*sequence as usize - 1]
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
                        || !position_within(*position, state.position)
                    {
                        return Err(Error::Malformed("invalid cancellation fence"));
                    }
                }
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
        };
        if !matches {
            return Err(Error::Malformed("outcome has no matching durable record"));
        }
    } else if !state.databases.is_empty() {
        return Err(Error::Malformed("non-genesis state lost its outcome"));
    }
    if !state.fits() {
        return Err(Error::Limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
