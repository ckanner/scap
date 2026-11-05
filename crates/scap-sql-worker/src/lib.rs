//! Trusted, thread-confined SQLite owner recovery and request orchestration.
//!
//! Construct, call and drop on one dedicated SQL thread, separate from the
//! Runtime owner and asynchronous networking. There is no background scheduler,
//! public authentication, business RPC, or automatic retry in this module.
//! Every start claims a fresh owner and uses a new directory; a prior local
//! cache is never evidence of authority or of a transaction's outcome.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use scap_cell::{AdminResult, CommandKind, Outcome, OwnerToken, Position, Reject};
use scap_cell_client::{CellPort, Client, Gate, RequestContext};
use scap_core::CommitTicket;
use scap_engine::{EngineIdentity, Head, Image, RecoveryTarget};
use scap_raft_runtime::Clock;
use scap_sql::{Statement, TransactionResult};
use scap_sqlite::{CommitGate, Completed, ReadInterrupt, SqliteWriter, WriterLimits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerRequest {
    pub identity: EngineIdentity,
    pub expected_owner_epoch: u64,
    /// Unique for this worker start; never reuse a previous live worker's ID.
    pub worker_instance_id: u128,
    pub claim_operation_id: u128,
    pub activate_operation_id: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerLimits {
    pub engine: scap_engine::Limits,
    pub sqlite: WriterLimits,
}

/// One buffered read-only snapshot authorized by this exact fresh cell view.
/// No transaction receipt is created and no database revision is advanced.
#[derive(Debug, PartialEq)]
pub struct ReadCompleted {
    pub result: TransactionResult,
    pub position: Position,
    pub revision: u64,
    pub commit_hash: [u8; 32],
}

#[derive(Debug)]
pub enum Error {
    Invalid,
    Stopped,
    Unknown,
    Client(scap_cell_client::Error),
    Rejected(Reject),
    Image(scap_engine::Error),
    Native(scap_sqlite::Error),
}

/// An exclusively owned engine. Errors or historical replay retire this writer;
/// head advances only after the full native commit completes. These obligations
/// are implemented by SqliteWriter and independently tested at its native gate.
pub trait Engine {
    fn head(&self) -> Head;
    fn is_stopped(&self) -> bool;
    fn execute(
        &mut self,
        ticket: CommitTicket,
        statements: &[Statement],
    ) -> Result<Completed, scap_sqlite::Error>;

    /// Read exactly the current head without mutating it. The native adapter
    /// enforces a read-only SQLite snapshot and invokes `interrupt` throughout
    /// execution. Legacy write-only adapters must fail closed for this API.
    fn query(
        &mut self,
        _statements: &[Statement],
        _interrupt: ReadInterrupt,
    ) -> Result<TransactionResult, scap_sqlite::Error> {
        Err(scap_sqlite::Error::ReadUnsupported)
    }
}

impl<G: CommitGate + 'static> Engine for SqliteWriter<G> {
    fn head(&self) -> Head {
        self.image().head()
    }

    fn is_stopped(&self) -> bool {
        SqliteWriter::is_stopped(self)
    }

    fn execute(
        &mut self,
        ticket: CommitTicket,
        statements: &[Statement],
    ) -> Result<Completed, scap_sqlite::Error> {
        SqliteWriter::execute(self, ticket, statements)
    }

    fn query(
        &mut self,
        statements: &[Statement],
        interrupt: ReadInterrupt,
    ) -> Result<TransactionResult, scap_sqlite::Error> {
        SqliteWriter::query(self, statements, interrupt)
    }
}

/// Filesystem/native construction boundary. An engine must use exactly `image`
/// and `gate`, and may not publish itself before the owner activation completes.
pub trait EngineFactory<P: CellPort + 'static> {
    type Engine: Engine;

    fn create(
        &mut self,
        directory: &Path,
        image: Image,
        limits: WriterLimits,
        gate: Gate<P>,
    ) -> Result<Self::Engine, scap_sqlite::Error>;
}

pub struct NativeFactory;

impl<P: CellPort + 'static> EngineFactory<P> for NativeFactory {
    type Engine = SqliteWriter<Gate<P>>;

    fn create(
        &mut self,
        directory: &Path,
        image: Image,
        limits: WriterLimits,
        gate: Gate<P>,
    ) -> Result<Self::Engine, scap_sqlite::Error> {
        SqliteWriter::create_new(directory, image, limits, gate)
    }
}

/// `Gate` holds an Rc, making a writer !Send/!Sync even for a mock engine. The
/// trusted caller bounds admission to this SQL thread; no queue is created here.
pub struct Writer<P: CellPort + 'static, E: Engine = SqliteWriter<Gate<P>>> {
    engine: E,
    client: Client<P>,
    gate: Gate<P>,
    identity: EngineIdentity,
    owner: OwnerToken,
    clock: Arc<dyn Clock>,
    image_limits: scap_engine::Limits,
    stopped: bool,
}

impl<P: CellPort + Clone + 'static> Writer<P> {
    pub fn recover(
        client: Client<P>,
        context: &RequestContext,
        request: OwnerRequest,
        directory: &Path,
        limits: WorkerLimits,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        Self::recover_with(
            client,
            context,
            request,
            directory,
            limits,
            clock,
            NativeFactory,
        )
    }
}

impl<P: CellPort + Clone + 'static, E: Engine> Writer<P, E> {
    pub fn recover_with<F: EngineFactory<P, Engine = E>>(
        mut client: Client<P>,
        context: &RequestContext,
        request: OwnerRequest,
        directory: &Path,
        limits: WorkerLimits,
        clock: Arc<dyn Clock>,
        mut factory: F,
    ) -> Result<Self, Error> {
        if request.worker_instance_id == 0
            || request.claim_operation_id == 0
            || request.activate_operation_id == 0
            || request.claim_operation_id == request.activate_operation_id
        {
            return Err(Error::Invalid);
        }
        let owner = OwnerToken {
            epoch: request
                .expected_owner_epoch
                .checked_add(1)
                .ok_or(Error::Invalid)?,
            worker_instance_id: request.worker_instance_id,
        };
        live(context, clock.as_ref())?;
        // Check target scope before any administrative mutation. Client also
        // binds every port call to the immutable full cluster/cell/node scope.
        let initial = client.read(context).map_err(Error::Client)?;
        if initial.identity() != request.identity.cell {
            return Err(Error::Invalid);
        }
        let database = initial
            .database(request.identity.database.database_id)
            .ok_or(Error::Rejected(Reject::NotFound))?;
        if database.identity != request.identity.database {
            return Err(Error::Rejected(Reject::Fenced));
        }
        administrative(
            client
                .submit(
                    context,
                    request.identity.database,
                    CommandKind::ClaimOwner {
                        operation_id: request.claim_operation_id,
                        expected_epoch: request.expected_owner_epoch,
                        worker_instance_id: request.worker_instance_id,
                    },
                )
                .map_err(Error::Client)?
                .outcome,
            AdminResult::OwnerClaimed(owner),
        )?;
        let state = client.read(context).map_err(Error::Client)?;
        let database = state
            .database(request.identity.database.database_id)
            .ok_or(Error::Rejected(Reject::NotFound))?;
        if database.identity != request.identity.database
            || database.owner != owner
            || database.active
        {
            return Err(Error::Rejected(Reject::Fenced));
        }
        let target = RecoveryTarget {
            position: state.position(),
            revision: database.revision,
            commit_hash: database.commit_hash,
        };
        let image = Image::recover(
            &state,
            request.identity,
            context.admission,
            target,
            limits.engine,
        )
        .map_err(Error::Image)?;
        let gate = Gate::new(client.clone());
        live(context, clock.as_ref())?;
        let engine = factory
            .create(directory, image, limits.sqlite, gate.clone())
            .map_err(Error::Native)?;
        // Filesystem construction and fsync cannot be forcibly cancelled. The
        // original budget is checked again before activation and before return.
        live(context, clock.as_ref())?;
        administrative(
            client
                .submit(
                    context,
                    request.identity.database,
                    CommandKind::ActivateOwner {
                        operation_id: request.activate_operation_id,
                        token: owner,
                        restored_revision: target.revision,
                        restored_hash: target.commit_hash,
                    },
                )
                .map_err(Error::Client)?
                .outcome,
            AdminResult::OwnerActivated,
        )?;
        let state = client.read(context).map_err(Error::Client)?;
        state
            .authorize_write(
                request.identity.database,
                context.admission,
                owner,
                target.revision,
            )
            .map_err(Error::Rejected)?;
        live(context, clock.as_ref())?;
        Ok(Self {
            engine,
            client,
            gate,
            identity: request.identity,
            owner,
            clock,
            image_limits: limits.engine,
            stopped: false,
        })
    }

    pub fn head(&self) -> Head {
        self.engine.head()
    }

    pub fn owner(&self) -> OwnerToken {
        self.owner
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped || self.engine.is_stopped()
    }

    /// A fresh Safe ReadIndex authorizes READ and binds the private native
    /// snapshot to the exact accepted physical head. This bounded first version
    /// replays retained physical history to verify its image digest against the
    /// current commit-hash chain; it is O(retained history), not a claimed
    /// low-latency implementation. It never proposes or records read results.
    pub fn query(
        &mut self,
        context: RequestContext,
        statements: &[Statement],
    ) -> Result<ReadCompleted, Error> {
        if self.is_stopped() {
            return Err(Error::Stopped);
        }
        self.stopped = true;
        live(&context, self.clock.as_ref())?;
        let state = self.client.read(&context).map_err(Error::Client)?;
        let view = state
            .authorize_read(self.identity.database, context.admission, self.owner)
            .map_err(Error::Rejected)?;
        let target = RecoveryTarget {
            position: view.position,
            revision: view.database.revision,
            commit_hash: view.database.commit_hash,
        };
        let verified = Image::recover(
            &state,
            self.identity,
            context.admission,
            target,
            self.image_limits,
        )
        .map_err(Error::Image)?;
        let head = self.engine.head();
        if head != verified.head() {
            return Err(Error::Image(scap_engine::Error::Head));
        }
        live(&context, self.clock.as_ref())?;
        let control = context.clone();
        let clock = self.clock.clone();
        let result = self
            .engine
            .query(
                statements,
                Arc::new(move || live(&control, clock.as_ref()).is_err()),
            )
            .map_err(Error::Native)?;
        live(&context, self.clock.as_ref())?;
        if self.engine.is_stopped() || self.engine.head() != head {
            return Err(Error::Image(scap_engine::Error::Head));
        }
        self.stopped = false;
        Ok(ReadCompleted {
            result,
            position: target.position,
            revision: target.revision,
            commit_hash: target.commit_hash,
        })
    }

    pub fn execute(
        &mut self,
        context: RequestContext,
        request_id: u128,
        statements: &[Statement],
    ) -> Result<Completed, Error> {
        if self.is_stopped() {
            return Err(Error::Stopped);
        }
        self.stopped = true;
        live(&context, self.clock.as_ref())?;
        if request_id == 0 {
            return Err(Error::Invalid);
        }
        let ticket = CommitTicket {
            cell_id: self.identity.cell.cell_id,
            cell_incarnation: self.identity.cell.cell_incarnation,
            database_id: self.identity.database.database_id,
            incarnation: self.identity.database.incarnation,
            placement_generation: self.identity.database.placement_generation,
            owner_epoch: self.owner.epoch,
            worker_instance_id: self.owner.worker_instance_id,
            auth_epoch: context.admission.auth_epoch,
            request_id,
            predecessor: self.engine.head().revision,
            payload_digest: [0; 32],
        };
        let _invocation = self
            .gate
            .begin(context.clone(), ticket.clone())
            .map_err(Error::Client)?;
        let completed = self
            .engine
            .execute(ticket, statements)
            .map_err(|error| match error {
                // The gate has current authorization and an authoritative
                // generation fence. Preserve that definitive status without
                // suggesting that the retired SQL never committed.
                scap_sqlite::Error::Rejected(scap_core::Rejection::Retired) => {
                    Error::Rejected(Reject::Retired)
                }
                other => Error::Native(other),
            })?;
        if live(&context, self.clock.as_ref()).is_err() {
            return Err(Error::Native(scap_sqlite::Error::CommittedButUnavailable {
                receipt: Box::new(completed.receipt),
            }));
        }
        self.stopped = self.engine.is_stopped();
        Ok(completed)
    }
}

fn live(context: &RequestContext, clock: &dyn Clock) -> Result<(), Error> {
    if context.cancelled.load(Ordering::Acquire)
        || clock.now().map_err(|_| Error::Unknown)?.instant >= context.deadline
    {
        return Err(Error::Unknown);
    }
    Ok(())
}

fn administrative(outcome: Outcome, expected: AdminResult) -> Result<(), Error> {
    match outcome {
        Outcome::Administrative(result) | Outcome::AlreadyApplied(result) if result == expected => {
            Ok(())
        }
        Outcome::Rejected(reason) => Err(Error::Rejected(reason)),
        _ => Err(Error::Unknown),
    }
}

#[cfg(test)]
mod tests;
