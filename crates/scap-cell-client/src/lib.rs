//! Trusted, thread-confined SQLite admission through one fixed cell runtime.
//!
//! The runtime owns Raft progress on another thread. This synchronous client
//! never polls it. A caller must authenticate `RequestContext::admission` and
//! retain its original absolute deadline; this is not a public network API.
//! Only a tracked, durably applied proposal can authorize native publication.
//! All post-submission errors are unknown outcomes, never proof of non-commit.

use std::cell::RefCell;
use std::fmt::{self, Display};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use scap_cell::{
    Admission, AppliedOutcome, CellIdentity, CellState, Command, CommandKind, CommitResult,
    DatabaseIdentity, Limits, Lookup, Outcome, OwnerToken, Position, Reject,
};
use scap_core::{CommitTicket, PreparedWrite, Rejection};
use scap_raft_driver::ProposalResult;
use scap_raft_runtime::{Clock, ReadView};
use scap_raft_store::Identity;
use scap_sqlite::{CommitGate, GateDecision, LookupDecision};

mod runtime;
pub use runtime::RuntimePort;

/// Transport and clock-independent cell boundary. Implementations must bind
/// every call to their immutable replica identity and correlate proposal
/// results to the exact submitted bytes. Returning admission is insufficient.
pub trait CellPort {
    fn identity(&self) -> Identity;
    fn read(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ReadView, scap_raft_runtime::Error>;
    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ProposalResult, scap_raft_runtime::Error>;
}

/// One trusted invocation, never a reusable authentication cache. Cancelling
/// stops waiting within a runtime tick; an already admitted write can commit.
#[derive(Clone)]
pub struct RequestContext {
    pub admission: Admission,
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A second invocation cannot replace a live request's identity or budget.
    Busy,
    /// No conclusion about whether an already submitted command committed.
    Unknown,
    /// Invalid local scope, command or invocation binding, before submission.
    InvalidContext,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Uncached trusted cell access. Clone shares the port's underlying runtime,
/// but never inherits an active SQL invocation or an old read barrier.
#[derive(Clone)]
pub struct Client<P> {
    identity: Identity,
    cell: CellIdentity,
    limits: Limits,
    port: P,
    clock: Arc<dyn Clock>,
}

impl<P: CellPort> Client<P> {
    pub fn new(
        cluster_id: u128,
        cell: CellIdentity,
        limits: Limits,
        port: P,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        let identity = port.identity();
        if cluster_id == 0
            || cell.cell_id == 0
            || cell.cell_incarnation == 0
            || identity.node_id == 0
            || identity.cluster_id != cluster_id
            || identity.cell_id != cell.cell_id
            || identity.cell_incarnation != cell.cell_incarnation
        {
            return Err(Error::InvalidContext);
        }
        Ok(Self {
            identity,
            cell,
            limits,
            port,
            clock,
        })
    }

    fn check(&self, context: &RequestContext) -> Result<(), Error> {
        if self.port.identity() != self.identity
            || context.cancelled.load(Ordering::Acquire)
            || self.clock.now().map_err(|_| Error::Unknown)?.instant >= context.deadline
        {
            return Err(Error::Unknown);
        }
        Ok(())
    }

    /// Fresh Safe ReadIndex plus strict decoding against that exact durable
    /// view. The full state is for trusted recovery/authorization code only;
    /// this method itself does not grant a tenant permission to export it.
    pub fn read(&mut self, context: &RequestContext) -> Result<CellState, Error> {
        self.check(context)?;
        let view = self
            .port
            .read(context.deadline, &context.cancelled)
            .map_err(|_| Error::Unknown)?;
        if view.identity != self.identity
            || view.term == 0
            || view.index == 0
            || view.barrier.ticket.boot_id == 0
            || view.barrier.ticket.sequence == 0
            || view.barrier.index == 0
            || view.barrier.index > view.index
        {
            return Err(Error::Unknown);
        }
        let state = CellState::decode_bound(
            &view.application,
            self.cell,
            Position {
                term: view.term,
                index: view.index,
            },
            self.limits,
        )
        .map_err(|_| Error::Unknown)?;
        self.check(context)?;
        Ok(state)
    }

    /// Submit one command, without retries, and return only its exact durable
    /// application result. The caller still checks the business outcome.
    pub fn submit(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        kind: CommandKind,
    ) -> Result<AppliedOutcome, Error> {
        self.check(context)?;
        let data = scap_cell::encode_command(
            &Command {
                cell: self.cell,
                database,
                admission: context.admission,
                kind,
            },
            self.limits,
        )
        .map_err(|_| Error::InvalidContext)?;
        self.check(context)?;
        let result = self
            .port
            .propose(data, context.deadline, &context.cancelled)
            .map_err(|_| Error::Unknown)?;
        if result.ticket.boot_id == 0 || result.ticket.sequence == 0 {
            return Err(Error::Unknown);
        }
        let applied = scap_cell::decode_applied_outcome(
            &result.data,
            Position {
                term: result.term,
                index: result.index,
            },
        )
        .map_err(|_| Error::Unknown)?;
        self.check(context)?;
        Ok(applied)
    }

    fn history(
        &mut self,
        context: &RequestContext,
        ticket: &CommitTicket,
        fingerprint: [u8; 32],
        expected: &CommitResult,
    ) -> Result<Vec<u8>, Error> {
        let state = self.read(context)?;
        let database = database(ticket);
        let revision = state
            .database(database.database_id)
            .ok_or(Error::Unknown)?
            .revision;
        // A concurrent accepted duplicate can advance revision after the
        // original preflight. Authorize the current owner/current view; the
        // historical receipt retains its own original predecessor and digest.
        state
            .authorize_write(database, context.admission, owner(ticket), revision)
            .map_err(|_| Error::Unknown)?;
        match state.lookup(database, context.admission, ticket.request_id, fingerprint) {
            Ok(Lookup::Committed { commit, result }) if &commit == expected => Ok(result),
            _ => Err(Error::Unknown),
        }
    }
}

enum Phase {
    Fresh,
    Prepared([u8; 32]),
    Finished,
}

struct Active {
    context: RequestContext,
    ticket: CommitTicket,
    phase: Phase,
}

struct Shared<P> {
    client: Client<P>,
    active: Option<Active>,
}

/// Clone this handle into a persistent `SqliteWriter`, then hold a fresh
/// `Invocation` around each `execute`. `Rc` keeps both on the SQL thread; the
/// runtime owner must remain on another thread while this gate waits.
pub struct Gate<P> {
    shared: Rc<RefCell<Shared<P>>>,
}

impl<P> Clone for Gate<P> {
    fn clone(&self) -> Self {
        Self {
            shared: Rc::clone(&self.shared),
        }
    }
}

pub struct Invocation<P> {
    shared: Rc<RefCell<Shared<P>>>,
}

impl<P> Drop for Invocation<P> {
    fn drop(&mut self) {
        self.shared.borrow_mut().active = None;
    }
}

impl<P: CellPort> Gate<P> {
    pub fn new(client: Client<P>) -> Self {
        Self {
            shared: Rc::new(RefCell::new(Shared {
                client,
                active: None,
            })),
        }
    }

    pub fn begin(
        &self,
        context: RequestContext,
        ticket: CommitTicket,
    ) -> Result<Invocation<P>, Error> {
        let mut shared = self.shared.borrow_mut();
        if shared.active.is_some() {
            return Err(Error::Busy);
        }
        if ticket.cell_id != shared.client.cell.cell_id
            || ticket.cell_incarnation != shared.client.cell.cell_incarnation
            || ticket.auth_epoch != context.admission.auth_epoch
            || ticket.payload_digest != [0; 32]
        {
            return Err(Error::InvalidContext);
        }
        shared.client.check(&context)?;
        shared.active = Some(Active {
            context,
            ticket,
            phase: Phase::Fresh,
        });
        Ok(Invocation {
            shared: Rc::clone(&self.shared),
        })
    }
}

impl<P: CellPort> CommitGate for Gate<P> {
    fn lookup(&mut self, ticket: &CommitTicket, fingerprint: [u8; 32]) -> LookupDecision {
        let mut shared = self.shared.borrow_mut();
        let Shared { client, active } = &mut *shared;
        let Some(active) = active else {
            return LookupDecision::Unknown;
        };
        let phase = std::mem::replace(&mut active.phase, Phase::Finished);
        if !matches!(phase, Phase::Fresh) || ticket != &active.ticket {
            return LookupDecision::Unknown;
        }
        let Ok(state) = client.read(&active.context) else {
            return LookupDecision::Unknown;
        };
        let database = database(ticket);
        if let Err(reject) = state.authorize_write(
            database,
            active.context.admission,
            owner(ticket),
            ticket.predecessor,
        ) {
            return LookupDecision::Rejected(rejection(reject));
        }
        match state.lookup(
            database,
            active.context.admission,
            ticket.request_id,
            fingerprint,
        ) {
            Ok(Lookup::Unknown) => {
                active.phase = Phase::Prepared(fingerprint);
                LookupDecision::NotFound
            }
            Ok(Lookup::Committed { commit, result }) => LookupDecision::AlreadyCommitted {
                receipt: commit.receipt,
                result,
            },
            Ok(Lookup::Cancelled { .. }) => LookupDecision::Rejected(Rejection::Conflict),
            Err(reject) => LookupDecision::Rejected(rejection(reject)),
        }
    }

    fn propose(
        &mut self,
        write: &PreparedWrite,
        fingerprint: [u8; 32],
        result: &[u8],
    ) -> GateDecision {
        let mut shared = self.shared.borrow_mut();
        let Shared { client, active } = &mut *shared;
        let Some(active) = active else {
            return GateDecision::Unknown;
        };
        let phase = std::mem::replace(&mut active.phase, Phase::Finished);
        let mut ticket = write.ticket.clone();
        ticket.payload_digest = [0; 32];
        if !matches!(phase, Phase::Prepared(expected) if expected == fingerprint)
            || ticket != active.ticket
        {
            return GateDecision::Unknown;
        }
        let applied = match client.submit(
            &active.context,
            database(&write.ticket),
            CommandKind::Commit {
                write: write.clone(),
                request_fingerprint: fingerprint,
                result: result.to_vec(),
            },
        ) {
            Ok(applied) => applied,
            Err(Error::InvalidContext) => {
                return GateDecision::Rejected(Rejection::InvalidTransaction);
            }
            Err(_) => return GateDecision::Unknown,
        };
        match applied.outcome {
            Outcome::Accepted(commit) => {
                if commit.position != applied.position
                    || commit.receipt.ticket != write.ticket
                    || Some(commit.receipt.sequence) != write.ticket.predecessor.checked_add(1)
                {
                    return GateDecision::Unknown;
                }
                GateDecision::Accepted(commit.receipt)
            }
            Outcome::AlreadyCommitted(commit) => {
                match client.history(&active.context, &write.ticket, fingerprint, &commit) {
                    Ok(result) => GateDecision::AlreadyCommitted {
                        receipt: commit.receipt,
                        result,
                    },
                    Err(_) => GateDecision::Unknown,
                }
            }
            Outcome::Rejected(reject) => GateDecision::Rejected(rejection(reject)),
            _ => GateDecision::Unknown,
        }
    }
}

fn database(ticket: &CommitTicket) -> DatabaseIdentity {
    DatabaseIdentity {
        database_id: ticket.database_id,
        incarnation: ticket.incarnation,
        placement_generation: ticket.placement_generation,
    }
}

fn owner(ticket: &CommitTicket) -> OwnerToken {
    OwnerToken {
        epoch: ticket.owner_epoch,
        worker_instance_id: ticket.worker_instance_id,
    }
}

fn rejection(reject: Reject) -> Rejection {
    match reject {
        Reject::Fenced | Reject::NotFound => Rejection::Fenced,
        Reject::Unauthorized => Rejection::Unauthorized,
        Reject::Conflict | Reject::Cancelled | Reject::Exists => Rejection::Conflict,
        _ => Rejection::InvalidTransaction,
    }
}

#[cfg(test)]
mod tests;
