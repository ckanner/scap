//! A narrow, synchronous commit-completion policy for the G0 architecture.
//!
//! The ports do not implement consensus, persistence, SQL execution, or authentication.
//! The physical module supplies the shared bounded page format and replay rules.
//! Their contracts require independent integration and fault-injection evidence.
//! In particular, an `Accepted` receipt is evidence supplied by a trusted adapter,
//! not a proof that this crate has implemented durable quorum replication.

pub mod physical;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellIdentity {
    pub cell_id: u128,
    pub cell_incarnation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseIdentity {
    pub database_id: u128,
    pub incarnation: u64,
    pub placement_generation: u64,
}

/// The complete authority and request binding for one immutable proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitTicket {
    pub cell_id: u128,
    pub cell_incarnation: u64,
    pub database_id: u128,
    pub incarnation: u64,
    pub placement_generation: u64,
    pub owner_epoch: u64,
    pub worker_instance_id: u128,
    pub auth_epoch: u64,
    pub request_id: u128,
    pub predecessor: u64,
    pub payload_digest: [u8; 32],
}

/// A staged transaction. Encoding, limits, and digest verification belong to
/// the engine and consensus adapters; this policy never executes or replays SQL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedWrite {
    pub ticket: CommitTicket,
    pub physical_changes: Vec<u8>,
}

/// Returned only after the cell has durably accepted this precise proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub ticket: CommitTicket,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Fenced,
    Unauthorized,
    Conflict,
    InvalidTransaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// A newly accepted transition, never a deduplication hit.
    Accepted(CommitReceipt),
    /// Historical acceptance. Newly staged pages must never be published.
    AlreadyCommitted(CommitReceipt),
    /// The adapter has authoritative evidence that this attempt was rejected.
    Rejected(Rejection),
    /// A timeout or disconnection cannot by itself establish rejection.
    Unknown,
}

/// Implementations must persist the complete proposal on a durable quorum and
/// obtain state-machine acceptance before returning `Accepted`. They must not
/// convert a transport timeout into `Rejected` or silently replay a proposal.
/// Deduplication must return `AlreadyCommitted`, never a fresh `Accepted`.
pub trait ConsensusPort {
    fn propose(&mut self, write: &PreparedWrite) -> Decision;
}

/// Publishes only the staged transaction corresponding to the supplied receipt.
/// A successful return means other SQLite connections may observe that commit.
/// The adapter must also compare its applied head with the expected predecessor;
/// it must not reapply older pages over a newer local state.
pub trait VisibilityPort {
    type Error;

    fn publish(
        &mut self,
        write: &PreparedWrite,
        receipt: &CommitReceipt,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompletionError<E> {
    Rejected(Rejection),
    OutcomeUnknown,
    /// Adapter corruption or an invalid binding: stop and reconcile authority.
    InvalidReceipt,
    /// Discard newly staged work, reconcile local state, and retrieve the
    /// original result under current authorization. Do not rerun SQL or publish.
    AlreadyCommitted {
        receipt: Box<CommitReceipt>,
    },
    /// The write is already committed. Failure to publish is not a rollback.
    CommittedButUnavailable {
        receipt: Box<CommitReceipt>,
        source: E,
    },
    /// A previous non-success requires external rollback/reconciliation before
    /// constructing a fresh coordinator; this instance cannot accept more work.
    Stopped,
}

/// Orders consensus before local visibility and before returning an ACK.
///
/// All non-success outcomes stop this execution context. The caller must resolve
/// unknown outcomes or roll back/recover as appropriate, then acquire validated
/// authority before constructing a new context. This type has no reset shortcut.
pub struct CommitCoordinator<C, V> {
    consensus: C,
    visibility: V,
    stopped: bool,
}

impl<C: ConsensusPort, V: VisibilityPort> CommitCoordinator<C, V> {
    pub fn new(consensus: C, visibility: V) -> Self {
        Self {
            consensus,
            visibility,
            stopped: false,
        }
    }

    pub fn complete(
        &mut self,
        write: &PreparedWrite,
    ) -> Result<CommitReceipt, CompletionError<V::Error>> {
        if self.stopped {
            return Err(CompletionError::Stopped);
        }

        // Fail closed, including an adapter panic. Only a completed publication
        // below re-enables this context. Panics are not durability outcomes.
        self.stopped = true;
        let (receipt, is_replay) = match self.consensus.propose(write) {
            Decision::Accepted(receipt) => (receipt, false),
            Decision::AlreadyCommitted(receipt) => (receipt, true),
            Decision::Rejected(reason) => return Err(CompletionError::Rejected(reason)),
            Decision::Unknown => return Err(CompletionError::OutcomeUnknown),
        };

        if receipt.ticket != write.ticket {
            return Err(CompletionError::InvalidReceipt);
        }
        if write.ticket.predecessor.checked_add(1) != Some(receipt.sequence) {
            return Err(CompletionError::InvalidReceipt);
        }
        if is_replay {
            return Err(CompletionError::AlreadyCommitted {
                receipt: Box::new(receipt),
            });
        }

        if let Err(source) = self.visibility.publish(write, &receipt) {
            return Err(CompletionError::CommittedButUnavailable {
                receipt: Box::new(receipt),
                source,
            });
        }
        self.stopped = false;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
