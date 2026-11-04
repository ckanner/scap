//! The serial scheduler depends on this operation boundary, not on RawNode's
//! internals. The production adapter delegates every operation to the durable
//! driver; tests can fail one operation without replacing Raft or persistence.

use raft::eraftpb::{ConfState, Message};
use raft::SnapshotStatus;
use scap_raft_driver::{
    Application, Driver, Error, MembershipChange, MembershipStatus, MembershipTicket, Output,
    ProposalTicket, ReadTicket, Status,
};
use scap_raft_store::{AtomicBackend, State};

/// A fatal operation returns an error and leaves `is_stopped()` true. Once
/// stopped, subsequent operations also return errors. Only `is_stopped` remains
/// usable; this is the contract of the formal durable Driver implementation.
pub trait RaftDriver {
    fn is_stopped(&self) -> bool;
    fn view(&self) -> Result<&State, Error>;
    fn status(&self) -> Result<Status, Error>;
    fn membership_status(&self) -> Result<MembershipStatus, Error>;
    fn change_membership(
        &mut self,
        expected: &ConfState,
        change: MembershipChange,
    ) -> Result<MembershipTicket, Error>;
    fn cancel_membership(&mut self, ticket: MembershipTicket) -> Result<bool, Error>;
    fn drain(&mut self) -> Result<Output, Error>;
    fn tick(&mut self) -> Result<(), Error>;
    fn step(&mut self, message: Message) -> Result<(), Error>;
    fn propose(&mut self, context: Vec<u8>, data: Vec<u8>) -> Result<(), Error>;
    fn propose_tracked(
        &mut self,
        data: Vec<u8>,
        max_result_bytes: usize,
    ) -> Result<ProposalTicket, Error>;
    fn cancel_proposal(&mut self, ticket: ProposalTicket) -> Result<bool, Error>;
    fn read_index(&mut self) -> Result<ReadTicket, Error>;
    fn cancel_read(&mut self, ticket: ReadTicket) -> Result<bool, Error>;
    fn checkpoint(&mut self) -> Result<(), Error>;
    fn report_unreachable(&mut self, peer: u64) -> Result<(), Error>;
    fn report_snapshot(&mut self, peer: u64, status: SnapshotStatus) -> Result<(), Error>;
}

impl<B: AtomicBackend, A: Application> RaftDriver for Driver<B, A> {
    fn is_stopped(&self) -> bool {
        self.is_stopped()
    }
    fn view(&self) -> Result<&State, Error> {
        self.view()
    }
    fn status(&self) -> Result<Status, Error> {
        self.status()
    }
    fn membership_status(&self) -> Result<MembershipStatus, Error> {
        self.membership_status()
    }
    fn change_membership(
        &mut self,
        expected: &ConfState,
        change: MembershipChange,
    ) -> Result<MembershipTicket, Error> {
        self.change_membership(expected, change)
    }
    fn cancel_membership(&mut self, ticket: MembershipTicket) -> Result<bool, Error> {
        self.cancel_membership(ticket)
    }
    fn drain(&mut self) -> Result<Output, Error> {
        self.drain()
    }
    fn tick(&mut self) -> Result<(), Error> {
        self.tick()
    }
    fn step(&mut self, message: Message) -> Result<(), Error> {
        self.step(message)
    }
    fn propose(&mut self, context: Vec<u8>, data: Vec<u8>) -> Result<(), Error> {
        self.propose(context, data)
    }
    fn propose_tracked(
        &mut self,
        data: Vec<u8>,
        max_result_bytes: usize,
    ) -> Result<ProposalTicket, Error> {
        self.propose_tracked(data, max_result_bytes)
    }
    fn cancel_proposal(&mut self, ticket: ProposalTicket) -> Result<bool, Error> {
        self.cancel_proposal(ticket)
    }
    fn read_index(&mut self) -> Result<ReadTicket, Error> {
        self.read_index()
    }
    fn cancel_read(&mut self, ticket: ReadTicket) -> Result<bool, Error> {
        self.cancel_read(ticket)
    }
    fn checkpoint(&mut self) -> Result<(), Error> {
        self.checkpoint()
    }
    fn report_unreachable(&mut self, peer: u64) -> Result<(), Error> {
        self.report_unreachable(peer)
    }
    fn report_snapshot(&mut self, peer: u64, status: SnapshotStatus) -> Result<(), Error> {
        self.report_snapshot(peer, status)
    }
}
