//! One bounded, serial Raft driver. Call from a dedicated blocking executor.
//!
//! Inputs, storage and application are separate boundaries. This module does not
//! supply a network listener, scheduler, SQLite acceptance or SQL read barrier.
//! Returned messages are handed to a separately bounded transport; transport
//! receipt is never a durable or business acknowledgement.

use std::collections::BTreeMap;
use std::fmt::{self, Display};

use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{ConfChange, ConfChangeV2, Entry, EntryType, Message, MessageType};
use raft::{RawNode, ReadOnlyOption, SnapshotStatus, StateRole};
use scap_raft_store::{AtomicBackend, State, Store};

/// Produce only a deterministic candidate image. No external effects may be
/// published here: a subsequent store failure cannot roll such effects back.
pub trait Application {
    type Error: Display;
    fn apply(&mut self, previous: &[u8], committed: &[Entry]) -> Result<Vec<u8>, Self::Error>;
}

/// Every resource budget is explicit. The driver fixes node identity and
/// applied from the store, and fixes safe/quorum/persistence policy below.
/// `boot_id` must be nonzero and unique for every driver instance; generating
/// and supplying that identity belongs to the caller, not the state machine.
pub struct DriverConfig {
    pub raft: raft::Config,
    pub boot_id: u128,
    pub max_input_bytes: usize,
    pub max_output_messages: usize,
    pub max_output_bytes: usize,
    pub max_pending_reads: usize,
    pub max_ready_rounds: usize,
}

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Stopped,
    NeedsDrain,
    NotLeader,
    InputLimit,
    ReadLimit,
    ReadIdExhausted,
    /// Detected after work may have become durable: fatal, never an admission
    /// rejection that permits blind replay of an unknown business proposal.
    OutputLimit,
    Raft(raft::Error),
    Store(scap_raft_store::Error),
    Application(String),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// An instance-bound public read identity. An old cancellation/completion cannot
/// identify a newly created driver's request with the same sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTicket {
    pub boot_id: u128,
    pub sequence: u64,
}

/// This identifies a completed Safe ReadIndex and durable application position.
/// It does not authorize a user, bind a SQLite snapshot or return SQL results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadBarrier {
    pub ticket: ReadTicket,
    pub index: u64,
}

pub struct Output {
    pub messages: Vec<Message>,
    pub reads: Vec<ReadBarrier>,
    pub more_ready: bool,
}

#[derive(Clone, Debug)]
pub struct Status {
    pub role: StateRole,
    pub leader_id: u64,
    /// Current protocol term; durable term is available in `view()`.
    pub term: u64,
    pub commit: u64,
    pub applied: u64,
    pub last_index: u64,
    pub snapshot_index: u64,
}

struct PendingRead {
    context: Vec<u8>,
    index: Option<u64>,
}

pub struct Driver<B: AtomicBackend, A: Application> {
    node: RawNode<Store<B>>,
    application: A,
    config: DriverConfig,
    context_prefix: Vec<u8>,
    next_read: u64,
    pending_reads: BTreeMap<u64, PendingRead>,
    stopped: bool,
}

impl<B: AtomicBackend, A: Application> Driver<B, A> {
    pub fn new(
        store: Store<B>,
        application: A,
        mut config: DriverConfig,
        logger: &slog::Logger,
    ) -> Result<Self, Error> {
        validate_config(&config)?;
        let state = store.view().map_err(Error::Store)?;
        config.raft.id = state.identity.node_id;
        config.raft.applied = state.applied;
        config.raft.pre_vote = true;
        config.raft.check_quorum = true;
        config.raft.read_only_option = ReadOnlyOption::Safe;
        config.raft.max_apply_unpersisted_log_limit = 0;
        config.raft.disable_proposal_forwarding = true;
        config.raft.batch_append = false;
        let mut context_prefix = b"SCAPREAD".to_vec();
        context_prefix.extend_from_slice(&state.identity.cluster_id.to_be_bytes());
        context_prefix.extend_from_slice(&state.identity.cell_id.to_be_bytes());
        context_prefix.extend_from_slice(&state.identity.cell_incarnation.to_be_bytes());
        context_prefix.extend_from_slice(&state.identity.node_id.to_be_bytes());
        context_prefix.extend_from_slice(&config.boot_id.to_be_bytes());
        let node = RawNode::new(&config.raft, store, logger).map_err(Error::Raft)?;
        Ok(Self {
            node,
            application,
            config,
            context_prefix,
            next_read: 1,
            pending_reads: BTreeMap::new(),
            stopped: false,
        })
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    pub fn view(&self) -> Result<&State, Error> {
        self.ensure_running()?;
        Ok(self.durable_view())
    }

    pub fn status(&self) -> Result<Status, Error> {
        let state = self.view()?;
        let snapshot_index = state.snapshot.get_metadata().index;
        Ok(Status {
            role: self.node.raft.state,
            leader_id: self.node.raft.leader_id,
            term: self.node.raft.term,
            commit: state.hard_state.commit,
            applied: state.applied,
            last_index: state
                .entries
                .last()
                .map_or(snapshot_index, |entry| entry.index),
            snapshot_index,
        })
    }

    pub fn tick(&mut self) -> Result<(), Error> {
        self.ensure_input()?;
        self.stopped = true;
        self.node.tick();
        self.stopped = false;
        Ok(())
    }

    pub fn campaign(&mut self) -> Result<(), Error> {
        self.ensure_input()?;
        self.stopped = true;
        let result = self.node.campaign().map_err(Error::Raft);
        self.stopped = result.is_err();
        result
    }

    /// Accept an already decoded, authenticated message for this cell. Wire
    /// allocation, peer authentication and cell routing belong to transport.
    pub fn step(&mut self, message: Message) -> Result<(), Error> {
        self.ensure_input()?;
        if message.compute_size() as usize > self.config.max_input_bytes {
            return Err(Error::InputLimit);
        }
        if message.to != self.node.raft.id || message.from == 0 {
            return Err(Error::Invalid("message endpoint mismatch"));
        }
        if matches!(
            message.get_msg_type(),
            MessageType::MsgReadIndex | MessageType::MsgReadIndexResp | MessageType::MsgPropose
        ) {
            return Err(Error::Invalid(
                "peer read/proposal forwarding is not supported",
            ));
        }
        self.stopped = true;
        let result = self.node.step(message);
        self.stopped = fatal_step_result(&result);
        result.map_err(Error::Raft)
    }

    /// Proposal admission is not a commit or business acknowledgement.
    pub fn propose(&mut self, context: Vec<u8>, data: Vec<u8>) -> Result<(), Error> {
        self.ensure_leader()?;
        if context.len().saturating_add(data.len()) > self.config.max_input_bytes {
            return Err(Error::InputLimit);
        }
        self.stopped = true;
        let result = self.node.propose(context, data);
        // ProposalDropped is an ordinary bounded-admission outcome. It does not
        // certify that a prior request with the same business ID was uncommitted.
        self.stopped = result
            .as_ref()
            .is_err_and(|error| *error != raft::Error::ProposalDropped);
        result.map_err(Error::Raft)
    }

    /// Mint a fresh bounded pending read. Tickets are never reused in this boot.
    pub fn read_index(&mut self) -> Result<ReadTicket, Error> {
        self.ensure_leader()?;
        // Cancellation only retires the caller's ticket. Raft may still hold
        // that context until quorum progress or a term/role reset; both live
        // collections must stay bounded independently.
        if self.pending_reads.len() >= self.config.max_pending_reads
            || self.node.raft.pending_read_count() >= self.config.max_pending_reads
        {
            return Err(Error::ReadLimit);
        }
        let next = self
            .next_read
            .checked_add(1)
            .ok_or(Error::ReadIdExhausted)?;
        let ticket = self.next_read;
        let mut context = self.context_prefix.clone();
        context.extend_from_slice(&ticket.to_be_bytes());
        self.stopped = true;
        self.node.read_index(context.clone());
        self.pending_reads.insert(
            ticket,
            PendingRead {
                context,
                index: None,
            },
        );
        self.next_read = next;
        self.stopped = false;
        Ok(ReadTicket {
            boot_id: self.config.boot_id,
            sequence: ticket,
        })
    }

    /// Explicit deadline/caller cancellation. Late read states cannot match a
    /// future ticket. No unbounded retired-context set is required.
    pub fn cancel_read(&mut self, ticket: ReadTicket) -> Result<bool, Error> {
        self.ensure_running()?;
        if ticket.boot_id != self.config.boot_id {
            return Ok(false);
        }
        Ok(self.pending_reads.remove(&ticket.sequence).is_some())
    }

    /// The transport must associate this feedback with the correct cell and
    /// delivery attempt; queue admission alone is not snapshot delivery.
    pub fn report_unreachable(&mut self, peer: u64) -> Result<(), Error> {
        self.ensure_input()?;
        if peer == 0 {
            return Err(Error::Invalid("feedback peer must be nonzero"));
        }
        self.stopped = true;
        self.node.report_unreachable(peer);
        self.stopped = false;
        Ok(())
    }

    pub fn report_snapshot(&mut self, peer: u64, status: SnapshotStatus) -> Result<(), Error> {
        self.ensure_input()?;
        if peer == 0 {
            return Err(Error::Invalid("feedback peer must be nonzero"));
        }
        self.stopped = true;
        self.node.report_snapshot(peer, status);
        self.stopped = false;
        Ok(())
    }

    /// Process bounded synchronous work. No RawNode mutation can interleave
    /// while Ready is held. All output is delayed until durable application.
    /// Any post-admission error or panic permanently stops this driver handle.
    pub fn drain(&mut self) -> Result<Output, Error> {
        self.ensure_running()?;
        self.stopped = true;
        let mut messages = Vec::new();
        let mut bytes = 0usize;
        for _ in 0..self.config.max_ready_rounds {
            if !self.node.has_ready() {
                break;
            }
            let mut ready = self.node.ready();
            let reads = ready.take_read_states();
            let mut committed = ready.take_committed_entries();
            let ordinary = ready.take_messages();
            let snapshot = (!ready.snapshot().is_empty()).then(|| ready.snapshot().clone());
            self.node
                .mut_store()
                .persist_ready(ready.entries(), ready.hs(), snapshot.as_ref())
                .map_err(Error::Store)?;
            messages.extend(ordinary);
            messages.extend(ready.take_persisted_messages());
            let mut light = self.node.advance_append(ready);
            committed.extend(light.take_committed_entries());
            messages.extend(light.take_messages());
            bytes = message_bytes(&messages);
            if messages.len() > self.config.max_output_messages
                || bytes > self.config.max_output_bytes
            {
                return Err(Error::OutputLimit);
            }
            let current = self.durable_view();
            let commit = light.commit_index().unwrap_or(current.hard_state.commit);
            let previous = current.application.clone();
            let mut conf = current.conf_state.clone();
            for entry in &committed {
                match entry.get_entry_type() {
                    EntryType::EntryNormal => {}
                    EntryType::EntryConfChange => {
                        let change = ConfChange::parse_from_bytes(&entry.data)
                            .map_err(raft::Error::from)
                            .map_err(Error::Raft)?;
                        conf = self.node.apply_conf_change(&change).map_err(Error::Raft)?;
                    }
                    EntryType::EntryConfChangeV2 => {
                        let change = ConfChangeV2::parse_from_bytes(&entry.data)
                            .map_err(raft::Error::from)
                            .map_err(Error::Raft)?;
                        conf = self.node.apply_conf_change(&change).map_err(Error::Raft)?;
                    }
                }
            }
            let application = if committed.is_empty() {
                previous
            } else {
                self.application
                    .apply(&previous, &committed)
                    .map_err(|error| Error::Application(error.to_string()))?
            };
            self.node
                .mut_store()
                .apply_committed(commit, &committed, &application, &conf)
                .map_err(Error::Store)?;
            let applied = self.durable_view().applied;
            self.node.advance_apply_to(applied);
            for read in reads {
                for pending in self.pending_reads.values_mut() {
                    if pending.context == read.request_ctx {
                        pending.index = Some(read.index);
                        break;
                    }
                }
            }
            // Return network work promptly; another call processes subsequent
            // Ready without growing a multi-round output queue.
            if !messages.is_empty() {
                break;
            }
        }
        let applied = self.durable_view().applied;
        let mut reads = Vec::new();
        let mut completed = Vec::new();
        for (&ticket, pending) in &self.pending_reads {
            if let Some(index) = pending.index {
                if index <= applied {
                    if bytes.saturating_add(32) > self.config.max_output_bytes {
                        break;
                    }
                    bytes += 32;
                    reads.push(ReadBarrier {
                        ticket: ReadTicket {
                            boot_id: self.config.boot_id,
                            sequence: ticket,
                        },
                        index,
                    });
                    completed.push(ticket);
                }
            }
        }
        for ticket in completed {
            self.pending_reads.remove(&ticket);
        }
        let more_ready = self.node.has_ready() || self.has_completed_read(applied);
        self.stopped = false;
        Ok(Output {
            messages,
            reads,
            more_ready,
        })
    }

    pub fn checkpoint(&mut self) -> Result<(), Error> {
        self.ensure_input()?;
        self.stopped = true;
        self.node
            .mut_store()
            .checkpoint_and_compact()
            .map_err(Error::Store)?;
        self.stopped = false;
        Ok(())
    }

    fn ensure_running(&self) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        Ok(())
    }

    fn ensure_input(&self) -> Result<(), Error> {
        self.ensure_running()?;
        if self.node.has_ready() || self.has_completed_read(self.durable_view().applied) {
            return Err(Error::NeedsDrain);
        }
        Ok(())
    }

    fn ensure_leader(&self) -> Result<(), Error> {
        self.ensure_input()?;
        if self.node.raft.state != StateRole::Leader {
            return Err(Error::NotLeader);
        }
        Ok(())
    }

    fn has_completed_read(&self, applied: u64) -> bool {
        self.pending_reads
            .values()
            .any(|read| read.index.is_some_and(|index| index <= applied))
    }

    fn durable_view(&self) -> &State {
        // The driver exclusively owns Store. Construction validates it, every
        // mutation stops the driver before touching Store, and any failed
        // transition returns without reaching this helper. Only an already
        // healthy store or a successful durable transition reaches this view.
        self.node
            .store()
            .view()
            .expect("validated successful store transition")
    }
}

fn validate_config(config: &DriverConfig) -> Result<(), Error> {
    if config.boot_id == 0
        || config.max_input_bytes == 0
        || config.max_output_messages == 0
        || config.max_output_bytes < 32
        || config.max_pending_reads == 0
        || config.max_ready_rounds == 0
    {
        return Err(Error::Invalid(
            "driver budgets and boot identity must be finite and nonzero",
        ));
    }
    for bound in [
        config.raft.max_size_per_msg,
        config.raft.max_uncommitted_size,
        config.raft.max_committed_size_per_ready,
    ] {
        if bound == 0 || bound == u64::MAX {
            return Err(Error::Invalid(
                "Raft byte budgets must be finite and nonzero",
            ));
        }
    }
    if config.raft.max_election_tick == 0 && config.raft.election_tick > usize::MAX / 2 {
        return Err(Error::Invalid("default election range overflows"));
    }
    Ok(())
}

fn message_bytes(messages: &[Message]) -> usize {
    messages.iter().fold(0usize, |total, message| {
        total.saturating_add(message.compute_size() as usize)
    })
}

fn fatal_step_result(result: &raft::Result<()>) -> bool {
    // The fixed RawNode implementation rejects these two cases before touching
    // Raft state. Unknown failures retain the conservative stop rule.
    matches!(result, Err(error) if !matches!(error, raft::Error::StepLocalMsg | raft::Error::StepPeerNotFound))
}

#[cfg(test)]
mod tests;
