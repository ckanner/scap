use super::*;
use raft::eraftpb::{ConfChangeSingle, ConfChangeType, ConfState, MessageType};
use raft::ReadState;
use scap_raft_store::{Identity, Limits, LoadState};
use std::cell::{Cell, RefCell};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

mod membership;

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Before(usize),
    After(usize),
    Panic(usize),
}

#[derive(Clone, Default)]
struct Backend {
    bytes: Rc<RefCell<Option<Vec<u8>>>>,
    writes: Rc<Cell<usize>>,
    fault: Rc<Cell<Fault>>,
}

impl AtomicBackend for Backend {
    type Error = &'static str;

    fn load(&mut self, _: usize) -> Result<LoadState, Self::Error> {
        Ok(self
            .bytes
            .borrow()
            .clone()
            .map_or(LoadState::Empty, LoadState::Image))
    }

    fn replace_sync(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        let write = self.writes.get() + 1;
        self.writes.set(write);
        match self.fault.get() {
            Fault::Before(at) if at == write => return Err("before sync"),
            Fault::Panic(at) if at == write => panic!("backend panic"),
            _ => {}
        }
        *self.bytes.borrow_mut() = Some(image.to_vec());
        if matches!(self.fault.get(), Fault::After(at) if at == write) {
            return Err("after sync");
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Counter {
    calls: Rc<Cell<usize>>,
    fail: Rc<Cell<bool>>,
    panic: Rc<Cell<bool>>,
    result_mode: Rc<Cell<u8>>,
}

impl Application for Counter {
    type Error = &'static str;

    fn apply(&mut self, previous: &[u8], entries: &[Entry]) -> Result<Vec<u8>, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        assert!(!self.panic.get(), "application panic");
        if self.fail.get() {
            return Err("application rejected image");
        }
        let mut value = value(previous);
        for entry in entries {
            if entry.get_entry_type() == EntryType::EntryNormal && !entry.data.is_empty() {
                value += u64::from_be_bytes(entry.data[..].try_into().unwrap());
            }
        }
        Ok(value.to_be_bytes().to_vec())
    }

    fn apply_with_results(
        &mut self,
        previous: &[u8],
        entries: &[Entry],
        requested: &[u64],
    ) -> Result<AppliedBatch, Self::Error> {
        let state = self.apply(previous, entries)?;
        let mut current = value(previous);
        let mut results = Vec::new();
        for entry in entries {
            if entry.get_entry_type() == EntryType::EntryNormal && !entry.data.is_empty() {
                current += value(&entry.data);
            }
            if requested.contains(&entry.index) {
                results.push(current.to_be_bytes().to_vec());
            }
        }
        match self.result_mode.get() {
            1 => results.clear(),
            2 => results.iter_mut().for_each(|result| result.resize(64, 0)),
            _ => {}
        }
        Ok(AppliedBatch { state, results })
    }
}

type Node = Driver<Backend, Counter>;

fn value(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        0
    } else {
        u64::from_be_bytes(bytes.try_into().unwrap())
    }
}

fn identity() -> Identity {
    Identity {
        cluster_id: 10,
        cell_id: 20,
        cell_incarnation: 30,
        node_id: 1,
    }
}

fn limits() -> Limits {
    Limits {
        max_image_bytes: 1024 * 1024,
        max_entry_bytes: 65536,
        max_entries: 1000,
        max_application_bytes: 65536,
    }
}

fn config() -> DriverConfig {
    DriverConfig {
        raft: raft::Config {
            election_tick: 10,
            heartbeat_tick: 1,
            max_size_per_msg: 1024,
            max_inflight_msgs: 16,
            max_uncommitted_size: 65536,
            max_committed_size_per_ready: 1024,
            ..Default::default()
        },
        boot_id: 40,
        max_input_bytes: 65536,
        max_output_messages: 64,
        max_output_bytes: 65536,
        max_pending_reads: 4,
        max_pending_proposals: 4,
        max_pending_proposal_bytes: 65536,
        max_ready_rounds: 16,
    }
}

fn store(backend: Backend, voters: &[u64]) -> Store<Backend> {
    let conf = ConfState {
        voters: voters.to_vec(),
        ..Default::default()
    };
    Store::create_new(backend, identity(), conf, limits()).unwrap()
}

fn build(voters: &[u64], config: DriverConfig) -> (Node, Backend, Counter) {
    let backend = Backend::default();
    let app = Counter::default();
    let node = Driver::new(
        store(backend.clone(), voters),
        app.clone(),
        config,
        &logger(),
    )
    .unwrap();
    (node, backend, app)
}

fn logger() -> slog::Logger {
    slog::Logger::root(slog::Discard, slog::o!())
}

fn drain(node: &mut Node) -> Output {
    let mut output = Output {
        messages: Vec::new(),
        reads: Vec::new(),
        proposals: Vec::new(),
        memberships: Vec::new(),
        more_ready: false,
    };
    for _ in 0..100 {
        let next = node.drain().unwrap();
        output.messages.extend(next.messages);
        output.reads.extend(next.reads);
        output.proposals.extend(next.proposals);
        output.memberships.extend(next.memberships);
        if !next.more_ready {
            return output;
        }
    }
    panic!("unit driver did not quiesce");
}

fn leader() -> (Node, Backend, Counter) {
    let (mut node, backend, app) = build(&[1], config());
    node.campaign().unwrap();
    drain(&mut node);
    assert_eq!(node.status().unwrap().role, StateRole::Leader);
    (node, backend, app)
}

fn entry(index: u64, amount: u64) -> Entry {
    Entry {
        index,
        term: 2,
        data: amount.to_be_bytes().to_vec().into(),
        ..Default::default()
    }
}

fn append(entries: Vec<Entry>, commit: u64) -> Message {
    let mut message = Message {
        from: 2,
        to: 1,
        term: 2,
        index: 1,
        log_term: 1,
        commit,
        ..Default::default()
    };
    message.set_msg_type(MessageType::MsgAppend);
    message.set_entries(entries.into());
    message
}

#[test]
fn initialization_uses_durable_identity_and_safe_effective_configuration() {
    let mut configuration = config();
    configuration.raft.id = 99;
    configuration.raft.applied = 999;
    configuration.raft.read_only_option = ReadOnlyOption::LeaseBased;
    configuration.raft.max_apply_unpersisted_log_limit = 99;
    configuration.raft.batch_append = true;
    let (mut node, backend, _) = build(&[1], configuration);
    assert_eq!(node.node.raft.id, 1);
    assert_eq!(node.node.raft.raft_log.applied, 1);
    assert!(node.config.raft.pre_vote);
    assert!(node.config.raft.check_quorum);
    assert!(node.config.raft.disable_proposal_forwarding);
    assert!(!node.config.raft.batch_append);
    assert_eq!(node.config.raft.read_only_option, ReadOnlyOption::Safe);
    assert_eq!(node.config.raft.max_apply_unpersisted_log_limit, 0);
    let status = node.status().unwrap();
    assert_eq!(status.leader_id, 0);
    assert_eq!(
        (
            status.term,
            status.commit,
            status.applied,
            status.last_index,
            status.snapshot_index
        ),
        (1, 1, 1, 1, 1)
    );
    assert!(!node.is_stopped());
    assert!(!node.drain().unwrap().more_ready);
    assert_eq!(backend.writes.get(), 1);
}

#[test]
fn invalid_driver_and_raft_configurations_are_rejected_before_rawnode_panics() {
    for field in 0..8 {
        let mut configuration = config();
        match field {
            0 => configuration.boot_id = 0,
            1 => configuration.max_input_bytes = 0,
            2 => configuration.max_output_messages = 0,
            3 => configuration.max_output_bytes = 31,
            4 => configuration.max_pending_reads = 0,
            5 => configuration.max_ready_rounds = 0,
            6 => configuration.max_pending_proposals = 0,
            _ => configuration.max_pending_proposal_bytes = 0,
        }
        assert!(matches!(
            Driver::new(
                store(Backend::default(), &[1]),
                Counter::default(),
                configuration,
                &logger()
            ),
            Err(Error::Invalid(_))
        ));
    }
    for field in 0..3 {
        for bad in [0, u64::MAX] {
            let mut configuration = config();
            match field {
                0 => configuration.raft.max_size_per_msg = bad,
                1 => configuration.raft.max_uncommitted_size = bad,
                _ => configuration.raft.max_committed_size_per_ready = bad,
            }
            assert!(matches!(
                Driver::new(
                    store(Backend::default(), &[1]),
                    Counter::default(),
                    configuration,
                    &logger()
                ),
                Err(Error::Invalid(_))
            ));
        }
    }
    let mut configuration = config();
    configuration.raft.election_tick = usize::MAX;
    assert!(matches!(
        Driver::new(
            store(Backend::default(), &[1]),
            Counter::default(),
            configuration,
            &logger()
        ),
        Err(Error::Invalid(_))
    ));
    let mut configuration = config();
    configuration.raft.heartbeat_tick = 0;
    assert!(matches!(
        Driver::new(
            store(Backend::default(), &[1]),
            Counter::default(),
            configuration,
            &logger()
        ),
        Err(Error::Raft(_))
    ));
    let mut configuration = config();
    configuration.raft.max_election_tick = 30;
    assert!(Driver::new(
        store(Backend::default(), &[1]),
        Counter::default(),
        configuration,
        &logger()
    )
    .is_ok());
}

#[test]
fn stopped_store_cannot_initialize_a_driver() {
    let backend = Backend::default();
    let mut store = store(backend.clone(), &[1]);
    backend.fault.set(Fault::Before(2));
    assert!(store.checkpoint_and_compact().is_err());
    assert!(matches!(
        Driver::new(store, Counter::default(), config(), &logger()),
        Err(Error::Store(_))
    ));
}

#[test]
fn proposals_are_leader_only_and_ready_work_blocks_new_inputs() {
    let (mut node, _, _) = build(&[1], config());
    assert!(matches!(
        node.propose(vec![], vec![1]),
        Err(Error::NotLeader)
    ));
    assert!(matches!(node.read_index(), Err(Error::NotLeader)));
    node.tick().unwrap();
    node.campaign().unwrap();
    assert!(matches!(node.tick(), Err(Error::NeedsDrain)));
    assert!(matches!(node.campaign(), Err(Error::NeedsDrain)));
    assert!(matches!(
        node.propose(vec![], vec![]),
        Err(Error::NeedsDrain)
    ));
    assert!(matches!(node.read_index(), Err(Error::NeedsDrain)));
    assert!(matches!(
        node.step(append(vec![], 1)),
        Err(Error::NeedsDrain)
    ));
    assert!(matches!(node.checkpoint(), Err(Error::NeedsDrain)));
    assert!(!node.is_stopped());
    drain(&mut node);
    node.propose(b"request".to_vec(), 7u64.to_be_bytes().to_vec())
        .unwrap();
    drain(&mut node);
    assert_eq!(value(&node.view().unwrap().application), 7);
    assert_eq!(
        node.status().unwrap().last_index,
        node.view().unwrap().applied
    );
}

#[test]
fn input_limits_and_endpoint_rejections_do_not_stop_a_healthy_driver() {
    let (mut node, _, _) = leader();
    assert!(matches!(
        node.propose(vec![0; 65536], vec![0]),
        Err(Error::InputLimit)
    ));
    let mut message = append(vec![entry(2, 1)], 2);
    message.context = vec![0; 65536].into();
    assert!(matches!(node.step(message), Err(Error::InputLimit)));
    for (from, to) in [(2, 99), (0, 1)] {
        let mut message = append(vec![], 1);
        message.from = from;
        message.to = to;
        assert!(matches!(node.step(message), Err(Error::Invalid(_))));
    }
    assert!(!node.is_stopped());
    node.propose(vec![], 1u64.to_be_bytes().to_vec()).unwrap();
    drain(&mut node);
}

#[test]
fn known_non_mutating_raft_input_errors_do_not_stop_the_handle() {
    let (mut node, _, _) = build(&[1, 2], config());
    let mut message = append(vec![], 1);
    message.set_msg_type(MessageType::MsgHup);
    assert!(matches!(node.step(message), Err(Error::Raft(_))));
    let mut missing_peer = Message {
        from: 99,
        to: 1,
        ..Default::default()
    };
    missing_peer.set_msg_type(MessageType::MsgAppendResponse);
    assert!(matches!(node.step(missing_peer), Err(Error::Raft(_))));
    assert!(!node.is_stopped());
    node.step(append(vec![entry(2, 7)], 2)).unwrap();
    drain(&mut node);
    assert_eq!(value(&node.view().unwrap().application), 7);
    for (result, fatal) in [
        (Ok(()), false),
        (Err(raft::Error::StepLocalMsg), false),
        (Err(raft::Error::StepPeerNotFound), false),
        (Err(raft::Error::ProposalDropped), true),
        (
            Err(raft::Error::Store(raft::StorageError::Unavailable)),
            true,
        ),
    ] {
        assert_eq!(fatal_step_result(&result), fatal);
    }
}

#[test]
fn follower_persists_before_releasing_append_response_and_applies_lightready() {
    let (mut node, backend, app) = build(&[1, 2], config());
    node.step(append(vec![entry(2, 7)], 2)).unwrap();
    assert_eq!(backend.writes.get(), 1);
    let output = drain(&mut node);
    assert!(output
        .messages
        .iter()
        .any(|message| message.get_msg_type() == MessageType::MsgAppendResponse));
    assert_eq!(backend.writes.get(), 3);
    assert_eq!(app.calls.get(), 1);
    assert_eq!(node.view().unwrap().hard_state.commit, 2);
    assert_eq!(node.view().unwrap().applied, 2);
    assert_eq!(value(&node.view().unwrap().application), 7);
}

#[test]
fn synchronization_and_application_errors_never_release_output_or_continue() {
    for fault in [
        Fault::Before(2),
        Fault::After(2),
        Fault::Before(3),
        Fault::After(3),
    ] {
        let (mut node, backend, _) = build(&[1, 2], config());
        node.step(append(vec![entry(2, 7)], 2)).unwrap();
        backend.fault.set(fault);
        assert!(matches!(node.drain(), Err(Error::Store(_))));
        assert!(node.is_stopped());
        assert!(matches!(node.status(), Err(Error::Stopped)));
        assert!(matches!(node.drain(), Err(Error::Stopped)));
        assert!(matches!(
            node.cancel_read(ReadTicket {
                boot_id: 40,
                sequence: 1
            }),
            Err(Error::Stopped)
        ));
        assert!(matches!(node.tick(), Err(Error::Stopped)));
        assert!(matches!(node.checkpoint(), Err(Error::Stopped)));
        backend.fault.set(Fault::None);
        let recovered = Store::open_existing(backend, identity(), limits()).unwrap();
        assert!(recovered.view().unwrap().applied <= recovered.view().unwrap().hard_state.commit);
    }
    let (mut node, _, app) = build(&[1, 2], config());
    node.step(append(vec![entry(2, 7)], 2)).unwrap();
    app.fail.set(true);
    let error = node.drain().err().unwrap();
    assert!(matches!(error, Error::Application(_)));
    assert!(error.to_string().contains("application rejected"));
    assert!(node.is_stopped());
}

#[test]
fn captured_storage_and_application_panics_leave_driver_stopped() {
    for native in [true, false] {
        let (mut node, backend, app) = build(&[1, 2], config());
        node.step(append(vec![entry(2, 7)], 2)).unwrap();
        if native {
            backend.fault.set(Fault::Panic(2));
        } else {
            app.panic.set(true);
        }
        assert!(catch_unwind(AssertUnwindSafe(|| node.drain())).is_err());
        assert!(node.is_stopped());
        assert!(matches!(node.view(), Err(Error::Stopped)));
    }
}

#[test]
fn output_limits_are_fatal_after_admission_and_do_not_return_partial_batches() {
    for count_limit in [true, false] {
        let mut configuration = config();
        if count_limit {
            configuration.max_output_messages = 1;
        } else {
            configuration.max_output_bytes = 32;
        }
        let (mut node, _, _) = build(&[1, 2, 3, 4], configuration);
        node.campaign().unwrap();
        assert!(matches!(node.drain(), Err(Error::OutputLimit)));
        assert!(node.is_stopped());
    }
}

#[test]
fn read_tickets_are_fresh_context_bound_and_only_finish_after_application() {
    let (mut node, _, _) = leader();
    let first = node.read_index().unwrap();
    let first_context = node.pending_reads[&first.sequence].context.clone();
    assert!(first_context.starts_with(b"SCAPREAD"));
    assert_eq!(first_context.len(), 80);
    let output = drain(&mut node);
    assert_eq!(
        output.reads,
        vec![ReadBarrier {
            ticket: first,
            index: node.view().unwrap().applied
        }]
    );
    let second = node.read_index().unwrap();
    assert!(second.sequence > first.sequence);
    assert_ne!(node.pending_reads[&second.sequence].context, first_context);
    assert!(node.cancel_read(second).unwrap());
    assert!(!node.cancel_read(second).unwrap());
    assert!(drain(&mut node).reads.is_empty());
    let third = node.read_index().unwrap();
    // One-component boundary injection: the driver must ignore an unrelated
    // ReadState and retain a matching barrier ahead of its durable application.
    let context = node.pending_reads[&third.sequence].context.clone();
    node.node.raft.read_states = vec![
        ReadState {
            index: 999,
            request_ctx: b"unrelated".to_vec(),
        },
        ReadState {
            index: node.view().unwrap().applied + 1,
            request_ctx: context,
        },
    ];
    assert!(drain(&mut node).reads.is_empty());
    node.propose(vec![], 3u64.to_be_bytes().to_vec()).unwrap();
    let output = drain(&mut node);
    assert_eq!(output.reads[0].ticket, third);
    assert!(output.reads[0].index <= node.view().unwrap().applied);
}

#[test]
fn pending_reads_have_admission_bounds_and_exhaustion_does_not_reuse_ids() {
    let (mut node, _, _) = leader();
    // Control the single component's pending read outputs; no quorum behavior
    // is inferred from this unit fixture.
    for _ in 0..4 {
        node.read_index().unwrap();
        node.node.raft.read_states.clear();
    }
    assert!(matches!(node.read_index(), Err(Error::ReadLimit)));
    assert!(!node.is_stopped());
    node.pending_reads.clear();
    node.next_read = u64::MAX;
    assert!(matches!(node.read_index(), Err(Error::ReadIdExhausted)));
    assert!(!node.is_stopped());
}

#[test]
fn ready_and_read_output_budgets_yield_without_losing_pending_tickets() {
    let (mut node, _, _) = leader();
    node.config.max_ready_rounds = 1;
    node.config.max_output_bytes = 32;
    for _ in 0..2 {
        node.read_index().unwrap();
        node.node.raft.read_states.clear();
    }
    let index = node.view().unwrap().applied;
    for pending in node.pending_reads.values_mut() {
        pending.index = Some(index);
    }
    let first = node.drain().unwrap();
    assert_eq!(first.reads.len(), 1);
    assert!(first.more_ready);
    assert!(matches!(node.tick(), Err(Error::NeedsDrain)));
    assert!(matches!(node.checkpoint(), Err(Error::NeedsDrain)));
    let second = node.drain().unwrap();
    assert_eq!(second.reads.len(), 1);
    assert!(!second.more_ready);
    assert_ne!(first.reads[0].ticket, second.reads[0].ticket);
}

#[test]
fn checkpoint_and_recovery_keep_the_durable_application_cursor() {
    let (mut node, backend, _) = leader();
    node.propose(vec![], 7u64.to_be_bytes().to_vec()).unwrap();
    drain(&mut node);
    node.checkpoint().unwrap();
    assert!(node.view().unwrap().entries.is_empty());
    assert_eq!(
        node.status().unwrap().snapshot_index,
        node.view().unwrap().applied
    );
    drop(node);
    let store = Store::open_existing(backend.clone(), identity(), limits()).unwrap();
    let app = Counter::default();
    let mut configuration = config();
    configuration.boot_id += 1;
    let mut recovered = Driver::new(store, app.clone(), configuration, &logger()).unwrap();
    assert!(drain(&mut recovered).reads.is_empty());
    assert_eq!(value(&recovered.view().unwrap().application), 7);
    assert_eq!(app.calls.get(), 0);
    backend.fault.set(Fault::Before(backend.writes.get() + 1));
    assert!(matches!(recovered.checkpoint(), Err(Error::Store(_))));
    assert!(recovered.is_stopped());
}

#[test]
fn old_boot_ticket_and_read_context_cannot_complete_or_cancel_new_request() {
    let (mut node, backend, _) = leader();
    let old_ticket = node.read_index().unwrap();
    let old_context = node.pending_reads[&old_ticket.sequence].context.clone();
    drain(&mut node);
    drop(node);
    let reopened = Store::open_existing(backend, identity(), limits()).unwrap();
    let mut configuration = config();
    configuration.boot_id += 1;
    let mut node = Driver::new(reopened, Counter::default(), configuration, &logger()).unwrap();
    node.campaign().unwrap();
    drain(&mut node);
    let fresh_ticket = node.read_index().unwrap();
    assert_eq!(fresh_ticket.sequence, old_ticket.sequence);
    assert_ne!(fresh_ticket.boot_id, old_ticket.boot_id);
    assert!(!node.cancel_read(old_ticket).unwrap());
    node.node.raft.read_states = vec![ReadState {
        index: node.view().unwrap().applied,
        request_ctx: old_context,
    }];
    assert!(drain(&mut node).reads.is_empty());
    assert!(node.cancel_read(fresh_ticket).unwrap());
}

#[test]
fn transport_feedback_obeys_serial_input_and_stopped_boundaries() {
    let (mut node, _, _) = build(&[1, 2], config());
    assert!(matches!(node.report_unreachable(0), Err(Error::Invalid(_))));
    assert!(matches!(
        node.report_snapshot(0, SnapshotStatus::Failure),
        Err(Error::Invalid(_))
    ));
    node.report_unreachable(2).unwrap();
    node.report_snapshot(2, SnapshotStatus::Failure).unwrap();
    node.report_snapshot(2, SnapshotStatus::Finish).unwrap();
    node.campaign().unwrap();
    assert!(matches!(node.report_unreachable(2), Err(Error::NeedsDrain)));
    assert!(matches!(
        node.report_snapshot(2, SnapshotStatus::Failure),
        Err(Error::NeedsDrain)
    ));
    node.stopped = true;
    assert!(matches!(node.report_unreachable(2), Err(Error::Stopped)));
    assert!(matches!(
        node.report_snapshot(2, SnapshotStatus::Failure),
        Err(Error::Stopped)
    ));
}

fn elect_before_current_term_commit(node: &mut Node) -> Message {
    node.campaign().unwrap();
    let prevote = drain(node)
        .messages
        .into_iter()
        .find(|m| m.to == 2)
        .unwrap();
    let mut response = Message {
        from: 2,
        to: 1,
        term: prevote.term,
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgRequestPreVoteResponse);
    node.step(response).unwrap();
    let vote = drain(node)
        .messages
        .into_iter()
        .find(|m| m.to == 2)
        .unwrap();
    let mut response = Message {
        from: 2,
        to: 1,
        term: vote.term,
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgRequestVoteResponse);
    node.step(response).unwrap();
    drain(node)
        .messages
        .into_iter()
        .find(|m| m.to == 2 && m.get_msg_type() == MessageType::MsgAppend)
        .unwrap()
}

fn elect_with_peer(node: &mut Node) {
    let append = elect_before_current_term_commit(node);
    let mut response = Message {
        from: 2,
        to: 1,
        term: append.term,
        index: append.entries.last().unwrap().index,
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgAppendResponse);
    node.step(response).unwrap();
    drain(node);
    assert_eq!(node.status().unwrap().role, StateRole::Leader);
}

#[test]
fn new_leader_rejects_early_reads_without_allocating_a_lost_ticket() {
    let (mut node, backend, _) = build(&[1, 2, 3], config());
    let append = elect_before_current_term_commit(&mut node);
    assert_eq!(node.status().unwrap().role, StateRole::Leader);
    assert!(!node.node.raft.commit_to_current_term());
    let persisted = node.view().unwrap().clone();
    let writes = backend.writes.get();
    for _ in 0..8 {
        assert!(matches!(node.read_index(), Err(Error::ReadNotReady)));
        assert!(!node.is_stopped());
    }
    assert!(node.pending_reads.is_empty());
    assert_eq!(node.node.raft.pending_read_count(), 0);
    assert_eq!(node.next_read, 1);
    assert_eq!(node.view().unwrap(), &persisted);
    assert_eq!(backend.writes.get(), writes);

    // This single-driver fixture controls its peer boundary. The independent
    // three-process contract exercises the actual pre-vote/vote/append path.
    let mut response = Message {
        from: 2,
        to: 1,
        term: append.term,
        index: append.entries.last().unwrap().index,
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgAppendResponse);
    node.step(response).unwrap();
    drain(&mut node);
    assert!(node.node.raft.commit_to_current_term());
    let ticket = node.read_index().unwrap();
    assert_eq!(ticket.sequence, 1);
    let context = node.pending_reads[&ticket.sequence].context.clone();
    assert!(drain(&mut node).reads.is_empty());
    let mut response = Message {
        from: 2,
        to: 1,
        term: node.status().unwrap().term,
        context: context.into(),
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgHeartbeatResponse);
    node.step(response).unwrap();
    let completed = drain(&mut node).reads;
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].ticket, ticket);
    assert_eq!(completed[0].index, node.view().unwrap().applied);
}

#[test]
fn cancellation_cannot_bypass_rafts_internal_pending_read_limit() {
    let (mut node, _, _) = build(&[1, 2, 3], config());
    elect_with_peer(&mut node);
    let mut last_context = Vec::new();
    for _ in 0..node.config.max_pending_reads {
        let ticket = node.read_index().unwrap();
        last_context = node.pending_reads[&ticket.sequence].context.clone();
        drain(&mut node);
        assert!(node.cancel_read(ticket).unwrap());
    }
    assert!(node.pending_reads.is_empty());
    assert_eq!(
        node.node.raft.pending_read_count(),
        node.config.max_pending_reads
    );
    for _ in 0..20 {
        assert!(matches!(node.read_index(), Err(Error::ReadLimit)));
    }
    for kind in [
        MessageType::MsgReadIndex,
        MessageType::MsgReadIndexResp,
        MessageType::MsgPropose,
    ] {
        let mut forwarded = Message {
            from: 2,
            to: 1,
            ..Default::default()
        };
        forwarded.set_msg_type(kind);
        assert!(matches!(node.step(forwarded), Err(Error::Invalid(_))));
    }
    assert!(!node.is_stopped());
    // A real raft-rs heartbeat response retires its queued read contexts; all
    // cancelled results are ignored by the driver's separate ticket mapping.
    let mut response = Message {
        from: 2,
        to: 1,
        term: node.status().unwrap().term,
        context: last_context.into(),
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgHeartbeatResponse);
    node.step(response).unwrap();
    assert!(drain(&mut node).reads.is_empty());
    assert_eq!(node.node.raft.pending_read_count(), 0);
    assert!(node.read_index().is_ok());
}

#[test]
fn ready_round_budget_yields_and_continues_the_exact_committed_prefix() {
    let mut configuration = config();
    configuration.max_ready_rounds = 1;
    configuration.raft.max_committed_size_per_ready = 1;
    let (mut node, _, app) = build(&[1, 2], configuration);
    let entries = (2..=11).map(|index| entry(index, 1)).collect();
    node.step(append(entries, 11)).unwrap();
    let first = node.drain().unwrap();
    assert!(first.more_ready);
    assert_eq!(node.view().unwrap().applied, 2);
    assert!(matches!(node.tick(), Err(Error::NeedsDrain)));
    drain(&mut node);
    assert_eq!(node.view().unwrap().applied, 11);
    assert_eq!(value(&node.view().unwrap().application), 10);
    assert!(app.calls.get() > 1);
}

#[test]
fn raft_uncommitted_admission_drop_preserves_the_driver_and_existing_tail() {
    let mut configuration = config();
    configuration.raft.max_size_per_msg = 8;
    configuration.raft.max_uncommitted_size = 8;
    let (mut node, _, _) = build(&[1, 2, 3], configuration);
    elect_with_peer(&mut node);
    node.propose(vec![], 7u64.to_be_bytes().to_vec()).unwrap();
    drain(&mut node);
    let previous = node.view().unwrap().clone();
    assert!(matches!(
        node.propose(vec![], 9u64.to_be_bytes().to_vec()),
        Err(Error::Raft(raft::Error::ProposalDropped))
    ));
    assert!(!node.is_stopped());
    assert_eq!(node.view().unwrap(), &previous);
    assert_eq!(value(&node.view().unwrap().application), 0);
}

#[test]
fn configuration_entries_are_applied_by_rawnode_and_persisted_with_the_cursor() {
    for v2 in [false, true] {
        let (mut node, _, _) = build(&[1, 2], config());
        let mut change_entry = entry(2, 0);
        if v2 {
            let single = ConfChangeSingle {
                node_id: 3,
                change_type: ConfChangeType::AddLearnerNode,
                ..Default::default()
            };
            let mut change = ConfChangeV2::default();
            change.set_changes(vec![single].into());
            change_entry.set_entry_type(EntryType::EntryConfChangeV2);
            change_entry.data = change.write_to_bytes().unwrap().into();
        } else {
            let change = ConfChange {
                node_id: 3,
                change_type: ConfChangeType::AddLearnerNode,
                ..Default::default()
            };
            change_entry.set_entry_type(EntryType::EntryConfChange);
            change_entry.data = change.write_to_bytes().unwrap().into();
        }
        node.step(append(vec![change_entry], 2)).unwrap();
        drain(&mut node);
        assert!(node.view().unwrap().conf_state.learners.contains(&3));
        assert_eq!(node.view().unwrap().applied, 2);
    }
}

#[test]
fn malformed_and_invalid_committed_configuration_stop_the_driver() {
    for ty in [EntryType::EntryConfChange, EntryType::EntryConfChangeV2] {
        let (mut node, _, _) = build(&[1, 2], config());
        let mut change = entry(2, 0);
        change.set_entry_type(ty);
        change.data = vec![255].into();
        node.step(append(vec![change], 2)).unwrap();
        assert!(matches!(node.drain(), Err(Error::Raft(_))));
        assert!(node.is_stopped());
    }
    let (mut node, _, _) = build(&[1, 2], config());
    let mut change = ConfChangeV2::default();
    change.set_changes(
        vec![ConfChangeSingle {
            node_id: 1,
            change_type: ConfChangeType::AddLearnerNode,
            ..Default::default()
        }]
        .into(),
    );
    let mut change_entry = entry(2, 0);
    change_entry.set_entry_type(EntryType::EntryConfChangeV2);
    change_entry.data = change.write_to_bytes().unwrap().into();
    node.step(append(vec![change_entry], 2)).unwrap();
    // A legal voter demotion is accepted by raft-rs; its result still has to be
    // atomically recorded. Other malformed encodings above are fatal.
    drain(&mut node);
    assert_eq!(node.view().unwrap().applied, 2);
}

#[test]
fn snapshot_only_ready_installs_application_configuration_and_applied_together() {
    let (mut node, _, app) = build(&[1, 2], config());
    let mut snapshot = raft::eraftpb::Snapshot::default();
    snapshot.mut_metadata().index = 20;
    snapshot.mut_metadata().term = 2;
    snapshot.mut_metadata().set_conf_state(ConfState {
        voters: vec![1, 2],
        ..Default::default()
    });
    snapshot.data = 7u64.to_be_bytes().to_vec().into();
    let mut message = Message {
        from: 2,
        to: 1,
        term: 3,
        ..Default::default()
    };
    message.set_msg_type(MessageType::MsgSnapshot);
    message.set_snapshot(snapshot);
    node.step(message).unwrap();
    drain(&mut node);
    assert_eq!(app.calls.get(), 0);
    assert_eq!(node.view().unwrap().applied, 20);
    assert_eq!(node.view().unwrap().hard_state.commit, 20);
    assert_eq!(node.node.raft.raft_log.applied, 20);
    assert_eq!(value(&node.view().unwrap().application), 7);
}

#[test]
fn impossible_committed_configuration_has_no_partial_durable_membership() {
    for v2 in [false, true] {
        let (mut node, backend, app) = build(&[1, 2], config());
        let mut entries = Vec::new();
        if v2 {
            let changes = [1, 2]
                .into_iter()
                .map(|id| ConfChangeSingle {
                    node_id: id,
                    change_type: ConfChangeType::RemoveNode,
                    ..Default::default()
                })
                .collect::<Vec<_>>();
            let mut change = ConfChangeV2::default();
            change.set_changes(changes.into());
            let mut item = entry(2, 0);
            item.set_entry_type(EntryType::EntryConfChangeV2);
            item.data = change.write_to_bytes().unwrap().into();
            entries.push(item);
        } else {
            for id in [1, 2] {
                let change = ConfChange {
                    node_id: id,
                    change_type: ConfChangeType::RemoveNode,
                    ..Default::default()
                };
                let mut item = entry(id + 1, 0);
                item.set_entry_type(EntryType::EntryConfChange);
                item.data = change.write_to_bytes().unwrap().into();
                entries.push(item);
            }
        }
        let commit = entries.last().unwrap().index;
        node.step(append(entries, commit)).unwrap();
        assert!(matches!(node.drain(), Err(Error::Raft(_))));
        assert!(node.is_stopped());
        assert_eq!(app.calls.get(), 0);
        let disk = Store::open_existing(backend, identity(), limits()).unwrap();
        assert_eq!(disk.view().unwrap().conf_state.voters, vec![1, 2]);
        assert_eq!(disk.view().unwrap().applied, 1);
    }
}

#[test]
fn legacy_application_keeps_ordinary_proposals_and_propagates_application_failure() {
    struct Legacy(bool);
    impl Application for Legacy {
        type Error = &'static str;
        fn apply(&mut self, previous: &[u8], _: &[Entry]) -> Result<Vec<u8>, Self::Error> {
            if self.0 {
                Err("legacy failure")
            } else {
                Ok(previous.to_vec())
            }
        }
    }
    let batch = Legacy(false)
        .apply_with_results(b"image", &[], &[])
        .unwrap();
    assert_eq!(batch.state, b"image");
    assert!(batch.results.is_empty());
    assert!(Legacy(true).apply_with_results(b"image", &[], &[]).is_err());
}

fn acknowledge_tail(node: &mut Node) -> Output {
    let status = node.status().unwrap();
    let mut response = Message {
        from: 2,
        to: 1,
        term: status.term,
        index: status.last_index,
        ..Default::default()
    };
    response.set_msg_type(MessageType::MsgAppendResponse);
    node.step(response).unwrap();
    drain(node)
}

#[test]
fn tracked_batch_results_follow_exact_commands_and_only_durable_application() {
    let (mut node, backend, _) = build(&[1, 2, 3], config());
    elect_with_peer(&mut node);
    let mut tickets = Vec::new();
    for amount in [5u64, 7, 11] {
        tickets.push(
            node.propose_tracked(amount.to_be_bytes().to_vec(), 8)
                .unwrap(),
        );
        assert!(drain(&mut node).proposals.is_empty());
    }
    assert_eq!(value(&node.view().unwrap().application), 0);
    assert_eq!(node.pending_proposals.len(), 3);
    let output = acknowledge_tail(&mut node);
    assert_eq!(output.proposals.len(), 3);
    for ((result, ticket), expected) in output.proposals.iter().zip(tickets).zip([5, 12, 23]) {
        assert_eq!(result.ticket, ticket);
        assert_eq!(value(&result.data), expected);
        let entry = node
            .view()
            .unwrap()
            .entries
            .iter()
            .find(|entry| entry.index == result.index)
            .unwrap();
        assert_eq!(entry.term, result.term);
        assert_eq!(
            entry.context[entry.context.len() - 8..],
            ticket.sequence.to_be_bytes()
        );
        assert!(result.index <= node.view().unwrap().applied);
    }
    assert!(node.pending_proposals.is_empty());
    assert_eq!(node.pending_proposal_bytes, 0);
    let reopened = Store::open_existing(backend, identity(), limits()).unwrap();
    assert_eq!(value(&reopened.view().unwrap().application), 23);
    assert_eq!(
        reopened.view().unwrap().applied,
        output.proposals.last().unwrap().index
    );
}

#[test]
fn tracked_storage_failure_never_releases_a_result_even_after_sync_took_effect() {
    for after in [false, true] {
        for offset in [1, 2] {
            let (mut node, backend, _) = leader();
            let ticket = node
                .propose_tracked(7u64.to_be_bytes().to_vec(), 8)
                .unwrap();
            let at = backend.writes.get() + offset;
            backend.fault.set(if after {
                Fault::After(at)
            } else {
                Fault::Before(at)
            });
            assert!(matches!(node.drain(), Err(Error::Store(_))));
            assert!(node.is_stopped());
            assert!(node.pending_proposals[&ticket.sequence].result.is_none());
            assert!(matches!(node.cancel_proposal(ticket), Err(Error::Stopped)));
            backend.fault.set(Fault::None);
            let reopened = Store::open_existing(backend, identity(), limits()).unwrap();
            assert_eq!(
                value(&reopened.view().unwrap().application),
                if after && offset == 2 { 7 } else { 0 }
            );
        }
    }
}

#[test]
fn tracked_admission_budgets_reserved_context_and_exhaustion_do_not_mutate_raft() {
    let (mut follower, _, _) = build(&[1], config());
    assert!(matches!(
        follower.propose_tracked(vec![1], 8),
        Err(Error::NotLeader)
    ));
    let (mut node, _, _) = leader();
    assert!(matches!(
        node.propose(PROPOSAL_CONTEXT.to_vec(), vec![1]),
        Err(Error::Invalid(_))
    ));
    for (data, limit) in [
        (vec![], 8),
        (vec![0; 65536], 8),
        (vec![1], 0),
        (vec![1], 65536),
    ] {
        assert!(matches!(
            node.propose_tracked(data, limit),
            Err(Error::InputLimit)
        ));
    }
    node.next_proposal = u64::MAX;
    assert!(matches!(
        node.propose_tracked(vec![1], 8),
        Err(Error::ProposalIdExhausted)
    ));
    assert!(!node.is_stopped());

    for count in [true, false] {
        let (mut node, _, _) = build(&[1, 2, 3], config());
        elect_with_peer(&mut node);
        let ticket = node
            .propose_tracked(5u64.to_be_bytes().to_vec(), 8)
            .unwrap();
        drain(&mut node);
        if count {
            node.config.max_pending_proposals = 1;
        } else {
            node.config.max_pending_proposal_bytes = node.pending_proposal_bytes;
        }
        assert!(matches!(
            node.propose_tracked(7u64.to_be_bytes().to_vec(), 8),
            Err(Error::ProposalLimit)
        ));
        assert!(!node
            .cancel_proposal(ProposalTicket {
                boot_id: ticket.boot_id + 1,
                ..ticket
            })
            .unwrap());
        assert!(!node
            .cancel_proposal(ProposalTicket {
                sequence: ticket.sequence + 1,
                ..ticket
            })
            .unwrap());
        assert!(node.cancel_proposal(ticket).unwrap());
        assert!(!node.cancel_proposal(ticket).unwrap());
        assert_eq!(node.pending_proposal_bytes, 0);
        let next = node
            .propose_tracked(7u64.to_be_bytes().to_vec(), 8)
            .unwrap();
        assert!(next.sequence > ticket.sequence);
        drain(&mut node);
        let results = acknowledge_tail(&mut node).proposals;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ticket, next);
        assert_eq!(value(&results[0].data), 12);
    }
}

#[test]
fn tracked_raft_drop_retires_the_attempt_without_a_waiter_or_false_result() {
    let mut configuration = config();
    configuration.raft.max_size_per_msg = 8;
    configuration.raft.max_uncommitted_size = 8;
    let (mut node, _, _) = build(&[1, 2, 3], configuration);
    elect_with_peer(&mut node);
    let first = node
        .propose_tracked(7u64.to_be_bytes().to_vec(), 8)
        .unwrap();
    drain(&mut node);
    let reserved = node.pending_proposal_bytes;
    assert!(matches!(
        node.propose_tracked(9u64.to_be_bytes().to_vec(), 8),
        Err(Error::Raft(raft::Error::ProposalDropped))
    ));
    assert!(!node.is_stopped());
    assert_eq!(node.pending_proposal_bytes, reserved);
    assert_eq!(node.next_proposal, first.sequence + 2);
    assert_eq!(acknowledge_tail(&mut node).proposals[0].ticket, first);
}

#[test]
fn tracked_result_bounds_missing_results_and_duplicate_context_fail_closed() {
    for mode in [1, 2] {
        let (mut node, _, app) = leader();
        node.propose_tracked(7u64.to_be_bytes().to_vec(), 8)
            .unwrap();
        app.result_mode.set(mode);
        let result = node.drain();
        if mode == 1 {
            assert!(matches!(result, Err(Error::Application(_))));
        } else {
            assert!(matches!(result, Err(Error::OutputLimit)));
        }
        assert!(node.is_stopped());
    }
    let (mut node, _, _) = leader();
    let ticket = node
        .propose_tracked(7u64.to_be_bytes().to_vec(), 8)
        .unwrap();
    let pending = &node.pending_proposals[&ticket.sequence];
    node.node
        .propose(pending.context.clone(), pending.data.clone())
        .unwrap();
    assert!(matches!(node.drain(), Err(Error::Application(_))));
    assert!(node.is_stopped());
}

#[test]
fn completed_results_obey_shared_output_budget_and_keep_admission_closed_until_drained() {
    let (mut node, _, _) = leader();
    node.config.max_output_bytes = 48;
    let ticket = node
        .propose_tracked(7u64.to_be_bytes().to_vec(), 8)
        .unwrap();
    node.pending_reads.insert(
        9,
        PendingRead {
            context: vec![],
            index: Some(1),
        },
    );
    let first = node.drain().unwrap();
    assert_eq!(first.reads.len(), 1);
    assert!(first.proposals.is_empty());
    assert!(first.more_ready);
    assert!(matches!(node.tick(), Err(Error::NeedsDrain)));
    let entry = node.view().unwrap().entries.last().unwrap().clone();
    assert!(node.match_proposal(&entry).is_none());
    let next = node.drain().unwrap();
    assert_eq!(next.proposals[0].ticket, ticket);
    assert!(!next.more_ready);
    assert_eq!(node.pending_proposal_bytes, 0);
}

#[test]
fn old_boot_and_mismatched_entries_cannot_complete_a_new_attempt() {
    let (mut old, backend, _) = build(&[1, 2, 3], config());
    elect_with_peer(&mut old);
    let old_ticket = old.propose_tracked(7u64.to_be_bytes().to_vec(), 8).unwrap();
    drain(&mut old);
    let old_entry = old.view().unwrap().entries.last().unwrap().clone();
    drop(old);
    let mut configuration = config();
    configuration.boot_id += 1;
    let mut node = Driver::new(
        Store::open_existing(backend, identity(), limits()).unwrap(),
        Counter::default(),
        configuration,
        &logger(),
    )
    .unwrap();
    elect_with_peer(&mut node);
    assert_eq!(value(&node.view().unwrap().application), 7);
    let ticket = node
        .propose_tracked(9u64.to_be_bytes().to_vec(), 8)
        .unwrap();
    assert_eq!(old_ticket.sequence, ticket.sequence);
    assert_ne!(old_ticket.boot_id, ticket.boot_id);
    assert!(!node.cancel_proposal(old_ticket).unwrap());
    drain(&mut node);
    let current = node.view().unwrap().entries.last().unwrap().clone();
    assert_eq!(node.match_proposal(&current), Some(ticket.sequence));
    assert!(node.match_proposal(&old_entry).is_none());
    for field in 0..7 {
        let mut entry = current.clone();
        match field {
            0 => entry.set_entry_type(EntryType::EntryConfChange),
            1 => entry.data = vec![].into(),
            2 => entry.context = vec![].into(),
            3 => entry.context = vec![0; 81].into(),
            4 => {
                let mut context = entry.context.to_vec();
                *context.last_mut().unwrap() = 99;
                entry.context = context.into();
            }
            5 => entry.term += 1,
            _ => entry.data = 8u64.to_be_bytes().to_vec().into(),
        }
        assert!(node.match_proposal(&entry).is_none());
    }
    // Same sequence and term still cannot substitute a foreign boot/context.
    let mut foreign = current.clone();
    let mut context = foreign.context.to_vec();
    context[0] ^= 1;
    foreign.context = context.into();
    assert!(node.match_proposal(&foreign).is_none());
    let result = acknowledge_tail(&mut node).proposals.remove(0);
    assert_eq!(result.ticket, ticket);
    assert_eq!(value(&result.data), 16);
}

#[test]
fn term_change_can_finish_the_exact_old_entry_but_snapshot_never_invents_its_outcome() {
    for snapshot in [false, true] {
        let (mut node, _, _) = build(&[1, 2, 3], config());
        elect_with_peer(&mut node);
        let ticket = node
            .propose_tracked(7u64.to_be_bytes().to_vec(), 8)
            .unwrap();
        drain(&mut node);
        let old = node.view().unwrap().entries.last().unwrap().clone();
        let mut message = Message {
            from: 2,
            to: 1,
            term: old.term + 1,
            commit: old.index,
            ..Default::default()
        };
        if snapshot {
            message.set_msg_type(MessageType::MsgSnapshot);
            let mut snapshot = raft::eraftpb::Snapshot::default();
            snapshot.mut_metadata().index = old.index + 10;
            snapshot.mut_metadata().term = old.term + 1;
            snapshot.mut_metadata().set_conf_state(ConfState {
                voters: vec![1, 2, 3],
                ..Default::default()
            });
            snapshot.data = 7u64.to_be_bytes().to_vec().into();
            message.set_snapshot(snapshot);
        } else {
            message.set_msg_type(MessageType::MsgHeartbeat);
        }
        node.step(message).unwrap();
        let output = drain(&mut node);
        assert_eq!(node.status().unwrap().role, StateRole::Follower);
        assert_eq!(value(&node.view().unwrap().application), 7);
        if snapshot {
            assert!(output.proposals.is_empty());
            assert!(node.cancel_proposal(ticket).unwrap());
        } else {
            let result = &output.proposals[0];
            assert_eq!(result.ticket, ticket);
            assert_eq!((result.term, result.index), (old.term, old.index));
            assert!(result.term < node.status().unwrap().term);
        }
    }
}
