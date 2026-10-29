//! Real dependencies and process-exit evidence. This is a test fixture, not a
//! reusable node driver, authenticated transport, or SQL state machine.

use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{
    ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfChangeV2, ConfState, Entry,
    EntryType, Message, MessageType, Snapshot,
};
use raft::{Config, RawNode, ReadOnlyOption, StateRole, Storage};
use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use scap_raft_store::{AtomicBackend, Identity, Limits, LoadState, Store};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const IMAGE_KEY: &[u8] = b"scap/g0/atomic-image";
const CHILD_PATH: &str = "SCAP_RAFT_STORE_CHILD_PATH";
const CHILD_POINT: &str = "SCAP_RAFT_STORE_CHILD_POINT";
const CRASH_EXIT: i32 = 73;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    WriteAttempt(usize),
    Synced(usize),
    ReplyReleased(usize),
    AdvanceAppend(usize),
    ApplyDurable(usize, u64),
    AdvanceApply(usize, u64),
}

#[derive(Clone, Default)]
struct Control {
    round: Arc<AtomicUsize>,
    // 1 rejects before native I/O; 2 reports an ambiguous error after native sync.
    next_write_fault: Arc<AtomicU8>,
    events: Arc<Mutex<Vec<Event>>>,
}

impl Control {
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct RocksImage {
    db: DB,
    control: Control,
}

impl RocksImage {
    fn open(path: &Path, create: bool) -> Result<(Self, Control), String> {
        if create && path.exists() {
            return Err("new fixture database path already exists".into());
        }
        let mut options = Options::default();
        options.create_if_missing(create);
        let db = DB::open(&options, path).map_err(|error| error.to_string())?;
        let control = Control::default();
        Ok((
            Self {
                db,
                control: control.clone(),
            },
            control,
        ))
    }
}

impl AtomicBackend for RocksImage {
    type Error = String;

    fn load(&mut self, max_image_bytes: usize) -> Result<LoadState, Self::Error> {
        let mut keys = self.db.raw_iterator();
        keys.seek_to_first();
        if !keys.valid() {
            keys.status().map_err(|error| error.to_string())?;
            return Ok(LoadState::Empty);
        }
        if keys.key() != Some(IMAGE_KEY) {
            return Ok(LoadState::Unrecognized);
        }
        keys.next();
        if keys.valid() {
            return Ok(LoadState::Unrecognized);
        }
        keys.status().map_err(|error| error.to_string())?;
        let image = self
            .db
            .get_pinned(IMAGE_KEY)
            .map_err(|error| error.to_string())?
            .ok_or("image disappeared from the exclusive fixture namespace")?;
        if image.len() > max_image_bytes {
            return Err("stored image exceeds configured owned-copy bound".into());
        }
        Ok(LoadState::Image(image.to_vec()))
    }

    fn replace_sync(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let round = self.control.round.load(Ordering::SeqCst);
        self.control.record(Event::WriteAttempt(round));
        let fault = self.control.next_write_fault.swap(0, Ordering::SeqCst);
        if fault == 1 {
            return Err("injected failure before native write".into());
        }
        let mut batch = WriteBatch::default();
        batch.put(IMAGE_KEY, bytes);
        let mut options = WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(true);
        self.db
            .write_opt(batch, &options)
            .map_err(|error| error.to_string())?;
        self.control.record(Event::Synced(round));
        if fault == 2 {
            return Err("injected ambiguous failure after native sync".into());
        }
        Ok(())
    }
}

type DiskStore = Store<RocksImage>;

fn identity(node_id: u64) -> Identity {
    Identity {
        cluster_id: 0x53434150,
        cell_id: 0x4750,
        cell_incarnation: 7,
        node_id,
    }
}

fn limits() -> Limits {
    Limits {
        max_image_bytes: 8 * 1024 * 1024,
        max_entry_bytes: 1024 * 1024,
        max_entries: 4096,
        max_application_bytes: 1024 * 1024,
    }
}

fn configuration(voters: &[u64]) -> ConfState {
    let mut state = ConfState::default();
    state.set_voters(voters.to_vec());
    state
}

fn canonical_configuration(mut state: ConfState) -> ConfState {
    state.voters.sort_unstable();
    state.voters_outgoing.sort_unstable();
    state.learners.sort_unstable();
    state.learners_next.sort_unstable();
    state
}

fn create_store(path: &Path, node_id: u64, voters: &[u64]) -> (DiskStore, Control) {
    let (backend, control) = RocksImage::open(path, true).unwrap();
    let store =
        Store::create_new(backend, identity(node_id), configuration(voters), limits()).unwrap();
    (store, control)
}

fn reopen_store(path: &Path, node_id: u64) -> (DiskStore, Control) {
    let (backend, control) = RocksImage::open(path, false).unwrap();
    let store = Store::open_existing(backend, identity(node_id), limits()).unwrap();
    (store, control)
}

fn counter(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        0
    } else {
        u64::from_be_bytes(
            bytes
                .try_into()
                .expect("fixture counter is exactly eight bytes"),
        )
    }
}

fn delta_entry(index: u64, term: u64, amount: u64) -> Entry {
    let mut entry = Entry {
        index,
        term,
        ..Entry::default()
    };
    entry.set_data(amount.to_be_bytes().to_vec().into());
    entry
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrashPoint {
    BeforeReady,
    AfterReady,
    AfterCommit,
    AfterApply,
    AfterCheckpoint,
}

struct Harness {
    node: RawNode<DiskStore>,
    control: Control,
    messages: Vec<Message>,
    read_states: Vec<(u64, Vec<u8>)>,
    light_commits: Vec<u64>,
    round: usize,
}

impl Harness {
    fn from_store(store: DiskStore, control: Control, node_id: u64) -> Self {
        let config = Config {
            id: node_id,
            applied: store.view().unwrap().applied,
            election_tick: 10,
            heartbeat_tick: 1,
            max_size_per_msg: 64 * 1024,
            max_inflight_msgs: 16,
            pre_vote: true,
            check_quorum: true,
            read_only_option: ReadOnlyOption::Safe,
            ..Config::default()
        };
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        Self {
            node: RawNode::new(&config, store, &logger).unwrap(),
            control,
            messages: Vec::new(),
            read_states: Vec::new(),
            light_commits: Vec::new(),
            round: 0,
        }
    }

    fn create(path: &Path, node_id: u64, voters: &[u64]) -> Self {
        let (store, control) = create_store(path, node_id, voters);
        Self::from_store(store, control, node_id)
    }

    fn reopen(path: &Path, node_id: u64) -> Self {
        let (store, control) = reopen_store(path, node_id);
        Self::from_store(store, control, node_id)
    }

    fn elect(&mut self) {
        self.node.campaign().unwrap();
        self.drain(None).unwrap();
        assert_eq!(self.node.raft.state, StateRole::Leader);
    }

    fn propose(&mut self, amount: u64) {
        self.node
            .propose(Vec::new(), amount.to_be_bytes().to_vec())
            .unwrap();
    }

    fn value(&self) -> u64 {
        counter(&self.node.store().view().unwrap().application)
    }

    fn drain(&mut self, crash: Option<CrashPoint>) -> Result<(), String> {
        for _ in 0..256 {
            if !self.node.has_ready() {
                return Ok(());
            }
            self.round += 1;
            self.control.round.store(self.round, Ordering::SeqCst);
            let mut ready = self.node.ready();
            let mut committed = ready.take_committed_entries();
            let reads = ready.take_read_states();
            // The fixture conservatively delays ordinary leader messages too.
            let ordinary = ready.take_messages();
            if crash == Some(CrashPoint::BeforeReady) {
                std::process::exit(CRASH_EXIT);
            }
            let snapshot = (!ready.snapshot().is_empty()).then(|| ready.snapshot().clone());
            self.node
                .mut_store()
                .persist_ready(ready.entries(), ready.hs(), snapshot.as_ref())
                .map_err(|error| error.to_string())?;
            if crash == Some(CrashPoint::AfterReady) {
                std::process::exit(CRASH_EXIT);
            }
            let persisted = ready.take_persisted_messages();
            if !persisted.is_empty() {
                self.control.record(Event::ReplyReleased(self.round));
            }
            self.messages.extend(ordinary);
            self.messages.extend(persisted);
            self.control.record(Event::AdvanceAppend(self.round));
            let mut light = self.node.advance_append(ready);
            let current = self
                .node
                .store()
                .view()
                .map_err(|error| error.to_string())?;
            let commit = light.commit_index().unwrap_or(current.hard_state.commit);
            if let Some(index) = light.commit_index() {
                self.light_commits.push(index);
            }
            let old_application = current.application.clone();
            let mut conf_state = current.conf_state.clone();
            committed.extend(light.take_committed_entries());
            self.messages.extend(light.take_messages());

            if crash == Some(CrashPoint::AfterCommit) {
                self.node
                    .mut_store()
                    .apply_committed(commit, &[], &old_application, &conf_state)
                    .map_err(|error| error.to_string())?;
                std::process::exit(CRASH_EXIT);
            }
            let mut value = counter(&old_application);
            for entry in &committed {
                match entry.get_entry_type() {
                    EntryType::EntryNormal => {
                        if !entry.data.is_empty() {
                            value = value.checked_add(counter(&entry.data)).unwrap();
                        }
                    }
                    EntryType::EntryConfChangeV2 => {
                        let change = ConfChangeV2::parse_from_bytes(&entry.data)
                            .map_err(|error| error.to_string())?;
                        conf_state = self
                            .node
                            .apply_conf_change(&change)
                            .map_err(|error| error.to_string())?;
                    }
                    EntryType::EntryConfChange => {
                        return Err("fixture only supports ConfChangeV2".into());
                    }
                }
            }
            // Keep exact bytes on an empty apply; the production store rejects
            // attempts to mutate application/configuration without advancing.
            let application = if committed.is_empty() {
                old_application
            } else {
                value.to_be_bytes().to_vec()
            };
            self.node
                .mut_store()
                .apply_committed(commit, &committed, &application, &conf_state)
                .map_err(|error| error.to_string())?;
            let applied = self.node.store().view().unwrap().applied;
            self.control
                .record(Event::ApplyDurable(self.round, applied));
            if crash == Some(CrashPoint::AfterApply) {
                std::process::exit(CRASH_EXIT);
            }
            self.node.advance_apply_to(applied);
            self.control
                .record(Event::AdvanceApply(self.round, applied));
            self.read_states
                .extend(reads.into_iter().map(|read| (read.index, read.request_ctx)));
        }
        Err("fixture Ready loop exceeded its finite work budget".into())
    }
}

fn path(directory: &TempDir) -> PathBuf {
    directory.path().join("db")
}

#[test]
fn single_voter_lightready_commit_and_readindex_are_durable() {
    let directory = tempfile::tempdir().unwrap();
    let mut harness = Harness::create(&path(&directory), 1, &[1]);
    harness.elect();
    harness.propose(7);
    harness.drain(None).unwrap();
    let state = harness.node.store().view().unwrap();
    assert_eq!(harness.value(), 7);
    assert_eq!(state.hard_state.commit, state.applied);
    assert_eq!(harness.node.raft.raft_log.applied, state.applied);
    assert!(harness.light_commits.contains(&state.applied));
    let identity = (state.hard_state.term, state.hard_state.vote);
    let context = b"unique-request-7".to_vec();
    harness.node.read_index(context.clone());
    harness.drain(None).unwrap();
    let state = harness.node.store().view().unwrap();
    assert!(harness.read_states.contains(&(state.applied, context)));
    assert_eq!((state.hard_state.term, state.hard_state.vote), identity);
    drop(harness);
    let mut recovered = Harness::reopen(&path(&directory), 1);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 7);
}

fn vote(from: u64, term: u64) -> Message {
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgRequestVote);
    message.from = from;
    message.to = 1;
    message.term = term;
    message.index = 1;
    message.log_term = 1;
    message
}

#[test]
fn persisted_vote_is_recovered_before_rejecting_a_second_vote() {
    let directory = tempfile::tempdir().unwrap();
    let mut harness = Harness::create(&path(&directory), 1, &[1, 2, 3]);
    harness.control.events.lock().unwrap().clear();
    harness.node.step(vote(2, 5)).unwrap();
    harness.drain(None).unwrap();
    assert!(harness.messages.iter().any(|message| {
        message.get_msg_type() == MessageType::MsgRequestVoteResponse
            && message.to == 2
            && !message.reject
    }));
    let events = harness.control.events.lock().unwrap().clone();
    let synced = events
        .iter()
        .position(|event| *event == Event::Synced(1))
        .unwrap();
    let reply = events
        .iter()
        .position(|event| *event == Event::ReplyReleased(1))
        .unwrap();
    assert!(synced < reply);
    drop(harness);
    let mut recovered = Harness::reopen(&path(&directory), 1);
    recovered.node.step(vote(3, 5)).unwrap();
    recovered.drain(None).unwrap();
    assert!(recovered.messages.iter().any(|message| {
        message.get_msg_type() == MessageType::MsgRequestVoteResponse
            && message.to == 3
            && message.reject
    }));
    let state = recovered.node.store().view().unwrap();
    assert_eq!((state.hard_state.term, state.hard_state.vote), (5, 2));
}

#[test]
fn write_errors_stop_the_store_and_do_not_release_persisted_replies() {
    for fault in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let mut harness = Harness::create(&path(&directory), 1, &[1, 2, 3]);
        harness.control.events.lock().unwrap().clear();
        harness
            .control
            .next_write_fault
            .store(fault, Ordering::SeqCst);
        harness.node.step(vote(2, 5)).unwrap();
        assert!(harness.drain(None).is_err());
        assert!(harness.node.store().is_stopped());
        assert!(harness.messages.is_empty());
        assert!(harness
            .control
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|event| { !matches!(event, Event::ReplyReleased(_) | Event::AdvanceAppend(_)) }));
        drop(harness);
        let recovered = Harness::reopen(&path(&directory), 1);
        let expected = if fault == 1 { (1, 0) } else { (5, 2) };
        let state = recovered.node.store().view().unwrap();
        assert_eq!((state.hard_state.term, state.hard_state.vote), expected);
    }
}

fn append(from: u64, term: u64, entries: Vec<Entry>, commit: u64) -> Message {
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgAppend);
    message.from = from;
    message.to = 1;
    message.term = term;
    message.index = 1;
    message.log_term = 1;
    message.commit = commit;
    message.set_entries(entries.into());
    message
}

#[test]
fn conflicting_append_replaces_only_the_uncommitted_suffix_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let mut harness = Harness::create(&path(&directory), 1, &[1, 2, 3]);
    harness
        .node
        .step(append(
            2,
            3,
            vec![delta_entry(2, 3, 5), delta_entry(3, 3, 9)],
            1,
        ))
        .unwrap();
    harness.drain(None).unwrap();
    assert_eq!(harness.value(), 0);
    assert_eq!(harness.node.store().last_index().unwrap(), 3);
    drop(harness);
    let mut recovered = Harness::reopen(&path(&directory), 1);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 0);
    recovered
        .node
        .step(append(3, 4, vec![delta_entry(2, 4, 11)], 2))
        .unwrap();
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 11);
    assert_eq!(recovered.node.store().last_index().unwrap(), 2);
    assert_eq!(recovered.node.store().term(2).unwrap(), 4);
    assert_eq!(recovered.node.store().view().unwrap().applied, 2);
}

#[test]
fn snapshot_only_ready_restores_complete_joint_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let mut harness = Harness::create(&path(&directory), 1, &[1, 2, 3]);
    let mut conf = configuration(&[1, 2]);
    conf.set_voters_outgoing(vec![1, 3]);
    conf.set_learners(vec![4]);
    conf.set_learners_next(vec![3]);
    conf.auto_leave = false;
    let mut snapshot = Snapshot::default();
    snapshot.set_data(31u64.to_be_bytes().to_vec().into());
    snapshot.mut_metadata().index = 20;
    snapshot.mut_metadata().term = 6;
    snapshot.mut_metadata().set_conf_state(conf.clone());
    let mut message = Message::default();
    message.set_msg_type(MessageType::MsgSnapshot);
    message.from = 2;
    message.to = 1;
    message.term = 7;
    message.set_snapshot(snapshot);
    harness.node.step(message).unwrap();
    harness.drain(None).unwrap();
    assert_eq!(harness.value(), 31);
    let state = harness.node.store().view().unwrap();
    assert_eq!(
        (state.snapshot.get_metadata().index, state.applied),
        (20, 20)
    );
    assert_eq!(state.hard_state.commit, 20);
    assert_eq!(state.conf_state, conf);
    assert_eq!(harness.node.raft.raft_log.applied, 20);
    assert_eq!(harness.node.store().first_index().unwrap(), 21);
    drop(harness);
    let mut recovered = Harness::reopen(&path(&directory), 1);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.node.store().view().unwrap().conf_state, conf);
    assert_eq!(
        canonical_configuration(recovered.node.raft.prs().conf().to_conf_state()),
        canonical_configuration(conf)
    );
    assert_eq!(recovered.value(), 31);
    assert_eq!(recovered.node.store().term(20).unwrap(), 6);
}

#[test]
fn committed_confchange_v2_and_joint_state_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let mut harness = Harness::create(&path(&directory), 1, &[1]);
    harness.elect();
    let mut change = ConfChangeV2::default();
    change.set_transition(ConfChangeTransition::Explicit);
    let mut learner = ConfChangeSingle {
        node_id: 2,
        ..ConfChangeSingle::default()
    };
    learner.set_change_type(ConfChangeType::AddLearnerNode);
    change.set_changes(vec![learner].into());
    harness
        .node
        .propose_conf_change(Vec::new(), change)
        .unwrap();
    harness.drain(None).unwrap();
    let conf = harness.node.store().view().unwrap().conf_state.clone();
    assert_eq!(conf.voters, vec![1]);
    assert_eq!(conf.voters_outgoing, vec![1]);
    assert_eq!(conf.learners, vec![2]);
    assert!(!conf.auto_leave);
    drop(harness);
    let mut recovered = Harness::reopen(&path(&directory), 1);
    assert_eq!(
        canonical_configuration(recovered.node.raft.prs().conf().to_conf_state()),
        canonical_configuration(conf)
    );
    recovered.elect();
    recovered
        .node
        .propose_conf_change(Vec::new(), ConfChangeV2::default())
        .unwrap();
    recovered.drain(None).unwrap();
    let stable = recovered.node.store().view().unwrap();
    assert_eq!(stable.conf_state.voters, vec![1]);
    assert_eq!(stable.conf_state.learners, vec![2]);
    assert!(stable.conf_state.voters_outgoing.is_empty());
}

fn crash_case(point: CrashPoint, test_name: &str) -> TempDir {
    if let Some(child_path) = std::env::var_os(CHILD_PATH) {
        assert_eq!(std::env::var(CHILD_POINT).unwrap(), format!("{point:?}"));
        let mut child = Harness::reopen(Path::new(&child_path), 1);
        child.elect();
        child.propose(7);
        if point == CrashPoint::AfterCheckpoint {
            child.drain(None).unwrap();
            child.node.mut_store().checkpoint_and_compact().unwrap();
            std::process::exit(CRASH_EXIT);
        }
        child.drain(Some(point)).unwrap();
        panic!("requested crash boundary was not reached");
    }
    let directory = tempfile::tempdir().unwrap();
    drop(create_store(&path(&directory), 1, &[1]));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_PATH, path(&directory))
        .env(CHILD_POINT, format!("{point:?}"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(CRASH_EXIT),
                "child failed before the expected crash: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "child exceeded deadline: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    directory
}

#[test]
fn process_exit_before_ready_sync_keeps_the_previous_image() {
    let directory = crash_case(
        CrashPoint::BeforeReady,
        "process_exit_before_ready_sync_keeps_the_previous_image",
    );
    let mut recovered = Harness::reopen(&path(&directory), 1);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 0);
    let state = recovered.node.store().view().unwrap();
    assert_eq!((state.applied, state.hard_state.commit), (2, 2));
    assert_eq!(recovered.node.store().last_index().unwrap(), 2);
    recovered.elect();
    assert_eq!(recovered.value(), 0);
}

#[test]
fn process_exit_after_ready_sync_retains_but_does_not_apply_uncommitted_tail() {
    let directory = crash_case(
        CrashPoint::AfterReady,
        "process_exit_after_ready_sync_retains_but_does_not_apply_uncommitted_tail",
    );
    let mut recovered = Harness::reopen(&path(&directory), 1);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 0);
    let state = recovered.node.store().view().unwrap();
    assert_eq!((state.applied, state.hard_state.commit), (2, 2));
    assert_eq!(recovered.node.store().last_index().unwrap(), 3);
    recovered.elect();
    // The unacknowledged proposal may later become committed by a new term.
    assert_eq!(recovered.value(), 7);
}

#[test]
fn process_exit_after_commit_sync_replays_the_committed_prefix_once() {
    let directory = crash_case(
        CrashPoint::AfterCommit,
        "process_exit_after_commit_sync_replays_the_committed_prefix_once",
    );
    let mut recovered = Harness::reopen(&path(&directory), 1);
    let state = recovered.node.store().view().unwrap();
    assert_eq!((state.applied, state.hard_state.commit), (2, 3));
    assert_eq!(recovered.value(), 0);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 7);
    drop(recovered);
    let mut again = Harness::reopen(&path(&directory), 1);
    again.drain(None).unwrap();
    assert_eq!(again.value(), 7);
}

#[test]
fn process_exit_after_apply_sync_does_not_repeat_application() {
    let directory = crash_case(
        CrashPoint::AfterApply,
        "process_exit_after_apply_sync_does_not_repeat_application",
    );
    let mut recovered = Harness::reopen(&path(&directory), 1);
    let state = recovered.node.store().view().unwrap();
    assert_eq!((state.applied, state.hard_state.commit), (3, 3));
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 7);
    recovered.elect();
    recovered.propose(5);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 12);
}

#[test]
fn checkpoint_sync_then_process_exit_restores_snapshot_and_boundary_term() {
    let directory = crash_case(
        CrashPoint::AfterCheckpoint,
        "checkpoint_sync_then_process_exit_restores_snapshot_and_boundary_term",
    );
    let mut recovered = Harness::reopen(&path(&directory), 1);
    let state = recovered.node.store().view().unwrap();
    assert_eq!(state.snapshot.get_metadata().index, 3);
    assert!(state.entries.is_empty());
    assert_eq!(recovered.node.store().first_index().unwrap(), 4);
    assert_eq!(recovered.node.store().last_index().unwrap(), 3);
    assert_eq!(recovered.node.store().term(3).unwrap(), 2);
    assert_eq!(recovered.value(), 7);
    assert!(recovered.node.store().snapshot(4, 2).is_err());
    recovered.elect();
    recovered.propose(5);
    recovered.drain(None).unwrap();
    assert_eq!(recovered.value(), 12);
}

#[test]
fn reopen_rejects_wrong_identity_corruption_and_unrecognized_namespace() {
    let directory = tempfile::tempdir().unwrap();
    let database = path(&directory);
    drop(create_store(&database, 1, &[1, 2]));
    let (backend, _) = RocksImage::open(&database, false).unwrap();
    assert!(Store::open_existing(backend, identity(2), limits()).is_err());
    let (mut backend, _) = RocksImage::open(&database, false).unwrap();
    assert!(backend.load(1).is_err());
    let LoadState::Image(mut bytes) = backend.load(limits().max_image_bytes).unwrap() else {
        panic!("fixture must contain exactly one image");
    };
    // Preserve the header and corrupt the stored integrity trailer.
    *bytes.last_mut().unwrap() ^= 0xff;
    backend.replace_sync(&bytes).unwrap();
    drop(backend);
    let (backend, _) = RocksImage::open(&database, false).unwrap();
    assert!(Store::open_existing(backend, identity(1), limits()).is_err());

    let (mut backend, _) = RocksImage::open(&database, false).unwrap();
    let mut foreign = WriteBatch::default();
    foreign.put(b"zzz-foreign-record", b"unexpected extra key");
    let mut options = WriteOptions::default();
    options.disable_wal(false);
    options.set_sync(true);
    backend.db.write_opt(foreign, &options).unwrap();
    assert!(matches!(
        backend.load(limits().max_image_bytes).unwrap(),
        LoadState::Unrecognized
    ));
    drop(backend);

    let other = directory.path().join("unrecognized");
    let (backend, _) = RocksImage::open(&other, true).unwrap();
    let mut batch = WriteBatch::default();
    batch.put(b"foreign-record", b"must-not-initialize-over-this");
    let mut options = WriteOptions::default();
    options.disable_wal(false);
    options.set_sync(true);
    backend.db.write_opt(batch, &options).unwrap();
    assert!(Store::create_new(backend, identity(1), configuration(&[1]), limits()).is_err());
    let (backend, _) = RocksImage::open(&other, false).unwrap();
    assert!(Store::open_existing(backend, identity(1), limits()).is_err());
}
