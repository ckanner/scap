//! Real, separately killed processes and disk stores; controlled IPC routing.
//! The router is a finite test fixture, not a production peer transport. No SQL
//! ACK, mTLS, cross-AZ, physical power-loss, or wall-clock RTO is claimed here.

use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{ConfState, Entry, EntryType, Message, MessageType};
use raft::{Config, ReadOnlyOption, SnapshotStatus, StateRole};
use scap_raft_driver::{Application, Driver, DriverConfig, ReadTicket};
use scap_raft_rocks::RocksBackend;
use scap_raft_store::{Identity, Limits, Store};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const PREFIX: &str = "SCAP_CLUSTER_V2";
const CHILD_ID: &str = "SCAP_CLUSTER_CHILD_ID";
const CHILD_PATH: &str = "SCAP_CLUSTER_CHILD_PATH";
const CHILD_BOOT: &str = "SCAP_CLUSTER_CHILD_BOOT";
const CHILD_CREATE: &str = "SCAP_CLUSTER_CHILD_CREATE";
const COMMAND_LIMIT: usize = 4096;
const RESPONSE_LIMIT: usize = 128 * 1024;
const ROUTE_LIMIT: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);
const ELECTION_TICKS: usize = 10;

fn identity(node_id: u64) -> Identity {
    Identity {
        cluster_id: 0x53434150,
        cell_id: 0x434c5553544552,
        cell_incarnation: 9,
        node_id,
    }
}

fn store_limits() -> Limits {
    Limits {
        max_image_bytes: 8 * 1024 * 1024,
        max_entry_bytes: 4096,
        max_entries: 4096,
        max_application_bytes: 64 * 1024,
    }
}

fn driver_config(boot_id: u128) -> DriverConfig {
    DriverConfig {
        raft: Config {
            election_tick: ELECTION_TICKS,
            heartbeat_tick: 1,
            min_election_tick: ELECTION_TICKS * 3,
            max_election_tick: ELECTION_TICKS * 3 + 1,
            max_size_per_msg: 1024,
            max_inflight_msgs: 16,
            max_uncommitted_size: 8192,
            max_committed_size_per_ready: 4096,
            pre_vote: true,
            check_quorum: true,
            read_only_option: ReadOnlyOption::Safe,
            ..Config::default()
        },
        boot_id,
        max_input_bytes: 1536,
        max_output_messages: 64,
        max_output_bytes: 32 * 1024,
        max_pending_reads: 16,
        max_ready_rounds: 32,
    }
}

/// Deliberately no deduplication: a repeated application duplicates an operation
/// in the durable history and changes its sum, so the oracle can observe it.
struct HistoryApplication;

impl Application for HistoryApplication {
    type Error = &'static str;

    fn apply(&mut self, previous: &[u8], entries: &[Entry]) -> Result<Vec<u8>, Self::Error> {
        if !previous.len().is_multiple_of(16) {
            return Err("invalid durable history length");
        }
        let mut next = previous.to_vec();
        for entry in entries {
            if entry.get_entry_type() == EntryType::EntryNormal && !entry.data.is_empty() {
                if entry.data.len() != 16 {
                    return Err("invalid operation length");
                }
                next.extend_from_slice(&entry.data);
            }
        }
        Ok(next)
    }
}

fn operation(id: u64, amount: u64) -> Vec<u8> {
    [id.to_be_bytes(), amount.to_be_bytes()].concat()
}

fn decode_history(bytes: &[u8]) -> Vec<(u64, u64)> {
    assert_eq!(bytes.len() % 16, 0, "malformed application history");
    bytes
        .chunks_exact(16)
        .map(|chunk| {
            (
                u64::from_be_bytes(chunk[..8].try_into().unwrap()),
                u64::from_be_bytes(chunk[8..].try_into().unwrap()),
            )
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                .expect("only valid fixture hexadecimal is accepted")
        })
        .collect()
}

fn bounded_line(reader: &mut impl BufRead, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let amount = reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if amount == 0 {
        return Ok(None);
    }
    if amount > limit || line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture frame limit",
        ));
    }
    Ok(Some(line))
}

#[derive(Clone, Debug)]
struct Observation {
    sequence: u64,
    error: Option<String>,
    ticket: Option<(u128, u64)>,
    role: u8,
    leader: u64,
    term: u64,
    durable_term: u64,
    durable_vote: u64,
    commit: u64,
    applied: u64,
    last: u64,
    snapshot: u64,
    history: Vec<(u64, u64)>,
    reads: Vec<(u128, u64, u64)>,
    messages: Vec<Vec<u8>>,
}

impl Observation {
    fn parse(line: &str) -> Self {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 17, "invalid response fields: {line}");
        assert_eq!(fields[0], PREFIX);
        let parse = |i: usize| fields[i].parse::<u64>().unwrap();
        let result = Self {
            sequence: parse(1),
            error: (fields[2] != "-").then(|| String::from_utf8(unhex(fields[2])).unwrap()),
            ticket: (fields[3] != "-").then(|| {
                let (boot, ticket) = fields[3].split_once(':').unwrap();
                (boot.parse().unwrap(), ticket.parse().unwrap())
            }),
            role: u8::try_from(parse(4)).unwrap(),
            leader: parse(5),
            term: parse(6),
            durable_term: parse(14),
            durable_vote: parse(15),
            commit: parse(7),
            applied: parse(8),
            last: parse(9),
            snapshot: parse(10),
            history: decode_history(&unhex(fields[11])),
            reads: if fields[12] == "-" {
                Vec::new()
            } else {
                fields[12]
                    .split(',')
                    .map(|item| {
                        let parts: Vec<_> = item.split(':').collect();
                        assert_eq!(parts.len(), 3);
                        (
                            parts[0].parse().unwrap(),
                            parts[1].parse().unwrap(),
                            parts[2].parse().unwrap(),
                        )
                    })
                    .collect()
            },
            messages: if fields[13] == "-" {
                Vec::new()
            } else {
                fields[13].split(',').map(unhex).collect()
            },
        };
        assert_eq!(fields[16], "END");
        assert_eq!(result.term, result.durable_term);
        assert!(result.durable_vote <= 3);
        assert!(result.snapshot <= result.applied);
        assert!(result.applied <= result.commit);
        assert!(result.commit <= result.last);
        assert!(result.messages.len() <= 64);
        result
    }
}

type DiskDriver = Driver<RocksBackend, HistoryApplication>;

fn emit(driver: &mut DiskDriver, sequence: u64, error: Option<String>, ticket: Option<ReadTicket>) {
    let mut messages = Vec::new();
    let mut reads = Vec::new();
    for round in 0..64 {
        let output = driver.drain().expect("formal driver drain must succeed");
        messages.extend(output.messages);
        reads.extend(output.reads);
        assert!(messages.len() <= 64, "fixture response message budget");
        if !output.more_ready {
            break;
        }
        assert!(round < 63, "fixture drain work budget exhausted");
    }
    let state = driver.view().unwrap();
    let status = driver.status().unwrap();
    let role = match status.role {
        StateRole::Follower => 0,
        StateRole::Candidate => 1,
        StateRole::Leader => 2,
        StateRole::PreCandidate => 3,
    };
    let reads = if reads.is_empty() {
        "-".into()
    } else {
        reads
            .iter()
            .map(|read| {
                format!(
                    "{}:{}:{}",
                    read.ticket.boot_id, read.ticket.sequence, read.index
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let messages = if messages.is_empty() {
        "-".into()
    } else {
        messages
            .iter()
            .map(|message| hex(&message.write_to_bytes().unwrap()))
            .collect::<Vec<_>>()
            .join(",")
    };
    let line = format!(
        "{PREFIX} {sequence} {} {} {role} {} {} {} {} {} {} {} {reads} {messages} {} {} END\n",
        error.map_or_else(|| "-".into(), |error| hex(error.as_bytes())),
        ticket.map_or_else(
            || "-".into(),
            |ticket| format!("{}:{}", ticket.boot_id, ticket.sequence)
        ),
        status.leader_id,
        status.term,
        status.commit,
        status.applied,
        status.last_index,
        status.snapshot_index,
        hex(&state.application),
        state.hard_state.term,
        state.hard_state.vote,
    );
    assert!(line.len() <= RESPONSE_LIMIT);
    let mut stdout = io::stdout().lock();
    stdout.write_all(line.as_bytes()).unwrap();
    stdout.flush().unwrap();
}

fn child_main() -> bool {
    let Ok(id) = std::env::var(CHILD_ID) else {
        return false;
    };
    let id = id.parse().unwrap();
    let boot = std::env::var(CHILD_BOOT).unwrap().parse().unwrap();
    let path = PathBuf::from(std::env::var_os(CHILD_PATH).unwrap());
    let create = std::env::var(CHILD_CREATE).unwrap() == "1";
    let store = if create {
        let backend = RocksBackend::create_new(&path).unwrap();
        let mut members = ConfState::default();
        members.set_voters(vec![1, 2, 3]);
        Store::create_new(backend, identity(id), members, store_limits()).unwrap()
    } else {
        Store::open_existing(
            RocksBackend::open_existing(&path).unwrap(),
            identity(id),
            store_limits(),
        )
        .unwrap()
    };
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let mut driver = Driver::new(store, HistoryApplication, driver_config(boot), &logger).unwrap();
    emit(&mut driver, 0, None, None);
    let mut reader = BufReader::new(io::stdin().lock());
    while let Some(line) = bounded_line(&mut reader, COMMAND_LIMIT).unwrap() {
        let line = std::str::from_utf8(&line).unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        assert!(fields.len() >= 2);
        let sequence = fields[1].parse().unwrap();
        let mut ticket = None;
        let result = match fields[0] {
            "campaign" => driver.campaign(),
            "tick" => driver.tick(),
            "step" => driver.step(Message::parse_from_bytes(&unhex(fields[2])).unwrap()),
            "propose" => driver.propose(Vec::new(), unhex(fields[2])),
            "read" => driver.read_index().map(|value| ticket = Some(value)),
            "checkpoint" => driver.checkpoint(),
            "unreachable" => driver.report_unreachable(fields[2].parse().unwrap()),
            "snapshot" => {
                let (peer, outcome) = fields[2].split_once(':').unwrap();
                let status = match outcome {
                    "finish" => SnapshotStatus::Finish,
                    "failure" => SnapshotStatus::Failure,
                    _ => panic!("unknown snapshot transport outcome"),
                };
                driver.report_snapshot(peer.parse().unwrap(), status)
            }
            "query" => Ok(()),
            _ => panic!("unknown fixture command"),
        };
        emit(
            &mut driver,
            sequence,
            result.err().map(|error| error.to_string()),
            ticket,
        );
    }
    // EOF is cleanup only. Fault oracles use Child::kill, which bypasses Drop.
    std::process::exit(0)
}

struct Node {
    child: Child,
    writer: Option<SyncSender<Vec<u8>>>,
    writes: Receiver<Result<(), String>>,
    responses: Option<Receiver<Result<Observation, String>>>,
    threads: Vec<JoinHandle<()>>,
    sequence: u64,
    last: Observation,
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .expect("fixture request deadline exceeded")
}

fn wait_for_exit(child: &mut Child) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child exit deadline",
            ));
        }
        // This polls process completion, never guesses persistence/readiness.
        thread::sleep(Duration::from_millis(5));
    }
}

impl Node {
    fn start(test: &str, id: u64, path: &Path, boot: u128, create: bool) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD_ID, id.to_string())
            .env(CHILD_PATH, path)
            .env(CHILD_BOOT, boot.to_string())
            .env(CHILD_CREATE, if create { "1" } else { "0" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (commands, incoming) = mpsc::sync_channel::<Vec<u8>>(1);
        let (write_results, writes) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            while let Ok(command) = incoming.recv() {
                let result = stdin
                    .write_all(&command)
                    .and_then(|()| stdin.flush())
                    .map_err(|error| error.to_string());
                if write_results.send(result).is_err() {
                    break;
                }
            }
        });
        let (results, responses) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            for _ in 0..100_000 {
                match bounded_line(&mut stdout, RESPONSE_LIMIT) {
                    Ok(Some(bytes)) => {
                        let line = String::from_utf8(bytes).unwrap();
                        // libtest prints its test name before invoking child_main.
                        // Only our versioned marker introduces a protocol frame.
                        if let Some(position) = line.find(PREFIX) {
                            if results
                                .send(Ok(Observation::parse(&line[position..])))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    other => {
                        let _ =
                            results.send(Err(format!("child response stream ended: {other:?}")));
                        return;
                    }
                }
            }
            let _ = results.send(Err("child output line budget exhausted".into()));
        });
        // Construct the owner before waiting, so failed startup kills the child.
        let placeholder = Observation {
            sequence: 0,
            error: None,
            ticket: None,
            role: 0,
            leader: 0,
            term: 0,
            durable_term: 0,
            durable_vote: 0,
            commit: 0,
            applied: 0,
            last: 0,
            snapshot: 0,
            history: Vec::new(),
            reads: Vec::new(),
            messages: Vec::new(),
        };
        let mut node = Self {
            child,
            writer: Some(commands),
            writes,
            responses: Some(responses),
            threads: vec![writer, reader],
            sequence: 0,
            last: placeholder,
        };
        node.last = node
            .responses
            .as_ref()
            .unwrap()
            .recv_timeout(REQUEST_TIMEOUT)
            .expect("child boot deadline")
            .expect("child boot response");
        assert_eq!(node.last.sequence, 0);
        assert!(node.last.error.is_none());
        node
    }

    fn request(&mut self, action: &str, argument: &str) -> Observation {
        self.sequence += 1;
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let frame = format!("{action} {} {argument}\n", self.sequence).into_bytes();
        assert!(frame.len() <= COMMAND_LIMIT);
        self.writer.as_ref().unwrap().try_send(frame).unwrap();
        self.writes
            .recv_timeout(remaining(deadline))
            .expect("child command write deadline")
            .expect("child command write");
        let response = self
            .responses
            .as_ref()
            .unwrap()
            .recv_timeout(remaining(deadline))
            .expect("child response deadline")
            .expect("child response stream");
        assert_eq!(response.sequence, self.sequence);
        self.last = response.clone();
        response
    }

    fn kill(&mut self) {
        self.child.kill().expect("kill live fixture child");
        let status = wait_for_exit(&mut self.child).expect("killed child must exit");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(9),
                "fault must be SIGKILL, not clean exit"
            );
        }
        #[cfg(not(unix))]
        assert!(!status.success());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = wait_for_exit(&mut self.child);
        self.writer.take();
        self.responses.take();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        while self.threads.iter().any(|thread| !thread.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        for thread in self.threads.drain(..) {
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Routed {
    from: u64,
    to: u64,
    kind: MessageType,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct VoteObservation {
    from: u64,
    to: u64,
    kind: MessageType,
    term: u64,
    reject: bool,
    durable_term: u64,
    durable_vote: u64,
}

struct Cluster {
    directory: TempDir,
    test: String,
    boot: u128,
    nodes: BTreeMap<u64, Node>,
    blocked: BTreeSet<(u64, u64)>,
    queue: VecDeque<Routed>,
    reads: Vec<(u64, u128, u64, u64)>,
    votes: Vec<VoteObservation>,
    snapshots: Vec<(u64, u64, u64)>,
    failed_snapshots: Vec<(u64, u64, u64)>,
    fail_next_snapshot_to: Option<u64>,
    history: Vec<String>,
    history_bytes: usize,
    deadline: Instant,
}

impl Cluster {
    fn new(test: &str) -> Self {
        let mut result = Self {
            directory: tempfile::tempdir().unwrap(),
            test: test.into(),
            boot: 0,
            nodes: BTreeMap::new(),
            blocked: BTreeSet::new(),
            queue: VecDeque::new(),
            reads: Vec::new(),
            votes: Vec::new(),
            snapshots: Vec::new(),
            failed_snapshots: Vec::new(),
            fail_next_snapshot_to: None,
            history: Vec::new(),
            history_bytes: 0,
            deadline: Instant::now() + SCENARIO_TIMEOUT,
        };
        for id in 1..=3 {
            result.start(id, true);
        }
        result.pump();
        result
    }

    fn start(&mut self, id: u64, create: bool) {
        assert!(Instant::now() < self.deadline, "scenario deadline exceeded");
        assert!(!self.nodes.contains_key(&id));
        self.boot += 1;
        let path = self.directory.path().join(format!("node-{id}"));
        let node = Node::start(&self.test, id, &path, self.boot, create);
        assert!(Instant::now() < self.deadline, "scenario deadline exceeded");
        let response = node.last.clone();
        self.nodes.insert(id, node);
        self.record(id, &response);
        self.event(format!(
            "start node={id} boot={} create={create}",
            self.boot
        ));
    }

    fn kill(&mut self, id: u64) {
        self.event(format!("SIGKILL node={id}"));
        self.nodes.get_mut(&id).unwrap().kill();
        self.nodes.remove(&id);
        self.queue
            .retain(|message| message.from != id && message.to != id);
    }

    fn record(&mut self, id: u64, response: &Observation) {
        self.event(format!(
            "node={id} seq={} role={} leader={} term={} durable_term={} durable_vote={} commit={} applied={} last={} snapshot={} app={:?} error={:?}",
            response.sequence, response.role, response.leader, response.term,
            response.durable_term, response.durable_vote,
            response.commit, response.applied, response.last, response.snapshot,
            response.history, response.error,
        ));
        for &(boot, ticket, index) in &response.reads {
            assert!(
                index <= response.applied,
                "read barrier precedes durable apply"
            );
            assert!(
                !self.reads.iter().any(|&(node, old_boot, old_ticket, _)| {
                    node == id && old_boot == boot && old_ticket == ticket
                }),
                "duplicate read completion"
            );
            self.reads.push((id, boot, ticket, index));
        }
        for bytes in &response.messages {
            assert!(bytes.len() <= 1536, "fixture peer message budget");
            let message = Message::parse_from_bytes(bytes).unwrap();
            assert_eq!(message.from, id);
            assert!((1..=3).contains(&message.to));
            if matches!(
                message.get_msg_type(),
                MessageType::MsgRequestPreVote
                    | MessageType::MsgRequestPreVoteResponse
                    | MessageType::MsgRequestVote
                    | MessageType::MsgRequestVoteResponse
            ) {
                let vote = VoteObservation {
                    from: message.from,
                    to: message.to,
                    kind: message.get_msg_type(),
                    term: message.term,
                    reject: message.reject,
                    durable_term: response.durable_term,
                    durable_vote: response.durable_vote,
                };
                self.event(format!("vote emitted: {vote:?}"));
                self.votes.push(vote);
                assert!(
                    self.votes.len() <= ROUTE_LIMIT,
                    "vote history budget exhausted"
                );
            }
            self.queue.push_back(Routed {
                from: message.from,
                to: message.to,
                kind: message.get_msg_type(),
                bytes: bytes.clone(),
            });
            assert!(
                self.queue.len() <= ROUTE_LIMIT,
                "router queue budget exhausted"
            );
        }
    }

    fn request(&mut self, id: u64, action: &str, argument: &str) -> Observation {
        assert!(Instant::now() < self.deadline, "scenario deadline exceeded");
        self.event(format!(
            "request node={id} action={action} argument={argument}"
        ));
        let result = self.nodes.get_mut(&id).unwrap().request(action, argument);
        assert!(Instant::now() < self.deadline, "scenario deadline exceeded");
        self.record(id, &result);
        result
    }

    fn ok(&mut self, id: u64, action: &str, argument: &str) -> Observation {
        let result = self.request(id, action, argument);
        assert!(
            result.error.is_none(),
            "{action} rejected: {:?}",
            result.error
        );
        result
    }

    fn pump(&mut self) {
        for _ in 0..ROUTE_LIMIT {
            let Some(message) = self.queue.pop_front() else {
                return;
            };
            self.deliver(message);
        }
        panic!("router work budget exhausted");
    }

    fn deliver_matching(&mut self, from: u64, to: u64, kind: MessageType) {
        let position = self
            .queue
            .iter()
            .position(|message| message.from == from && message.to == to && message.kind == kind)
            .expect("actual matching Raft message must have been emitted");
        let message = self.queue.remove(position).unwrap();
        self.deliver(message);
    }

    fn deliver(&mut self, message: Routed) {
        if self.blocked.contains(&(message.from, message.to)) {
            self.event(format!(
                "drop {}->{} {:?}",
                message.from, message.to, message.kind
            ));
            return;
        }
        if !self.nodes.contains_key(&message.to) {
            self.event(format!(
                "unreachable {}->{} {:?}",
                message.from, message.to, message.kind
            ));
            if self.nodes.contains_key(&message.from) {
                if message.kind == MessageType::MsgSnapshot {
                    self.ok(message.from, "snapshot", &format!("{}:failure", message.to));
                } else {
                    self.ok(message.from, "unreachable", &message.to.to_string());
                }
            }
            return;
        }
        if message.kind == MessageType::MsgSnapshot
            && self.fail_next_snapshot_to == Some(message.to)
        {
            self.fail_next_snapshot_to = None;
            let snapshot = Message::parse_from_bytes(&message.bytes).unwrap();
            let index = snapshot.get_snapshot().get_metadata().index;
            self.failed_snapshots
                .push((message.from, message.to, index));
            self.event(format!(
                "injected snapshot delivery failure {}->{} index={index}",
                message.from, message.to,
            ));
            self.ok(message.from, "snapshot", &format!("{}:failure", message.to));
            return;
        }
        if message.kind == MessageType::MsgSnapshot {
            let snapshot = Message::parse_from_bytes(&message.bytes).unwrap();
            self.snapshots.push((
                message.from,
                message.to,
                snapshot.get_snapshot().get_metadata().index,
            ));
        }
        self.event(format!(
            "deliver {}->{} {:?}",
            message.from, message.to, message.kind
        ));
        self.ok(message.to, "step", &hex(&message.bytes));
        if message.kind == MessageType::MsgSnapshot && self.nodes.contains_key(&message.from) {
            self.ok(message.from, "snapshot", &format!("{}:finish", message.to));
        }
    }

    fn tick(&mut self, ids: &[u64], count: usize) {
        assert!(count <= 100);
        for _ in 0..count {
            for &id in ids {
                self.ok(id, "tick", "-");
            }
            self.pump();
        }
    }

    fn elect(&mut self, id: u64, active: &[u64]) {
        for _ in 0..8 {
            let _ = self.request(id, "campaign", "-");
            self.pump();
            if self.nodes[&id].last.role == 2 {
                return;
            }
            self.tick(active, ELECTION_TICKS * 2);
        }
        panic!("node {id} did not become leader in finite election budget");
    }

    fn propose(&mut self, id: u64, token: u64, amount: u64) {
        self.ok(id, "propose", &hex(&operation(token, amount)));
        self.pump();
    }

    fn isolate(&mut self, id: u64) {
        for other in 1..=3 {
            if other != id {
                self.blocked.insert((id, other));
                self.blocked.insert((other, id));
            }
        }
        self.event(format!("isolate node={id}"));
    }

    fn heal(&mut self) {
        self.blocked.clear();
        self.event("heal all links".into());
        self.pump();
    }

    fn assert_history(&mut self, ids: &[u64], expected: &[(u64, u64)]) {
        for &id in ids {
            let state = self.ok(id, "query", "-");
            assert_eq!(state.history, expected, "node {id} durable application");
        }
    }

    fn read(&mut self, id: u64) -> (u128, u64) {
        let result = self.ok(id, "read", "-");
        let ticket = result.ticket.expect("accepted read gets a unique ticket");
        self.pump();
        ticket
    }

    fn assert_read_completed(&self, id: u64, ticket: (u128, u64)) {
        assert!(self
            .reads
            .iter()
            .any(|&(node, boot, actual, _)| node == id && (boot, actual) == ticket));
    }

    fn event(&mut self, event: String) {
        self.history_bytes += event.len();
        assert!(
            self.history.len() < 20_000,
            "history count budget exhausted"
        );
        assert!(
            self.history_bytes <= 8 * 1024 * 1024,
            "history byte budget exhausted"
        );
        self.history.push(event);
    }

    fn finish(mut self) {
        assert!(Instant::now() < self.deadline, "scenario deadline exceeded");
        self.event(format!(
            "verification passed; read_barriers={:?}; snapshot_routes={:?}; failed_snapshot_routes={:?}; votes={:?}",
            self.reads, self.snapshots, self.failed_snapshots, self.votes,
        ));
        let directory = std::env::var_os("SCAP_CLUSTER_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/evidence/raft-cluster"));
        std::fs::create_dir_all(&directory).unwrap();
        let header = concat!(
            "SCAP three-process contract evidence v2\n",
            "raft-rs=ad13f3d90780f53aea2488c6a4b76c0d334bf136 protobuf=2.28.0\n",
            "backend=scap-raft-rocks rocksdb=0.24.0 native=10.4.2 WAL=true sync=true\n",
            "recovery=AbsoluteConsistency paranoid_checks=true\n",
            "voters=1,2,3 genesis=index1/term1 application=raw-token-delta-history(no-dedup)\n",
            "transport=bounded-parent-IPC-router fault=SIGKILL-or-controlled-message-drop-or-WAL-checksum-corruption\n",
            "logical-ticks: heartbeat=1 election=10 randomized-min=30 randomized-max=31\n",
            "raft-policy: pre_vote=true check_quorum=true read=Safe; durable-term/vote recorded after drain\n",
            "not-validated=SQL-ACK,mTLS,TCP-faults,AZs,power-loss,RTO,throughput\n",
        );
        let file = directory.join(format!("{}.log", self.test));
        std::fs::write(&file, format!("{header}{}\n", self.history.join("\n"))).unwrap();
        println!("contract evidence: {}", file.display());
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "bounded cluster event history:\n{}",
                self.history.join("\n")
            );
        }
        // Kill every child before TempDir attempts to remove its live databases.
        self.nodes.clear();
    }
}

#[test]
fn leader_failure_and_full_restart_preserve_committed_history() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("leader_failure_and_full_restart_preserve_committed_history");
    cluster.elect(1, &[1, 2, 3]);
    cluster.isolate(3);
    cluster.propose(1, 101, 7);
    cluster.assert_history(&[1, 2], &[(101, 7)]);
    cluster.assert_history(&[3], &[]);
    let first_read = cluster.read(1);
    cluster.assert_read_completed(1, first_read);
    cluster.kill(1);
    cluster.heal();
    cluster.elect(2, &[2, 3]);
    cluster.propose(2, 102, 11);
    cluster.assert_history(&[2, 3], &[(101, 7), (102, 11)]);
    let second_read = cluster.read(2);
    cluster.assert_read_completed(2, second_read);
    cluster.start(1, false);
    cluster.tick(&[2, 3], 3);
    cluster.assert_history(&[1, 2, 3], &[(101, 7), (102, 11)]);
    for id in 1..=3 {
        cluster.kill(id);
    }
    for id in 1..=3 {
        cluster.start(id, false);
    }
    cluster.assert_history(&[1, 2, 3], &[(101, 7), (102, 11)]);
    cluster.elect(3, &[1, 2, 3]);
    cluster.propose(3, 103, 5);
    cluster.assert_history(&[1, 2, 3], &[(101, 7), (102, 11), (103, 5)]);
    let after_restart = cluster.read(3);
    cluster.assert_read_completed(3, after_restart);
    cluster.finish();
}

#[test]
fn minority_cannot_commit_or_complete_a_new_read_barrier() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("minority_cannot_commit_or_complete_a_new_read_barrier");
    cluster.elect(1, &[1, 2, 3]);
    cluster.propose(1, 201, 3);
    cluster.assert_history(&[1, 2, 3], &[(201, 3)]);
    let old_commit = cluster.nodes[&1].last.commit;
    cluster.isolate(1);
    cluster.propose(1, 202, 1000);
    let minority_read = cluster.read(1);
    assert!(cluster.nodes[&1].last.last > old_commit);
    assert_eq!(cluster.nodes[&1].last.commit, old_commit);
    assert!(!cluster
        .reads
        .iter()
        .any(|&(node, boot, ticket, _)| node == 1 && (boot, ticket) == minority_read));
    cluster.elect(2, &[2, 3]);
    cluster.propose(2, 203, 13);
    cluster.assert_history(&[2, 3], &[(201, 3), (203, 13)]);
    let majority_read = cluster.read(2);
    cluster.assert_read_completed(2, majority_read);
    cluster.tick(&[1], ELECTION_TICKS * 3);
    assert_ne!(
        cluster.nodes[&1].last.role, 2,
        "isolated leader must lose quorum leadership"
    );
    assert_eq!(cluster.nodes[&1].last.commit, old_commit);
    cluster.assert_history(&[1], &[(201, 3)]);
    assert!(!cluster
        .reads
        .iter()
        .any(|&(node, boot, ticket, _)| node == 1 && (boot, ticket) == minority_read));
    cluster.heal();
    cluster.tick(&[2, 3], 5);
    cluster.assert_history(&[1, 2, 3], &[(201, 3), (203, 13)]);
    // The old proposal is overwritten because this test commits a conflicting
    // new-term prefix. An arbitrary UNKNOWN proposal is not guaranteed rollback.
    cluster.propose(2, 204, 17);
    cluster.assert_history(&[1, 2, 3], &[(201, 3), (203, 13), (204, 17)]);
    cluster.finish();
}

#[test]
fn uncommitted_tail_is_not_applied_during_restart() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("uncommitted_tail_is_not_applied_during_restart");
    cluster.elect(1, &[1, 2, 3]);
    cluster.propose(1, 301, 19);
    cluster.assert_history(&[1, 2, 3], &[(301, 19)]);
    cluster.isolate(1);
    cluster.propose(1, 302, 23);
    let pending = cluster.nodes[&1].last.clone();
    assert!(pending.last > pending.commit);
    cluster.kill(1);
    cluster.start(1, false);
    let recovered = cluster.ok(1, "query", "-");
    assert_eq!(recovered.last, pending.last);
    assert_eq!(recovered.commit, pending.commit);
    assert_eq!(recovered.applied, pending.applied);
    cluster.assert_history(&[1], &[(301, 19)]);
    // A new-term majority commits a different entry before healing the link.
    cluster.elect(2, &[2, 3]);
    cluster.propose(2, 303, 29);
    cluster.heal();
    cluster.tick(&[2, 3], 5);
    cluster.assert_history(&[1, 2, 3], &[(301, 19), (303, 29)]);
    cluster.finish();
}

#[test]
fn compacted_leader_installs_a_real_snapshot_on_a_lagging_replica() {
    if child_main() {
        return;
    }
    let mut cluster =
        Cluster::new("compacted_leader_installs_a_real_snapshot_on_a_lagging_replica");
    cluster.elect(1, &[1, 2, 3]);
    cluster.propose(1, 401, 2);
    cluster.assert_history(&[1, 2, 3], &[(401, 2)]);
    let lagging = cluster.nodes[&3].last.clone();
    cluster.kill(3);
    cluster.propose(1, 402, 3);
    cluster.propose(1, 403, 5);
    cluster.assert_history(&[1, 2], &[(401, 2), (402, 3), (403, 5)]);
    let checkpoint = cluster.ok(1, "checkpoint", "-");
    assert!(checkpoint.snapshot > lagging.last);
    cluster.tick(&[1, 2], 3);
    cluster.fail_next_snapshot_to = Some(3);
    cluster.start(3, false);
    cluster.tick(&[1, 2], 5);
    assert_eq!(cluster.failed_snapshots, vec![(1, 3, checkpoint.snapshot)]);
    assert!(cluster.fail_next_snapshot_to.is_none());
    assert!(cluster
        .snapshots
        .iter()
        .any(|&(from, to, index)| from == 1 && to == 3 && index == checkpoint.snapshot));
    assert_eq!(cluster.nodes[&3].last.snapshot, checkpoint.snapshot);
    cluster.assert_history(&[1, 2, 3], &[(401, 2), (402, 3), (403, 5)]);
    cluster.kill(3);
    cluster.start(3, false);
    assert_eq!(cluster.nodes[&3].last.snapshot, checkpoint.snapshot);
    cluster.assert_history(&[3], &[(401, 2), (402, 3), (403, 5)]);
    cluster.propose(1, 404, 7);
    cluster.assert_history(&[1, 2, 3], &[(401, 2), (402, 3), (403, 5), (404, 7)]);
    let read = cluster.read(1);
    cluster.assert_read_completed(1, read);
    cluster.finish();
}

#[test]
fn corrupt_wal_is_rejected_without_reinitializing_the_replica() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("corrupt_wal_is_rejected_without_reinitializing_the_replica");
    cluster.elect(1, &[1, 2, 3]);
    cluster.propose(1, 501, 31);
    cluster.assert_history(&[1, 2, 3], &[(501, 31)]);
    cluster.kill(3);

    // Only this synthetic, SIGKILLed replica is modified. No live native handle
    // owns its directory. Successful sync and exact process exit were observed.
    let path = cluster.directory.path().join("node-3");
    let database_id = std::fs::read(path.join("IDENTITY")).unwrap();
    let current_manifest = std::fs::read(path.join("CURRENT")).unwrap();
    let synced_operation = operation(501, 31);
    let mut logs: Vec<_> = std::fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|file| file.extension().is_some_and(|extension| extension == "log"))
        .collect();
    logs.sort();
    let (wal, contents) = logs
        .into_iter()
        .rev()
        .find_map(|file| {
            let size = file.metadata().unwrap().len();
            assert!(size <= 8 * 1024 * 1024, "bounded synthetic WAL inspection");
            let bytes = std::fs::read(&file).unwrap();
            let carries_image = bytes
                .windows(b"scap/g0/atomic-image".len())
                .any(|window| window == b"scap/g0/atomic-image");
            let carries_operation = bytes
                .windows(16)
                .any(|window| window == synced_operation.as_slice());
            (carries_image && carries_operation).then_some((file, bytes))
        })
        .expect("SIGKILL must leave a real nonempty WAL containing the synced operation");
    assert!(contents.len() > 7);
    let record_length = u16::from_le_bytes([contents[4], contents[5]]) as usize;
    let record_type = contents[6];
    assert!(record_length > 0 && 7 + record_length <= contents.len());
    assert!(
        (1..=11).contains(&record_type),
        "expected a physical WAL record header"
    );
    // The first four physical-header bytes are the record's CRC32C checksum.
    // Flip one checksum bit while retaining every file, length and payload byte.
    let corrupted_checksum = contents[0] ^ 1;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wal)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[corrupted_checksum]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    cluster.event(format!(
        "corrupt synthetic WAL={} offset=0 checksum_bit=1 size={} first_record_type={record_type} first_record_length={record_length}",
        wal.file_name().unwrap().to_string_lossy(), contents.len(),
    ));

    let corruption = match RocksBackend::open_existing(&path) {
        Err(scap_raft_rocks::Error::Native(message)) => message,
        Err(other) => panic!("expected native Corruption, received unrelated error: {other}"),
        Ok(_) => panic!("corrupt WAL must not silently recover an earlier valid image"),
    };
    assert!(
        corruption.starts_with("Corruption:"),
        "specific corruption status required: {corruption}"
    );
    cluster.event(format!("open_existing rejected native {corruption}"));
    assert!(path.is_dir());
    assert_eq!(std::fs::read(path.join("IDENTITY")).unwrap(), database_id);
    assert_eq!(
        std::fs::read(path.join("CURRENT")).unwrap(),
        current_manifest
    );
    let after = std::fs::read(&wal).unwrap();
    assert_eq!(after.len(), contents.len());
    assert_eq!(after[0], corrupted_checksum);
    assert_eq!(&after[1..], &contents[1..]);
    cluster.event("corrupt directory, database identity, CURRENT manifest pointer and damaged WAL retained; no repair or reinitialization".into());

    cluster.propose(1, 502, 37);
    cluster.assert_history(&[1, 2], &[(501, 31), (502, 37)]);
    let read = cluster.read(1);
    cluster.assert_read_completed(1, read);
    cluster.finish();
}

#[test]
fn tick_election_prevotes_before_changing_durable_term_and_vote() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("tick_election_prevotes_before_changing_durable_term_and_vote");
    // The configured randomized interval is [30, 31), so no randomness or
    // explicit campaign command is needed to reach exactly this timeout.
    cluster.tick(&[1], ELECTION_TICKS * 3 - 1);
    assert_eq!(cluster.nodes[&1].last.role, 0);
    assert!(cluster.votes.is_empty());
    let pre_candidate = cluster.ok(1, "tick", "-");
    assert_eq!(pre_candidate.role, 3);
    assert_eq!(pre_candidate.term, 1);
    assert_eq!(pre_candidate.durable_term, 1);
    assert_eq!(pre_candidate.durable_vote, 0);
    assert_eq!(cluster.votes.len(), 2);
    for vote in &cluster.votes {
        assert_eq!(vote.from, 1);
        assert!([2, 3].contains(&vote.to));
        assert_eq!(vote.kind, MessageType::MsgRequestPreVote);
        assert_eq!(vote.term, 2);
        assert!(!vote.reject);
        assert_eq!(vote.durable_term, 1);
        assert_eq!(vote.durable_vote, 0);
    }

    // Deliver original messages one at a time. A real peer granting PreVote
    // neither increments its durable term nor records a real vote.
    cluster.deliver_matching(1, 2, MessageType::MsgRequestPreVote);
    let grant = cluster.votes.last().unwrap();
    assert_eq!(grant.kind, MessageType::MsgRequestPreVoteResponse);
    assert_eq!((grant.from, grant.to, grant.term), (2, 1, 2));
    assert!(!grant.reject);
    assert_eq!((grant.durable_term, grant.durable_vote), (1, 0));
    assert_eq!(cluster.nodes[&1].last.role, 3);

    cluster.deliver_matching(2, 1, MessageType::MsgRequestPreVoteResponse);
    let candidate = &cluster.nodes[&1].last;
    assert_eq!(candidate.role, 1);
    assert_eq!((candidate.durable_term, candidate.durable_vote), (2, 1));
    let real_votes: Vec<_> = cluster
        .votes
        .iter()
        .filter(|vote| vote.kind == MessageType::MsgRequestVote)
        .collect();
    assert_eq!(real_votes.len(), 2);
    assert!(real_votes.iter().all(|vote| {
        vote.from == 1 && vote.term == 2 && vote.durable_term == 2 && vote.durable_vote == 1
    }));

    // The responder must also persist its formal vote before its response is
    // released. The candidate is still not leader until that reply is delivered.
    cluster.deliver_matching(1, 2, MessageType::MsgRequestVote);
    let grant = cluster.votes.last().unwrap();
    assert_eq!(grant.kind, MessageType::MsgRequestVoteResponse);
    assert_eq!((grant.from, grant.to, grant.term), (2, 1, 2));
    assert!(!grant.reject);
    assert_eq!((grant.durable_term, grant.durable_vote), (2, 1));
    assert_eq!(cluster.nodes[&1].last.role, 1);
    cluster.deliver_matching(2, 1, MessageType::MsgRequestVoteResponse);
    assert_eq!(cluster.nodes[&1].last.role, 2);
    assert!(cluster.nodes[&1].last.last > cluster.nodes[&1].last.commit);
    // Election success alone does not establish the new term's read frontier.
    // Reject before allocating a ticket while its no-op is only local; the
    // fixed Raft library would otherwise silently drop this read request.
    let early_read = cluster.request(1, "read", "-");
    assert_eq!(early_read.error.as_deref(), Some("ReadNotReady"));
    assert!(early_read.ticket.is_none());
    cluster.pump();
    let read = cluster.read(1);
    assert_eq!(read.1, 1, "not-ready admission must not consume a ticket");
    cluster.assert_read_completed(1, read);
    cluster.propose(1, 601, 41);
    cluster.assert_history(&[1, 2, 3], &[(601, 41)]);
    assert!(cluster
        .history
        .iter()
        .all(|event| !event.contains("action=campaign")));
    cluster.finish();
}

#[test]
fn isolated_follower_prevote_preserves_the_healthy_leaders_term() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("isolated_follower_prevote_preserves_the_healthy_leaders_term");
    cluster.tick(&[1], ELECTION_TICKS * 3);
    assert_eq!(cluster.nodes[&1].last.role, 2);
    cluster.propose(1, 701, 43);
    cluster.assert_history(&[1, 2, 3], &[(701, 43)]);
    let term = cluster.nodes[&1].last.durable_term;
    let old_vote = cluster.nodes[&3].last.durable_vote;
    let votes_before_partition = cluster.votes.len();
    cluster.isolate(3);
    let mut expected = vec![(701, 43)];
    for round in 1..=3 {
        // Both healthy nodes continue processing ticks and actual heartbeats.
        // Node 3 crosses three separate election timeouts in the blackhole.
        cluster.tick(&[1, 2, 3], ELECTION_TICKS * 3);
        assert_eq!(cluster.nodes[&1].last.role, 2);
        assert_eq!(cluster.nodes[&1].last.term, term);
        assert_eq!(cluster.nodes[&2].last.term, term);
        assert_eq!(cluster.nodes[&3].last.role, 3);
        assert_eq!(cluster.nodes[&3].last.term, term);
        assert_eq!(cluster.nodes[&3].last.durable_term, term);
        assert_eq!(cluster.nodes[&3].last.durable_vote, old_vote);
        cluster.propose(1, 701 + round, round);
        expected.push((701 + round, round));
        cluster.assert_history(&[1, 2], &expected);
    }
    let isolated_votes = &cluster.votes[votes_before_partition..];
    assert!(isolated_votes.len() >= 6);
    assert!(isolated_votes.iter().all(|vote| {
        vote.from == 3
            && vote.kind == MessageType::MsgRequestPreVote
            && vote.term == term + 1
            && vote.durable_term == term
            && vote.durable_vote == old_vote
    }));
    cluster.assert_history(&[3], &[(701, 43)]);

    // Reconnect the still-running PreCandidate, not a freshly reset replacement.
    cluster.heal();
    cluster.tick(&[1, 2, 3], 3);
    assert_eq!(cluster.nodes[&1].last.role, 2);
    for id in 1..=3 {
        assert_eq!(cluster.nodes[&id].last.term, term);
        assert_eq!(cluster.nodes[&id].last.leader, 1);
    }
    cluster.assert_history(&[1, 2, 3], &expected);
    cluster.kill(3);
    cluster.start(3, false);
    assert_eq!(cluster.nodes[&3].last.durable_term, term);
    assert_eq!(cluster.nodes[&3].last.durable_vote, old_vote);
    cluster.tick(&[1, 2], 3);
    cluster.assert_history(&[1, 2, 3], &expected);
    let read = cluster.read(1);
    cluster.assert_read_completed(1, read);
    assert!(cluster
        .history
        .iter()
        .all(|event| !event.contains("action=campaign")));
    cluster.finish();
}

#[test]
fn one_way_partition_and_old_read_ack_cannot_complete_a_new_read() {
    if child_main() {
        return;
    }
    let mut cluster = Cluster::new("one_way_partition_and_old_read_ack_cannot_complete_a_new_read");
    cluster.tick(&[1], ELECTION_TICKS * 3);
    assert_eq!(cluster.nodes[&1].last.role, 2);
    cluster.propose(1, 801, 47);
    cluster.assert_history(&[1, 2, 3], &[(801, 47)]);

    let old_ticket = cluster.ok(1, "read", "-").ticket.unwrap();
    cluster.deliver_matching(1, 2, MessageType::MsgHeartbeat);
    let delayed_ack = cluster
        .queue
        .iter()
        .find(|message| {
            message.from == 2
                && message.to == 1
                && message.kind == MessageType::MsgHeartbeatResponse
        })
        .expect("capture an actual peer response, not a manufactured message")
        .clone();
    let old_context = Message::parse_from_bytes(&delayed_ack.bytes)
        .unwrap()
        .context;
    assert!(!old_context.is_empty());
    cluster.pump();
    cluster.assert_read_completed(1, old_ticket);

    cluster.blocked.insert((2, 1));
    cluster.blocked.insert((3, 1));
    cluster.event(
        "one-way partition: leader traffic reaches peers; peer replies to leader are dropped"
            .into(),
    );
    let commit = cluster.nodes[&1].last.commit;
    let new_ticket = cluster.ok(1, "read", "-").ticket.unwrap();
    assert_ne!(old_ticket, new_ticket);
    let fresh_heartbeat = cluster.queue.front().unwrap();
    assert_eq!(fresh_heartbeat.kind, MessageType::MsgHeartbeat);
    let new_context = Message::parse_from_bytes(&fresh_heartbeat.bytes)
        .unwrap()
        .context;
    assert_ne!(old_context, new_context);
    cluster.pump();
    assert_eq!(cluster.nodes[&1].last.role, 2);
    assert!(!cluster
        .reads
        .iter()
        .any(|&(node, boot, ticket, _)| { node == 1 && (boot, ticket) == new_ticket }));

    // One already captured old-context acknowledgement is delivered again;
    // every new acknowledgement remains blocked. Original protobuf bytes and
    // request context are retained, even though the network reorders/replays it.
    assert!(cluster.blocked.remove(&(2, 1)));
    cluster.event(format!(
        "deliver captured old read ACK unchanged: old_context={} new_context={}",
        hex(&old_context),
        hex(&new_context),
    ));
    cluster.deliver(delayed_ack);
    cluster.blocked.insert((2, 1));
    cluster.pump();
    assert_eq!(cluster.nodes[&1].last.role, 2);
    assert!(!cluster
        .reads
        .iter()
        .any(|&(node, boot, ticket, _)| { node == 1 && (boot, ticket) == new_ticket }));

    cluster.tick(&[1], ELECTION_TICKS * 2);
    assert_eq!(cluster.nodes[&1].last.role, 0);
    assert_eq!(cluster.nodes[&1].last.commit, commit);
    let rejected = cluster.request(1, "read", "-");
    assert_eq!(rejected.error.as_deref(), Some("NotLeader"));
    cluster.heal();
    cluster.tick(&[2], ELECTION_TICKS * 3);
    assert_eq!(cluster.nodes[&2].last.role, 2);
    cluster.propose(2, 802, 53);
    cluster.assert_history(&[1, 2, 3], &[(801, 47), (802, 53)]);
    assert!(!cluster
        .reads
        .iter()
        .any(|&(node, boot, ticket, _)| { node == 1 && (boot, ticket) == new_ticket }));
    let recovered = cluster.read(2);
    cluster.assert_read_completed(2, recovered);
    cluster.finish();
}
