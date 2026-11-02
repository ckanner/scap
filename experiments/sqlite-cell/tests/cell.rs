//! Independent real-engine contracts. Three actual drivers and disk backends
//! share one test process; the SQL writer is a separately killed OS process.
//! This is not the three-process Raft/network suite and is not a product SDK.
#[path = "../src/protocol.rs"]
mod protocol;

use libsql_sys::{ffi, rusqlite};
use protocol::{
    read_frame, write_frame, Wire, INIT_SCHEMA, MAX_PAGES, MAX_PHYSICAL, PAGE_SIZE, SQL, TIMEOUT,
};
use raft::eraftpb::{ConfState, Message, MessageType};
use raft::{Config, SnapshotStatus, StateRole};
use scap_cell::{
    encode_command, payload_digest, AdminResult, Admission, CellApplication, CellIdentity,
    CellState, Command, CommandKind, DatabaseIdentity, Limits as CellLimits, Lookup, Outcome,
    OwnerToken, Position, Reject, ADMIN, READ, WRITE,
};
use scap_core::{
    CommitCoordinator, CommitReceipt, CommitTicket, CompletionError, ConsensusPort, Decision,
    PreparedWrite, Rejection, VisibilityPort,
};
use scap_raft_driver::{Driver, DriverConfig, ReadTicket};
use scap_raft_rocks::RocksBackend;
use scap_raft_store::{Identity, Limits as StoreLimits, Store};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const CELL: CellIdentity = CellIdentity {
    cell_id: 0x53434150,
    cell_incarnation: 7,
};
const DATABASE: DatabaseIdentity = DatabaseIdentity {
    database_id: 0x53514c495445,
    incarnation: 4,
    placement_generation: 1,
};
const ADMIN_ID: u128 = 100;
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);
type Node = Driver<RocksBackend, CellApplication>;
type Input = (Wire, SyncSender<Result<(), String>>);

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .expect("fixture deadline exceeded")
}

fn cell_limits() -> CellLimits {
    CellLimits {
        max_state_bytes: 2 * 1024 * 1024,
        max_command_bytes: 400 * 1024,
        max_databases: 4,
        max_policy_grants: 8,
        max_admin_operations: 64,
        max_requests_per_database: 32,
        max_transaction_bytes: 300 * 1024,
        max_result_bytes: 1024,
    }
}

fn store_limits() -> StoreLimits {
    StoreLimits {
        max_image_bytes: 8 * 1024 * 1024,
        max_entry_bytes: 512 * 1024,
        max_entries: 1024,
        max_application_bytes: 2 * 1024 * 1024,
    }
}

fn identity(node_id: u64) -> Identity {
    Identity {
        cluster_id: 0x47524f5550,
        cell_id: CELL.cell_id,
        cell_incarnation: CELL.cell_incarnation,
        node_id,
    }
}

fn node_config(boot_id: u128) -> DriverConfig {
    DriverConfig {
        raft: Config {
            heartbeat_tick: 1,
            election_tick: 10,
            min_election_tick: 30,
            max_election_tick: 31,
            max_size_per_msg: 512 * 1024,
            max_inflight_msgs: 16,
            max_uncommitted_size: 2 * 1024 * 1024,
            max_committed_size_per_ready: 512 * 1024,
            ..Config::default()
        },
        boot_id,
        max_input_bytes: 3 * 1024 * 1024,
        max_output_messages: 64,
        max_output_bytes: 4 * 1024 * 1024,
        max_pending_reads: 16,
        max_pending_proposals: 16,
        max_pending_proposal_bytes: 8 * 1024 * 1024,
        max_ready_rounds: 32,
    }
}

struct Cluster {
    nodes: BTreeMap<u64, Node>,
    root: PathBuf,
    queue: VecDeque<Message>,
    paused: BTreeSet<u64>,
    reads: Vec<(u64, ReadTicket, u64)>,
    snapshots: Vec<(u64, u64, u64)>,
    history: Vec<String>,
    history_bytes: usize,
    next_boot: u128,
    next_admission: u128,
    deadline: Instant,
}

impl Cluster {
    fn new(root: &Path) -> Self {
        let mut cluster = Self {
            nodes: BTreeMap::new(),
            root: root.to_owned(),
            queue: VecDeque::new(),
            paused: BTreeSet::new(),
            reads: Vec::new(),
            snapshots: Vec::new(),
            history: Vec::new(),
            history_bytes: 0,
            next_boot: 1,
            next_admission: 1,
            deadline: Instant::now() + SCENARIO_TIMEOUT,
        };
        for id in 1..=3 {
            cluster.open(id, true);
        }
        cluster.elect();
        let create = cluster.command(CommandKind::Create {
            operation_id: 1,
            policy: Self::policy(),
        });
        assert_eq!(
            cluster.submit(create),
            Outcome::Administrative(AdminResult::Created)
        );
        let claim = cluster.command(CommandKind::ClaimOwner {
            operation_id: 2,
            expected_epoch: 0,
            worker_instance_id: 9001,
        });
        let Outcome::Administrative(AdminResult::OwnerClaimed(token)) = cluster.submit(claim)
        else {
            panic!("owner claim was not accepted");
        };
        let activate = cluster.command(CommandKind::ActivateOwner {
            operation_id: 3,
            token,
            restored_revision: 0,
            restored_hash: [0; 32],
        });
        assert_eq!(
            cluster.submit(activate),
            Outcome::Administrative(AdminResult::OwnerActivated)
        );
        cluster
    }

    fn policy() -> Vec<scap_cell::Grant> {
        vec![scap_cell::Grant {
            principal_id: ADMIN_ID,
            permissions: READ | WRITE | ADMIN,
        }]
    }

    fn open(&mut self, id: u64, create: bool) {
        let path = self.root.join(format!("raft-{id}"));
        let store = if create {
            let application = CellState::bootstrap(
                CELL,
                ADMIN_ID,
                Position { term: 1, index: 1 },
                cell_limits(),
            )
            .unwrap()
            .encode();
            Store::create_new_with_application(
                RocksBackend::create_new(&path).unwrap(),
                identity(id),
                ConfState {
                    voters: vec![1, 2, 3],
                    ..ConfState::default()
                },
                store_limits(),
                application,
            )
            .unwrap()
        } else {
            Store::open_existing(
                RocksBackend::open_existing(&path).unwrap(),
                identity(id),
                store_limits(),
            )
            .unwrap()
        };
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let driver = Driver::new(
            store,
            CellApplication::new(CELL, cell_limits()).unwrap(),
            node_config(self.next_boot),
            &logger,
        )
        .unwrap();
        self.next_boot += 1;
        assert!(self.nodes.insert(id, driver).is_none());
        self.event(format!("open node={id} create={create}"));
        self.state(id);
    }

    fn state(&self, id: u64) -> CellState {
        let view = self.nodes[&id].view().unwrap();
        let metadata = view.snapshot.get_metadata();
        assert!(metadata.index <= view.applied && view.applied <= view.hard_state.commit);
        let term = if view.applied == metadata.index {
            metadata.term
        } else {
            view.entries
                .iter()
                .find(|entry| entry.index == view.applied)
                .unwrap()
                .term
        };
        CellState::decode_bound(
            &view.application,
            CELL,
            Position {
                term,
                index: view.applied,
            },
            cell_limits(),
        )
        .unwrap()
    }

    fn event(&mut self, text: String) {
        assert!(Instant::now() < self.deadline, "scenario deadline exceeded");
        self.history_bytes += text.len();
        assert!(self.history.len() < 2000 && self.history_bytes <= 2 * 1024 * 1024);
        self.history.push(text);
    }

    fn drain(&mut self, id: u64) {
        for _ in 0..64 {
            let output = self.nodes.get_mut(&id).unwrap().drain().unwrap();
            let state = self.state(id);
            for read in output.reads {
                assert!(state.position().index >= read.index);
                assert!(!self
                    .reads
                    .iter()
                    .any(|(node, ticket, _)| *node == id && *ticket == read.ticket));
                self.reads.push((id, read.ticket, read.index));
            }
            assert!(self.queue.len() + output.messages.len() <= 4096);
            self.queue.extend(output.messages);
            if !output.more_ready {
                return;
            }
        }
        panic!("driver drain work budget exceeded");
    }

    fn pump(&mut self) {
        for _ in 0..4096 {
            let Some(message) = self.queue.pop_front() else {
                return;
            };
            let (from, to) = (message.from, message.to);
            if self.paused.contains(&from) || self.paused.contains(&to) {
                continue;
            }
            let snapshot = (message.get_msg_type() == MessageType::MsgSnapshot)
                .then(|| message.get_snapshot().get_metadata().index);
            self.nodes.get_mut(&to).unwrap().step(message).unwrap();
            self.drain(to);
            if let Some(index) = snapshot {
                assert_eq!(self.nodes[&to].status().unwrap().snapshot_index, index);
                self.state(to);
                self.snapshots.push((from, to, index));
                self.nodes
                    .get_mut(&from)
                    .unwrap()
                    .report_snapshot(to, SnapshotStatus::Finish)
                    .unwrap();
                self.drain(from);
                self.event(format!(
                    "snapshot installed from={from} to={to} index={index}"
                ));
            }
        }
        panic!("message route work budget exceeded");
    }

    fn elect(&mut self) {
        self.nodes.get_mut(&1).unwrap().campaign().unwrap();
        self.drain(1);
        self.pump();
        assert_eq!(self.nodes[&1].status().unwrap().role, StateRole::Leader);
        self.read_state();
    }

    fn admission(&mut self) -> Admission {
        let epoch = self
            .state(1)
            .database(DATABASE.database_id)
            .map_or(1, |db| db.auth_epoch);
        let admission = Admission {
            principal_id: ADMIN_ID,
            credential_id: 200,
            admission_id: self.next_admission,
            auth_epoch: epoch,
        };
        self.next_admission += 1;
        admission
    }

    fn command(&mut self, kind: CommandKind) -> Command {
        Command {
            cell: CELL,
            database: DATABASE,
            admission: self.admission(),
            kind,
        }
    }

    fn submit(&mut self, command: Command) -> Outcome {
        let status = self.nodes[&1].status().unwrap();
        let expected = Position {
            term: status.term,
            index: status.last_index + 1,
        };
        let bytes = encode_command(&command, cell_limits()).unwrap();
        self.nodes
            .get_mut(&1)
            .unwrap()
            .propose(Vec::new(), bytes)
            .unwrap();
        self.drain(1);
        self.pump();
        let state = self.state(1);
        let applied = state.last_outcome().expect("command produced an outcome");
        assert_eq!(
            applied.position, expected,
            "never use a historical outcome as a fresh acceptance"
        );
        let persisted = self
            .nodes
            .values()
            .filter(|driver| {
                let status = driver.status().unwrap();
                status.applied >= expected.index && status.commit >= expected.index
            })
            .count();
        assert!(
            persisted >= 2,
            "business outcome requires a real durable quorum"
        );
        let outcome = applied.outcome.clone();
        self.event(format!(
            "applied term={} index={} durable_replicas={persisted} outcome={outcome:?}",
            expected.term, expected.index
        ));
        outcome
    }

    fn read_state(&mut self) -> CellState {
        let ticket = self.nodes.get_mut(&1).unwrap().read_index().unwrap();
        self.drain(1);
        self.pump();
        assert!(self
            .reads
            .iter()
            .any(|(id, completed, _)| *id == 1 && *completed == ticket));
        self.state(1)
    }

    fn pause_third(&mut self) {
        assert!(self.queue.is_empty());
        self.paused.insert(3);
        self.event("pause third replica before new physical transactions and fences".into());
    }

    fn checkpoint_install_and_reopen(&mut self) {
        let lagging = self.nodes[&3].status().unwrap().last_index;
        self.nodes.get_mut(&1).unwrap().checkpoint().unwrap();
        let checkpoint = self.nodes[&1].status().unwrap().snapshot_index;
        assert!(checkpoint > lagging);
        self.paused.clear();
        for _ in 0..5 {
            for id in [1, 2] {
                self.nodes.get_mut(&id).unwrap().tick().unwrap();
                self.drain(id);
            }
            self.pump();
        }
        assert!(self.snapshots.contains(&(1, 3, checkpoint)));
        let expected = self.state(1).encode();
        assert_eq!(self.state(3).encode(), expected);
        self.nodes.clear();
        assert!(self.queue.is_empty());
        for id in 1..=3 {
            self.open(id, false);
        }
        self.elect();
        self.event(
            "all three cell backends reopened from the same directories; no SQL replay".into(),
        );
    }
}

struct SqlChild {
    child: Child,
    input: Option<SyncSender<Input>>,
    output: Option<Receiver<Result<Wire, String>>>,
    threads: Vec<JoinHandle<()>>,
    reaped: bool,
}

impl SqlChild {
    fn spawn(path: &Path, initialize: bool) -> Self {
        let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_sqlite-cell-writer"));
        if initialize {
            command.arg("--initialize");
        }
        let mut child = command
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (input_tx, input_rx) = mpsc::sync_channel::<Input>(1);
        let (output_tx, output_rx) = mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            while let Ok((message, reply)) = input_rx.recv() {
                let result = write_frame(&mut stdin, &message).map_err(|error| error.to_string());
                let stop = result.is_err();
                let _ = reply.send(result);
                if stop {
                    break;
                }
            }
        });
        let reader = thread::spawn(move || loop {
            let result = read_frame(&mut stdout).map_err(|error| error.to_string());
            let stop = result.is_err();
            if output_tx.send(result).is_err() || stop {
                break;
            }
        });
        Self {
            child,
            input: Some(input_tx),
            output: Some(output_rx),
            threads: vec![writer, reader],
            reaped: false,
        }
    }

    fn send(&self, message: Wire, deadline: Instant) {
        let (tx, rx) = mpsc::sync_channel(1);
        self.input
            .as_ref()
            .unwrap()
            .try_send((message, tx))
            .unwrap();
        rx.recv_timeout(remaining(deadline)).unwrap().unwrap();
    }

    fn receive(&self, deadline: Instant) -> Wire {
        self.output
            .as_ref()
            .unwrap()
            .recv_timeout(remaining(deadline))
            .unwrap()
            .unwrap()
    }

    fn exchange(&self, message: Wire) -> Wire {
        let deadline = Instant::now() + TIMEOUT;
        self.send(message, deadline);
        self.receive(deadline)
    }

    fn no_completion(&self) {
        assert!(matches!(
            self.output.as_ref().unwrap().try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.reaped = true;
                return status;
            }
            assert!(Instant::now() < deadline, "writer exit deadline exceeded");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn kill(&mut self) {
        self.child.kill().unwrap();
        assert_eq!(self.wait().signal(), Some(9), "must observe actual SIGKILL");
    }

    fn reject(&mut self) {
        assert_eq!(
            self.exchange(Wire::Reject),
            Wire::Rejected(ffi::SQLITE_ABORT)
        );
        assert!(self.wait().success());
    }
}

impl Drop for SqlChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let deadline = Instant::now() + EXIT_TIMEOUT;
            while Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => {
                        self.reaped = true;
                        break;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        }
        self.input.take();
        self.output.take();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        for handle in self.threads.drain(..) {
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else if !thread::panicking() {
                panic!("fixture I/O cleanup deadline exceeded");
            }
        }
        if !thread::panicking() {
            assert!(self.reaped, "writer process not reaped");
        }
    }
}

struct Stage {
    worker: RefCell<SqlChild>,
    write: PreparedWrite,
    admission: Admission,
    result: Vec<u8>,
}

struct Fixture {
    reader: Option<rusqlite::Connection>,
    cell: RefCell<Cluster>,
    directory: TempDir,
    database: PathBuf,
    test: &'static str,
}

fn read_payload(connection: &rusqlite::Connection) -> Vec<u8> {
    connection
        .query_row("SELECT payload FROM items WHERE id=0", [], |row| row.get(0))
        .unwrap()
}

fn read_revision(connection: &rusqlite::Connection) -> u64 {
    connection
        .query_row("SELECT revision FROM cache_meta", [], |row| row.get(0))
        .unwrap()
}

fn open_reader(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn evidence_path(test: &str) -> PathBuf {
    let directory = std::env::var_os("SCAP_SQLITE_CELL_EVIDENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/evidence/sqlite-cell"));
    fs::create_dir_all(&directory).unwrap();
    directory.join(format!("{test}.log"))
}

impl Fixture {
    fn new(test: &'static str) -> Self {
        // A failed rerun must not leave a previous run's success as its evidence.
        fs::write(
            evidence_path(test),
            "SCAP SQLite/cell contract in progress; no verified result\n",
        )
        .unwrap();
        let directory = TempDir::new().unwrap();
        let database = directory.path().join("writer.sqlite");
        File::create(&database).unwrap().sync_all().unwrap();
        let cell = RefCell::new(Cluster::new(directory.path()));
        let mut fixture = Self {
            reader: None,
            cell,
            directory,
            database,
            test,
        };
        fixture.initialize_sqlite();
        fixture.reader = Some(open_reader(&fixture.database));
        assert_eq!(fixture.payload(), b"base");
        // Initialization itself is in the durable cell history. No external
        // prebuilt SQLite baseline is assumed by any subsequent recovery test.
        let restored = fixture.rebuild("initial-rebuilt.sqlite");
        assert_eq!(read_payload(&open_reader(&restored)), b"base");
        fixture
    }

    fn reader(&self) -> &rusqlite::Connection {
        self.reader.as_ref().unwrap()
    }
    fn payload(&self) -> Vec<u8> {
        read_payload(self.reader())
    }
    fn revision(&self) -> u64 {
        read_revision(self.reader())
    }

    fn initialize_sqlite(&mut self) {
        let mut worker = SqlChild::spawn(&self.database, true);
        let mut ready = false;
        let mut accepted = 0;
        for phase in 0..8_u128 {
            match worker.receive(Instant::now() + TIMEOUT) {
                Wire::Ready => {
                    assert!(!ready);
                    ready = true;
                    let revision = self
                        .cell
                        .borrow()
                        .state(1)
                        .database(DATABASE.database_id)
                        .unwrap()
                        .revision;
                    worker.send(Wire::Start(revision), Instant::now() + TIMEOUT);
                }
                Wire::Gate { changes, result } => {
                    assert!(result.is_empty());
                    let (write, admission) = self.write(changes, 10_000 + phase);
                    let command = Command {
                        cell: CELL,
                        database: DATABASE,
                        admission,
                        kind: CommandKind::Commit {
                            write,
                            request_fingerprint: payload_digest(INIT_SCHEMA.as_bytes()),
                            result,
                        },
                    };
                    assert!(matches!(
                        self.cell.borrow_mut().submit(command),
                        Outcome::Accepted(_)
                    ));
                    accepted += 1;
                    worker.send(Wire::Publish, Instant::now() + TIMEOUT);
                }
                Wire::Ack(result) => {
                    assert!(ready && accepted > 0 && result.is_empty());
                    assert!(worker.wait().success());
                    self.cell.borrow_mut().event(format!("initial DDL/base acknowledged after {accepted} real accepted physical batches"));
                    return;
                }
                other => panic!("unexpected initialization event {other:?}"),
            }
        }
        panic!("initialization gate budget exceeded");
    }

    fn write(&self, changes: Vec<u8>, request_id: u128) -> (PreparedWrite, Admission) {
        validate_physical(&changes);
        let mut cluster = self.cell.borrow_mut();
        let db = cluster.state(1).database(DATABASE.database_id).unwrap();
        let admission = cluster.admission();
        let ticket = CommitTicket {
            cell_id: CELL.cell_id,
            cell_incarnation: CELL.cell_incarnation,
            database_id: DATABASE.database_id,
            incarnation: DATABASE.incarnation,
            placement_generation: DATABASE.placement_generation,
            owner_epoch: db.owner.epoch,
            worker_instance_id: db.owner.worker_instance_id,
            auth_epoch: admission.auth_epoch,
            request_id,
            predecessor: db.revision,
            payload_digest: payload_digest(&changes),
        };
        (
            PreparedWrite {
                ticket,
                physical_changes: changes,
            },
            admission,
        )
    }

    fn stage(&self, request_id: u128) -> Stage {
        let worker = SqlChild::spawn(&self.database, false);
        assert_eq!(worker.receive(Instant::now() + TIMEOUT), Wire::Ready);
        let revision = self.revision();
        let Wire::Gate { changes, result } = worker.exchange(Wire::Start(revision)) else {
            panic!("writer did not reach its real gate");
        };
        assert_eq!(result.len(), 32);
        worker.no_completion();
        let (write, admission) = self.write(changes, request_id);
        assert_eq!(write.ticket.predecessor, revision);
        self.cell.borrow_mut().event(format!("SQL gate request={request_id} predecessor={revision} physical_bytes={} digest={:?}; provisional result buffered, no ACK", write.physical_changes.len(), write.ticket.payload_digest));
        Stage {
            worker: RefCell::new(worker),
            write,
            admission,
            result,
        }
    }

    fn command_for(stage: &Stage) -> Command {
        Command {
            cell: CELL,
            database: DATABASE,
            admission: stage.admission,
            kind: CommandKind::Commit {
                write: stage.write.clone(),
                request_fingerprint: payload_digest(SQL.as_bytes()),
                result: stage.result.clone(),
            },
        }
    }

    fn complete(&self, stage: &Stage) -> Result<CommitReceipt, CompletionError<&'static str>> {
        let publications = Cell::new(0);
        let prior = self.payload();
        let consensus = RealConsensus {
            fixture: self,
            stage,
            prior,
        };
        let visibility = RealVisibility {
            fixture: self,
            stage,
            publications: &publications,
        };
        let mut coordinator = CommitCoordinator::new(consensus, visibility);
        let result = coordinator.complete(&stage.write);
        assert_eq!(publications.get(), usize::from(result.is_ok()));
        result
    }

    fn lookup(&self, request_id: u128) -> Lookup {
        let mut cluster = self.cell.borrow_mut();
        let state = cluster.read_state();
        let admission = cluster.admission();
        let owner = state.database(DATABASE.database_id).unwrap().owner;
        state.authorize_read(DATABASE, admission, owner).unwrap();
        state
            .lookup(
                DATABASE,
                admission,
                request_id,
                payload_digest(SQL.as_bytes()),
            )
            .unwrap()
    }

    fn rebuild(&self, name: &str) -> PathBuf {
        let mut cluster = self.cell.borrow_mut();
        let state = cluster.read_state();
        let admission = cluster.admission();
        let transactions = state.recovery_transactions(DATABASE, admission).unwrap();
        assert!(!transactions.is_empty());
        let path = self.directory.path().join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
        let mut materialized = BTreeSet::new();
        for transaction in transactions {
            assert_eq!(
                payload_digest(&transaction.physical_changes),
                transaction.commit.receipt.ticket.payload_digest
            );
            let (size, pages) = validate_physical(&transaction.physical_changes);
            for (number, bytes) in pages {
                file.seek(SeekFrom::Start((u64::from(number) - 1) * PAGE_SIZE as u64))
                    .unwrap();
                file.write_all(bytes).unwrap();
                materialized.insert(number);
            }
            file.set_len(u64::from(size) * PAGE_SIZE as u64).unwrap();
            materialized.retain(|number| *number <= size);
            assert_eq!(
                materialized,
                (1..=size).collect(),
                "complete recovery may not depend on an external baseline or holes"
            );
        }
        file.sync_all().unwrap();
        drop(file);
        File::open(self.directory.path())
            .unwrap()
            .sync_all()
            .unwrap();
        let reader = open_reader(&path);
        let integrity: String = reader
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        assert_eq!(
            read_revision(&reader),
            state.database(DATABASE.database_id).unwrap().revision
        );
        cluster.event(format!("rebuilt {name} from empty file using {} accepted physical batches; integrity_check=ok revision={}", transactions.len(), read_revision(&reader)));
        path
    }

    fn finish(&self) {
        let mut cluster = self.cell.borrow_mut();
        cluster.event("verification passed".into());
        let header = concat!(
            "SCAP SQLite/cell contract evidence v1\n",
            "libSQL=d8bc862d20bedc72945a1da27c8b7045414c0261 SQLite=3.47.0 page_size=4096 spill=reject\n",
            "raft-rs=ad13f3d90780f53aea2488c6a4b76c0d334bf136 native=RocksDB10.4.2 strict_WAL=true\n",
            "cell=real-scap-cell drivers=3 disks=3 raft_processes=1 SQL_writer=separate-OS-process\n",
            "initialization=real-gated-DDL-and-base-through-cell recovery=empty-file-plus-retained-physical-transactions\n",
            "protocol=bounded-private-test-IPC not=SDK,Hrana,mTLS,TCP-faults,AZs,power-loss,RTO,production-engine-adapter\n",
        );
        fs::write(
            evidence_path(self.test),
            format!("{header}{}\n", cluster.history.join("\n")),
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!(
                "bounded SQLite/cell history:\n{}",
                self.cell.borrow().history.join("\n")
            );
        }
    }
}

fn validate_physical(changes: &[u8]) -> (u32, Vec<(u32, &[u8])>) {
    assert!((16..=MAX_PHYSICAL).contains(&changes.len()));
    assert_eq!(&changes[..8], b"SCAPPG01");
    let size = u32::from_le_bytes(changes[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(changes[12..16].try_into().unwrap()) as usize;
    assert!((1..=MAX_PAGES as u32).contains(&size) && (1..=MAX_PAGES).contains(&count));
    assert_eq!(changes.len(), 16 + count * (4 + PAGE_SIZE));
    let mut numbers = BTreeSet::new();
    let pages = changes[16..]
        .chunks_exact(4 + PAGE_SIZE)
        .map(|entry| {
            let number = u32::from_le_bytes(entry[..4].try_into().unwrap());
            assert!(number > 0 && number <= size && numbers.insert(number));
            (number, &entry[4..])
        })
        .collect();
    (size, pages)
}

struct RealConsensus<'a> {
    fixture: &'a Fixture,
    stage: &'a Stage,
    prior: Vec<u8>,
}

impl ConsensusPort for RealConsensus<'_> {
    fn propose(&mut self, write: &PreparedWrite) -> Decision {
        assert_eq!(write, &self.stage.write);
        let outcome = self
            .fixture
            .cell
            .borrow_mut()
            .submit(Fixture::command_for(self.stage));
        self.stage.worker.borrow().no_completion();
        assert_eq!(
            self.fixture.payload(),
            self.prior,
            "quorum acceptance must precede native visibility"
        );
        assert_eq!(self.fixture.revision(), write.ticket.predecessor);
        match outcome {
            Outcome::Accepted(commit) => Decision::Accepted(commit.receipt),
            Outcome::AlreadyCommitted(commit) => Decision::AlreadyCommitted(commit.receipt),
            Outcome::Rejected(reason) => Decision::Rejected(match reason {
                Reject::Fenced => Rejection::Fenced,
                Reject::Unauthorized => Rejection::Unauthorized,
                Reject::Conflict | Reject::Cancelled => Rejection::Conflict,
                _ => Rejection::InvalidTransaction,
            }),
            other => panic!("unexpected committed transaction outcome {other:?}"),
        }
    }
}

struct RealVisibility<'a> {
    fixture: &'a Fixture,
    stage: &'a Stage,
    publications: &'a Cell<usize>,
}

impl VisibilityPort for RealVisibility<'_> {
    type Error = &'static str;
    fn publish(
        &mut self,
        write: &PreparedWrite,
        receipt: &CommitReceipt,
    ) -> Result<(), Self::Error> {
        assert_eq!(write, &self.stage.write);
        assert_eq!(&receipt.ticket, &write.ticket);
        // The fixture's cache cursor is a SQLite row changed by the same native
        // transaction (via trigger), so this check observes actual durable data.
        if self.fixture.revision() != write.ticket.predecessor {
            return Err("SQLite predecessor changed");
        }
        self.publications.set(self.publications.get() + 1);
        let mut worker = self.stage.worker.borrow_mut();
        match worker.exchange(Wire::Publish) {
            Wire::Ack(result) if result == self.stage.result => {}
            _ => return Err("native publication failed"),
        }
        assert!(worker.wait().success());
        assert_eq!(self.fixture.payload(), self.stage.result);
        assert_eq!(self.fixture.revision(), receipt.sequence);
        self.fixture.cell.borrow_mut().event(format!(
            "native SQLite publish completed; ACK sequence={} result={:?}",
            receipt.sequence, self.stage.result
        ));
        Ok(())
    }
}

#[test]
fn returning_is_buffered_until_real_quorum_acceptance_and_native_publication() {
    let fixture =
        Fixture::new("returning_is_buffered_until_real_quorum_acceptance_and_native_publication");
    let stage = fixture.stage(101);
    assert_eq!(fixture.payload(), b"base");
    assert_eq!(fixture.lookup(101), Lookup::Unknown);
    let receipt = fixture.complete(&stage).unwrap();
    assert_eq!(receipt.sequence, stage.write.ticket.predecessor + 1);
    let Lookup::Committed { commit, result } = fixture.lookup(101) else {
        panic!("accepted request missing");
    };
    assert_eq!(commit.receipt, receipt);
    assert_eq!(result, stage.result);
    fixture.finish();
}

#[test]
fn newly_claimed_owner_fences_a_staged_old_writer_without_publishing() {
    let fixture = Fixture::new("newly_claimed_owner_fences_a_staged_old_writer_without_publishing");
    let stage = fixture.stage(201);
    let claim = fixture.cell.borrow_mut().command(CommandKind::ClaimOwner {
        operation_id: 20,
        expected_epoch: stage.write.ticket.owner_epoch,
        worker_instance_id: 9002,
    });
    assert!(matches!(
        fixture.cell.borrow_mut().submit(claim),
        Outcome::Administrative(AdminResult::OwnerClaimed(_))
    ));
    assert_eq!(
        fixture.complete(&stage),
        Err(CompletionError::Rejected(Rejection::Fenced))
    );
    assert_eq!(
        fixture
            .cell
            .borrow()
            .state(1)
            .last_outcome()
            .unwrap()
            .outcome,
        Outcome::Rejected(Reject::Fenced)
    );
    stage.worker.borrow_mut().reject();
    assert_eq!(fixture.payload(), b"base");
    assert_eq!(fixture.revision(), stage.write.ticket.predecessor);
    fixture.finish();
}

#[test]
fn auth_fence_rejects_old_admission_after_raft_commit_without_sql_visibility() {
    let fixture =
        Fixture::new("auth_fence_rejects_old_admission_after_raft_commit_without_sql_visibility");
    let stage = fixture.stage(301);
    let fence = fixture.cell.borrow_mut().command(CommandKind::AuthFence {
        operation_id: 30,
        expected_epoch: 1,
        policy: Cluster::policy(),
    });
    assert_eq!(
        fixture.cell.borrow_mut().submit(fence),
        Outcome::Administrative(AdminResult::AuthChanged(2))
    );
    assert_eq!(
        fixture.complete(&stage),
        Err(CompletionError::Rejected(Rejection::Unauthorized))
    );
    assert_eq!(
        fixture
            .cell
            .borrow()
            .state(1)
            .last_outcome()
            .unwrap()
            .outcome,
        Outcome::Rejected(Reject::Unauthorized)
    );
    stage.worker.borrow_mut().reject();
    assert_eq!(fixture.payload(), b"base");
    assert_eq!(fixture.revision(), stage.write.ticket.predecessor);
    fixture.finish();
}

#[test]
fn killed_sql_writer_recovers_random_result_from_cell_pages_without_sql_replay() {
    let fixture =
        Fixture::new("killed_sql_writer_recovers_random_result_from_cell_pages_without_sql_replay");
    let stage = fixture.stage(401);
    let Outcome::Accepted(commit) = fixture
        .cell
        .borrow_mut()
        .submit(Fixture::command_for(&stage))
    else {
        panic!("real cell did not accept");
    };
    assert_eq!(fixture.payload(), b"base");
    stage.worker.borrow().no_completion();
    stage.worker.borrow_mut().kill();
    fixture.cell.borrow_mut().event("SIGKILL SQL writer after durable quorum acceptance and before native publication; signal=9".into());
    assert_eq!(fixture.payload(), b"base");
    assert_eq!(fixture.revision(), stage.write.ticket.predecessor);
    let recovered = fixture.rebuild("after-kill.sqlite");
    let reader = open_reader(&recovered);
    assert_eq!(read_payload(&reader), stage.result);
    assert_eq!(read_revision(&reader), commit.receipt.sequence);
    let Lookup::Committed {
        commit: stored,
        result,
    } = fixture.lookup(401)
    else {
        panic!("committed result missing");
    };
    assert_eq!(stored, commit);
    assert_eq!(result, stage.result);
    fixture.finish();
}

#[test]
fn duplicate_business_request_discards_new_random_pages_and_returns_original_result() {
    let fixture = Fixture::new(
        "duplicate_business_request_discards_new_random_pages_and_returns_original_result",
    );
    let first = fixture.stage(501);
    let receipt = fixture.complete(&first).unwrap();
    let second = fixture.stage(501);
    assert_ne!(first.result, second.result);
    assert_ne!(
        first.write.ticket.payload_digest,
        second.write.ticket.payload_digest
    );
    assert_ne!(
        first.write.ticket.predecessor,
        second.write.ticket.predecessor
    );
    let Outcome::AlreadyCommitted(original) = fixture
        .cell
        .borrow_mut()
        .submit(Fixture::command_for(&second))
    else {
        panic!("duplicate was accepted as new work");
    };
    assert_eq!(original.receipt, receipt);
    assert_ne!(original.receipt.ticket, second.write.ticket);
    // CommitCoordinator accepts an immutable physical proposal's receipt. A
    // freshly rerun SQL request has another ticket: never forge a new receipt to
    // fit that contract or send its pages to the publication port.
    second.worker.borrow().no_completion();
    second.worker.borrow_mut().reject();
    assert_eq!(fixture.payload(), first.result);
    assert_eq!(fixture.revision(), receipt.sequence);
    let Lookup::Committed { result, .. } = fixture.lookup(501) else {
        panic!("original result missing");
    };
    assert_eq!(result, first.result);
    fixture.cell.borrow_mut().event("business dedup returned original receipt/result; newly staged random pages rolled back without publication".into());
    fixture.finish();
}

#[test]
fn cancellation_owner_auth_results_and_pages_survive_snapshot_install_and_reopen() {
    let fixture = Fixture::new(
        "cancellation_owner_auth_results_and_pages_survive_snapshot_install_and_reopen",
    );
    fixture.cell.borrow_mut().pause_third();
    let accepted = fixture.stage(601);
    fixture.complete(&accepted).unwrap();
    let fence = fixture.cell.borrow_mut().command(CommandKind::AuthFence {
        operation_id: 60,
        expected_epoch: 1,
        policy: Cluster::policy(),
    });
    fixture.cell.borrow_mut().submit(fence);
    let claim = fixture.cell.borrow_mut().command(CommandKind::ClaimOwner {
        operation_id: 61,
        expected_epoch: 1,
        worker_instance_id: 9002,
    });
    let Outcome::Administrative(AdminResult::OwnerClaimed(owner)) =
        fixture.cell.borrow_mut().submit(claim)
    else {
        panic!("owner claim failed");
    };
    assert_eq!(
        owner,
        OwnerToken {
            epoch: 2,
            worker_instance_id: 9002
        }
    );
    let db = fixture
        .cell
        .borrow()
        .state(1)
        .database(DATABASE.database_id)
        .unwrap();
    let activate = fixture
        .cell
        .borrow_mut()
        .command(CommandKind::ActivateOwner {
            operation_id: 62,
            token: owner,
            restored_revision: db.revision,
            restored_hash: db.commit_hash,
        });
    fixture.cell.borrow_mut().submit(activate);
    let cancel = fixture
        .cell
        .borrow_mut()
        .command(CommandKind::ResolveOrCancel {
            request_id: 602,
            request_fingerprint: payload_digest(SQL.as_bytes()),
        });
    assert_eq!(fixture.cell.borrow_mut().submit(cancel), Outcome::Cancelled);
    let cancelled = fixture.lookup(602);
    assert!(matches!(cancelled, Lookup::Cancelled { .. }));
    let late = fixture.stage(602);
    assert_eq!(
        fixture.complete(&late),
        Err(CompletionError::Rejected(Rejection::Conflict))
    );
    assert_eq!(
        fixture
            .cell
            .borrow()
            .state(1)
            .last_outcome()
            .unwrap()
            .outcome,
        Outcome::Rejected(Reject::Cancelled)
    );
    late.worker.borrow_mut().reject();
    let original = fixture.lookup(601);
    let before = fixture.cell.borrow().state(1);
    let current = fixture.cell.borrow_mut().admission();
    let retained = before
        .recovery_transactions(DATABASE, current)
        .unwrap()
        .to_vec();
    fixture.cell.borrow_mut().checkpoint_install_and_reopen();
    let mut cluster = fixture.cell.borrow_mut();
    let after = cluster.read_state();
    let current = cluster.admission();
    assert_eq!(
        after.database(DATABASE.database_id),
        before.database(DATABASE.database_id)
    );
    assert_eq!(
        after.recovery_transactions(DATABASE, current).unwrap(),
        retained
    );
    assert_eq!(
        after
            .lookup(DATABASE, current, 601, payload_digest(SQL.as_bytes()))
            .unwrap(),
        original
    );
    assert_eq!(
        after
            .lookup(DATABASE, current, 602, payload_digest(SQL.as_bytes()))
            .unwrap(),
        cancelled
    );
    assert_eq!(
        cluster
            .state(3)
            .recovery_transactions(DATABASE, current)
            .unwrap(),
        retained
    );
    drop(cluster);
    let rebuilt = fixture.rebuild("after-snapshot.sqlite");
    assert_eq!(read_payload(&open_reader(&rebuilt)), accepted.result);
    assert_eq!(fixture.payload(), accepted.result);
    fixture.finish();
}
