//! Independent contracts for the formal native adapter. Three actual Raft
//! drivers use separate RocksDB directories in this test process. Only the SQL
//! kill boundary launches another OS process; this is not a network/AZ test.
#[path = "../src/common.rs"]
mod common;
#[path = "../src/protocol.rs"]
mod protocol;

use common::{engine_identity, engine_limits, sql, writer_limits, KILL_REQUEST};
use libsql_sys::rusqlite::{self, OpenFlags};
use protocol::{read_frame, write_frame, Wire, TIMEOUT};
use raft::eraftpb::{ConfState, Message, MessageType};
use raft::{Config, SnapshotStatus, StateRole};
use scap_cell::{
    encode_command, payload_digest, AdminResult, Admission, CellApplication, CellIdentity,
    CellState, Command, CommandKind, DatabaseIdentity, Limits as CellLimits, Lookup, Outcome,
    OwnerToken, Position, Reject, ADMIN, READ, WRITE,
};
use scap_core::{CommitTicket, PreparedWrite, Rejection};
use scap_engine::{Image, RecoveryTarget};
use scap_raft_driver::{Driver, DriverConfig, ReadTicket};
use scap_raft_rocks::RocksBackend;
use scap_raft_store::{Identity, Limits as StoreLimits, Store};
use scap_sql::{Statement, Value};
use scap_sqlite::{CommitGate, Completed, Error, GateDecision, LookupDecision, SqliteWriter};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub const CELL: CellIdentity = CellIdentity {
    cell_id: 0x53434150,
    cell_incarnation: 7,
};
pub const DATABASE: DatabaseIdentity = DatabaseIdentity {
    database_id: 0x53514c495445,
    incarnation: 4,
    placement_generation: 1,
};
const ADMIN_ID: u128 = 100;
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);
type Node = Driver<RocksBackend, CellApplication>;

fn cell_limits() -> CellLimits {
    CellLimits {
        max_state_bytes: 2 * 1024 * 1024,
        max_command_bytes: 400 * 1024,
        max_databases: 4,
        max_policy_grants: 8,
        max_admin_operations: 64,
        max_requests_per_database: 32,
        max_transaction_bytes: 300 * 1024,
        max_result_bytes: 16 * 1024,
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

enum Hook {
    None,
    Observe { previous: Vec<u8> },
    OwnerFence,
    AuthFence,
    LoseQuorum,
}

struct RealGate {
    cell: Rc<RefCell<Cluster>>,
    proposals: Rc<Cell<usize>>,
    hook: Hook,
    path: PathBuf,
}

fn reject(reason: Reject) -> Rejection {
    match reason {
        Reject::Fenced => Rejection::Fenced,
        Reject::Unauthorized => Rejection::Unauthorized,
        Reject::Retired => Rejection::Retired,
        Reject::Conflict | Reject::Cancelled => Rejection::Conflict,
        _ => Rejection::InvalidTransaction,
    }
}

fn admission_for(cluster: &mut Cluster, ticket: &CommitTicket) -> Admission {
    let mut admission = cluster.admission();
    // The trusted fixture principal is fixed; preserve the caller's epoch so
    // the real ordered state machine can reject a revoked admission.
    admission.auth_epoch = ticket.auth_epoch;
    admission
}

fn lookup(cluster: &mut Cluster, ticket: &CommitTicket, fingerprint: [u8; 32]) -> LookupDecision {
    let Some(state) = cluster.try_read_state() else {
        return LookupDecision::Unknown;
    };
    let admission = admission_for(cluster, ticket);
    let owner = OwnerToken {
        epoch: ticket.owner_epoch,
        worker_instance_id: ticket.worker_instance_id,
    };
    if let Err(error) = state.authorize_read(DATABASE, admission, owner) {
        return LookupDecision::Rejected(reject(error));
    }
    match state.lookup(DATABASE, admission, ticket.request_id, fingerprint) {
        Ok(Lookup::Unknown) => LookupDecision::NotFound,
        Ok(Lookup::Committed { commit, result, .. }) => LookupDecision::AlreadyCommitted {
            receipt: commit.receipt,
            result,
        },
        Ok(Lookup::Cancelled { .. }) => LookupDecision::Rejected(Rejection::Conflict),
        Ok(Lookup::Retired { .. }) => LookupDecision::Rejected(Rejection::Retired),
        Err(error) => LookupDecision::Rejected(reject(error)),
    }
}

fn propose(
    cluster: &mut Cluster,
    write: &PreparedWrite,
    fingerprint: [u8; 32],
    result: &[u8],
) -> GateDecision {
    assert_eq!(
        payload_digest(&write.physical_changes),
        write.ticket.payload_digest
    );
    scap_sql::decode_result(result, writer_limits().sql).unwrap();
    let command = Command {
        control_revision: None,
        cell: CELL,
        database: DATABASE,
        admission: admission_for(cluster, &write.ticket),
        kind: CommandKind::Commit {
            write: write.clone(),
            request_fingerprint: fingerprint,
            result: result.to_vec(),
        },
    };
    match cluster.submit_maybe(command) {
        Some(Outcome::Accepted(commit)) => GateDecision::Accepted(commit.receipt),
        Some(Outcome::AlreadyCommitted(commit)) => {
            let state = cluster.read_state();
            let admission = admission_for(cluster, &write.ticket);
            let Lookup::Committed {
                commit: original,
                result,
                ..
            } = state
                .lookup(DATABASE, admission, write.ticket.request_id, fingerprint)
                .unwrap()
            else {
                panic!("historical result missing");
            };
            assert_eq!(commit, original);
            GateDecision::AlreadyCommitted {
                receipt: commit.receipt,
                result,
            }
        }
        Some(Outcome::Rejected(reason)) => GateDecision::Rejected(reject(reason)),
        None => GateDecision::Unknown,
        other => panic!("unexpected commit outcome: {other:?}"),
    }
}

impl CommitGate for RealGate {
    fn lookup(&mut self, ticket: &CommitTicket, fingerprint: [u8; 32]) -> LookupDecision {
        lookup(&mut self.cell.borrow_mut(), ticket, fingerprint)
    }

    fn propose(
        &mut self,
        write: &PreparedWrite,
        fingerprint: [u8; 32],
        result: &[u8],
    ) -> GateDecision {
        self.proposals.set(self.proposals.get() + 1);
        let mut cluster = self.cell.borrow_mut();
        match std::mem::replace(&mut self.hook, Hook::None) {
            Hook::None => {}
            Hook::Observe { previous } => {
                assert_eq!(
                    read_payload(&self.path),
                    previous,
                    "unaccepted RETURNING pages leaked"
                );
                let buffered = scap_sql::decode_result(result, writer_limits().sql).unwrap();
                assert_eq!(buffered.statements.last().unwrap().rows.len(), 1);
                cluster.event(
                    "WAL gate observed private result buffer and old external SQL snapshot".into(),
                );
            }
            Hook::OwnerFence => {
                let command = cluster.command(CommandKind::ClaimOwner {
                    operation_id: 40,
                    expected_epoch: 1,
                    worker_instance_id: 9002,
                });
                assert!(matches!(
                    cluster.submit(command),
                    Outcome::Administrative(AdminResult::OwnerClaimed(_))
                ));
            }
            Hook::AuthFence => {
                let command = cluster.command(CommandKind::AuthFence {
                    operation_id: 41,
                    expected_epoch: 1,
                    policy: Cluster::policy(),
                });
                assert_eq!(
                    cluster.submit(command),
                    Outcome::Administrative(AdminResult::AuthChanged(2))
                );
            }
            Hook::LoseQuorum => {
                cluster.paused.extend([2, 3]);
                cluster
                    .event("isolated leader after preflight and before physical proposal".into());
            }
        }
        propose(&mut cluster, write, fingerprint, result)
    }
}

struct Fixture {
    directory: TempDir,
    cell: Rc<RefCell<Cluster>>,
    proposals: Rc<Cell<usize>>,
    test: &'static str,
    next_writer: Cell<u32>,
}

impl Fixture {
    fn new(test: &'static str) -> Self {
        let directory = TempDir::new().unwrap();
        let cell = Rc::new(RefCell::new(Cluster::new(directory.path())));
        let fixture = Self {
            directory,
            cell,
            proposals: Rc::new(Cell::new(0)),
            test,
            next_writer: Cell::new(0),
        };
        fs::write(fixture.evidence_path(), "verification in progress\n").unwrap();
        fixture
    }

    fn evidence_path(&self) -> PathBuf {
        let root = std::env::var_os("SCAP_ENGINE_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/evidence/sqlite-engine")
            });
        fs::create_dir_all(&root).unwrap();
        root.join(format!("{}.log", self.test))
    }

    fn image(&self) -> Image {
        let mut cluster = self.cell.borrow_mut();
        let state = cluster.read_state();
        let admission = cluster.admission();
        let database = state.database(DATABASE.database_id).unwrap();
        Image::recover(
            &state,
            engine_identity(),
            admission,
            RecoveryTarget {
                position: state.position(),
                revision: database.revision,
                commit_hash: database.commit_hash,
            },
            engine_limits(),
        )
        .unwrap()
    }

    fn writer(&self, hook: Hook) -> (SqliteWriter<RealGate>, PathBuf) {
        let id = self.next_writer.get();
        self.next_writer.set(id + 1);
        let directory = self.directory.path().join(format!("writer-{id}"));
        let writer = SqliteWriter::create_new(
            &directory,
            self.image(),
            writer_limits(),
            RealGate {
                cell: self.cell.clone(),
                proposals: self.proposals.clone(),
                hook,
                path: directory.join("database.sqlite"),
            },
        )
        .unwrap();
        (writer, directory.join("database.sqlite"))
    }

    fn ticket(&self, image: &Image, request_id: u128) -> CommitTicket {
        let state = self.cell.borrow().state(1);
        let db = state.database(DATABASE.database_id).unwrap();
        CommitTicket {
            cell_id: CELL.cell_id,
            cell_incarnation: CELL.cell_incarnation,
            database_id: DATABASE.database_id,
            incarnation: DATABASE.incarnation,
            placement_generation: DATABASE.placement_generation,
            owner_epoch: db.owner.epoch,
            worker_instance_id: db.owner.worker_instance_id,
            auth_epoch: db.auth_epoch,
            request_id,
            predecessor: image.head().revision,
            payload_digest: [0; 32],
        }
    }

    fn run(
        &self,
        writer: &mut SqliteWriter<RealGate>,
        request: u128,
        statements: &[Statement],
    ) -> Result<Completed, Error> {
        let result = writer.execute(self.ticket(writer.image(), request), statements);
        let outcome = match &result {
            Ok(completed) => format!(
                "completed sequence={} replayed={}",
                completed.receipt.sequence, completed.replayed
            ),
            Err(error) => format!("error={error:?}"),
        };
        self.cell.borrow_mut().event(format!(
            "request={request} {outcome} local_revision={} stopped={}",
            writer.image().head().revision,
            writer.is_stopped()
        ));
        result
    }

    fn initialize(&self) -> (SqliteWriter<RealGate>, PathBuf) {
        let (mut writer, path) = self.writer(Hook::None);
        self.run(
            &mut writer,
            1,
            &[
                sql("CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"),
                sql("INSERT INTO items VALUES(1, X'62617365')"),
            ],
        )
        .unwrap();
        assert_eq!(read_payload(&path), b"base");
        (writer, path)
    }

    fn finish(&self) {
        let mut cluster = self.cell.borrow_mut();
        cluster.event("verification passed".into());
        let header = concat!(
            "SCAP formal SQLite adapter contract evidence v1\n",
            "production=scap-sqlite,scap-engine,scap-sql,scap-cell,scap-raft-driver,scap-raft-rocks\n",
            "libSQL=d8bc862d20bedc72945a1da27c8b7045414c0261 SQLite=3.47.0 page_size=4096\n",
            "raft_drivers=3 disk_backends=3 raft_OS_processes=1 peer_routing=bounded-in-process\n",
            "SQL_kill_case=separate-child-with-real-SIGKILL recovery=fresh-directory-plus-complete-authoritative-physical-history\n",
            "authorization=synthetic-trusted-principal-READ-WRITE-ADMIN not=mTLS,SDK,Hrana,AZ-failure,power-loss,RTO\n",
        );
        fs::write(
            self.evidence_path(),
            format!("{header}{}\n", cluster.history.join("\n")),
        )
        .unwrap();
    }
}

fn open_reader(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn read_payload(path: &Path) -> Vec<u8> {
    open_reader(path)
        .query_row("SELECT payload FROM items WHERE id=1", [], |row| row.get(0))
        .unwrap()
}

fn random_update() -> Vec<Statement> {
    vec![sql(
        "UPDATE items SET payload=randomblob(32) WHERE id=1 RETURNING payload",
    )]
}

#[test]
fn typed_sql_results_are_buffered_before_real_cell_acceptance() {
    let fixture = Fixture::new("typed_sql_results_are_buffered_before_real_cell_acceptance");
    let (writer, _) = fixture.initialize();
    drop(writer);
    let (mut writer, path) = fixture.writer(Hook::Observe {
        previous: b"base".to_vec(),
    });
    let statements = vec![
        Statement {
            sql: "SELECT ?1 AS i, ?2 AS r, ?3 AS t, ?4 AS b, ?5 AS n".into(),
            parameters: vec![
                Value::Integer(i64::MAX),
                Value::Real(2.5),
                Value::Text("中文".into()),
                Value::Blob(vec![0, 255]),
                Value::Null,
            ],
        },
        random_update().remove(0),
    ];
    let completed = fixture.run(&mut writer, 2, &statements).unwrap();
    assert_eq!(
        completed.result.statements[0].rows,
        vec![statements[0].parameters.clone()]
    );
    let Value::Blob(payload) = &completed.result.statements[1].rows[0][0] else {
        panic!("expected blob");
    };
    assert_eq!(payload.len(), 32);
    assert_eq!(read_payload(&path), *payload);
    assert_eq!(writer.image(), &fixture.image());
    assert_eq!(fixture.proposals.get(), 2);
    fixture.finish();
}

#[test]
fn ddl_retry_returns_original_receipt_without_reexecuting_sql() {
    let fixture = Fixture::new("ddl_retry_returns_original_receipt_without_reexecuting_sql");
    let (mut writer, _) = fixture.writer(Hook::None);
    let statements = [sql("CREATE TABLE unique_table(id INTEGER PRIMARY KEY)")];
    let original = fixture.run(&mut writer, 10, &statements).unwrap();
    let replay = fixture.run(&mut writer, 10, &statements).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, original.receipt);
    assert_eq!(replay.result, original.result);
    assert_eq!(fixture.proposals.get(), 1);
    assert!(writer.is_stopped());
    assert!(matches!(
        fixture.run(&mut writer, 11, &statements),
        Err(Error::Stopped)
    ));
    fixture.finish();
}

#[test]
fn read_only_and_zero_row_writes_require_durable_noop_records() {
    let fixture = Fixture::new("read_only_and_zero_row_writes_require_durable_noop_records");
    let (mut writer, _) = fixture.writer(Hook::None);
    let empty = writer.image().head().image_digest;
    let read = fixture
        .run(&mut writer, 20, &[sql("SELECT randomblob(32)")])
        .unwrap();
    assert_eq!(read.receipt.sequence, 1);
    assert_eq!(writer.image().head().image_digest, empty);
    assert!(writer.image().bytes().is_empty());
    fixture
        .run(
            &mut writer,
            21,
            &[sql(
                "CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)",
            )],
        )
        .unwrap();
    let before = writer.image().head().image_digest;
    let no_op = fixture
        .run(
            &mut writer,
            22,
            &[sql(
                "UPDATE items SET payload=randomblob(32) WHERE id=9 RETURNING payload",
            )],
        )
        .unwrap();
    assert_eq!(no_op.receipt.sequence, 3);
    assert_eq!(no_op.result.statements[0].affected_rows, 0);
    assert!(no_op.result.statements[0].rows.is_empty());
    assert_eq!(writer.image().head().image_digest, before);
    assert_eq!(fixture.proposals.get(), 3);
    assert_eq!(writer.image(), &fixture.image());
    fixture.finish();
}

#[test]
fn failed_batch_rolls_back_all_changes_before_any_proposal() {
    let fixture = Fixture::new("failed_batch_rolls_back_all_changes_before_any_proposal");
    let (mut writer, path) = fixture.initialize();
    let before = writer.image().clone();
    let result = fixture.run(
        &mut writer,
        30,
        &[
            sql("UPDATE items SET payload=X'6e6577' WHERE id=1 RETURNING payload"),
            sql("INSERT INTO items VALUES(1, X'647570')"),
        ],
    );
    assert!(matches!(result, Err(Error::Sqlite(_))));
    assert!(writer.is_stopped());
    assert_eq!(read_payload(&path), b"base");
    assert_eq!(fixture.proposals.get(), 1);
    assert_eq!(writer.image(), &before);
    assert_eq!(fixture.image(), before);
    fixture.finish();
}

#[test]
fn owner_fence_between_lookup_and_proposal_blocks_native_publish() {
    let fixture = Fixture::new("owner_fence_between_lookup_and_proposal_blocks_native_publish");
    let (initial, _) = fixture.initialize();
    drop(initial);
    let (mut writer, path) = fixture.writer(Hook::OwnerFence);
    assert!(matches!(
        fixture.run(&mut writer, 40, &random_update()),
        Err(Error::Rejected(Rejection::Fenced))
    ));
    assert!(writer.is_stopped());
    assert_eq!(read_payload(&path), b"base");
    assert_eq!(
        fixture
            .cell
            .borrow()
            .state(1)
            .database(DATABASE.database_id)
            .unwrap()
            .revision,
        1
    );
    fixture.finish();
}

#[test]
fn auth_fence_between_lookup_and_proposal_blocks_native_publish() {
    let fixture = Fixture::new("auth_fence_between_lookup_and_proposal_blocks_native_publish");
    let (initial, _) = fixture.initialize();
    drop(initial);
    let (mut writer, path) = fixture.writer(Hook::AuthFence);
    assert!(matches!(
        fixture.run(&mut writer, 50, &random_update()),
        Err(Error::Rejected(Rejection::Unauthorized))
    ));
    assert!(writer.is_stopped());
    assert_eq!(read_payload(&path), b"base");
    assert_eq!(
        fixture
            .cell
            .borrow()
            .state(1)
            .database(DATABASE.database_id)
            .unwrap()
            .revision,
        1
    );
    fixture.finish();
}

#[test]
fn partition_returns_unknown_and_later_commit_is_recovered_without_sql_replay() {
    let fixture =
        Fixture::new("partition_returns_unknown_and_later_commit_is_recovered_without_sql_replay");
    let (initial, _) = fixture.initialize();
    drop(initial);
    let (mut writer, path) = fixture.writer(Hook::LoseQuorum);
    let statements = random_update();
    assert!(matches!(
        fixture.run(&mut writer, 60, &statements),
        Err(Error::OutcomeUnknown)
    ));
    assert!(writer.is_stopped());
    assert_eq!(read_payload(&path), b"base");
    let expected_payload = {
        let mut cluster = fixture.cell.borrow_mut();
        assert_eq!(
            cluster
                .state(1)
                .database(DATABASE.database_id)
                .unwrap()
                .revision,
            1
        );
        assert!(
            cluster.try_read_state().is_none(),
            "isolated leader cannot complete a new Safe ReadIndex"
        );
        cluster.paused.clear();
        for _ in 0..5 {
            cluster.nodes.get_mut(&1).unwrap().tick().unwrap();
            cluster.drain(1);
            cluster.pump();
        }
        let state = cluster.read_state();
        let admission = cluster.admission();
        let Lookup::Committed { commit, result, .. } = state
            .lookup(
                DATABASE,
                admission,
                60,
                scap_sql::request_fingerprint(&statements, writer_limits().sql).unwrap(),
            )
            .unwrap()
        else {
            panic!("unknown proposal should have committed after healing");
        };
        assert_eq!(commit.receipt.sequence, 2);
        let result = scap_sql::decode_result(&result, writer_limits().sql).unwrap();
        cluster.event(format!(
            "healed unknown proposal; original result bytes={}",
            scap_sql::encode_result(&result, writer_limits().sql)
                .unwrap()
                .len()
        ));
        let Value::Blob(payload) = &result.statements[0].rows[0][0] else {
            panic!("retained result must be a blob");
        };
        payload.clone()
    };
    let (restored, recovered_path) = fixture.writer(Hook::None);
    assert_eq!(restored.image().head().revision, 2);
    assert_eq!(read_payload(&recovered_path), expected_payload);
    assert_eq!(
        fixture.proposals.get(),
        2,
        "no automatic SQL retry occurred"
    );
    fixture.finish();
}

#[test]
fn snapshot_reopen_preserves_results_cancellation_and_physical_recovery() {
    let fixture =
        Fixture::new("snapshot_reopen_preserves_results_cancellation_and_physical_recovery");
    let (mut writer, _) = fixture.initialize();
    fixture.cell.borrow_mut().pause_third();
    let original = fixture.run(&mut writer, 70, &random_update()).unwrap();
    let image = writer.image().clone();
    let cancelled_sql = [sql("SELECT 123")];
    let fingerprint = scap_sql::request_fingerprint(&cancelled_sql, writer_limits().sql).unwrap();
    {
        let mut cluster = fixture.cell.borrow_mut();
        let command = cluster.command(CommandKind::ResolveOrCancel {
            request_id: 71,
            request_fingerprint: fingerprint,
        });
        assert_eq!(cluster.submit(command), Outcome::Cancelled);
        let before = cluster.state(1);
        let admission = cluster.admission();
        let retained = before.recovery_source(DATABASE, admission).unwrap();
        cluster.checkpoint_install_and_reopen();
        let state = cluster.read_state();
        let admission = cluster.admission();
        assert_eq!(
            state.recovery_source(DATABASE, admission).unwrap(),
            retained
        );
        assert!(matches!(
            state.lookup(DATABASE, admission, 71, fingerprint).unwrap(),
            Lookup::Cancelled { .. }
        ));
    }
    drop(writer);
    assert_eq!(fixture.image(), image);
    let (mut restored, path) = fixture.writer(Hook::None);
    let Value::Blob(payload) = &original.result.statements[0].rows[0][0] else {
        panic!("blob expected");
    };
    assert_eq!(read_payload(&path), *payload);
    assert!(matches!(
        fixture.run(&mut restored, 71, &cancelled_sql),
        Err(Error::Rejected(Rejection::Conflict))
    ));
    assert_eq!(fixture.proposals.get(), 2);
    fixture.finish();
}

#[test]
fn recovery_preserves_connection_dependent_checks_and_enforces_future_writes() {
    let fixture =
        Fixture::new("recovery_preserves_connection_dependent_checks_and_enforces_future_writes");
    let (mut original, _) = fixture.writer(Hook::None);
    let accepted = fixture
        .run(
            &mut original,
            72,
            &[
                sql("CREATE TABLE seed(id INTEGER PRIMARY KEY)"),
                sql("INSERT INTO seed VALUES(7)"),
                sql("CREATE TABLE checked(x INTEGER CHECK(last_insert_rowid()=7))"),
                sql("INSERT INTO checked(rowid,x) VALUES(7,1)"),
            ],
        )
        .unwrap();
    assert_eq!(accepted.receipt.sequence, 1);
    assert_eq!(accepted.result.statements[3].last_insert_rowid, 7);
    let before = original.image().clone();
    assert_eq!(fixture.image(), before);
    drop(original);

    // This new native connection starts with last_insert_rowid() = 0. Physical
    // recovery must not reinterpret the already accepted CHECK expression.
    // A CHECK failure is not used as an oracle for physical corruption.
    let (mut restored, path) = fixture.writer(Hook::None);
    assert_eq!(restored.image(), &before);
    let read = fixture
        .run(
            &mut restored,
            73,
            &[sql("SELECT rowid,x,last_insert_rowid() FROM checked")],
        )
        .unwrap();
    assert_eq!(
        read.result.statements[0].rows,
        vec![vec![
            Value::Integer(7),
            Value::Integer(1),
            Value::Integer(0)
        ]]
    );
    assert_eq!(restored.image(), &fixture.image());
    assert_eq!(restored.image().bytes(), before.bytes());
    let authority = fixture.image();
    assert_eq!(authority.head().revision, 2);
    assert_eq!(fixture.proposals.get(), 2);

    let failed = fixture
        .run(
            &mut restored,
            74,
            &[sql("INSERT INTO checked(rowid,x) VALUES(8,2)")],
        )
        .unwrap_err();
    let Error::Sqlite(error) = failed else {
        panic!("future CHECK enforcement must report a SQLite constraint failure");
    };
    assert_eq!(
        error.sqlite_error().unwrap().extended_code,
        libsql_sys::ffi::SQLITE_CONSTRAINT_CHECK
    );
    assert!(restored.is_stopped());
    assert_eq!(restored.image(), &authority);
    assert_eq!(fixture.image(), authority);
    assert_eq!(
        fixture.proposals.get(),
        2,
        "invalid INSERT reached the cell"
    );
    let rows: u64 = open_reader(&path)
        .query_row("SELECT count(*) FROM checked", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "invalid INSERT became locally visible");
    fixture.cell.borrow_mut().event(
        "fresh connection preserved accepted CHECK-dependent row; original image bytes retained; future CHECK failure stopped before proposal and native publication".into(),
    );
    fixture.finish();
}

#[test]
fn unsafe_sql_limits_and_existing_worker_directories_fail_closed() {
    let fixture = Fixture::new("unsafe_sql_limits_and_existing_worker_directories_fail_closed");
    let (initial, _) = fixture.initialize();
    drop(initial);
    for (offset, statement) in [
        "ATTACH ':memory:' AS extra",
        "PRAGMA journal_mode=DELETE",
        "PRAGMA cache_spill=ON",
        "PRAGMA writable_schema=ON",
        "COMMIT",
        "ROLLBACK",
        "CREATE TEMP TABLE temporary(x)",
        "SELECT load_extension('missing')",
        "CREATE VIRTUAL TABLE v USING fts5(text)",
        "SELECT randomblob(13000)",
    ]
    .into_iter()
    .enumerate()
    {
        let (mut writer, path) = fixture.writer(Hook::None);
        assert!(
            fixture
                .run(&mut writer, 80 + offset as u128, &[sql(statement)])
                .is_err(),
            "unsafe statement succeeded: {statement}"
        );
        assert!(writer.is_stopped());
        assert_eq!(read_payload(&path), b"base");
    }
    assert_eq!(fixture.proposals.get(), 1);
    let directory = fixture.directory.path().join("inherited-cache");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("database.sqlite-wal"), b"stale").unwrap();
    let error = SqliteWriter::create_new(
        &directory,
        fixture.image(),
        writer_limits(),
        RealGate {
            cell: fixture.cell.clone(),
            proposals: fixture.proposals.clone(),
            hook: Hook::None,
            path: directory.join("database.sqlite"),
        },
    );
    assert!(matches!(error, Err(Error::Io(_))));
    assert!(!directory.join("database.sqlite").exists());
    fixture.finish();
}

struct SqlChild {
    child: Child,
    output: Option<Receiver<Result<Wire, String>>>,
    reader: Option<JoinHandle<()>>,
    reaped: bool,
}

impl SqlChild {
    fn spawn(directory: &Path) -> Self {
        let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_sqlite-engine-child"))
            .arg(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || loop {
            let frame = read_frame(&mut stdout).map_err(|error| error.to_string());
            let done = frame.is_err();
            if sender.send(frame).is_err() || done {
                break;
            }
        });
        Self {
            child,
            output: Some(output),
            reader: Some(reader),
            reaped: false,
        }
    }

    fn receive(&self) -> Wire {
        self.output
            .as_ref()
            .unwrap()
            .recv_timeout(TIMEOUT)
            .unwrap()
            .unwrap()
    }

    fn send(&mut self, frame: Wire) {
        write_frame(self.child.stdin.as_mut().unwrap(), &frame).unwrap();
    }

    fn kill(&mut self) {
        self.child.kill().unwrap();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.signal(), Some(9), "must exercise actual SIGKILL");
                self.reaped = true;
                break;
            }
            assert!(
                Instant::now() < deadline,
                "writer did not exit after SIGKILL"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for SqlChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.child.stdin.take();
        self.output.take();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

#[test]
fn sigkill_after_durable_acceptance_rebuilds_the_exact_original_result() {
    let fixture =
        Fixture::new("sigkill_after_durable_acceptance_rebuilds_the_exact_original_result");
    let directory = fixture.directory.path().join("killed-writer");
    let mut child = SqlChild::spawn(&directory);
    assert_eq!(child.receive(), Wire::Lookup);
    let empty = fixture.image();
    let ticket = fixture.ticket(&empty, KILL_REQUEST);
    let fingerprint =
        scap_sql::request_fingerprint(&common::kill_batch(), writer_limits().sql).unwrap();
    assert_eq!(
        lookup(&mut fixture.cell.borrow_mut(), &ticket, fingerprint),
        LookupDecision::NotFound
    );
    child.send(Wire::NotFound);
    let Wire::Proposal { changes, result } = child.receive() else {
        panic!("expected physical proposal");
    };
    let mut ticket = ticket;
    ticket.payload_digest = payload_digest(&changes);
    let write = PreparedWrite {
        ticket,
        physical_changes: changes,
    };
    let GateDecision::Accepted(receipt) =
        propose(&mut fixture.cell.borrow_mut(), &write, fingerprint, &result)
    else {
        panic!("real quorum did not accept");
    };
    assert_eq!(receipt.sequence, 1);
    child.send(Wire::Accept);
    assert_eq!(child.receive(), Wire::AcceptedHeld);
    let reader = open_reader(&directory.join("database.sqlite"));
    let tables: u64 = reader
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='items'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "accepted transaction must still be unpublished");
    drop(reader);
    assert!(
        child.output.as_ref().unwrap().try_recv().is_err(),
        "no SQL ACK before native publish"
    );
    child.kill();
    fixture.cell.borrow_mut().event("actual SQL child SIGKILL signal=9 after durable cell acceptance and before native publication; no ACK".into());
    let retained = scap_sql::decode_result(&result, writer_limits().sql).unwrap();
    let Value::Blob(payload) = &retained.statements[1].rows[0][0] else {
        panic!("blob expected");
    };
    assert_eq!(payload.len(), 32);
    let (mut restored, path) = fixture.writer(Hook::None);
    assert_eq!(
        read_payload(&path),
        *payload,
        "recovery must not regenerate randomblob"
    );
    let integrity: String = open_reader(&path)
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let replay = fixture
        .run(&mut restored, KILL_REQUEST, &common::kill_batch())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, receipt);
    assert_eq!(replay.result, retained);
    fixture.finish();
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
            request_epoch: 1,
        };
        self.next_admission += 1;
        admission
    }

    fn command(&mut self, kind: CommandKind) -> Command {
        Command {
            control_revision: None,
            cell: CELL,
            database: DATABASE,
            admission: self.admission(),
            kind,
        }
    }

    fn submit_maybe(&mut self, command: Command) -> Option<Outcome> {
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
        if state.position().index < expected.index {
            self.event(format!(
                "proposal outcome unknown at index={} without quorum",
                expected.index
            ));
            return None;
        }
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
        Some(outcome)
    }

    fn submit(&mut self, command: Command) -> Outcome {
        self.submit_maybe(command)
            .expect("command requires durable quorum")
    }

    fn try_read_state(&mut self) -> Option<CellState> {
        let ticket = self.nodes.get_mut(&1).unwrap().read_index().unwrap();
        self.drain(1);
        self.pump();
        if self
            .reads
            .iter()
            .any(|(id, completed, _)| *id == 1 && *completed == ticket)
        {
            Some(self.state(1))
        } else {
            self.nodes.get_mut(&1).unwrap().cancel_read(ticket).unwrap();
            None
        }
    }

    fn read_state(&mut self) -> CellState {
        self.try_read_state()
            .expect("fresh Safe ReadIndex must complete")
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
