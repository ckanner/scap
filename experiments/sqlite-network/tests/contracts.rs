//! Independent real-process evidence. No profile from this executable enters
//! first-party unit coverage, and fixture deadlines are not production RTOs.
#[path = "../src/certs.rs"]
mod certs;
#[path = "../src/child.rs"]
mod child;
#[path = "../src/common.rs"]
mod common;
#[path = "../src/harness.rs"]
mod harness;
#[path = "../src/protocol.rs"]
mod protocol;
#[path = "../src/proxy.rs"]
mod proxy;
#[path = "../src/sql_thread.rs"]
mod sql_thread;

use std::collections::BTreeMap;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use libsql_sys::rusqlite::{Connection, OpenFlags};
use scap_cell::{CellState, Lookup, Position};
use scap_raft_rocks::RocksBackend;
use scap_raft_store::Store;
use scap_sql::{Statement, TransactionResult, Value};

use harness::Cluster;
use protocol::{hex, unhex, Reply};
use proxy::Mode;

#[derive(Debug, PartialEq)]
struct Completed {
    revision: u64,
    replayed: bool,
    encoded: Vec<u8>,
    result: TransactionResult,
    owner_epoch: u64,
    worker: u128,
    payload_digest: Vec<u8>,
}

fn completed(reply: Reply) -> Completed {
    assert_eq!(reply.kind, "sql", "{reply:?} error={:?}", reply.error());
    assert_eq!(reply.fields.len(), 6);
    let encoded = unhex(&reply.fields[2]);
    Completed {
        revision: reply.fields[0].parse().unwrap(),
        replayed: reply.fields[1].parse().unwrap(),
        result: scap_sql::decode_result(&encoded, common::writer_limits().sql).unwrap(),
        encoded,
        owner_epoch: reply.fields[3].parse().unwrap(),
        worker: reply.fields[4].parse().unwrap(),
        payload_digest: unhex(&reply.fields[5]),
    }
}

fn rejected(reply: Reply, expected: &str) {
    let error = reply
        .error()
        .unwrap_or_else(|| panic!("expected rejection: {reply:?}"));
    assert!(error.contains(expected), "expected {expected}, got {error}");
}

fn queried(reply: Reply) -> (u64, Position, Vec<u8>, TransactionResult) {
    assert_eq!(reply.kind, "query", "{reply:?} error={:?}", reply.error());
    assert_eq!(reply.fields.len(), 5);
    (
        reply.fields[0].parse().unwrap(),
        Position {
            term: reply.fields[1].parse().unwrap(),
            index: reply.fields[2].parse().unwrap(),
        },
        unhex(&reply.fields[3]),
        scap_sql::decode_result(&unhex(&reply.fields[4]), common::writer_limits().sql).unwrap(),
    )
}

#[test]
fn strong_sql_reads_use_fresh_quorum_authority_without_write_permission_or_history_growth() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, old, path, original) = initialized(
        "strong_sql_reads_use_fresh_quorum_authority_without_write_permission_or_history_growth",
    );
    assert!(cluster
        .apply(old, "reader", "5000 1 9101")
        .contains("AuthChanged(2)"));
    let before = cluster.try_read(old, 2000).unwrap();
    let database = before.database(common::DATABASE.database_id).unwrap();
    let select = [common::sql("SELECT payload FROM items WHERE id=1")];
    let first = queried(cluster.query(old, 80, 2, &select));
    assert_eq!(first.0, 1);
    assert!(first.1.index >= before.position().index);
    assert_eq!(first.2, database.commit_hash);
    assert_eq!(payload(&first.3), payload(&original.result));
    assert_eq!(first.3.statements[0].affected_rows, 0);
    let again = queried(cluster.query(old, 81, 2, &select));
    assert_eq!(again.3, first.3);
    assert_eq!(
        cluster
            .try_read(old, 2000)
            .unwrap()
            .database(common::DATABASE.database_id)
            .unwrap(),
        database
    );
    assert_eq!(read_payload(&path), payload(&original.result));

    // A read already holding a fresh barrier can finish at that snapshot. The
    // subsequent read must get new authority and reject the old owner token.
    cluster.begin_query(old, 82, 2, "read", &select);
    assert!(cluster.wait_hook(old, 82).contains("SafeReadIndex"));
    assert!(cluster
        .apply(old, "claim", "5000 2 9102 1 8001")
        .contains("OwnerClaimed"));
    cluster.resume(old, 82);
    let previous_snapshot = queried(cluster.nodes.get_mut(&old).unwrap().receive());
    assert_eq!(previous_snapshot.3, first.3);
    rejected(cluster.query(old, 83, 2, &select), "Fenced");
    cluster.recover(old, 1010, 2, 2);
    assert_eq!(queried(cluster.query(old, 84, 2, &select)).3, first.3);

    cluster.partition(old, Mode::Blackhole);
    rejected(cluster.query(old, 85, 2, &select), "Unknown");
    let others = (1..=3).filter(|id| *id != old).collect::<Vec<_>>();
    let leader = cluster.leader(&others);
    let state = cluster.try_read(leader, 2000).unwrap();
    assert_eq!(
        state
            .database(common::DATABASE.database_id)
            .unwrap()
            .revision,
        1
    );
    assert_eq!(
        state
            .database(common::DATABASE.database_id)
            .unwrap()
            .commit_hash,
        database.commit_hash
    );
    cluster.recover(leader, 1011, 3, 2);
    let recovered = queried(cluster.query(leader, 86, 2, &select));
    assert_eq!(recovered.3, first.3);
    assert_eq!(recovered.0, 1);
    cluster.partition(old, Mode::Open);
    let final_state = cluster.try_read(leader, 2000).unwrap();
    caught_up(&mut cluster, old, final_state.position().index);
    assert_eq!(
        final_state
            .database(common::DATABASE.database_id)
            .unwrap()
            .revision,
        1
    );
    assert_eq!(read_payload(&path), payload(&original.result));
    cluster.record("READ-only principal used fresh SafeReadIndex and exact physical-head binding for native queries; repeated reads created no accepted transaction/revision; a bounded already-authorized snapshot finished while subsequent old-owner read was fenced; real TCP quorum loss rejected new read, surviving majority recovered original bytes and served a new strong read");
    cluster.finish();
}

fn seed() -> Vec<Statement> {
    vec![
        common::sql("CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"),
        common::sql("INSERT INTO items VALUES(1, randomblob(32)) RETURNING payload"),
    ]
}

fn update() -> Vec<Statement> {
    vec![common::sql(
        "UPDATE items SET payload=randomblob(32) WHERE id=1 RETURNING payload",
    )]
}

fn payload(result: &TransactionResult) -> Vec<u8> {
    match &result.statements.last().unwrap().rows[0][0] {
        Value::Blob(value) => value.clone(),
        value => panic!("expected original randomblob result, got {value:?}"),
    }
}

fn read_payload(path: &Path) -> Vec<u8> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
        .query_row("SELECT payload FROM items WHERE id=1", [], |row| row.get(0))
        .unwrap()
}

fn lookup(state: &CellState, request: u128, statements: &[Statement], auth: u64) -> Lookup {
    let mut admission = common::admission();
    admission.auth_epoch = auth;
    state
        .lookup(
            common::DATABASE,
            admission,
            request,
            scap_sql::request_fingerprint(statements, common::writer_limits().sql).unwrap(),
        )
        .unwrap()
}

fn initialized(test: &'static str) -> (Cluster, u64, std::path::PathBuf, Completed) {
    let mut cluster = Cluster::new(test, BTreeMap::new());
    cluster.start_all();
    let leader = cluster.leader(&[1, 2, 3]);
    cluster.initialize(leader);
    let path = cluster.recover(leader, 1001, 0, 1);
    let original = completed(cluster.sql(leader, 10, 1, &seed()));
    assert_eq!(original.revision, 1);
    assert!(!original.replayed);
    assert_eq!(read_payload(&path), payload(&original.result));
    (cluster, leader, path, original)
}

fn caught_up(cluster: &mut Cluster, id: u64, target: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while cluster.status(id).applied < target {
        assert!(Instant::now() < deadline, "replica failed to catch up");
        thread::sleep(Duration::from_millis(10));
    }
}

fn resolve(cluster: &mut Cluster, leader: u64, request: u128, statements: &[Statement]) -> String {
    let fingerprint =
        scap_sql::request_fingerprint(statements, common::writer_limits().sql).unwrap();
    cluster.apply(
        leader,
        "resolve",
        &format!("5000 1 {request} {}", hex(&fingerprint)),
    )
}

#[test]
fn real_sql_returning_and_duplicate_ddl_keep_exact_original_results() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, leader, path, original) =
        initialized("real_sql_returning_and_duplicate_ddl_keep_exact_original_results");
    let state = cluster.try_read(leader, 2000).unwrap();
    let Lookup::Committed { commit, result } = lookup(&state, 10, &seed(), 1) else {
        panic!("SQL success did not have a durable cell record")
    };
    assert_eq!(commit.receipt.sequence, original.revision);
    assert_eq!(result, original.encoded);
    let duplicate = completed(cluster.sql(leader, 10, 1, &seed()));
    assert!(duplicate.replayed);
    assert_eq!(duplicate.revision, original.revision);
    assert_eq!(duplicate.encoded, original.encoded);
    assert_eq!(duplicate.owner_epoch, original.owner_epoch);
    assert_eq!(duplicate.worker, original.worker);
    assert_eq!(duplicate.payload_digest, original.payload_digest);
    assert_eq!(read_payload(&path), payload(&original.result));
    rejected(cluster.sql(leader, 11, 1, &update()), "Stopped");
    let current = cluster.try_read(leader, 2000).unwrap();
    assert_eq!(
        current
            .database(common::DATABASE.database_id)
            .unwrap()
            .revision,
        1
    );
    cluster.record("real DDL/unique INSERT/randomblob RETURNING accepted through correlated mTLS quorum; duplicate returned original complete result and receipt without executing DDL again; historical replay retired cache");
    cluster.finish();
}

#[test]
fn owner_fence_after_preflight_rejects_and_never_publishes() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, leader, path, original) =
        initialized("owner_fence_after_preflight_rejects_and_never_publishes");
    cluster.begin_sql(leader, 20, 1, "read", &update());
    assert!(cluster.wait_hook(leader, 20).contains("SafeReadIndex"));
    assert!(cluster
        .apply(leader, "claim", "5000 1 9001 1 8001")
        .contains("OwnerClaimed"));
    cluster.resume(leader, 20);
    rejected(cluster.nodes.get_mut(&leader).unwrap().receive(), "Fenced");
    assert_eq!(read_payload(&path), payload(&original.result));
    let state = cluster.try_read(leader, 2000).unwrap();
    let database = state.database(common::DATABASE.database_id).unwrap();
    assert_eq!(database.revision, 1);
    assert_eq!(database.owner.epoch, 2);
    assert!(!database.active);
    assert_eq!(lookup(&state, 20, &update(), 1), Lookup::Unknown);
    cluster.record("ordered owner claim overtook a prior SafeReadIndex preflight; the old SQLite attempt was fenced with unchanged native payload and cell revision");
    cluster.finish();
}

#[test]
fn auth_fence_after_preflight_rejects_and_never_publishes() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, leader, path, original) =
        initialized("auth_fence_after_preflight_rejects_and_never_publishes");
    cluster.begin_sql(leader, 30, 1, "read", &update());
    cluster.wait_hook(leader, 30);
    assert!(cluster
        .apply(leader, "auth", "5000 1 9002")
        .contains("AuthChanged(2)"));
    cluster.resume(leader, 30);
    rejected(
        cluster.nodes.get_mut(&leader).unwrap().receive(),
        "Unauthorized",
    );
    assert_eq!(read_payload(&path), payload(&original.result));
    let state = cluster.try_read(leader, 2000).unwrap();
    let database = state.database(common::DATABASE.database_id).unwrap();
    assert_eq!(database.revision, 1);
    assert_eq!(database.auth_epoch, 2);
    assert_eq!(lookup(&state, 30, &update(), 2), Lookup::Unknown);
    cluster.record("ordered authorization epoch changed after SQL preflight; stale invocation was rejected at the native gate without publishing or creating a request record");
    cluster.finish();
}

#[test]
fn quorum_loss_is_unknown_then_ordered_cancel_fences_the_late_attempt() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, old, path, original) =
        initialized("quorum_loss_is_unknown_then_ordered_cancel_fences_the_late_attempt");
    let original_term = cluster.status(old).term;
    cluster.begin_sql(old, 40, 1, "proposal", &update());
    cluster.wait_hook(old, 40);
    cluster.partition(old, Mode::Blackhole);
    cluster.resume(old, 40);
    rejected(cluster.nodes.get_mut(&old).unwrap().receive(), "Unknown");
    assert_eq!(read_payload(&path), payload(&original.result));
    let others = (1..=3).filter(|id| *id != old).collect::<Vec<_>>();
    let leader = cluster.leader(&others);
    assert!(cluster.status(leader).term > original_term);
    let before = cluster.try_read(leader, 2000).unwrap();
    assert_eq!(lookup(&before, 40, &update(), 1), Lookup::Unknown);
    assert!(resolve(&mut cluster, leader, 40, &update()).contains("Cancelled"));
    cluster.partition(old, Mode::Open);
    let state = cluster.try_read(leader, 2000).unwrap();
    caught_up(&mut cluster, old, state.position().index);
    assert!(matches!(
        lookup(&state, 40, &update(), 1),
        Lookup::Cancelled { .. }
    ));
    let new_path = cluster.recover(leader, 1002, 1, 1);
    assert_eq!(read_payload(&new_path), payload(&original.result));
    rejected(cluster.sql(leader, 40, 1, &update()), "Conflict");
    assert_eq!(read_payload(&new_path), payload(&original.result));
    assert_eq!(
        cluster
            .try_read(leader, 2000)
            .unwrap()
            .database(common::DATABASE.database_id)
            .unwrap()
            .revision,
        1
    );
    cluster.record("real TCP minority lost quorum; attempted write returned UNKNOWN and native pages stayed old; majority's ordered ResolveOrCancel recorded cancellation before healing; subsequent same-ID attempt could not execute or publish");
    cluster.finish();
}

#[test]
fn accepted_reply_after_deadline_stays_unknown_and_resolves_without_sql_replay() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, leader, path, original) =
        initialized("accepted_reply_after_deadline_stays_unknown_and_resolves_without_sql_replay");
    cluster.begin_sql(leader, 50, 1, "accepted", &update());
    assert!(cluster.wait_hook(leader, 50).contains("Accepted"));
    assert_eq!(read_payload(&path), payload(&original.result));
    // Hold the actual durable reply beyond the invocation's original 2500 ms
    // budget; no clock substitution or manufactured cell decision is used.
    thread::sleep(Duration::from_millis(2600));
    cluster.resume(leader, 50);
    rejected(cluster.nodes.get_mut(&leader).unwrap().receive(), "Unknown");
    assert_eq!(read_payload(&path), payload(&original.result));
    assert!(resolve(&mut cluster, leader, 50, &update()).contains("AlreadyCommitted"));
    let state = cluster.try_read(leader, 2000).unwrap();
    let Lookup::Committed { commit, result } = lookup(&state, 50, &update(), 1) else {
        panic!("accepted request disappeared")
    };
    assert_eq!(commit.receipt.sequence, 2);
    let durable = scap_sql::decode_result(&result, common::writer_limits().sql).unwrap();
    let new_path = cluster.recover(leader, 1003, 1, 1);
    assert_eq!(read_payload(&new_path), payload(&durable));
    let replay = completed(cluster.sql(leader, 50, 1, &update()));
    assert!(replay.replayed);
    assert_eq!(replay.encoded, result);
    cluster.record("a real Accepted result arriving after the original deadline remained UNKNOWN and unpublished locally; ordered resolution retained the original outcome; new-directory recovery and explicit lookup returned the exact random result");
    cluster.finish();
}

#[test]
fn sigkill_after_accepted_before_native_publish_recovers_on_another_process() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, old, path, original) =
        initialized("sigkill_after_accepted_before_native_publish_recovers_on_another_process");
    cluster.begin_sql(old, 60, 1, "accepted", &update());
    assert!(cluster.wait_hook(old, 60).contains("Accepted"));
    assert_eq!(read_payload(&path), payload(&original.result));
    cluster.nodes[&old].assert_no_reply();
    cluster.kill(old);
    let others = (1..=3).filter(|id| *id != old).collect::<Vec<_>>();
    let leader = cluster.leader(&others);
    let state = cluster.try_read(leader, 2000).unwrap();
    let Lookup::Committed { commit, result } = lookup(&state, 60, &update(), 1) else {
        panic!("quorum-accepted write lost after SIGKILL")
    };
    assert_eq!(commit.receipt.sequence, 2);
    let durable = scap_sql::decode_result(&result, common::writer_limits().sql).unwrap();
    let new_path = cluster.recover(leader, 1004, 1, 1);
    assert_ne!(new_path, path);
    assert_eq!(read_payload(&new_path), payload(&durable));
    let replay = completed(cluster.sql(leader, 60, 1, &update()));
    assert!(replay.replayed);
    assert_eq!(replay.encoded, result);
    assert_eq!(replay.owner_epoch, 1);
    assert_eq!(replay.worker, 1001);
    cluster.restart(old);
    let state = cluster.try_read(leader, 2000).unwrap();
    caught_up(&mut cluster, old, state.position().index);
    cluster.record("SIGKILL signal=9 killed writer and its voter after durable Accepted but before native publish or SQL ACK; surviving voters elected a new leader; formal claim/recover/activate in a new directory reconstructed exact physical pages and original result, with no SQL replay");
    cluster.finish();
}

#[test]
fn physical_history_and_cancellation_survive_network_snapshot_and_full_restart() {
    if child::maybe_run() {
        return;
    }
    let (mut cluster, leader, _path, original) =
        initialized("physical_history_and_cancellation_survive_network_snapshot_and_full_restart");
    let lagging = (1..=3).find(|id| *id != leader).unwrap();
    let previous = cluster.status(lagging);
    cluster.kill(lagging);
    let mut last = original;
    for request in 70..=75 {
        last = completed(cluster.sql(leader, request, 1, &update()));
    }
    assert!(resolve(&mut cluster, leader, 79, &update()).contains("Cancelled"));
    let reply = cluster
        .nodes
        .get_mut(&leader)
        .unwrap()
        .command("checkpoint", "5000");
    assert_eq!(reply.kind, "checkpoint", "{reply:?}");
    let checkpoint = cluster.status(leader);
    assert!(checkpoint.snapshot > previous.last);
    cluster.restart(lagging);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = cluster.status(lagging);
        if status.snapshot >= checkpoint.snapshot && status.applied >= checkpoint.applied {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "physical snapshot was not installed"
        );
        thread::sleep(Duration::from_millis(10));
    }
    cluster.kill(lagging);
    let store = Store::open_existing(
        RocksBackend::open_existing(&cluster.directory.path().join(format!("node{lagging}")))
            .unwrap(),
        common::identity(lagging),
        common::store_limits(),
    )
    .unwrap();
    let view = store.view().unwrap();
    let snapshot = &view.snapshot;
    assert!(snapshot.get_metadata().index >= checkpoint.snapshot);
    let installed = CellState::decode_bound(
        snapshot.get_data(),
        common::cell(),
        Position {
            term: snapshot.get_metadata().term,
            index: snapshot.get_metadata().index,
        },
        common::cell_limits(),
    )
    .unwrap();
    assert!(matches!(
        lookup(&installed, 79, &update(), 1),
        Lookup::Cancelled { .. }
    ));
    let Lookup::Committed { result, .. } = lookup(&installed, 75, &update(), 1) else {
        panic!("snapshot omitted the final physical transaction")
    };
    assert_eq!(result, last.encoded);
    drop(store);
    cluster.restart(lagging);
    for id in 1..=3 {
        caught_up(&mut cluster, id, checkpoint.applied)
    }
    for id in 1..=3 {
        cluster.kill(id)
    }
    for id in 1..=3 {
        cluster.restart(id)
    }
    let leader = cluster.leader(&[1, 2, 3]);
    let state = cluster.try_read(leader, 2000).unwrap();
    assert!(matches!(
        lookup(&state, 79, &update(), 1),
        Lookup::Cancelled { .. }
    ));
    let new_path = cluster.recover(leader, 1005, 1, 1);
    assert_eq!(read_payload(&new_path), payload(&last.result));
    let duplicate = completed(cluster.sql(leader, 75, 1, &update()));
    assert!(duplicate.replayed);
    assert_eq!(duplicate.encoded, last.encoded);
    cluster.record("actual mTLS MsgSnapshot installed complete accepted physical history plus cancellation on a lagging replica; receiver snapshot was inspected after SIGKILL; all three voters then reopened original RocksDB paths; fresh owner recovered exact native SQLite state in a new directory");
    cluster.finish();
}
