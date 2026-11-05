//! Fault evidence for production control ordering. This executable and every
//! profile it could emit are excluded from first-party unit coverage.
#[path = "../src/archive_port.rs"]
mod archive_port;
#[path = "../../sqlite-network/src/certs.rs"]
mod certs;
#[path = "../src/child.rs"]
mod child;
#[path = "../src/common.rs"]
mod common;
#[path = "../src/harness.rs"]
mod harness;
#[path = "../../sqlite-network/src/protocol.rs"]
mod protocol;
// The shared transparent TCP proxy also exposes partition modes used by
// other fault suites; this contract injects process and result-boundary faults.
#[allow(dead_code)]
#[path = "../../sqlite-network/src/proxy.rs"]
mod proxy;
#[path = "../src/sql_thread.rs"]
mod sql_thread;

use harness::Cluster;
use protocol::{hex, unhex, Reply};
use scap_cell::{
    AdminResult, AppliedOutcome, CellState, Command, CommandKind, ControlResult, DatabaseView,
    Grant, Lookup, Outcome, Position, Reject, ADMIN, READ, WRITE,
};
use scap_raft_driver::Application;
use scap_raft_rocks::RocksBackend;
use scap_raft_store::Store;
use scap_sql::{Statement, TransactionResult, Value};
use serde_json::{json, Value as Json};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

const MANY: u64 = 4097;
fn evidence() -> PathBuf {
    PathBuf::from(
        std::env::var_os("SCAP_CONTROL_EVIDENCE_DIR")
            .expect("explicit private /tmp evidence directory"),
    )
}
fn write_json(name: &str, value: Json) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence().join(name))
        .unwrap();
    writeln!(file, "{}", serde_json::to_string_pretty(&value).unwrap()).unwrap();
    file.sync_all().unwrap();
}
fn event(file: &mut File, name: &str, fields: Json) {
    writeln!(file, "{}", json!({"event":name,"observed":fields})).unwrap();
    file.flush().unwrap();
}
fn command(auth: u64, revision: Option<u64>, kind: CommandKind) -> Command {
    let mut admission = common::admission();
    admission.auth_epoch = auth;
    Command {
        cell: common::cell(),
        database: common::DATABASE,
        admission,
        control_revision: revision,
        kind,
    }
}
fn raw(cluster: &mut Cluster, node: u64, command: &Command) -> AppliedOutcome {
    let bytes = scap_cell::encode_command(command, common::cell_limits()).unwrap();
    raw_bytes(cluster, node, &bytes)
}
fn raw_bytes(cluster: &mut Cluster, node: u64, bytes: &[u8]) -> AppliedOutcome {
    let reply = cluster
        .nodes
        .get_mut(&node)
        .unwrap()
        .command("raw_control", &format!("5000 {}", hex(bytes)));
    assert_eq!(
        reply.kind,
        "raw_result",
        "{reply:?} error={:?}",
        reply.error()
    );
    scap_cell::decode_applied_outcome(
        &unhex(&reply.fields[2]),
        Position {
            term: reply.fields[0].parse().unwrap(),
            index: reply.fields[1].parse().unwrap(),
        },
    )
    .unwrap()
}
fn applied(outcome: AppliedOutcome) -> ControlResult {
    match outcome.outcome {
        Outcome::ControlApplied(result) => {
            assert_eq!(outcome.position, result.position);
            result
        }
        other => panic!("new control did not apply: {other:?}"),
    }
}
fn view(cluster: &mut Cluster, node: u64) -> (CellState, DatabaseView) {
    let state = cluster.try_read(node, 3000).unwrap();
    let view = state.database(common::DATABASE.database_id).unwrap();
    (state, view)
}
fn auth_command(auth: u64, revision: u64, operation: u128) -> Command {
    command(
        auth,
        Some(revision),
        CommandKind::AuthFence {
            operation_id: operation,
            expected_epoch: auth,
            policy: vec![Grant {
                principal_id: common::ADMINISTRATOR,
                permissions: READ | WRITE | ADMIN,
            }],
        },
    )
}
fn seed() -> Vec<Statement> {
    vec![
        common::sql("CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"),
        common::sql("INSERT INTO items VALUES(1,randomblob(32)) RETURNING payload"),
    ]
}
fn result(reply: Reply) -> (Vec<u8>, TransactionResult) {
    assert_eq!(reply.kind, "sql", "{reply:?}");
    assert_eq!(reply.fields[1], "false");
    let bytes = unhex(&reply.fields[2]);
    let decoded = scap_sql::decode_result(&bytes, common::writer_limits().sql).unwrap();
    (bytes, decoded)
}
fn payload(result: &TransactionResult) -> Vec<u8> {
    match &result.statements.last().unwrap().rows[0][0] {
        Value::Blob(bytes) => bytes.clone(),
        other => panic!("unexpected SQL payload {other:?}"),
    }
}
fn lookup(state: &CellState, auth: u64) -> Lookup {
    let mut admission = common::admission();
    admission.auth_epoch = auth;
    state
        .lookup(
            common::DATABASE,
            admission,
            10,
            scap_sql::request_fingerprint(&seed(), common::writer_limits().sql).unwrap(),
        )
        .unwrap()
}
fn original(state: &CellState, auth: u64, bytes: &[u8]) {
    let Lookup::Committed {
        commit,
        result,
        acknowledged,
    } = lookup(state, auth)
    else {
        panic!("original result lost")
    };
    assert_eq!(commit.receipt.sequence, 1);
    assert_eq!(result, bytes);
    assert!(!acknowledged);
}
fn sql_oracle(cluster: &mut Cluster, node: u64, auth: u64, expected: &[u8]) {
    let reply = cluster.query(
        node,
        9000,
        auth,
        &[common::sql("SELECT payload FROM items WHERE id=1")],
    );
    assert_eq!(reply.kind, "query", "{reply:?} error={:?}", reply.error());
    let decoded =
        scap_sql::decode_result(&unhex(&reply.fields[4]), common::writer_limits().sql).unwrap();
    assert_eq!(payload(&decoded), expected);
}
fn archive(
    cluster: &mut Cluster,
    node: u64,
    verb: &str,
    auth: u64,
    operation: u128,
    lose: bool,
) -> Reply {
    cluster.nodes.get_mut(&node).unwrap().command(
        verb,
        &format!(
            "5000 {auth} {operation} {}",
            if lose { "lose" } else { "keep" }
        ),
    )
}
fn archive_ok(reply: Reply) {
    assert_eq!(
        reply.kind,
        "archive_ok",
        "{reply:?} error={:?}",
        reply.error()
    );
}
fn rejected(reply: Reply, expected: &str) {
    assert!(
        reply
            .error()
            .unwrap_or_else(|| panic!("expected error {reply:?}"))
            .contains(expected),
        "{reply:?}"
    );
}
fn caught_up(cluster: &mut Cluster, node: u64, index: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while cluster.status(node).applied < index {
        assert!(Instant::now() < deadline, "node{node} catchup deadline");
        thread::sleep(Duration::from_millis(10));
    }
}
fn checkpoint(cluster: &mut Cluster, nodes: &[u64], index: u64) {
    for node in nodes {
        caught_up(cluster, *node, index);
        assert_eq!(
            cluster
                .nodes
                .get_mut(node)
                .unwrap()
                .command("checkpoint", "5000")
                .kind,
            "checkpoint"
        );
    }
}
fn fence(cluster: &mut Cluster, node: u64, auth: &mut u64, operation: u128) -> ControlResult {
    let (_, before) = view(cluster, node);
    let receipt = applied(raw(
        cluster,
        node,
        &auth_command(*auth, before.control_revision.unwrap(), operation),
    ));
    *auth += 1;
    assert_eq!(receipt.result, AdminResult::AuthChanged(*auth));
    receipt
}

#[test]
fn bounded_control_faults() {
    if child::maybe_run() {
        return;
    }
    assert!(
        std::env::var_os("LLVM_PROFILE_FILE").is_none(),
        "fault profiles must not enter unit coverage"
    );
    let mut events = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence().join("rust-events.jsonl"))
        .unwrap();
    let mut operations = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence().join("control-operations.jsonl"))
        .unwrap();
    let mut cluster = Cluster::new("bounded_control_faults", BTreeMap::new());
    cluster.start_all();
    let mut leader = cluster.leader(&[1, 2, 3]);
    cluster.initialize(leader);
    cluster.recover(leader, 1001, 0, 1);
    let (retained, decoded) = result(cluster.sql(leader, 10, 1, &seed()));
    let payload = payload(&decoded);
    let (_, before) = view(&mut cluster, leader);
    let mut auth = before.auth_epoch;
    let first_revision = before.control_revision.unwrap();
    assert_eq!(before.revision, 1);
    assert!(first_revision >= 3);
    event(
        &mut events,
        "native_sql_seed",
        json!({"revision":before.revision,"control_revision":first_revision,"result":hex(&retained),"payload":hex(&payload),"request_id":"10"}),
    );

    let mut sizes = Vec::new();
    let mut last_command = None;
    let mut last_receipt = None;
    for ordinal in 0..MANY {
        let proposal = auth_command(auth, first_revision + ordinal, 10000 + u128::from(ordinal));
        let receipt = applied(raw(&mut cluster, leader, &proposal));
        assert_eq!(receipt.revision, first_revision + ordinal + 1);
        auth += 1;
        assert_eq!(receipt.result, AdminResult::AuthChanged(auth));
        writeln!(operations,"{}",json!({"ordinal":ordinal,"operation_id":(10000+ordinal).to_string(),"expected_revision":first_revision+ordinal,"revision":receipt.revision,"auth_epoch":auth,"term":receipt.position.term,"index":receipt.position.index,"outcome":"ControlApplied"})).unwrap();
        if ordinal == 0 || (ordinal + 1) % 128 == 0 || ordinal + 1 == MANY {
            let (state, current) = view(&mut cluster, leader);
            let bytes = state.encode().len();
            assert_eq!(current.control_revision, Some(receipt.revision));
            original(&state, auth, &retained);
            sizes.push(json!({"completed":ordinal+1,"bytes":bytes,"revision":receipt.revision}));
            if ordinal == 0 {
                assert!(
                    bytes < 100_000,
                    "small real SQL fixture must not hide receipt growth in a large state"
                );
            }
            if ordinal > 0 {
                assert_eq!(
                    bytes,
                    sizes[0]["bytes"].as_u64().unwrap() as usize,
                    "one latest receipt must keep encoded state size constant"
                );
            }
            checkpoint(&mut cluster, &[1, 2, 3], state.position().index);
        }
        last_command = Some(proposal);
        last_receipt = Some(receipt);
    }
    operations.sync_all().unwrap();
    drop(operations);
    let mut last_command = last_command.unwrap();
    last_command.admission.auth_epoch = auth;
    let repeated = raw(&mut cluster, leader, &last_command);
    assert_eq!(
        repeated.outcome,
        Outcome::ControlAlreadyApplied(last_receipt.clone().unwrap())
    );
    let mut stale = auth_command(auth, first_revision, 10000);
    stale.admission.auth_epoch = auth;
    assert_eq!(
        raw(&mut cluster, leader, &stale).outcome,
        Outcome::Rejected(Reject::ControlRetired)
    );
    let mut legacy = last_command.clone();
    legacy.control_revision = None;
    assert_eq!(
        raw(&mut cluster, leader, &legacy).outcome,
        Outcome::Rejected(Reject::ControlRetired)
    );
    let (state, current) = view(&mut cluster, leader);
    original(&state, auth, &retained);
    sql_oracle(&mut cluster, leader, auth, &payload);
    event(
        &mut events,
        "more_than_4096_bounded",
        json!({"successful_controls":MANY,"first_revision":first_revision,"final_revision":current.control_revision,"sizes":sizes,"last_receipt_original_index":last_receipt.unwrap().position.index,"repeat_application_index":repeated.position.index,"exact_latest_retry":true,"retired_old_sequence":true,"unknown_legacy_closed":true,"retained_result_identical":true}),
    );

    // All archive bytes are produced, uploaded, verified, pruned, fetched and
    // hydrated by the production Controller against an actual SeaweedFS S3.
    for cycle in 0..2_u128 {
        let operation = 20000 + cycle * 20;
        archive_ok(archive(
            &mut cluster,
            leader,
            "s3_suspend",
            auth,
            operation,
            false,
        ));
        archive_ok(archive(
            &mut cluster,
            leader,
            "s3_publish",
            auth,
            operation + 1,
            false,
        ));
        let (_, published) = view(&mut cluster, leader);
        let old_prune = command(
            auth,
            published.control_revision,
            CommandKind::PruneArchive {
                operation_id: operation + 2,
                expected_owner: published.owner,
                archive_digest: published.archive.unwrap().object_digest,
            },
        );
        archive_ok(archive(
            &mut cluster,
            leader,
            "s3_prune",
            auth,
            operation + 2,
            false,
        ));
        let (cold, cold_view) = view(&mut cluster, leader);
        assert!(cold_view.cold);
        original(&cold, auth, &retained);
        archive_ok(archive(
            &mut cluster,
            leader,
            "s3_hydrate",
            auth,
            operation + 3,
            false,
        ));
        assert_eq!(
            raw(&mut cluster, leader, &old_prune).outcome,
            Outcome::Rejected(Reject::ControlRetired)
        );
        let (hydrated, hot) = view(&mut cluster, leader);
        assert!(!hot.cold);
        assert_eq!(hot.revision, 1);
        original(&hydrated, auth, &retained);
        cluster.recover(leader, 1100 + cycle, hot.owner.epoch, auth);
        sql_oracle(&mut cluster, leader, auth, &payload);
        event(
            &mut events,
            "real_cold_cycle",
            json!({"cycle":cycle,"archive_digest":hex(&published.archive.unwrap().object_digest),"cold_control_revision":cold_view.control_revision,"hydrated_control_revision":hot.control_revision,"old_prune":"ControlRetired","original_result_identical":true,"native_sql_payload_identical":true}),
        );
    }

    archive_ok(archive(
        &mut cluster,
        leader,
        "s3_suspend",
        auth,
        21000,
        false,
    ));
    let (_, publish_before) = view(&mut cluster, leader);
    rejected(
        archive(&mut cluster, leader, "s3_publish", auth, 21001, true),
        "Unknown",
    );
    let (_, lost_publication) = view(&mut cluster, leader);
    assert!(!lost_publication.cold);
    assert!(lost_publication.archive.is_some());
    let publish_log =
        fs::read_to_string(evidence().join(format!("lost-response-node-{leader}.jsonl"))).unwrap();
    assert_eq!(
        publish_log.lines().count(),
        1,
        "exactly one Publish response was discarded"
    );
    let lost_publish: Json = serde_json::from_str(publish_log.lines().next().unwrap()).unwrap();
    let lost_publish_position = Position {
        term: lost_publish["term"].as_u64().unwrap(),
        index: lost_publish["index"].as_u64().unwrap(),
    };
    let publish_applied = scap_cell::decode_applied_outcome(
        &unhex(lost_publish["result"].as_str().unwrap()),
        lost_publish_position,
    )
    .unwrap();
    let publish_receipt = applied(publish_applied);
    let published_archive = lost_publication.archive.unwrap();
    assert_eq!(
        publish_receipt.result,
        AdminResult::ArchivePublished(published_archive.object_digest)
    );
    assert_eq!(
        publish_receipt.revision,
        publish_before.control_revision.unwrap() + 1
    );
    assert_eq!(
        lost_publication.control_revision,
        Some(publish_receipt.revision)
    );
    let exact_publish = command(
        auth,
        publish_before.control_revision,
        CommandKind::PublishArchive {
            operation_id: 21001,
            expected_owner: publish_before.owner,
            expected_previous: publish_before.archive.map(|archive| archive.object_digest),
            archive: published_archive,
        },
    );
    assert_eq!(
        unhex(lost_publish["command"].as_str().unwrap()),
        scap_cell::encode_command(&exact_publish, common::cell_limits()).unwrap()
    );
    rejected(
        archive(&mut cluster, leader, "s3_prune", auth, 21002, false),
        "NoConfirmedPublication",
    );
    let mut delayed_prune = command(
        auth,
        lost_publication.control_revision,
        CommandKind::PruneArchive {
            operation_id: 21002,
            expected_owner: lost_publication.owner,
            archive_digest: lost_publication.archive.unwrap().object_digest,
        },
    );
    fence(&mut cluster, leader, &mut auth, 21003);
    fence(&mut cluster, leader, &mut auth, 21004);
    delayed_prune.admission.auth_epoch = auth;
    assert_eq!(
        raw(&mut cluster, leader, &delayed_prune).outcome,
        Outcome::Rejected(Reject::ControlRetired)
    );
    assert!(!view(&mut cluster, leader).1.cold);
    // Also exercise the production bound receipt after a confirmed Publish:
    // its captured view cannot be silently replaced after an interleaving.
    archive_ok(archive(
        &mut cluster,
        leader,
        "s3_publish",
        auth,
        21005,
        false,
    ));
    fence(&mut cluster, leader, &mut auth, 21006);
    rejected(
        archive(&mut cluster, leader, "s3_saved_prune", auth, 21007, false),
        "Fenced",
    );
    assert!(!view(&mut cluster, leader).1.cold);
    event(
        &mut events,
        "lost_publish_interleaving",
        json!({"durable_publish_response_discarded":true,"captured_command_exact":true,"original_index":publish_receipt.position.index,"control_revision_before":publish_before.control_revision,"control_revision_after":publish_receipt.revision,"archive_digest":hex(&published_archive.object_digest),"no_confirmed_publication_token":true,"interleavings":2,"delayed_prune":"ControlRetired","confirmed_stale_publication_prune":"Fenced","physical_bytes_preserved":true}),
    );

    archive_ok(archive(
        &mut cluster,
        leader,
        "s3_publish",
        auth,
        22000,
        false,
    ));
    archive_ok(archive(
        &mut cluster,
        leader,
        "s3_prune",
        auth,
        22001,
        false,
    ));
    assert!(view(&mut cluster, leader).1.cold);
    rejected(
        archive(&mut cluster, leader, "s3_hydrate", auth, 22002, true),
        "Unknown",
    );
    let (state, hot) = view(&mut cluster, leader);
    assert!(!hot.cold);
    original(&state, auth, &retained);
    // Re-submit the exact captured wire command, never reconstruct a new
    // revision after UNKNOWN. Its original durable receipt must be preserved.
    let discarded =
        fs::read_to_string(evidence().join(format!("lost-response-node-{leader}.jsonl"))).unwrap();
    let lost: Json = serde_json::from_str(discarded.lines().last().unwrap()).unwrap();
    let hydrate_bytes = unhex(lost["command"].as_str().unwrap());
    let first = scap_cell::decode_applied_outcome(
        &unhex(lost["result"].as_str().unwrap()),
        Position {
            term: lost["term"].as_u64().unwrap(),
            index: lost["index"].as_u64().unwrap(),
        },
    )
    .unwrap();
    let Outcome::ControlApplied(hydrate_receipt) = first.outcome else {
        panic!("lost hydrate was not durably accepted")
    };
    assert_eq!(
        raw_bytes(&mut cluster, leader, &hydrate_bytes).outcome,
        Outcome::ControlAlreadyApplied(hydrate_receipt.clone())
    );
    archive_ok(archive(
        &mut cluster,
        leader,
        "s3_suspend",
        auth,
        22003,
        false,
    ));
    assert_eq!(
        raw_bytes(&mut cluster, leader, &hydrate_bytes).outcome,
        Outcome::Rejected(Reject::ControlRetired)
    );
    let (_, hot) = view(&mut cluster, leader);
    cluster.recover(leader, 1200, hot.owner.epoch, auth);
    sql_oracle(&mut cluster, leader, auth, &payload);
    event(
        &mut events,
        "lost_hydrate_response",
        json!({"durable_response_discarded":true,"original_receipt_index":hydrate_receipt.position.index,"exact_retry":"ControlAlreadyApplied","after_interleaving":"ControlRetired","native_sql_payload_identical":true,"retained_result_identical":true}),
    );

    for (round, phase) in ["claimed", "activated"].into_iter().enumerate() {
        let (_, before) = view(&mut cluster, leader);
        let worker = 1300 + round as u128 * 10;
        let operation = worker * 2;
        let old = leader;
        cluster.nodes.get_mut(&old).unwrap().begin(
            "recover",
            &format!(
                "15000 {worker} {} {auth} {operation} {phase}",
                before.owner.epoch
            ),
        );
        let hook = cluster.wait_hook(old, worker);
        assert!(hook.contains("ControlApplied"));
        cluster.kill(old);
        let others = (1..=3).filter(|id| *id != old).collect::<Vec<_>>();
        leader = cluster.leader(&others);
        let (_, lost) = view(&mut cluster, leader);
        assert_eq!(lost.owner.worker_instance_id, worker);
        assert_eq!(lost.active, phase == "activated");
        let saved_activate = command(
            auth,
            Some(if phase == "claimed" {
                lost.control_revision.unwrap()
            } else {
                lost.control_revision.unwrap() - 1
            }),
            CommandKind::ActivateOwner {
                operation_id: operation + 1,
                token: lost.owner,
                restored_revision: lost.revision,
                restored_hash: lost.commit_hash,
            },
        );
        cluster.recover(leader, worker + 1, lost.owner.epoch, auth);
        assert_eq!(
            raw(&mut cluster, leader, &saved_activate).outcome,
            Outcome::Rejected(Reject::ControlRetired)
        );
        let (_, fresh) = view(&mut cluster, leader);
        let mut forged_refresh = saved_activate.clone();
        forged_refresh.control_revision = fresh.control_revision;
        assert_eq!(
            raw(&mut cluster, leader, &forged_refresh).outcome,
            Outcome::Rejected(Reject::Fenced)
        );
        sql_oracle(&mut cluster, leader, auth, &payload);
        let (state, _) = view(&mut cluster, leader);
        original(&state, auth, &retained);
        let boundary = state.position().index;
        checkpoint(&mut cluster, &others, boundary);
        let minimum = others
            .iter()
            .map(|id| cluster.status(*id).snapshot)
            .min()
            .unwrap();
        cluster.restart(old);
        caught_up(&mut cluster, old, boundary);
        assert!(
            cluster.status(old).snapshot >= minimum,
            "old process must install the compacted snapshot, not only append a retained tail"
        );
        event(
            &mut events,
            "owner_sigkill",
            json!({"phase":phase,"signal":9,"old_node":old,"old_worker":worker.to_string(),"durable_control_revision":lost.control_revision,"new_worker":(worker+1).to_string(),"old_activation":"ControlRetired","refreshed_old_activation":"Fenced","snapshot_boundary":minimum,"native_sql_payload_identical":true,"retained_result_identical":true}),
        );
    }

    // Capture one exact latest receipt before any snapshot/restart. The
    // refreshed admission below preserves the command's original intent.
    let (_, checkpoint_view) = view(&mut cluster, leader);
    let mut snapshot_command = auth_command(auth, checkpoint_view.control_revision.unwrap(), 30090);
    let snapshot_receipt = applied(raw(&mut cluster, leader, &snapshot_command));
    auth += 1;
    snapshot_command.admission.auth_epoch = auth;
    // Node4 has never run its Raft loop. All possible source voters compact
    // beyond the final authoritative database observation before adding it.
    let (final_state, final_view) = view(&mut cluster, leader);
    original(&final_state, auth, &retained);
    let boundary = final_state.position().index;
    checkpoint(&mut cluster, &[1, 2, 3], boundary);
    let source_snapshots = (1..=3)
        .map(|id| json!({"node":id,"snapshot":cluster.status(id).snapshot}))
        .collect::<Vec<_>>();
    let minimum = source_snapshots
        .iter()
        .map(|x| x["snapshot"].as_u64().unwrap())
        .min()
        .unwrap();
    assert!(minimum >= boundary);
    let joined = cluster
        .nodes
        .get_mut(&leader)
        .unwrap()
        .command("add_learner", "-");
    assert_eq!(joined.kind, "learner_added");
    let joined_at = joined.fields[0].parse::<u64>().unwrap();
    cluster.start(4);
    caught_up(&mut cluster, 4, joined_at);
    let learner_status = cluster.status(4);
    assert!(learner_status.snapshot >= minimum);
    cluster.kill(4);
    let store = Store::open_existing(
        RocksBackend::open_existing(&cluster.directory.path().join("node4")).unwrap(),
        common::identity(4),
        common::store_limits(),
    )
    .unwrap();
    let durable = store.view().unwrap();
    assert_eq!(durable.conf_state.learners, vec![4]);
    let snapshot = &durable.snapshot;
    assert!(snapshot.get_metadata().index >= minimum);
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
    assert_eq!(
        installed.database(common::DATABASE.database_id).unwrap(),
        final_view
    );
    original(&installed, auth, &retained);
    // Inspect the actual installed bytes through the production application.
    // This pure in-memory replay is an audit postcondition, not a new durable
    // command and is never counted among the real network submissions.
    let probe_position = Position {
        term: snapshot.get_metadata().term,
        index: snapshot.get_metadata().index + 1,
    };
    let entry = raft::eraftpb::Entry {
        term: probe_position.term,
        index: probe_position.index,
        data: scap_cell::encode_command(&snapshot_command, common::cell_limits())
            .unwrap()
            .into(),
        ..Default::default()
    };
    let candidate = scap_cell::CellApplication::new(common::cell(), common::cell_limits())
        .unwrap()
        .apply(snapshot.get_data(), &[entry])
        .unwrap();
    let audited = CellState::decode_bound(
        &candidate,
        common::cell(),
        probe_position,
        common::cell_limits(),
    )
    .unwrap();
    assert_eq!(
        audited.last_outcome().unwrap().outcome,
        Outcome::ControlAlreadyApplied(snapshot_receipt.clone())
    );
    fs::write(evidence().join("learner-state.bin"), snapshot.get_data()).unwrap();
    drop(store);
    event(
        &mut events,
        "learner_snapshot",
        json!({"node":4,"source_snapshots":source_snapshots,"required_boundary":boundary,"installed_snapshot":learner_status.snapshot,"control_revision":final_view.control_revision,"latest_receipt_revision":snapshot_receipt.revision,"latest_receipt_original_term":snapshot_receipt.position.term,"latest_receipt_original_index":snapshot_receipt.position.index,"exact_latest_receipt_preserved":true,"receipt_postcondition_is_new_commit":false,"direct_closed_disk_inspection":true,"durable_learners":[4],"joined_at":joined_at,"database_view_identical":true,"retained_result_identical":true}),
    );

    // Close/reopen every voter. The original retained SQL result and current
    // control revision must remain recoverable from the real durable stores.
    for node in 1..=3 {
        cluster.kill(node);
    }
    for node in 1..=3 {
        cluster.restart(node);
    }
    leader = cluster.leader(&[1, 2, 3]);
    let (reopened, reopened_view) = view(&mut cluster, leader);
    assert_eq!(reopened_view, final_view);
    original(&reopened, auth, &retained);
    let after_restart_retry = raw(&mut cluster, leader, &snapshot_command);
    assert_eq!(
        after_restart_retry.outcome,
        Outcome::ControlAlreadyApplied(snapshot_receipt.clone())
    );
    cluster.recover(leader, 1500, reopened_view.owner.epoch, auth);
    sql_oracle(&mut cluster, leader, auth, &payload);
    let (last, last_view) = view(&mut cluster, leader);
    original(&last, auth, &retained);
    event(
        &mut events,
        "all_voters_reopened",
        json!({"before_control_revision":final_view.control_revision,"reopened_control_revision":reopened_view.control_revision,"after_owner_recovery_control_revision":last_view.control_revision,"latest_receipt_original_index":snapshot_receipt.position.index,"retry_application_index":after_restart_retry.position.index,"exact_latest_receipt_preserved":true,"retained_result_identical":true,"native_sql_payload_identical":true}),
    );
    events.sync_all().unwrap();
    drop(events);
    cluster.finish();
    write_json(
        "rust-summary.json",
        json!({"schema":1,"complete":true,"successful_new_controls":MANY,"configured_legacy_bound":4096,"bounded_control_state":true,"cold_cycles":2,"discarded_durable_responses":2,"owner_sigkills":2,"learner_snapshot":true,"all_voters_reopened":true,"production_slo_verified":false,"contracts":["more_than_4096_bounded","real_cold_cycle","lost_publish_interleaving","lost_hydrate_response","owner_sigkill","learner_snapshot","all_voters_reopened"]}),
    );
}

#[test]
fn full_v4_fixture_activates_bounded_control() {
    if child::maybe_run() {
        return;
    }
    let source = PathBuf::from(
        std::env::var_os("SCAP_CONTROL_LEGACY_FIXTURE_DIR")
            .expect("real closed v4 producer fixture is required"),
    );
    let metadata: Json =
        serde_json::from_slice(&fs::read(source.join("producer.json")).unwrap()).unwrap();
    assert_eq!(metadata["state_version"], 4);
    assert_eq!(metadata["successful_legacy_controls"], 4096);
    assert_eq!(metadata["synthetic_old_state"], false);
    let retained = unhex(metadata["retained_result"].as_str().unwrap());
    let auth = metadata["auth_epoch"].as_u64().unwrap();
    let mut cluster = Cluster::reopen_fixture("full_v4_fixture_activates_bounded_control", &source);
    cluster.start_all();
    let leader = cluster.leader(&[1, 2, 3]);
    let (before, old_view) = view(&mut cluster, leader);
    assert_eq!(before.physical_history_version(), 4);
    assert_eq!(old_view.control_revision, None);
    original(&before, auth, &retained);
    assert_eq!(
        cluster
            .nodes
            .get_mut(&leader)
            .unwrap()
            .command("activate_control", "-")
            .kind,
        "activated_control"
    );
    let (activated, current) = view(&mut cluster, leader);
    assert_eq!(activated.physical_history_version(), 5);
    assert_eq!(current.control_revision, Some(0));
    let mut known = auth_command(auth, 0, 14092);
    known.control_revision = None;
    if let CommandKind::AuthFence { expected_epoch, .. } = &mut known.kind {
        *expected_epoch = auth - 1;
    }
    assert_eq!(
        raw(&mut cluster, leader, &known).outcome,
        Outcome::AlreadyApplied(AdminResult::AuthChanged(auth))
    );
    let mut unknown = auth_command(auth, 0, 999999);
    unknown.control_revision = None;
    assert_eq!(
        raw(&mut cluster, leader, &unknown).outcome,
        Outcome::Rejected(Reject::ControlRetired)
    );
    let receipt = applied(raw(&mut cluster, leader, &auth_command(auth, 0, 30000)));
    assert_eq!(receipt.revision, 1);
    cluster.recover(leader, 1600, current.owner.epoch, auth + 1);
    let expected =
        payload(&scap_sql::decode_result(&retained, common::writer_limits().sql).unwrap());
    sql_oracle(&mut cluster, leader, auth + 1, &expected);
    let (after, new_view) = view(&mut cluster, leader);
    original(&after, auth + 1, &retained);
    assert_eq!(new_view.control_revision, Some(3));
    assert_eq!(new_view.revision, old_view.revision);
    fs::write(evidence().join("legacy-upgraded-state.bin"), after.encode()).unwrap();
    checkpoint(&mut cluster, &[1, 2, 3], after.position().index);
    // Node4 was pretrusted by the old producer but remains a genesis-only
    // nonmember. Its new runtime has not started; closing it needs no Raft stop.
    cluster.kill(4);
    cluster.finish();
    write_json(
        "legacy-upgrade.json",
        json!({"schema":1,"complete":true,"legacy_controls":4096,"old_state_version":4,"new_state_version":5,"legacy_known_retry":"AlreadyApplied","unknown_legacy":"ControlRetired","new_controls_after_full_legacy_table":3,"control_revision":3,"retained_result_identical":true,"native_sql_payload_identical":true,"source_fixture_copied_without_reinitialization":true}),
    );
}
