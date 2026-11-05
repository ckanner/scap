//! Build only against the archived, pinned v4 source. No synthetic old image.
#[path = "../../sqlite-network/src/certs.rs"]
mod certs;
#[path = "../src/legacy_child.rs"]
mod child;
#[path = "../src/common.rs"]
mod common;
#[path = "../src/harness.rs"]
mod harness;
#[path = "../../sqlite-network/src/protocol.rs"]
mod protocol;
#[path = "../../sqlite-network/src/proxy.rs"]
mod proxy;
#[path = "../../sqlite-network/src/sql_thread.rs"]
mod sql_thread;
use protocol::{hex, unhex};
use scap_cell::{Lookup, Position};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn real_v4_full_legacy_table() {
    if child::maybe_run() {
        return;
    }
    assert!(std::env::var_os("LLVM_PROFILE_FILE").is_none());
    let evidence = PathBuf::from(std::env::var_os("SCAP_CONTROL_EVIDENCE_DIR").unwrap());
    let fixture = PathBuf::from(std::env::var_os("SCAP_CONTROL_LEGACY_FIXTURE_DIR").unwrap());
    assert!(
        !fixture.exists(),
        "old producer requires a new private destination"
    );
    let mut cluster = harness::Cluster::new("real_v4_full_legacy_table", BTreeMap::new());
    cluster.start_all();
    let leader = cluster.leader(&[1, 2, 3]);
    assert_eq!(
        cluster
            .nodes
            .get_mut(&leader)
            .unwrap()
            .command("activate_retention", "-")
            .kind,
        "activated_retention"
    );
    assert!(cluster
        .apply(leader, "create", "5000 1")
        .contains("Created"));
    cluster.recover(leader, 1001, 0, 1);
    let statements = vec![
        common::sql("CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)"),
        common::sql("INSERT INTO items VALUES(1,randomblob(32)) RETURNING payload"),
    ];
    let seed = cluster.sql(leader, 10, 1, &statements);
    assert_eq!(seed.kind, "sql");
    let result = unhex(&seed.fields[2]);
    let mut trace = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("legacy-operations.jsonl"))
        .unwrap();
    let mut auth = 1;
    // Create, ClaimOwner and ActivateOwner above are exactly three successful
    // legacy administrative operations, all produced through the real runtime.
    for ordinal in 0..4093_u64 {
        let operation = 10000 + ordinal;
        let applied = cluster.apply(leader, "auth", &format!("5000 {auth} {operation}"));
        auth += 1;
        assert!(
            applied.contains(&format!("Administrative(AuthChanged({auth}))")),
            "{applied}"
        );
        writeln!(trace,"{}",json!({"ordinal":ordinal,"operation_id":operation.to_string(),"auth_epoch":auth,"outcome":"Administrative"})).unwrap();
        if (ordinal + 1) % 128 == 0 {
            let state = cluster.try_read(leader, 3000).unwrap();
            let index = state.position().index;
            for node in 1..=3 {
                let deadline = Instant::now() + Duration::from_secs(10);
                while cluster.status(node).applied < index {
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    cluster
                        .nodes
                        .get_mut(&node)
                        .unwrap()
                        .command("checkpoint", "5000")
                        .kind,
                    "checkpoint"
                );
            }
        }
    }
    trace.sync_all().unwrap();
    drop(trace);
    let rejected = cluster.apply(leader, "auth", &format!("5000 {auth} 999999"));
    assert!(rejected.contains("Rejected(Capacity)"));
    let state = cluster.try_read(leader, 3000).unwrap();
    assert_eq!(state.physical_history_version(), 4);
    let mut admission = common::admission();
    admission.auth_epoch = auth;
    let Lookup::Committed {
        result: retained, ..
    } = state
        .lookup(
            common::DATABASE,
            admission,
            10,
            scap_sql::request_fingerprint(&statements, common::writer_limits().sql).unwrap(),
        )
        .unwrap()
    else {
        panic!("lost original old SQL result")
    };
    assert_eq!(retained, result);
    let fingerprint =
        scap_sql::request_fingerprint(&statements, common::writer_limits().sql).unwrap();
    let metadata = json!({"schema":1,"source_commit":env!("SCAP_CONTROL_LEGACY_SOURCE_COMMIT"),"source_tree":env!("SCAP_CONTROL_LEGACY_SOURCE_TREE"),"state_version":4,"successful_legacy_controls":4096,"initial_control_operations":3,"auth_fences":4093,"overflow":"Capacity","auth_epoch":auth,"last_operation_id":"14092","last_expected_auth_epoch":auth-1,"retained_result":hex(&result),"request_fingerprint":hex(&fingerprint),"sql_revision":1,"state_bytes":state.encode().len(),"synthetic_old_state":false,"real_voter_processes":3});
    fs::write(evidence.join("legacy-full-state.bin"), state.encode()).unwrap();
    fs::write(
        evidence.join("legacy-producer.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
    fs::write(
        cluster.directory.path().join("producer.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
    let index = state.position().index;
    for node in 1..=3 {
        let deadline = Instant::now() + Duration::from_secs(10);
        while cluster.status(node).applied < index {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            cluster
                .nodes
                .get_mut(&node)
                .unwrap()
                .command("checkpoint", "5000")
                .kind,
            "checkpoint"
        );
    }
    for node in 1..=4 {
        cluster.kill(node);
    }
    // Verify the actual old checkpoint before publishing the closed fixture.
    let store = scap_raft_store::Store::open_existing(
        scap_raft_rocks::RocksBackend::open_existing(&cluster.directory.path().join("node1"))
            .unwrap(),
        common::identity(1),
        common::store_limits(),
    )
    .unwrap();
    let snapshot = &store.view().unwrap().snapshot;
    scap_cell::CellState::decode_bound(
        snapshot.get_data(),
        common::cell(),
        Position {
            term: snapshot.get_metadata().term,
            index: snapshot.get_metadata().index,
        },
        common::cell_limits(),
    )
    .unwrap();
    drop(store);
    fs::rename(cluster.directory.path(), &fixture).unwrap();
    cluster.finish();
}
