use super::*;
use crate::snapshot_wire::{Identity as SnapshotIdentity, Limits, Prepare, Reference};
use serde_json::json;

fn fixed(head: &Value, operation: u64) -> Prepare {
    serde_json::from_value(json!({"creator":"3","operation":operation.to_string(),
        "expected_revision":head["revision"],"expected_head_serial":head["head_serial"],
        "label":format!("migration-{operation}")}))
    .unwrap()
}

fn reference(value: &Value) -> Reference {
    serde_json::from_value(value["reference"].clone()).unwrap()
}

fn head_puts(memory: &Memory) -> usize {
    memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.starts_with("PUT ") && call.ends_with("/head"))
        .count()
}

#[test]
fn retained_point_is_metadata_only_and_does_not_evict_the_warm_sql_session() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    active(&mut engine);
    invoke(
        &mut engine,
        action(1, "CREATE TABLE saved AS SELECT 42 AS v"),
    );
    let before = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    let saved = invoke(
        &mut engine,
        Action::SnapshotPrepare {
            input: fixed(&before, 71),
        },
    );
    let reference = reference(&saved);
    let pending = invoke(
        &mut engine,
        Action::SnapshotInspect {
            identity: SnapshotIdentity {
                creator: Decimal(3),
                operation: Decimal(71),
            },
        },
    );
    assert_eq!(pending["state"], "prepared");
    let retained = invoke(
        &mut engine,
        Action::SnapshotCapture {
            reference: reference.clone(),
        },
    );
    assert_eq!(retained["state"], "retained");
    assert_eq!(retained["status"]["revision"], before["revision"]);
    assert_eq!(retained["status"]["owner_epoch"], before["owner_epoch"]);
    assert_eq!(retained["status"]["sequence"], before["sequence"]);
    assert!(engine.cache.values().all(|entry| entry.session.is_some()));
    let list = invoke(&mut engine, Action::SnapshotList {});
    assert_eq!(list["snapshots"], json!([retained["accepted"].clone()]));
    memory.calls.lock().unwrap().clear();
    let result = result(&invoke(
        &mut engine,
        Action::Query {
            statements: statements("SELECT v FROM saved"),
        },
    ));
    assert_eq!(
        result.statements[0].rows,
        vec![vec![scap_sql::Value::Integer(42)]]
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 1);
    let released = invoke(
        &mut engine,
        Action::SnapshotRelease {
            reference: reference.clone(),
        },
    );
    assert_eq!(released["state"], "released_observed");
    let count = head_puts(&memory);
    assert_eq!(
        invoke(&mut engine, Action::SnapshotRelease { reference }),
        released
    );
    assert_eq!(head_puts(&memory), count);
    assert!(invoke(&mut engine, Action::SnapshotList {})["snapshots"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn lost_capture_response_preserves_exact_identity_across_engine_restart() {
    let (directory, memory, mut engine) = fixture(4, 10000);
    let head = active(&mut engine);
    let input = fixed(&head, 72);
    let saved = invoke(
        &mut engine,
        Action::SnapshotPrepare {
            input: input.clone(),
        },
    );
    let reference = reference(&saved);
    *memory.lose_head.lock().unwrap() = true;
    let count = head_puts(&memory);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::SnapshotCapture { reference }),
                until()
            )
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(head_puts(&memory), count + 1);
    drop(engine);
    let mut engine = Engine::new(
        memory.clone(),
        100,
        Options::default(),
        directory.path(),
        4,
        10000,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    assert_eq!(
        invoke(&mut engine, Action::SnapshotPrepare { input }),
        saved
    );
    let observed = invoke(
        &mut engine,
        Action::SnapshotInspect {
            identity: SnapshotIdentity {
                creator: Decimal(3),
                operation: Decimal(72),
            },
        },
    );
    assert_eq!(observed["state"], "retained");
    assert_eq!(head_puts(&memory), count + 1);
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
}

#[test]
fn bounded_control_replies_cover_limits_and_all_snapshot_operations() {
    use crate::output::tests::small_pool;
    use crate::output::BASE_BYTES;
    let (_directory, _memory, mut engine) = fixture(4, 10000);
    let head = active(&mut engine);
    let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let limited = budgeted(
        &mut engine,
        Action::SnapshotLimits {
            expected_revision: revision(&head),
            nonce: Decimal(91),
            limits: Limits {
                max_points: 1,
                max_logical_bytes: Decimal(1048576),
            },
        },
        &pool,
    );
    assert_eq!(limited["value"]["limits"]["max_points"], 1);
    let saved = budgeted(
        &mut engine,
        Action::SnapshotPrepare {
            input: fixed(&limited["value"]["status"], 73),
        },
        &pool,
    );
    let reference = reference(&saved["value"]);
    let inspected = budgeted(
        &mut engine,
        Action::SnapshotInspect {
            identity: SnapshotIdentity {
                creator: Decimal(3),
                operation: Decimal(73),
            },
        },
        &pool,
    );
    assert_eq!(inspected["value"]["state"], "prepared");
    let captured = budgeted(
        &mut engine,
        Action::SnapshotCapture {
            reference: reference.clone(),
        },
        &pool,
    );
    assert_eq!(captured["value"]["state"], "retained");
    let list = budgeted(&mut engine, Action::SnapshotList {}, &pool);
    assert_eq!(list["value"]["snapshots"].as_array().unwrap().len(), 1);
    let released = budgeted(&mut engine, Action::SnapshotRelease { reference }, &pool);
    assert_eq!(released["value"]["state"], "released_observed");
    let denied = engine
        .execute(
            &Principal {
                principal: 4,
                ..principal()
            },
            call(Action::SnapshotList {}),
            until(),
        )
        .unwrap_err();
    assert_eq!(denied.code, "DENIED");
}

#[test]
fn snapshot_validation_and_internal_dispatch_reject_bad_typed_inputs_before_io() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = active(&mut engine);
    let mut input = fixed(&head, 74);
    input.expected_revision = Decimal(0);
    let reference = Reference {
        creator: Decimal(3),
        operation: Decimal(74),
        capture_serial: Decimal(3),
        descriptor_hash: "invalid".into(),
    };
    let mut entry = engine.cache.pop_first().unwrap().1;
    let path = engine.directory.path().join("invalid-snapshot-input");
    memory.calls.lock().unwrap().clear();
    for action in [
        Action::SnapshotPrepare { input },
        Action::SnapshotInspect {
            identity: SnapshotIdentity {
                creator: Decimal(0),
                operation: Decimal(74),
            },
        },
        Action::SnapshotCapture {
            reference: reference.clone(),
        },
        Action::SnapshotRelease { reference },
        Action::SnapshotLimits {
            expected_revision: revision(&head),
            nonce: Decimal(92),
            limits: Limits {
                max_points: 65,
                max_logical_bytes: Decimal(0),
            },
        },
    ] {
        assert_eq!(action.validate().unwrap_err().code, "INVALID");
        assert_eq!(
            engine
                .dispatch(&principal(), &mut entry, action, &path, until(), None)
                .unwrap_err()
                .code,
            "INVALID"
        );
        assert!(memory.calls.lock().unwrap().is_empty());
        assert!(!path.exists());
    }
}

#[test]
fn snapshot_control_storage_failures_remain_unknown_without_hidden_publication() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = active(&mut engine);
    let input = fixed(&head, 75);
    let saved = invoke(
        &mut engine,
        Action::SnapshotPrepare {
            input: input.clone(),
        },
    );
    let reference = reference(&saved);
    for action in [
        Action::SnapshotPrepare { input },
        Action::SnapshotInspect {
            identity: SnapshotIdentity {
                creator: Decimal(3),
                operation: Decimal(75),
            },
        },
        Action::SnapshotCapture {
            reference: reference.clone(),
        },
        Action::SnapshotRelease { reference },
        Action::SnapshotLimits {
            expected_revision: revision(&head),
            nonce: Decimal(93),
            limits: Limits {
                max_points: 1,
                max_logical_bytes: Decimal(1048576),
            },
        },
    ] {
        let count = head_puts(&memory);
        *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
        assert_eq!(
            engine
                .execute(&principal(), call(action), until())
                .unwrap_err()
                .code,
            "UNKNOWN"
        );
        assert_eq!(head_puts(&memory), count);
    }
    assert_eq!(
        invoke(
            &mut engine,
            Action::SnapshotInspect {
                identity: SnapshotIdentity {
                    creator: Decimal(3),
                    operation: Decimal(75)
                }
            }
        )["state"],
        "prepared"
    );
}
