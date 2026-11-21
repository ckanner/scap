use super::*;
use crate::tests::{call, principal, until, Memory};
use crate::wire::{Decimal, Identity, Parameter, WireStatement};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use scap_object_store::StoreError;
use serde_json::json;

fn limits() -> scap_object::GroupLimits {
    scap_object::GroupLimits {
        max_members: 4,
        max_input_bytes: 65536,
        max_changed_pages: 2048,
        max_result_bytes: 1048576,
    }
}

fn sql(id: u64, sql: &str) -> Call {
    let statements = vec![WireStatement {
        sql: sql.into(),
        params: vec![],
    }];
    let request = scap_object::request(1, id, 3, &wire::statements(&statements).unwrap()).unwrap();
    call(Action::Execute {
        request: Identity {
            epoch: Decimal(1),
            id: Decimal(id),
            principal: Decimal(3),
            fingerprint: request.fingerprint,
        },
        statements,
    })
}

fn fixture() -> (tempfile::TempDir, Arc<Memory>, Engine) {
    let directory = tempfile::tempdir().unwrap();
    let objects = Arc::new(Memory::default());
    let mut engine = Engine::new(
        objects.clone(),
        100,
        Options::default(),
        directory.path(),
        1,
        2621440,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    engine
        .execute(
            &principal(),
            call(Action::Create { nonce: Decimal(11) }),
            until(),
        )
        .unwrap();
    engine
        .execute(
            &principal(),
            call(Action::Activate {
                expected_worker_instance: None,
                expected_revision: Decimal(1),
                nonce: Decimal(12),
            }),
            until(),
        )
        .unwrap();
    engine
        .execute(
            &principal(),
            sql(
                1,
                "CREATE TABLE grouped (id INTEGER PRIMARY KEY, v INTEGER)",
            ),
            until(),
        )
        .unwrap();
    objects.calls.lock().unwrap().clear();
    (directory, objects, engine)
}

fn members<'a>(calls: &'a [Call], principal: &'a Principal) -> Vec<Member<'a>> {
    calls
        .iter()
        .map(|call| Member {
            principal,
            call,
            deadline: until(),
            output: None,
        })
        .collect()
}

fn completed(outcome: Outcome) -> Vec<Result<Value, Failure>> {
    match outcome {
        Outcome::Completed(results) => results,
        Outcome::Declined => panic!("expected an executed group"),
    }
}

fn result(value: &Value) -> scap_sql::TransactionResult {
    scap_sql::decode_result(
        &STANDARD.decode(value["result"].as_str().unwrap()).unwrap(),
        scap_object::options::durable_sql_limits(),
    )
    .unwrap()
}

fn query(engine: &mut Engine, text: &str) -> scap_sql::TransactionResult {
    result(
        &engine
            .execute(
                &principal(),
                call(Action::Query {
                    statements: vec![WireStatement {
                        sql: text.into(),
                        params: vec![],
                    }],
                }),
                until(),
            )
            .unwrap(),
    )
}

#[test]
fn native_group_keeps_independent_results_receipts_and_one_authority_publication() {
    let (directory, objects, mut engine) = fixture();
    let calls = [
        sql(2, "INSERT INTO grouped VALUES (1, 10) RETURNING v"),
        sql(
            3,
            "INSERT INTO grouped SELECT 2, v + 1 FROM grouped WHERE id = 1 RETURNING v",
        ),
        sql(4, "SELECT sum(v) FROM grouped"),
    ];
    let caller = principal();
    // Exercise the actual Worker forwarding boundary used by the scheduler.
    let results = completed(crate::scheduler::Worker::execute_group(
        &mut engine,
        &mut members(&calls, &caller),
        limits(),
    ));
    let values: Vec<_> = results.into_iter().map(Result::unwrap).collect();
    for (index, value) in values.iter().enumerate() {
        assert_eq!(value["receipt"]["request"]["id"], (index + 2).to_string());
        assert_eq!(value["receipt"]["sequence"], (index + 2).to_string());
        assert_eq!(
            value["receipt"]["transition"]["nonce"],
            (index + 2).to_string()
        );
        let Action::Execute { request, .. } = &calls[index].action else {
            unreachable!()
        };
        let looked_up = engine
            .execute(
                &caller,
                call(Action::Lookup {
                    request: request.clone(),
                }),
                until(),
            )
            .unwrap();
        assert_eq!(looked_up, *value);
    }
    assert_eq!(
        result(&values[0]).statements[0].rows,
        vec![vec![scap_sql::Value::Integer(10)]]
    );
    assert_eq!(
        result(&values[1]).statements[0].rows,
        vec![vec![scap_sql::Value::Integer(11)]]
    );
    assert_eq!(
        result(&values[2]).statements[0].rows,
        vec![vec![scap_sql::Value::Integer(21)]]
    );
    assert_eq!(
        objects
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("PUT ") && call.ends_with("/head"))
            .count(),
        1
    );
    assert!(engine.cache.values().next().unwrap().session.is_some());
    drop(engine);
    let mut recovered = Engine::new(
        objects,
        100,
        Options::default(),
        directory.path(),
        1,
        2621440,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    assert_eq!(
        query(&mut recovered, "SELECT sum(v) FROM grouped").statements[0].rows,
        vec![vec![scap_sql::Value::Integer(21)]]
    );
}

#[test]
fn a_failed_member_consumes_only_its_real_prefix_and_never_executes_the_suffix() {
    let (_directory, objects, mut engine) = fixture();
    let calls = [
        sql(2, "INSERT INTO grouped VALUES (1, 10) RETURNING v"),
        sql(3, "INSERT INTO grouped VALUES (1, 20)"),
        sql(4, "INSERT INTO grouped VALUES (2, 30)"),
    ];
    let caller = principal();
    let results = completed(engine.execute_group(&mut members(&calls, &caller), limits()));
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert_eq!(results[1].as_ref().unwrap_err().code, "ENGINE");
    assert!(engine.cache.values().next().unwrap().session.is_none());
    assert_eq!(
        query(&mut engine, "SELECT id, v FROM grouped").statements[0].rows,
        vec![vec![
            scap_sql::Value::Integer(1),
            scap_sql::Value::Integer(10)
        ]]
    );
    let Action::Execute { request, .. } = &calls[2].action else {
        unreachable!()
    };
    assert_eq!(
        engine
            .execute(
                &caller,
                call(Action::Lookup {
                    request: request.clone()
                }),
                until()
            )
            .unwrap(),
        json!({"state":"unknown"})
    );
    assert_eq!(
        objects
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("PUT ") && call.ends_with("/head"))
            .count(),
        1
    );
}

#[test]
fn lost_group_head_response_keeps_every_original_identity_resolvable_without_replay() {
    let (_directory, objects, mut engine) = fixture();
    let calls = [
        sql(2, "INSERT INTO grouped VALUES (1, random()) RETURNING v"),
        sql(3, "INSERT INTO grouped VALUES (2, random()) RETURNING v"),
    ];
    let caller = principal();
    *objects.lose_head.lock().unwrap() = true;
    let results = completed(engine.execute_group(&mut members(&calls, &caller), limits()));
    assert_eq!(results.len(), 2);
    assert!(results
        .iter()
        .all(|result| result.as_ref().unwrap_err().code == "UNKNOWN"));
    assert!(engine.cache.values().next().unwrap().session.is_none());
    for call_value in &calls {
        let Action::Execute { request, .. } = &call_value.action else {
            unreachable!()
        };
        let resolved = engine
            .execute(
                &caller,
                call(Action::Lookup {
                    request: request.clone(),
                }),
                until(),
            )
            .unwrap();
        assert_eq!(resolved["state"], "committed");
        assert_eq!(
            resolved["receipt"]["request"]["fingerprint"],
            request.fingerprint
        );
    }
    assert_eq!(
        objects
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("PUT ") && call.ends_with("/head"))
            .count(),
        1
    );
}

#[test]
fn group_preflight_declines_incompatible_or_invalid_members_before_any_sql() {
    let (_directory, objects, mut engine) = fixture();
    let caller = principal();
    let original = [sql(2, "SELECT 1"), sql(3, "SELECT 2")];
    assert!(prepare(&[], limits().max_input_bytes).is_none());
    for length in [0, 1] {
        assert!(matches!(
            engine.execute_group(&mut members(&original[..length], &caller), limits()),
            Outcome::Declined
        ));
    }
    let mut invalid_limits = limits();
    invalid_limits.max_members = 0;
    assert_eq!(
        completed(engine.execute_group(&mut members(&original, &caller), invalid_limits))[0]
            .as_ref()
            .unwrap_err()
            .code,
        "LIMIT"
    );
    let mut two = limits();
    two.max_members = 2;
    let three = [original[0].clone(), original[1].clone(), sql(4, "SELECT 3")];
    assert!(matches!(
        engine.execute_group(&mut members(&three, &caller), two),
        Outcome::Declined
    ));
    let mutations: [fn(&mut Call); 8] = [
        |call| call.version = 2,
        |call| call.scope.incarnation.0 += 1,
        |call| {
            call.action = Action::Status {
                expected_worker_instance: None,
            }
        },
        |call| {
            if let Action::Execute { request, .. } = &mut call.action {
                request.principal.0 += 1
            }
        },
        |call| {
            if let Action::Execute { request, .. } = &mut call.action {
                request.fingerprint = "a".repeat(64)
            }
        },
        |call| {
            if let Action::Execute { statements, .. } = &mut call.action {
                statements[0]
                    .params
                    .push(Parameter::Integer { value: "01".into() })
            }
        },
        |call| {
            if let Action::Execute { statements, .. } = &mut call.action {
                statements.clear()
            }
        },
        |call| call.scope.generation.0 = 0,
    ];
    for mutate in mutations {
        let mut calls = original.clone();
        mutate(&mut calls[1]);
        assert!(matches!(
            engine.execute_group(&mut members(&calls, &caller), limits()),
            Outcome::Declined
        ));
    }
    let mut invalid_scope = original.clone();
    invalid_scope[0].scope.deployment.0 = 0;
    assert!(matches!(
        engine.execute_group(&mut members(&invalid_scope, &caller), limits()),
        Outcome::Declined
    ));
    let mut different = caller.clone();
    different.provision = false;
    let mut selected = members(&original, &caller);
    selected[1].principal = &different;
    assert!(matches!(
        engine.execute_group(&mut selected, limits()),
        Outcome::Declined
    ));
    let mut selected = members(&original, &caller);
    selected[1].deadline = Instant::now();
    assert!(matches!(
        engine.execute_group(&mut selected, limits()),
        Outcome::Declined
    ));
    let mut denied = caller.clone();
    denied.tenant += 1;
    assert!(matches!(
        engine.execute_group(&mut members(&original, &denied), limits()),
        Outcome::Declined
    ));
    assert!(objects.calls.lock().unwrap().is_empty());
}

#[test]
fn direct_engine_groups_bound_all_wire_inputs_before_native_payload_decoding() {
    let (directory, objects, mut engine) = fixture();
    let caller = principal();
    let text = format!("SELECT '{}'", "x".repeat(4096));
    let calls = [sql(2, &text), sql(3, &text)];
    let bounded = scap_object::GroupLimits {
        max_input_bytes: 5000,
        ..limits()
    };
    for call in &calls {
        let Action::Execute {
            request,
            statements,
        } = &call.action
        else {
            unreachable!()
        };
        assert!(crate::group::input_remaining(request, statements, 5000).is_some());
    }
    assert!(matches!(
        engine.execute_group(&mut members(&calls, &caller), bounded),
        Outcome::Declined
    ));
    let mut smaller = Engine::new(
        objects.clone(),
        100,
        Options {
            max_input_bytes: 5000,
            ..Options::default()
        },
        directory.path(),
        1,
        2621440,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    assert!(matches!(
        smaller.execute_group(&mut members(&calls, &caller), limits()),
        Outcome::Declined
    ));
    assert!(objects.calls.lock().unwrap().is_empty());
    // Decline has no side effects. A caller may now execute only the original
    // queue head once; the second identity still has no execution or result.
    let value = engine.execute(&caller, calls[0].clone(), until()).unwrap();
    assert_eq!(value["receipt"]["sequence"], "2");
    let Action::Execute { request, .. } = &calls[1].action else {
        unreachable!()
    };
    let suffix = engine
        .execute(
            &caller,
            call(Action::Lookup {
                request: request.clone(),
            }),
            until(),
        )
        .unwrap();
    assert_eq!(suffix["state"], "unknown");
}

#[test]
fn core_fallback_and_outer_errors_do_not_replay_or_consume_unstarted_suffixes() {
    let (_directory, objects, mut engine) = fixture();
    let caller = principal();
    let existing = [
        sql(
            1,
            "CREATE TABLE grouped (id INTEGER PRIMARY KEY, v INTEGER)",
        ),
        sql(2, "SELECT 2"),
    ];
    assert!(matches!(
        engine.execute_group(&mut members(&existing, &caller), limits()),
        Outcome::Declined
    ));
    let fresh = [sql(2, "SELECT 1"), sql(3, "SELECT 2")];
    objects.calls.lock().unwrap().clear();
    *objects.fail_get.lock().unwrap() = Some(StoreError::Unknown);
    let results = completed(engine.execute_group(&mut members(&fresh, &caller), limits()));
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().unwrap_err().code, "UNKNOWN");
    assert!(engine.cache.values().next().unwrap().session.is_none());
    let slot = engine.recovery.clone().try_acquire_owned().unwrap();
    assert_eq!(
        completed(engine.execute_group(&mut members(&fresh, &caller), limits()))[0]
            .as_ref()
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    drop(slot);
    engine.cache.clear();
    engine.worker = 0;
    assert_eq!(
        completed(engine.execute_group(&mut members(&fresh, &caller), limits()))[0]
            .as_ref()
            .unwrap_err()
            .code,
        "FENCED"
    );
    engine.worker = 100;
    engine.serial = u64::MAX;
    assert_eq!(
        completed(engine.execute_group(&mut members(&fresh, &caller), limits()))[0]
            .as_ref()
            .unwrap_err()
            .code,
        "LIMIT"
    );
    assert!(!objects
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call.starts_with("PUT ")));
}

#[test]
fn absent_cache_recovers_once_and_group_output_failure_preserves_each_receipt() {
    let (_directory, objects, mut engine) = fixture();
    engine.cache.clear();
    let caller = principal();
    let calls = [
        sql(
            2,
            "INSERT INTO grouped VALUES (1, 1) RETURNING zeroblob(8192)",
        ),
        sql(3, "INSERT INTO grouped VALUES (2, 2) RETURNING v"),
    ];
    let capacity = 2 * crate::output::BASE_BYTES + 1024;
    let pool = crate::output::tests::small_pool(capacity, capacity);
    let mut outputs: Vec<_> = calls
        .iter()
        .map(|_| pool.acquire(&caller, false).unwrap())
        .collect();
    let mut selected: Vec<_> = calls
        .iter()
        .zip(&mut outputs)
        .map(|(call, output)| Member {
            principal: &caller,
            call,
            deadline: until(),
            output: Some(output),
        })
        .collect();
    let results = completed(engine.execute_group(&mut selected, limits()));
    drop(selected);
    assert_eq!(
        results[0].as_ref().unwrap_err().code,
        "COMMITTED_BUT_UNAVAILABLE"
    );
    assert_eq!(
        results[0]
            .as_ref()
            .unwrap_err()
            .receipt
            .as_ref()
            .unwrap()
            .request
            .id,
        2
    );
    assert_eq!(
        results[1].as_ref().unwrap()["receipt"]["request"]["id"],
        "3"
    );
    for (value, output) in results.into_iter().zip(outputs) {
        let reply = crate::output::OwnedValue::new(value, output)
            .finish(until())
            .unwrap();
        let value: Value = serde_json::from_slice(&reply.bytes).unwrap();
        assert!(value["ok"] == true || value["error"]["code"] == "COMMITTED_BUT_UNAVAILABLE");
    }
    assert_eq!(
        objects
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("PUT ") && call.ends_with("/head"))
            .count(),
        1
    );
    assert_eq!(
        query(&mut engine, "SELECT count(*) FROM grouped").statements[0].rows,
        vec![vec![scap_sql::Value::Integer(2)]]
    );
}

#[test]
fn post_publication_decode_limit_never_discards_the_accepted_receipt() {
    let receipt = crate::output::tests::receipt();
    let result = scap_sql::TransactionResult { statements: vec![] };
    let bytes =
        scap_sql::encode_result(&result, scap_object::options::durable_sql_limits()).unwrap();
    let error = group_committed(
        scap_object::GroupCommitted {
            receipt: receipt.clone(),
            bytes,
        },
        1,
        None,
    )
    .unwrap_err();
    assert_eq!(error.code, "COMMITTED_BUT_UNAVAILABLE");
    assert_eq!(*error.receipt.unwrap(), receipt);
}

#[test]
fn a_stale_group_image_declines_before_sql_and_only_the_original_head_runs_on_fallback() {
    let (directory, objects, mut engine) = fixture();
    let mut other = Engine::new(
        objects.clone(),
        100,
        Options::default(),
        directory.path(),
        1,
        2621440,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    other
        .execute(
            &principal(),
            sql(2, "INSERT INTO grouped VALUES (1, 10)"),
            until(),
        )
        .unwrap();
    objects.calls.lock().unwrap().clear();
    let caller = principal();
    let calls = [
        sql(3, "INSERT INTO grouped VALUES (2, 20) RETURNING v"),
        sql(4, "INSERT INTO grouped VALUES (3, 30)"),
    ];
    assert!(matches!(
        engine.execute_group(&mut members(&calls, &caller), limits()),
        Outcome::Declined
    ));
    assert!(engine.cache.values().next().unwrap().session.is_none());
    assert!(!objects
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call.starts_with("PUT ")));
    let value = engine.execute(&caller, calls[0].clone(), until()).unwrap();
    assert_eq!(value["receipt"]["sequence"], "3");
    let Action::Execute { request, .. } = &calls[1].action else {
        unreachable!()
    };
    assert_eq!(
        engine
            .execute(
                &caller,
                call(Action::Lookup {
                    request: request.clone()
                }),
                until()
            )
            .unwrap(),
        json!({"state":"unknown"})
    );
    assert_eq!(
        query(&mut engine, "SELECT sum(v) FROM grouped").statements[0].rows,
        vec![vec![scap_sql::Value::Integer(30)]]
    );
}
