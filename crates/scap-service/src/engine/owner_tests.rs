use super::*;
use crate::owner_wire::{Identity as OwnerIdentity, Prepare, Reference};
use serde_json::json;

fn fixed(head: &Value, operation: u64, mode: &str, target: u64) -> Prepare {
    serde_json::from_value(json!({
        "creator":"3", "operation":operation.to_string(),
        "expected_revision":head["revision"], "expected_head_serial":head["head_serial"],
        "mode":mode, "target_worker":target.to_string(),
        "nonces":{"claim":"101", "cancel":"102", "activate":"103", "abort":"104"}
    }))
    .unwrap()
}

fn prepared(engine: &mut Engine, input: Prepare) -> Reference {
    let value = invoke(engine, Action::OwnerPrepare { input });
    assert_eq!(value["state"], "prepared");
    serde_json::from_value(value["prepared"]["reference"].clone()).unwrap()
}

fn inspect_action(plan: &Reference) -> Action {
    Action::OwnerInspect {
        identity: OwnerIdentity {
            creator: plan.creator,
            operation: plan.operation,
        },
    }
}

fn claim(plan: &Reference) -> Action {
    Action::OwnerClaim {
        plan: plan.clone(),
        expected_worker_instance: Decimal(100),
    }
}

fn resume(plan: &Reference) -> Action {
    Action::OwnerResume {
        plan: plan.clone(),
        expected_worker_instance: Decimal(100),
    }
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
fn durable_owner_activation_reuses_only_the_session_created_by_this_resume() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
    let plan = prepared(&mut engine, fixed(&head, 71, "activate", 100));
    let candidate = invoke(&mut engine, inspect_action(&plan));
    assert_eq!(candidate["state"], "prepared");
    assert!(candidate["accepted"].is_null());
    let accepted = invoke(&mut engine, claim(&plan));
    assert_eq!(accepted["state"], "claimed");
    assert_eq!(accepted["status"]["active"], false);
    assert_eq!(accepted["status"]["owner_epoch"], "1");
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
    let active = invoke(&mut engine, resume(&plan));
    assert_eq!(active["state"], "active");
    assert_eq!(active["status"]["revision"], "3");
    assert_eq!(active["status"]["owner_plan"], active["accepted"]);
    assert_eq!(engine.recovery.available_permits(), 1);
    assert!(engine.cache.values().all(|entry| entry.session.is_some()));
    let committed = invoke(
        &mut engine,
        action(1, "CREATE TABLE owned AS SELECT 42 AS v"),
    );
    assert_eq!(committed["state"], "committed");
    memory.calls.lock().unwrap().clear();
    let hot = invoke(
        &mut engine,
        Action::Query {
            statements: statements("SELECT v FROM owned"),
        },
    );
    assert_eq!(
        result(&hot).statements[0].rows,
        vec![vec![scap_sql::Value::Integer(42)]]
    );
    let calls = memory.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with("GET ") && calls[0].ends_with("/head"));

    memory.calls.lock().unwrap().clear();
    let observed = invoke(&mut engine, resume(&plan));
    assert_eq!(observed["state"], "active");
    assert_eq!(observed["status"]["revision"], "4");
    assert_eq!(observed["accepted"]["phase"]["revision"], "3");
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
    assert_eq!(head_puts(&memory), 0);
    assert!(memory.calls.lock().unwrap().iter().all(|call| {
        call.starts_with("GET ") && (call.ends_with("/head") || call.contains("/owner/v1/"))
    }));
    assert_eq!(
        result(&invoke(
            &mut engine,
            Action::Query {
                statements: statements("SELECT v FROM owned")
            }
        ))
        .statements[0]
            .rows,
        vec![vec![scap_sql::Value::Integer(42)]]
    );
}

#[test]
fn original_unknown_claim_is_inspected_after_cache_loss_and_never_replayed() {
    let (directory, memory, mut engine) = fixture(4, 10000);
    let head = active(&mut engine);
    invoke(
        &mut engine,
        action(1, "CREATE TABLE retained AS SELECT 'original' AS v"),
    );
    let current = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    assert!(revision(&current).0 > revision(&head).0);
    let input = fixed(&current, 72, "takeover", 100);
    let plan = prepared(&mut engine, input.clone());
    *memory.lose_head.lock().unwrap() = true;
    let before = head_puts(&memory);
    assert_eq!(
        engine
            .execute(&principal(), call(claim(&plan)), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(head_puts(&memory), before + 1);
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
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
    let recovered = invoke(&mut engine, Action::OwnerPrepare { input });
    assert_eq!(
        recovered["prepared"]["reference"],
        crate::owner_wire::reference(&plan.native().unwrap())
    );
    let observed = invoke(&mut engine, inspect_action(&plan));
    assert_eq!(observed["state"], "claimed");
    assert_eq!(observed["status"]["owner_epoch"], "2");
    assert_eq!(head_puts(&memory), before + 1);
    let finished = invoke(&mut engine, resume(&plan));
    assert_eq!(finished["state"], "active");
    assert_eq!(head_puts(&memory), before + 2);
    let original = invoke(
        &mut engine,
        Action::Query {
            statements: statements("SELECT v FROM retained"),
        },
    );
    assert_eq!(
        result(&original).statements[0].rows,
        vec![vec![scap_sql::Value::Text("original".into())]]
    );
}

#[test]
fn pending_owner_does_not_prepare_a_second_intent_and_abort_takes_one_step_per_call() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
    let plan = prepared(&mut engine, fixed(&head, 73, "activate", 100));
    let before = head_puts(&memory);
    let cancelling = invoke(&mut engine, Action::OwnerAbort { plan: plan.clone() });
    assert_eq!(cancelling["state"], "cancelling");
    assert_eq!(head_puts(&memory), before + 1);
    memory.calls.lock().unwrap().clear();
    let other = invoke(
        &mut engine,
        Action::OwnerPrepare {
            input: fixed(&cancelling["status"], 74, "takeover", 200),
        },
    );
    assert_eq!(other["state"], "pending");
    assert_eq!(
        other["reference"],
        crate::owner_wire::reference(&plan.native().unwrap())
    );
    assert!(memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| !call.starts_with("PUT ")));
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Activate {
                    expected_worker_instance: Some(Decimal(100)),
                    expected_revision: Decimal(2),
                    nonce: Decimal(80),
                }),
                until()
            )
            .unwrap_err()
            .code,
        "FENCED"
    );
    let aborted = invoke(&mut engine, Action::OwnerAbort { plan: plan.clone() });
    assert_eq!(aborted["state"], "aborted");
    assert_eq!(aborted["status"]["active"], false);
    assert_eq!(head_puts(&memory), 1);
    assert_eq!(invoke(&mut engine, Action::OwnerAbort { plan }), aborted);
    assert_eq!(head_puts(&memory), 1);
}

#[test]
fn guarded_owner_actions_reject_before_storage_and_current_authority_is_still_required() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
    let plan = prepared(&mut engine, fixed(&head, 75, "activate", 100));
    memory.calls.lock().unwrap().clear();
    let serial = engine.serial;
    let calls = [
        Action::OwnerClaim {
            plan: plan.clone(),
            expected_worker_instance: Decimal(200),
        },
        Action::OwnerResume {
            plan: plan.clone(),
            expected_worker_instance: Decimal(200),
        },
    ];
    for action in calls {
        assert_eq!(
            engine
                .execute(&principal(), call(action.clone()), until())
                .unwrap_err()
                .code,
            "TARGET_MISMATCH"
        );
        let mut foreign = principal();
        foreign.tenant = 99;
        assert_eq!(
            engine
                .execute(&foreign, call(action), until())
                .unwrap_err()
                .code,
            "DENIED"
        );
        assert!(memory.calls.lock().unwrap().is_empty());
        assert_eq!(engine.serial, serial);
        assert_eq!(engine.recovery.available_permits(), 1);
    }
    let mut reader = principal();
    reader.principal = 4;
    assert_eq!(
        engine
            .execute(&reader, call(inspect_action(&plan)), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 1);
    assert!(memory.calls.lock().unwrap()[0].ends_with("/head"));
    memory.calls.lock().unwrap().clear();
    let other = prepared(&mut engine, fixed(&head, 76, "takeover", 200));
    assert_eq!(
        engine
            .execute(&principal(), call(claim(&other)), until())
            .unwrap_err()
            .code,
        "FENCED"
    );
    assert_eq!(
        engine
            .execute(&principal(), call(resume(&other)), until())
            .unwrap_err()
            .code,
        "FENCED"
    );
    assert_eq!(head_puts(&memory), 0);
}

#[test]
fn recovery_saturation_does_not_block_owner_control_and_errors_do_not_leak_permits() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
    let plan = prepared(&mut engine, fixed(&head, 77, "activate", 100));
    let accepted = invoke(&mut engine, claim(&plan));
    let recovery = engine.recovery.clone();
    let slot = recovery.try_acquire().unwrap();
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        engine
            .execute(&principal(), call(resume(&plan)), until())
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
    assert_eq!(invoke(&mut engine, inspect_action(&plan)), accepted);
    let aborted = invoke(&mut engine, Action::OwnerAbort { plan: plan.clone() });
    assert_eq!(aborted["state"], "aborted");
    drop(slot);
    assert_eq!(engine.recovery.available_permits(), 1);
    for action in [
        Action::OwnerPrepare {
            input: fixed(&aborted["status"], 78, "takeover", 100),
        },
        inspect_action(&plan),
        claim(&plan),
        resume(&plan),
        Action::OwnerAbort { plan: plan.clone() },
    ] {
        *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
        assert_eq!(
            engine
                .execute(&principal(), call(action), until())
                .unwrap_err()
                .code,
            "UNKNOWN"
        );
        assert_eq!(engine.recovery.available_permits(), 1);
        assert!(engine.cache.values().all(|entry| entry.session.is_none()));
    }
}

#[test]
fn bounded_owner_responses_release_output_credit_for_every_control() {
    use crate::output::tests::{small_pool, usage};
    use crate::output::BASE_BYTES;
    let (_directory, _memory, mut engine) = fixture(4, 10000);
    let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
    let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let prepared = budgeted(
        &mut engine,
        Action::OwnerPrepare {
            input: fixed(&head, 79, "activate", 100),
        },
        &pool,
    );
    assert_eq!(prepared["value"]["state"], "prepared");
    let plan: Reference =
        serde_json::from_value(prepared["value"]["prepared"]["reference"].clone()).unwrap();
    for action in [
        inspect_action(&plan),
        claim(&plan),
        resume(&plan),
        Action::OwnerAbort { plan: plan.clone() },
    ] {
        let response = budgeted(&mut engine, action, &pool);
        assert_eq!(response["ok"], true);
        assert_eq!(usage(&pool), (0, 0, 0));
    }
}

#[test]
fn internal_owner_dispatch_defensively_rejects_invalid_typed_inputs_before_io() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
    let plan = prepared(&mut engine, fixed(&head, 80, "activate", 100));
    let mut input = fixed(&head, 81, "takeover", 100);
    input.expected_revision = Decimal(0);
    let mut reference = plan;
    reference.descriptor_hash = "invalid".into();
    let mut entry = engine.cache.pop_first().unwrap().1;
    let path = engine.directory.path().join("invalid-owner-input");
    memory.calls.lock().unwrap().clear();
    for action in [
        Action::OwnerPrepare { input },
        Action::OwnerInspect {
            identity: OwnerIdentity {
                creator: Decimal(0),
                operation: Decimal(80),
            },
        },
        claim(&reference),
        resume(&reference),
        Action::OwnerAbort { plan: reference },
    ] {
        assert_eq!(
            engine
                .dispatch(&principal(), &mut entry, action, &path, until(), None)
                .unwrap_err()
                .code,
            "INVALID"
        );
        assert!(memory.calls.lock().unwrap().is_empty());
        assert_eq!(engine.recovery.available_permits(), 1);
        assert!(!path.exists());
    }
}

#[test]
fn zero_owner_payload_budget_keeps_authority_healthy_and_does_not_activate() {
    for bytes_limit in [false, true] {
        let (_directory, memory, mut engine) = fixture(4, 10000);
        if bytes_limit {
            engine.options.owner_recovery_bytes = 0;
        } else {
            engine.options.owner_recovery_gets = 0;
        }
        let head = invoke(&mut engine, Action::Create { nonce: Decimal(11) });
        let plan = prepared(&mut engine, fixed(&head, 82, "activate", 100));
        let accepted = invoke(&mut engine, claim(&plan));
        memory.calls.lock().unwrap().clear();
        for _ in 0..2 {
            assert_eq!(
                engine
                    .execute(&principal(), call(resume(&plan)), until())
                    .unwrap_err()
                    .code,
                "LIMIT"
            );
            assert_eq!(engine.recovery.available_permits(), 1);
            assert!(engine.cache.values().all(|entry| entry.session.is_none()));
            assert_eq!(invoke(&mut engine, inspect_action(&plan)), accepted);
        }
        assert_eq!(head_puts(&memory), 0);
        assert!(memory
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| !call.contains("/objects/")));
        // The local owner recovery limit is not corruption and does not change
        // the ordinary read contract. A fresh READ still verifies real payload.
        let query = invoke(
            &mut engine,
            Action::Query {
                statements: statements("SELECT 42"),
            },
        );
        assert_eq!(
            result(&query).statements[0].rows,
            vec![vec![scap_sql::Value::Integer(42)]]
        );
        let aborted = invoke(&mut engine, Action::OwnerAbort { plan });
        assert_eq!(aborted["state"], "aborted");
        assert_eq!(aborted["status"]["active"], false);
    }
}
