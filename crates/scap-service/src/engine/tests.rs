use super::*;
use crate::tests::{call, principal, scope, until, Memory};
use crate::wire::{Decimal, Identity, Parameter, WirePermission, WireStatement};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use scap_object::format::Lifecycle;

#[path = "owner_tests.rs"]
mod owner_tests;

#[path = "snapshot_tests.rs"]
mod snapshot_tests;

fn fixture(maximum: usize, pages: u64) -> (tempfile::TempDir, Arc<Memory>, Engine) {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    let mut options = Options::default();
    options.retention.max_entries = 2;
    let engine = Engine::new(
        memory.clone(),
        100,
        options,
        directory.path(),
        maximum,
        pages,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    (directory, memory, engine)
}

fn statements(sql: &str) -> Vec<WireStatement> {
    vec![WireStatement {
        sql: sql.into(),
        params: vec![],
    }]
}
fn identity(id: u64, statements: &[WireStatement]) -> Identity {
    let request = scap_object::request(1, id, 3, &wire::statements(statements).unwrap()).unwrap();
    Identity {
        epoch: Decimal(request.epoch),
        id: Decimal(request.id),
        principal: Decimal(3),
        fingerprint: request.fingerprint,
    }
}
fn action(id: u64, sql: &str) -> Action {
    let statements = statements(sql);
    Action::Execute {
        request: identity(id, &statements),
        statements,
    }
}
fn invoke(engine: &mut Engine, action: Action) -> Value {
    engine.execute(&principal(), call(action), until()).unwrap()
}
fn revision(value: &Value) -> Decimal {
    Decimal(value["revision"].as_str().unwrap().parse().unwrap())
}
fn active(engine: &mut Engine) -> Value {
    let head = invoke(engine, Action::Create { nonce: Decimal(11) });
    invoke(
        engine,
        Action::Activate {
            expected_worker_instance: None,
            expected_revision: revision(&head),
            nonce: Decimal(12),
        },
    )
}
fn result(value: &Value) -> scap_sql::TransactionResult {
    let bytes = STANDARD.decode(value["result"].as_str().unwrap()).unwrap();
    scap_sql::decode_result(&bytes, scap_object::options::durable_sql_limits()).unwrap()
}

#[test]
fn reader_refreshes_a_stale_private_image_before_sql_and_preserves_fresh_authorization() {
    let (directory, memory, mut writer) = fixture(4, 10000);
    active(&mut writer);
    invoke(
        &mut writer,
        action(1, "CREATE TABLE read_pool(value INTEGER)"),
    );
    let mut reader = Engine::new(
        memory.clone(),
        200,
        Options::default(),
        directory.path(),
        1,
        10000,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap()
    .with_query_refresh(true);
    let query = Action::Query {
        statements: statements("SELECT value FROM read_pool"),
    };
    assert!(result(&invoke(&mut reader, query.clone())).statements[0]
        .rows
        .is_empty());
    let make_reader = || {
        Engine::new(
            memory.clone(),
            201,
            Options::default(),
            directory.path(),
            1,
            10000,
            Arc::new(Semaphore::new(1)),
        )
        .unwrap()
    };
    let mut legacy = make_reader();
    let mut faulted = make_reader().with_query_refresh(true);
    invoke(&mut legacy, query.clone());
    invoke(&mut faulted, query.clone());
    invoke(&mut writer, action(2, "INSERT INTO read_pool VALUES (42)"));
    assert_eq!(
        legacy
            .execute(&principal(), call(query.clone()), until())
            .unwrap_err()
            .code,
        "STALE_SNAPSHOT"
    );
    // Once the stale pre-SQL image has been rebuilt, even the next HEAD GET
    // failure is returned directly. There is no second reactivation attempt.
    memory.calls.lock().unwrap().clear();
    *memory.fail_head_after.lock().unwrap() = Some(2);
    assert_eq!(
        faulted
            .execute(&principal(), call(query.clone()), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(
        memory
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.ends_with("/head"))
            .count(),
        3
    );
    let values = result(&invoke(&mut reader, query.clone()));
    assert_eq!(
        values.statements[0].rows,
        vec![vec![scap_sql::Value::Integer(42)]]
    );
    assert_eq!(reader.cache.len(), 1);
    assert!(reader.cache.values().next().unwrap().session.is_some());
    // Every warm read still GETs HEAD. A failed GET must not fall back to the
    // successfully rebuilt local image or rerun the original query.
    memory.calls.lock().unwrap().clear();
    *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        reader
            .execute(&principal(), call(query.clone()), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 1);
    assert!(reader.cache.values().next().unwrap().session.is_none());
    invoke(&mut reader, query.clone());
    let database = Database::new(memory.clone(), scope().native().unwrap(), 100).unwrap();
    let status = database.status(3, until()).unwrap();
    database
        .set_policy(
            3,
            status.revision,
            18,
            vec![scap_object::format::Permission {
                principal: 3,
                read: false,
                write: true,
                admin: true,
            }],
            until(),
        )
        .unwrap();
    assert_eq!(
        reader
            .execute(&principal(), call(query), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
}

#[test]
fn read_refresh_does_not_hide_sql_errors_or_retry_when_recovery_has_no_capacity() {
    let (directory, memory, mut writer) = fixture(4, 10000);
    active(&mut writer);
    invoke(
        &mut writer,
        action(1, "CREATE TABLE read_pool(value INTEGER)"),
    );
    let recovery = Arc::new(Semaphore::new(1));
    let mut reader = Engine::new(
        memory.clone(),
        200,
        Options::default(),
        directory.path(),
        1,
        10000,
        recovery.clone(),
    )
    .unwrap()
    .with_query_refresh(true);
    let query = Action::Query {
        statements: statements("SELECT value FROM read_pool"),
    };
    invoke(&mut reader, query.clone());
    invoke(&mut writer, action(2, "INSERT INTO read_pool VALUES (8)"));
    let held = recovery.try_acquire().unwrap();
    assert_eq!(
        reader
            .execute(&principal(), call(query.clone()), until())
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    drop(held);
    invoke(&mut reader, query);
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        reader
            .execute(
                &principal(),
                call(Action::Query {
                    statements: statements("INSERT INTO read_pool VALUES (9)")
                }),
                until()
            )
            .unwrap_err()
            .code,
        "ENGINE"
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 1);
}

fn budgeted(engine: &mut Engine, action: Action, pool: &Arc<crate::output::Pool>) -> Value {
    let deadline = until();
    let mut context = pool
        .acquire(&principal(), action.admission() != "data")
        .unwrap();
    let value = engine.execute_budgeted(&principal(), call(action), deadline, &mut context);
    let reply = crate::output::OwnedValue::new(value, context)
        .finish(deadline)
        .unwrap();
    serde_json::from_slice(&reply.bytes).unwrap()
}

#[test]
fn budgeted_engine_preserves_query_commit_resolution_and_small_head_shapes() {
    use crate::output::tests::{small_pool, usage};
    use crate::output::BASE_BYTES;
    let (_directory, _memory, mut engine) = fixture(4, 10000);
    let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let created = budgeted(&mut engine, Action::Create { nonce: Decimal(11) }, &pool);
    assert_eq!(created["value"]["revision"], "1");
    let activated = budgeted(
        &mut engine,
        Action::Activate {
            expected_worker_instance: None,
            expected_revision: Decimal(1),
            nonce: Decimal(12),
        },
        &pool,
    );
    assert_eq!(activated["value"]["active"], true);
    let read = budgeted(
        &mut engine,
        Action::Query {
            statements: statements("SELECT 'budgeted'"),
        },
        &pool,
    );
    assert_eq!(
        result(&read["value"]).statements[0].rows,
        vec![vec![scap_sql::Value::Text("budgeted".into())]]
    );

    let write = action(1, "CREATE TABLE budgeted (x)");
    let request = match &write {
        Action::Execute { request, .. } => request.clone(),
        _ => unreachable!(),
    };
    let committed = budgeted(&mut engine, write, &pool);
    assert_eq!(committed["value"]["state"], "committed");
    let looked_up = budgeted(
        &mut engine,
        Action::Lookup {
            request: request.clone(),
        },
        &pool,
    );
    assert_eq!(looked_up, committed);
    let cancelled_committed = budgeted(&mut engine, Action::Cancel { request }, &pool);
    assert_eq!(cancelled_committed, committed);
    let pending = identity(2, &statements("INSERT INTO budgeted VALUES (1)"));
    assert_eq!(
        budgeted(
            &mut engine,
            Action::Lookup {
                request: pending.clone()
            },
            &pool
        )["value"]["state"],
        "unknown"
    );
    assert_eq!(
        budgeted(&mut engine, Action::Cancel { request: pending }, &pool)["value"]["state"],
        "cancelled"
    );
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn exhausted_output_never_relabels_a_durable_write_or_retained_resolution_as_uncommitted() {
    use crate::output::tests::{small_pool, usage};
    use crate::output::BASE_BYTES;
    let (_directory, _memory, mut engine) = fixture(4, 10000);
    active(&mut engine);
    let pool = small_pool(BASE_BYTES, BASE_BYTES);
    let read = budgeted(
        &mut engine,
        Action::Query {
            statements: statements("SELECT 1"),
        },
        &pool,
    );
    assert_eq!(read["error"]["code"], "LIMIT");
    assert!(read["error"].get("receipt").is_none());
    let write = action(1, "CREATE TABLE output_committed (x)");
    let request = match &write {
        Action::Execute { request, .. } => request.clone(),
        _ => unreachable!(),
    };
    let error = budgeted(&mut engine, write, &pool);
    assert_eq!(error["error"]["code"], "COMMITTED_BUT_UNAVAILABLE");
    let original = error["error"]["receipt"].clone();
    let lookup = invoke(
        &mut engine,
        Action::Lookup {
            request: request.clone(),
        },
    );
    assert_eq!(lookup["receipt"], original);
    assert_eq!(lookup["state"], "committed");
    // Protected control admission still works when shared dynamic credit is
    // occupied by another operation. Both retained result verbs preserve CBU.
    let occupied = pool.acquire(&principal(), false).unwrap();
    for action in [
        Action::Lookup {
            request: request.clone(),
        },
        Action::Cancel { request },
    ] {
        let error = budgeted(&mut engine, action, &pool);
        assert_eq!(error["error"]["code"], "COMMITTED_BUT_UNAVAILABLE");
        assert_eq!(error["error"]["receipt"], original);
    }
    let status = budgeted(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
        &pool,
    );
    assert_eq!(status["value"]["sequence"], "1");
    drop(occupied);
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn expected_worker_guard_rejects_before_authority_cache_or_recovery_effects() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    for action in [
        Action::Status {
            expected_worker_instance: Some(Decimal(200)),
        },
        Action::Activate {
            expected_revision: Decimal(1),
            nonce: Decimal(1),
            expected_worker_instance: Some(Decimal(200)),
        },
        Action::Takeover {
            expected_revision: Decimal(1),
            nonce: Decimal(2),
            expected_worker_instance: Some(Decimal(200)),
        },
    ] {
        assert_eq!(
            engine
                .execute(&principal(), call(action), until())
                .unwrap_err()
                .code,
            "TARGET_MISMATCH"
        );
        assert!(memory.calls.lock().unwrap().is_empty());
        assert!(engine.cache.is_empty());
        assert_eq!(engine.serial, 0);
        assert_eq!(engine.recovery.available_permits(), 1);
    }
    let mut wrong_tenant = principal();
    wrong_tenant.tenant = 99;
    assert_eq!(
        engine
            .execute(
                &wrong_tenant,
                call(Action::Status {
                    expected_worker_instance: Some(Decimal(200)),
                }),
                until(),
            )
            .unwrap_err()
            .code,
        "DENIED"
    );
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Status {
                    expected_worker_instance: Some(Decimal(0)),
                }),
                until(),
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
    assert!(engine.cache.is_empty());
    assert_eq!(engine.serial, 0);
    let head = active(&mut engine);
    let claimed = invoke(
        &mut engine,
        Action::Takeover {
            expected_revision: revision(&head),
            nonce: Decimal(50),
            expected_worker_instance: Some(Decimal(100)),
        },
    );
    assert_eq!(claimed["owner_instance"], "100");
    assert_eq!(claimed["active"], false);
    let activated = invoke(
        &mut engine,
        Action::Activate {
            expected_revision: revision(&claimed),
            nonce: Decimal(51),
            expected_worker_instance: Some(Decimal(100)),
        },
    );
    assert_eq!(activated["active"], true);
    assert_eq!(activated["owner_epoch"], claimed["owner_epoch"]);
}

#[test]
fn guarded_status_reads_fresh_authority_on_a_nonowner_without_native_recovery() {
    let (directory, memory, mut creator) = fixture(4, 10000);
    let created = invoke(&mut creator, Action::Create { nonce: Decimal(11) });
    let administrator = WirePermission {
        principal: Decimal(3),
        read: true,
        write: true,
        admin: true,
    };
    let granted = invoke(
        &mut creator,
        Action::Policy {
            expected_revision: revision(&created),
            nonce: Decimal(12),
            permissions: vec![
                administrator.clone(),
                WirePermission {
                    principal: Decimal(4),
                    read: true,
                    write: false,
                    admin: false,
                },
            ],
        },
    );
    let mut observer = Engine::new(
        memory.clone(),
        200,
        Options::default(),
        directory.path(),
        1,
        10000,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    let reader = Principal {
        principal: 4,
        provision: false,
        ..principal()
    };
    let status = Action::Status {
        expected_worker_instance: Some(Decimal(200)),
    };
    let only_head = vec![format!("GET {}", head_key(&scope().native().unwrap()))];
    memory.calls.lock().unwrap().clear();
    let observed = observer
        .execute(&reader, call(status.clone()), until())
        .unwrap();
    assert_eq!(observed, granted);
    assert_eq!(observed["owner_instance"], "100");
    assert_eq!(*memory.calls.lock().unwrap(), only_head);
    assert!(observer.cache.values().all(|entry| entry.session.is_none()));
    assert_eq!(observer.recovery.available_permits(), 1);

    invoke(
        &mut creator,
        Action::Policy {
            expected_revision: revision(&granted),
            nonce: Decimal(13),
            permissions: vec![administrator],
        },
    );
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        observer
            .execute(&reader, call(status.clone()), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
    assert_eq!(*memory.calls.lock().unwrap(), only_head);
    memory.calls.lock().unwrap().clear();
    *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        observer
            .execute(&principal(), call(status), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(*memory.calls.lock().unwrap(), only_head);
    assert!(observer.cache.values().all(|entry| entry.session.is_none()));
}

#[test]
fn native_sessions_preserve_original_ack_lookup_and_independent_reader() {
    let (directory, memory, mut engine) = fixture(4, 10000);
    let head = active(&mut engine);
    assert_eq!(head["revision"], "2");
    let first = action(1, "CREATE TABLE t (x INTEGER)");
    invoke(&mut engine, first);
    let insert = action(2, "INSERT INTO t VALUES (random()) RETURNING x");
    let ack = invoke(&mut engine, insert.clone());
    assert_eq!(ack["state"], "committed");
    let request = match insert {
        Action::Execute { request, .. } => request,
        _ => unreachable!(),
    };
    let lookup = invoke(
        &mut engine,
        Action::Lookup {
            request: request.clone(),
        },
    );
    assert_eq!(lookup, ack);
    assert_eq!(
        invoke(
            &mut engine,
            Action::Cancel {
                request: request.clone()
            }
        ),
        ack
    );
    let query = invoke(
        &mut engine,
        Action::Query {
            statements: statements("SELECT x FROM t"),
        },
    );
    assert_eq!(
        result(&query).statements[0].rows,
        result(&ack).statements[0].rows
    );
    let opened = invoke(&mut engine, Action::Open {});
    assert_eq!(opened["sequence"], "2");
    let mut reader = Engine::new(
        memory.clone(),
        200,
        Options::default(),
        directory.path(),
        4,
        10000,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    assert_eq!(
        result(&invoke(
            &mut reader,
            Action::Query {
                statements: statements("SELECT x FROM t")
            }
        ))
        .statements[0]
            .rows,
        result(&ack).statements[0].rows
    );
    assert_eq!(
        reader
            .execute(
                &principal(),
                call(action(3, "INSERT INTO t VALUES (8)")),
                until()
            )
            .unwrap_err()
            .code,
        "FENCED"
    );
    let head = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    let closed = invoke(
        &mut engine,
        Action::CloseFull {
            expected_revision: revision(&head),
            nonce: Decimal(13),
        },
    );
    assert_eq!(closed["request_epoch"], "2");
    assert_eq!(invoke(&mut engine, Action::Lookup { request }), ack);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(action(3, "INSERT INTO t VALUES (8)")),
                until()
            )
            .unwrap_err()
            .code,
        "CLOSED"
    );
}

#[test]
fn cancellation_ambiguous_publication_and_full_scope_cache_identity() {
    let (_directory, memory, mut engine) = fixture(8, 10000);
    active(&mut engine);
    let sql = statements("CREATE TABLE cancelled (x)");
    let request = identity(1, &sql);
    assert_eq!(
        invoke(
            &mut engine,
            Action::Lookup {
                request: request.clone()
            }
        )["state"],
        "unknown"
    );
    assert_eq!(
        invoke(
            &mut engine,
            Action::Cancel {
                request: request.clone()
            }
        )["state"],
        "cancelled"
    );
    assert!(engine
        .execute(
            &principal(),
            call(Action::Execute {
                request,
                statements: sql
            }),
            until()
        )
        .is_err());
    let write = action(2, "CREATE TABLE committed (x)");
    *memory.lose_head.lock().unwrap() = true;
    assert_eq!(
        engine
            .execute(&principal(), call(write.clone()), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    let request = match write {
        Action::Execute { request, .. } => request,
        _ => unreachable!(),
    };
    assert_eq!(
        invoke(&mut engine, Action::Lookup { request })["state"],
        "committed"
    );
    // Both identity components are part of a local cache key, even though the
    // durable HEAD key remains the same to reject reincarnation ABA.
    for generation in [false, true] {
        let mut stale = call(Action::Status {
            expected_worker_instance: None,
        });
        if generation {
            stale.scope.generation.0 += 1;
        } else {
            stale.scope.incarnation.0 += 1;
        }
        assert_eq!(
            engine
                .execute(&principal(), stale, until())
                .unwrap_err()
                .code,
            "CORRUPT"
        );
        assert_eq!(
            invoke(
                &mut engine,
                Action::Status {
                    expected_worker_instance: None
                }
            )["scope"]["generation"],
            "5"
        );
    }
    let mut wrong = identity(77, &statements("SELECT 1"));
    wrong.fingerprint = "a".repeat(64);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Execute {
                    request: wrong,
                    statements: statements("SELECT 1")
                }),
                until()
            )
            .unwrap_err()
            .code,
        "REQUEST_CONFLICT"
    );
    let bad = WireStatement {
        sql: "SELECT ?".into(),
        params: vec![Parameter::Integer {
            value: "bad".into(),
        }],
    };
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Query {
                    statements: vec![bad]
                }),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
}

#[test]
fn ownership_quota_policy_and_lifecycle_use_the_same_remote_order() {
    let (directory, memory, mut first) = fixture(4, 10000);
    active(&mut first);
    invoke(&mut first, action(1, "CREATE TABLE t (x)"));
    let mut second = Engine::new(
        memory.clone(),
        200,
        Options::default(),
        directory.path(),
        4,
        10000,
        Arc::new(Semaphore::new(1)),
    )
    .unwrap();
    let head = invoke(
        &mut second,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    let fenced = invoke(
        &mut second,
        Action::Takeover {
            expected_worker_instance: None,
            expected_revision: revision(&head),
            nonce: Decimal(31),
        },
    );
    assert!(!fenced["active"].as_bool().unwrap());
    let head = invoke(
        &mut second,
        Action::Activate {
            expected_worker_instance: None,
            expected_revision: revision(&fenced),
            nonce: Decimal(32),
        },
    );
    assert_eq!(
        first
            .execute(
                &principal(),
                call(action(2, "INSERT INTO t VALUES (1)")),
                until()
            )
            .unwrap_err()
            .code,
        "FENCED"
    );
    let head = invoke(
        &mut second,
        Action::Quota {
            expected_revision: revision(&head),
            nonce: Decimal(33),
            max_bytes: None,
        },
    );
    assert!(head["max_bytes"].is_null());
    let head = invoke(
        &mut second,
        Action::Quota {
            expected_revision: revision(&head),
            nonce: Decimal(34),
            max_bytes: Some(Decimal(1024 * 1024)),
        },
    );
    assert_eq!(head["max_bytes"], "1048576");
    let head = invoke(
        &mut second,
        Action::Policy {
            expected_revision: revision(&head),
            nonce: Decimal(35),
            permissions: vec![
                WirePermission {
                    principal: Decimal(3),
                    read: true,
                    write: true,
                    admin: true,
                },
                WirePermission {
                    principal: Decimal(9),
                    read: true,
                    write: false,
                    admin: false,
                },
            ],
        },
    );
    let reader = Principal {
        principal: 9,
        provision: false,
        deployment_inventory: false,
        ..principal()
    };
    assert!(second
        .execute(
            &reader,
            call(Action::Query {
                statements: statements("SELECT * FROM t")
            }),
            until()
        )
        .is_ok());
    let head = invoke(
        &mut second,
        Action::Policy {
            expected_revision: revision(&head),
            nonce: Decimal(36),
            permissions: vec![WirePermission {
                principal: Decimal(3),
                read: true,
                write: true,
                admin: true,
            }],
        },
    );
    assert_eq!(
        second
            .execute(
                &reader,
                call(Action::Query {
                    statements: statements("SELECT * FROM t")
                }),
                until()
            )
            .unwrap_err()
            .code,
        "DENIED"
    );
    let head = invoke(
        &mut second,
        Action::Lifecycle {
            expected_revision: revision(&head),
            nonce: Decimal(37),
            lifecycle: Lifecycle::Maintenance,
        },
    );
    assert_eq!(
        second
            .execute(
                &principal(),
                call(action(2, "INSERT INTO t VALUES (1)")),
                until()
            )
            .unwrap_err()
            .code,
        "LIFECYCLE"
    );
    let head = invoke(
        &mut second,
        Action::Lifecycle {
            expected_revision: revision(&head),
            nonce: Decimal(38),
            lifecycle: Lifecycle::Ready,
        },
    );
    assert_eq!(head["lifecycle"], "ready");
    *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        second
            .execute(
                &principal(),
                call(Action::Query {
                    statements: statements("SELECT * FROM t")
                }),
                until()
            )
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
}

#[test]
fn cache_eviction_is_bounded_and_recovery_slots_are_released_after_failure() {
    let (_directory, memory, mut engine) = fixture(1, 10000);
    active(&mut engine);
    invoke(&mut engine, action(1, "CREATE TABLE t (x)"));
    assert!(engine.cache.values().next().unwrap().session.is_some());
    let mut other = call(Action::Create { nonce: Decimal(10) });
    other.scope.database.0 = 10;
    engine.execute(&principal(), other, until()).unwrap();
    assert_eq!(engine.cache.len(), 1);
    assert!(engine.cache.keys().next().unwrap().contains("/10/head"));
    invoke(&mut engine, Action::Open {});
    assert!(engine.cache.values().next().unwrap().session.is_some());
    engine.max_pages = 1;
    engine.trim();
    assert!(engine.cache.is_empty());
    engine.max_pages = 10000;
    let semaphore = engine.recovery.clone();
    let permit = semaphore.try_acquire().unwrap();
    assert_eq!(
        engine
            .execute(&principal(), call(Action::Open {}), until())
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    let head = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Activate {
                    expected_worker_instance: None,
                    expected_revision: revision(&head),
                    nonce: Decimal(22)
                }),
                until()
            )
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    drop(permit);
    *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        engine
            .execute(&principal(), call(Action::Open {}), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(semaphore.available_permits(), 1);
    invoke(&mut engine, Action::Open {});
}

#[test]
fn invalid_inputs_fail_before_database_io_and_startup_does_not_make_unbounded_resources() {
    let (directory, memory, mut engine) = fixture(1, 10);
    let mut bad = call(Action::Status {
        expected_worker_instance: None,
    });
    bad.version = 2;
    assert_eq!(
        engine.execute(&principal(), bad, until()).unwrap_err().code,
        "VERSION"
    );
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Status {
                    expected_worker_instance: None
                }),
                Instant::now()
            )
            .unwrap_err()
            .code,
        "DEADLINE"
    );
    let mut bad = call(Action::Status {
        expected_worker_instance: None,
    });
    bad.scope.database.0 = 0;
    assert_eq!(
        engine.execute(&principal(), bad, until()).unwrap_err().code,
        "INVALID"
    );
    let mut bad = call(Action::Status {
        expected_worker_instance: None,
    });
    bad.scope.tenant.0 = 99;
    assert_eq!(
        engine.execute(&principal(), bad, until()).unwrap_err().code,
        "DENIED"
    );
    assert_eq!(
        engine
            .execute(
                &Principal {
                    provision: false,
                    deployment_inventory: false,
                    ..principal()
                },
                call(Action::Create { nonce: Decimal(1) }),
                until()
            )
            .unwrap_err()
            .code,
        "DENIED"
    );
    engine.serial = u64::MAX;
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Status {
                    expected_worker_instance: None
                }),
                until()
            )
            .unwrap_err()
            .code,
        "LIMIT"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
    for (worker, maximum, pages) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(Engine::new(
            memory.clone(),
            worker,
            Options::default(),
            directory.path(),
            maximum,
            pages,
            Arc::new(Semaphore::new(1))
        )
        .is_err());
    }
    let options = Options {
        max_vm_steps: 0,
        ..Options::default()
    };
    assert!(Engine::new(
        memory.clone(),
        1,
        options,
        directory.path(),
        1,
        1,
        Arc::new(Semaphore::new(1))
    )
    .is_err());
    assert!(Engine::new(
        memory.clone(),
        1,
        Options::default(),
        &directory.path().join("missing"),
        1,
        1,
        Arc::new(Semaphore::new(1))
    )
    .is_err());
    engine.serial = 0;
    engine.worker = 0;
    assert!(engine
        .execute(
            &principal(),
            call(Action::Status {
                expected_worker_instance: None
            }),
            until()
        )
        .is_err());
}

#[test]
fn failure_to_encode_an_already_committed_result_keeps_its_receipt() {
    let receipt = scap_object::Receipt {
        scope: scope().native().unwrap(),
        request: identity(1, &statements("SELECT 1")).native(3).unwrap(),
        sequence: 1,
        transition: scap_object::format::Transition {
            revision: 2,
            nonce: 1,
        },
        data_root: "a".repeat(64),
        result_hash: "b".repeat(64),
    };
    let bad = scap_sql::TransactionResult {
        statements: vec![scap_sql::StatementResult {
            columns: vec![],
            rows: vec![vec![]],
            affected_rows: 0,
            last_insert_rowid: 0,
        }],
    };
    let error = committed(receipt.clone(), bad).unwrap_err();
    assert_eq!(error.code, "COMMITTED_BUT_UNAVAILABLE");
    assert_eq!(*error.receipt.unwrap(), receipt);
}

#[test]
fn every_failed_admin_or_resolution_call_propagates_without_a_second_attempt() {
    let (_directory, memory, mut engine) = fixture(8, 10000);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Create { nonce: Decimal(0) }),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
    active(&mut engine);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Create { nonce: Decimal(1) }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    for operation in [
        Action::Activate {
            expected_worker_instance: None,
            expected_revision: Decimal(99),
            nonce: Decimal(1),
        },
        Action::Takeover {
            expected_worker_instance: None,
            expected_revision: Decimal(99),
            nonce: Decimal(1),
        },
        Action::CloseFull {
            expected_revision: Decimal(99),
            nonce: Decimal(1),
        },
        Action::Policy {
            expected_revision: Decimal(99),
            nonce: Decimal(1),
            permissions: vec![WirePermission {
                principal: Decimal(3),
                read: true,
                write: true,
                admin: true,
            }],
        },
        Action::Quota {
            expected_revision: Decimal(99),
            nonce: Decimal(1),
            max_bytes: None,
        },
        Action::Lifecycle {
            expected_revision: Decimal(99),
            nonce: Decimal(1),
            lifecycle: Lifecycle::Maintenance,
        },
    ] {
        assert_eq!(
            engine
                .execute(&principal(), call(operation), until())
                .unwrap_err()
                .code,
            "CONFLICT"
        );
    }
    let valid = identity(7, &statements("SELECT 1"));
    let mut wrong = valid.clone();
    wrong.principal.0 = 999;
    for operation in [
        Action::Lookup {
            request: wrong.clone(),
        },
        Action::Cancel {
            request: wrong.clone(),
        },
        Action::Execute {
            request: wrong,
            statements: statements("SELECT 1"),
        },
    ] {
        assert_eq!(
            engine
                .execute(&principal(), call(operation), until())
                .unwrap_err()
                .code,
            "DENIED"
        );
    }
    for operation in [
        Action::Lookup {
            request: valid.clone(),
        },
        Action::Cancel {
            request: valid.clone(),
        },
    ] {
        *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
        assert_eq!(
            engine
                .execute(&principal(), call(operation), until())
                .unwrap_err()
                .code,
            "UNKNOWN"
        );
    }
    let bad = WireStatement {
        sql: "SELECT ?".into(),
        params: vec![Parameter::Integer {
            value: "bad".into(),
        }],
    };
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Execute {
                    request: valid.clone(),
                    statements: vec![bad]
                }),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Execute {
                    request: valid.clone(),
                    statements: statements("")
                }),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::Execute {
                    request: valid,
                    statements: statements("SELECT 1")
                }),
                until()
            )
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    // Restoration succeeds, but the final status HEAD is unavailable. The
    // operation must not report the previous root as currently available.
    *memory.fail_head_after.lock().unwrap() = Some(1);
    assert_eq!(
        engine
            .execute(&principal(), call(Action::Open {}), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    let invalid = scap_sql::TransactionResult {
        statements: vec![scap_sql::StatementResult {
            columns: vec![],
            rows: vec![vec![]],
            affected_rows: 0,
            last_insert_rowid: 0,
        }],
    };
    assert_eq!(queried(invalid).unwrap_err().code, "CORRUPT");
}

#[cfg(target_os = "linux")]
#[test]
fn direct_engine_construction_rejects_unsupported_cache_mounts() {
    let error = Engine::new(
        Arc::new(Memory::default()),
        100,
        Options::default(),
        Path::new("/proc"),
        4,
        10000,
        Arc::new(Semaphore::new(1)),
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "CACHE_IO");
}

#[cfg(target_os = "linux")]
#[test]
fn directory_creation_failure_after_storage_admission_is_reported() {
    let directory = tempfile::tempdir().unwrap();
    let mut attempted = false;
    let error = create_cache(directory.path(), |parent| {
        assert_eq!(parent, directory.path());
        attempted = true;
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "controlled directory creation failure",
        ))
    })
    .err()
    .unwrap();
    assert!(attempted);
    assert_eq!(error.code, "CACHE_IO");
    assert!(directory.path().exists());
}

fn physical_serial(value: &Value) -> Decimal {
    Decimal(value["head_serial"].as_str().unwrap().parse().unwrap())
}
fn copy_serial(value: &Value) -> Decimal {
    Decimal(
        value["storage"]["plan"]["serial"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    )
}
fn batch_serial(value: &Value) -> Decimal {
    Decimal(
        value["status"]["storage"]["sweep"]["serial"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    )
}

#[test]
fn direct_terminal_management_requires_admin_and_retires_metadata_before_final_payload_gc() {
    use scap_object::format::{decode_head, head_key, TerminalSeal};
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let activated = active(&mut engine);
    for action in [
        Action::StorageStatus {},
        Action::RetireStorage {
            expected_head_serial: physical_serial(&activated),
        },
    ] {
        assert_eq!(
            engine
                .execute(&principal(), call(action), until())
                .unwrap_err()
                .code,
            "LIFECYCLE"
        );
    }
    invoke(
        &mut engine,
        Action::Policy {
            expected_revision: revision(&activated),
            nonce: Decimal(20),
            permissions: vec![
                WirePermission {
                    principal: Decimal(3),
                    read: true,
                    write: true,
                    admin: true,
                },
                WirePermission {
                    principal: Decimal(4),
                    read: true,
                    write: false,
                    admin: false,
                },
                WirePermission {
                    principal: Decimal(9),
                    read: false,
                    write: false,
                    admin: true,
                },
            ],
        },
    );
    invoke(
        &mut engine,
        action(1, "CREATE TABLE final_payload (value INTEGER)"),
    );
    let committed = invoke(
        &mut engine,
        action(2, "INSERT INTO final_payload VALUES (7) RETURNING value"),
    );
    assert_eq!(committed["state"], "committed");
    let request = identity(
        2,
        &statements("INSERT INTO final_payload VALUES (7) RETURNING value"),
    );
    let before_delete = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    let deleted = invoke(
        &mut engine,
        Action::Lifecycle {
            expected_revision: revision(&before_delete),
            nonce: Decimal(21),
            lifecycle: Lifecycle::Deleted,
        },
    );
    let mut reader = principal();
    reader.principal = 4;
    let mut admin = principal();
    admin.principal = 9;
    admin.provision = false;
    for action in [
        Action::StorageStatus {},
        Action::RetireStorage {
            expected_head_serial: physical_serial(&deleted),
        },
    ] {
        assert_eq!(
            engine
                .execute(&reader, call(action), until())
                .unwrap_err()
                .code,
            "DENIED"
        );
    }
    assert_eq!(
        engine
            .execute(&admin, call(Action::StorageStatus {}), until())
            .unwrap(),
        deleted
    );
    assert_eq!(
        engine
            .execute(
                &admin,
                call(Action::RetireStorage {
                    expected_head_serial: Decimal(physical_serial(&deleted).0 + 1),
                }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    let native_scope = scope().native().unwrap();
    let key = head_key(&native_scope);
    let old = decode_head(&memory.values.lock().unwrap()[&key].bytes, &native_scope).unwrap();
    memory.calls.lock().unwrap().clear();
    assert!(engine.collector.is_none());
    let sealed = engine
        .execute(
            &admin,
            call(Action::RetireStorage {
                expected_head_serial: physical_serial(&deleted),
            }),
            until(),
        )
        .unwrap();
    assert_eq!(
        sealed["storage"]["terminal"]["serial"],
        sealed["head_serial"]
    );
    assert_eq!(sealed["active"], false);
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
    let mut expected = old;
    expected.format = 7;
    expected.head_serial += 1;
    expected.active = false;
    expected.storage.terminal = Some(TerminalSeal {
        serial: expected.head_serial,
    });
    assert_eq!(
        decode_head(&memory.values.lock().unwrap()[&key].bytes, &native_scope).unwrap(),
        expected
    );
    assert!(memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| call == &format!("GET {key}") || call == &format!("PUT {key}")));
    assert_eq!(
        engine
            .execute(
                &admin,
                call(Action::RetireStorage {
                    expected_head_serial: physical_serial(&sealed),
                }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    let prepare = Action::GcPrepare {
        expected_head_serial: physical_serial(&sealed),
        generation: Decimal(1),
        after: None,
    };
    assert_eq!(
        engine
            .execute(&admin, call(prepare.clone()), until())
            .unwrap_err()
            .code,
        "GC_DISABLED"
    );
    engine.collector = Some(Collector {
        deployment: 1,
        listings: memory.clone(),
        garbage: memory.clone(),
    });
    let prepared = engine.execute(&admin, call(prepare), until()).unwrap();
    assert_eq!(prepared["exhausted"], true);
    let done = engine
        .execute(
            &admin,
            call(Action::GcResume {
                batch_serial: batch_serial(&prepared),
            }),
            until(),
        )
        .unwrap();
    assert_eq!(
        done["status"]["storage"]["terminal"],
        sealed["storage"]["terminal"]
    );
    assert!(done["status"]["storage"]["sweep"].is_null());
    assert!(!memory
        .values
        .lock()
        .unwrap()
        .keys()
        .any(|key| key.contains("/storage/1/objects/")));
    assert!(memory.values.lock().unwrap().contains_key(&key));
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        engine
            .execute(&admin, call(Action::StorageStatus {}), until())
            .unwrap(),
        done["status"]
    );
    assert!(memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| call == &format!("GET {key}")));
    for action in [
        Action::Status {
            expected_worker_instance: None,
        },
        Action::Lookup { request },
        Action::Query {
            statements: statements("SELECT * FROM final_payload"),
        },
        Action::Open {},
    ] {
        assert_eq!(
            engine
                .execute(&principal(), call(action), until())
                .unwrap_err()
                .code,
            "LIFECYCLE"
        );
    }
}

#[test]
fn direct_terminal_unknown_keeps_original_condition_and_does_not_replay_the_seal() {
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let active = active(&mut engine);
    let deleted = invoke(
        &mut engine,
        Action::Lifecycle {
            expected_revision: revision(&active),
            nonce: Decimal(20),
            lifecycle: Lifecycle::Deleted,
        },
    );
    let retire = Action::RetireStorage {
        expected_head_serial: physical_serial(&deleted),
    };
    memory.calls.lock().unwrap().clear();
    *memory.lose_head.lock().unwrap() = true;
    assert_eq!(
        engine
            .execute(&principal(), call(retire.clone()), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    let observed = invoke(&mut engine, Action::StorageStatus {});
    assert_eq!(
        physical_serial(&observed).0,
        physical_serial(&deleted).0 + 1
    );
    assert_eq!(
        observed["storage"]["terminal"]["serial"],
        observed["head_serial"]
    );
    assert_eq!(
        engine
            .execute(&principal(), call(retire), until())
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    assert_eq!(
        memory
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("PUT "))
            .count(),
        1
    );
    memory.calls.lock().unwrap().clear();
    *memory.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        engine
            .execute(&principal(), call(Action::StorageStatus {}), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 1);
    assert_eq!(invoke(&mut engine, Action::StorageStatus {}), observed);
}

#[test]
fn manual_compaction_and_gc_preserve_native_data_receipts_and_explicit_owner_activation() {
    use crate::output::{tests::small_pool, BASE_BYTES};
    let (_directory, memory, mut engine) = fixture(4, 10000);
    let activated = active(&mut engine);
    invoke(
        &mut engine,
        Action::Policy {
            expected_revision: revision(&activated),
            nonce: Decimal(20),
            permissions: vec![
                WirePermission {
                    principal: Decimal(3),
                    read: true,
                    write: true,
                    admin: true,
                },
                WirePermission {
                    principal: Decimal(4),
                    read: true,
                    write: false,
                    admin: false,
                },
            ],
        },
    );
    invoke(
        &mut engine,
        action(1, "CREATE TABLE kept(id INTEGER PRIMARY KEY)"),
    );
    let insert = action(2, "INSERT INTO kept VALUES(1) RETURNING id");
    let request = match &insert {
        Action::Execute { request, .. } => request.clone(),
        _ => unreachable!(),
    };
    let original = invoke(&mut engine, insert);
    let before = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::CompactBegin {
                    expected_head_serial: Decimal(physical_serial(&before).0 + 1),
                }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    let begun = invoke(
        &mut engine,
        Action::CompactBegin {
            expected_head_serial: physical_serial(&before),
        },
    );
    assert_eq!(begun["active"], false);
    assert_eq!(begun["revision"], before["revision"]);
    assert_eq!(begun["sequence"], before["sequence"]);
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
    let plan = copy_serial(&begun);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::CompactPromote { plan_serial: plan }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    let occupied = engine.recovery.clone().try_acquire_owned().unwrap();
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::CompactCopy { plan_serial: plan }),
                until()
            )
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    drop(occupied);
    let mut reader = principal();
    reader.principal = 4;
    assert_eq!(
        engine
            .execute(
                &reader,
                call(Action::CompactCopy { plan_serial: plan }),
                until()
            )
            .unwrap_err()
            .code,
        "DENIED"
    );
    let copied = invoke(&mut engine, Action::CompactCopy { plan_serial: plan });
    assert_eq!(copied["storage"]["plan"]["phase"], "sealed");
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::CompactAbort {
                    plan_serial: Decimal(plan.0 + 1)
                }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    let promoted = invoke(&mut engine, Action::CompactPromote { plan_serial: plan });
    assert_eq!(promoted["storage"]["active_generation"], "2");
    assert_eq!(promoted["active"], false);
    assert!(promoted["storage"]["plan"].is_null());
    assert!(engine.cache.values().all(|entry| entry.session.is_none()));
    assert_eq!(
        invoke(
            &mut engine,
            Action::Lookup {
                request: request.clone()
            }
        ),
        original
    );
    let reactivated = invoke(
        &mut engine,
        Action::Activate {
            expected_revision: revision(&promoted),
            nonce: Decimal(30),
            expected_worker_instance: None,
        },
    );
    assert_eq!(reactivated["active"], true);
    assert_eq!(
        result(&invoke(
            &mut engine,
            Action::Query {
                statements: statements("SELECT count(*) FROM kept")
            }
        ))
        .statements[0]
            .rows,
        vec![vec![scap_sql::Value::Integer(1)]]
    );

    let prepare = Action::GcPrepare {
        expected_head_serial: physical_serial(&reactivated),
        generation: Decimal(1),
        after: None,
    };
    assert_eq!(
        engine
            .execute(&principal(), call(prepare.clone()), until())
            .unwrap_err()
            .code,
        "GC_DISABLED"
    );
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::GcResume {
                    batch_serial: Decimal(1)
                }),
                until()
            )
            .unwrap_err()
            .code,
        "GC_DISABLED"
    );
    engine.collector = Some(Collector {
        deployment: 9,
        listings: memory.clone(),
        garbage: memory.clone(),
    });
    assert_eq!(
        engine
            .execute(&principal(), call(prepare.clone()), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
    engine.collector.as_mut().unwrap().deployment = 1;
    let occupied = engine.recovery.clone().try_acquire_owned().unwrap();
    for action in [
        prepare.clone(),
        Action::GcResume {
            batch_serial: Decimal(1),
        },
    ] {
        assert_eq!(
            engine
                .execute(&principal(), call(action), until())
                .unwrap_err()
                .code,
            "RECOVERY_BUSY"
        );
    }
    drop(occupied);
    assert_eq!(
        engine
            .execute(&reader, call(prepare.clone()), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
    let prepared = invoke(&mut engine, prepare);
    let batch = batch_serial(&prepared);
    assert_eq!(
        engine
            .execute(
                &principal(),
                call(Action::GcResume {
                    batch_serial: Decimal(batch.0 + 1)
                }),
                until()
            )
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    assert!(memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| !call.starts_with("DELETE ")));
    let pool = small_pool(8 * BASE_BYTES, 8 * BASE_BYTES);
    let swept = budgeted(
        &mut engine,
        Action::GcResume {
            batch_serial: batch,
        },
        &pool,
    );
    assert!(swept["value"]["status"]["storage"]["sweep"].is_null());
    assert!(!memory
        .values
        .lock()
        .unwrap()
        .keys()
        .any(|key| key.contains("/storage/1/objects/")));
    assert_eq!(
        invoke(
            &mut engine,
            Action::Lookup {
                request: request.clone()
            }
        ),
        original
    );

    // An aborted target is retired even though it lies above the active number.
    let current = invoke(
        &mut engine,
        Action::Status {
            expected_worker_instance: None,
        },
    );
    let begun = invoke(
        &mut engine,
        Action::CompactBegin {
            expected_head_serial: physical_serial(&current),
        },
    );
    let plan = copy_serial(&begun);
    invoke(&mut engine, Action::CompactCopy { plan_serial: plan });
    let aborted = invoke(&mut engine, Action::CompactAbort { plan_serial: plan });
    assert_eq!(aborted["storage"]["active_generation"], "2");
    assert_eq!(aborted["storage"]["allocated_through"], "3");
    let prepared = budgeted(
        &mut engine,
        Action::GcPrepare {
            expected_head_serial: physical_serial(&aborted),
            generation: Decimal(3),
            after: None,
        },
        &pool,
    );
    let swept = invoke(
        &mut engine,
        Action::GcResume {
            batch_serial: batch_serial(&prepared["value"]),
        },
    );
    assert!(swept["status"]["storage"]["sweep"].is_null());
    assert!(!memory
        .values
        .lock()
        .unwrap()
        .keys()
        .any(|key| key.contains("/storage/3/objects/")));
    assert_eq!(invoke(&mut engine, Action::Lookup { request }), original);
    assert!(memory
        .values
        .lock()
        .unwrap()
        .keys()
        .any(|key| key.contains("/storage/2/objects/")));
}
