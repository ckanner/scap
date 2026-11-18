use super::*;
use crate::tests::{call, principal, sample_config, until, Memory};
use crate::wire::{Action, Decimal};

mod startup_s3;

#[test]
fn kernel_envelope_is_revalidated_before_permanent_worker_claim() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = prepared(directory.path()).service;
    config.resource_envelope = Some(crate::resource_envelope::tests::profile());
    config.resource_envelope.as_mut().unwrap().tasks = 0;
    let objects = Arc::new(Memory::default());
    assert_eq!(
        assemble(config, objects.clone()).err().unwrap().code,
        "CONFIG"
    );
    assert!(objects.calls.lock().unwrap().is_empty());
    let mut config = prepared(directory.path());
    config.service.resource_envelope = Some(crate::resource_envelope::tests::profile());
    config.service.resource_envelope.as_mut().unwrap().tasks = 0;
    assert_eq!(
        serve(config, Box::pin(async {})).unwrap_err().code,
        "CONFIG"
    );
}

#[test]
fn check_config_validates_without_opening_a_listener_or_consuming_an_identity() {
    let directory = tempfile::tempdir().unwrap();
    let _credentials = crate::tests::test_credentials();
    let path = directory.path().join("config.json");
    // The configured backend need not exist: checking is a local operation.
    let mut value = sample_config(directory.path());
    value["s3"]["endpoint"] = serde_json::json!("http://127.0.0.1:1");
    std::fs::write(&path, value.to_string()).unwrap();
    entry(vec!["--check-config".into(), path.clone().into()]).unwrap();
    value["worker_instance"] = serde_json::json!("0");
    std::fs::write(&path, value.to_string()).unwrap();
    assert_eq!(
        entry(vec!["--check-config".into(), path.clone().into()])
            .unwrap_err()
            .code,
        "CONFIG"
    );
    assert_eq!(
        entry(vec!["--unknown".into(), path.into()])
            .unwrap_err()
            .code,
        "USAGE"
    );
}

fn prepared(parent: &std::path::Path) -> Prepared {
    let _credentials = crate::tests::test_credentials();
    Config::parse(&serde_json::to_vec(&sample_config(parent)).unwrap())
        .unwrap()
        .prepare()
        .unwrap()
}

#[test]
fn read_pool_is_validated_before_identity_claim_and_wired_to_native_readers() {
    let directory = tempfile::tempdir().unwrap();
    let objects = Arc::new(Memory::default());
    let profile = crate::scheduler::ReadPool {
        workers: 2,
        active_per_tenant: 2,
        active_per_database: 2,
    };
    let mut configuration = prepared(directory.path()).service;
    configuration.admission.read_pool = Some(crate::scheduler::ReadPool {
        workers: 0,
        ..profile
    });
    assert_eq!(
        assemble(configuration, objects.clone()).err().unwrap().code,
        "CONFIG"
    );
    assert!(objects.calls.lock().unwrap().is_empty());
    let mut configuration = prepared(directory.path()).service;
    configuration.admission.read_pool = Some(profile);
    let (_, state) = assemble(configuration, objects.clone()).unwrap();
    let create = state
        .scheduler
        .submit(
            principal(),
            call(Action::Create { nonce: Decimal(1) }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(create["revision"], "1");
    let activated = state
        .scheduler
        .submit(
            principal(),
            call(Action::Activate {
                expected_worker_instance: None,
                expected_revision: Decimal(1),
                nonce: Decimal(2),
            }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(activated["active"], true);
    let read = state
        .scheduler
        .submit(
            principal(),
            call(Action::Query {
                statements: vec![crate::wire::WireStatement {
                    sql: "SELECT 42".into(),
                    params: vec![],
                }],
            }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert!(read["result"].is_string());
    drop(state);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn assembly_validates_restore_before_io_and_builds_a_separate_bounded_pool() {
    let directory = tempfile::tempdir().unwrap();
    let profile = || {
        serde_json::from_value::<crate::restore::Profile>(crate::restore::tests::profile()).unwrap()
    };
    let mut config = prepared(directory.path()).service;
    config.restore = Some(profile());
    let objects = Arc::new(Memory::default());
    assert_eq!(
        assemble(config, objects.clone()).err().unwrap().code,
        "CONFIG"
    );
    assert!(objects.calls.lock().unwrap().is_empty());
    let mut config = prepared(directory.path()).service;
    config.catalogue = Some(profile().admission);
    config.restore = Some(profile());
    config.restore.as_mut().unwrap().max_staging_bytes = 1;
    config.worker_instance = WorkerInstance::Auto;
    let objects = Arc::new(Memory::default());
    assert_eq!(
        assemble(config, objects.clone()).err().unwrap().code,
        "CONFIG"
    );
    assert!(objects.calls.lock().unwrap().is_empty());
    let mut config = prepared(directory.path()).service;
    config.catalogue = Some(profile().admission);
    config.restore = Some(profile());
    let (_, state) = assemble(config, Arc::new(Memory::default())).unwrap();
    assert!(state.catalogue.is_some());
    let restore = state.restore.as_ref().unwrap();
    assert_eq!(restore.timeout, Duration::from_secs(30));
    restore.pool.intake.validate(Class::Recovery, 4096).unwrap();
    assert!(!Arc::ptr_eq(&restore.pool.intake, &state.recovery_intake));
    drop(http::router(state.clone()).unwrap());
    drop(state);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn restore_configuration_with_missing_cache_fails_before_identity_claim() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = prepared(directory.path()).service;
    let profile = || {
        serde_json::from_value::<crate::restore::Profile>(crate::restore::tests::profile()).unwrap()
    };
    config.catalogue = Some(profile().admission);
    config.restore = Some(profile());
    // Parsed preparation cannot substitute for the assembly-time local check:
    // no durable identity is consumed when this cache is already missing.
    std::fs::remove_dir(directory.path()).unwrap();
    let objects = Arc::new(Memory::default());
    assert_eq!(
        assemble(config, objects.clone()).err().unwrap().code,
        "CACHE_IO"
    );
    assert!(objects.calls.lock().unwrap().is_empty());
    assert!(!directory.path().exists());
}

#[test]
fn output_validation_and_budgeted_factory_are_wired_into_actual_assembly() {
    use crate::output::{tests::usage, BASE_BYTES};
    let directory = tempfile::tempdir().unwrap();
    let mut invalid = prepared(directory.path());
    invalid.service.output.version = 2;
    assert_eq!(
        assemble(invalid.service, Arc::new(Memory::default()))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
    let mut invalid = prepared(directory.path());
    invalid.service.output.control_bytes = 0;
    assert_eq!(
        serve(invalid, Box::pin(async {})).unwrap_err().code,
        "CONFIG"
    );
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());

    let (_, state) = assemble(
        prepared(directory.path()).service,
        Arc::new(Memory::default()),
    )
    .unwrap();
    let pool = state.output.clone();
    let reply = state
        .scheduler
        .submit_encoded(
            principal(),
            call(Action::Create { nonce: Decimal(1) }),
            until(),
            state.intake.acquire(&principal()).unwrap(),
            pool.acquire(&principal(), false).unwrap(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap();
    assert_eq!(reply.status, axum::http::StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(&reply.bytes).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["value"]["revision"], "1");
    // Joining the actual workers removes the send/wakeup race. The final
    // response still independently owns the base output allowance.
    drop(state);
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(reply);
    assert_eq!(usage(&pool), (0, 0, 0));
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn service_factory_calls_the_real_engine_and_drops_all_private_cache_files() {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    let (address, state) = assemble(prepared(directory.path()).service, memory).unwrap();
    assert!(address.ip().is_loopback());
    let created = state
        .scheduler
        .submit(
            principal(),
            call(Action::Create { nonce: Decimal(1) }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(created["revision"], "1");
    let active = state
        .scheduler
        .submit(
            principal(),
            call(Action::Activate {
                expected_worker_instance: None,
                expected_revision: Decimal(1),
                nonce: Decimal(2),
            }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(active["active"], true);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_some());
    drop(state);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn configured_graph_allowance_reaches_the_actual_native_worker_and_preserves_control_access() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = prepared(directory.path());
    configuration.service.options.result_memory_bytes =
        std::mem::size_of::<scap_sql::TransactionResult>() as u64;
    let (_, state) = assemble(configuration.service, Arc::new(Memory::default())).unwrap();
    for action in [
        Action::Create { nonce: Decimal(1) },
        Action::Activate {
            expected_worker_instance: None,
            expected_revision: Decimal(1),
            nonce: Decimal(2),
        },
    ] {
        state
            .scheduler
            .submit(principal(), call(action), until())
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap();
    }
    let error = state
        .scheduler
        .submit(
            principal(),
            call(Action::Query {
                statements: vec![crate::wire::WireStatement {
                    sql: "SELECT 1".into(),
                    params: vec![],
                }],
            }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, "LIMIT");
    assert!(error.receipt.is_none());
    let status = state
        .scheduler
        .submit(
            principal(),
            call(Action::Status {
                expected_worker_instance: None,
            }),
            until(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(status["active"], true);
    drop(state);
    let mut invalid = prepared(directory.path());
    invalid.service.options.result_memory_bytes = 0;
    assert_eq!(
        assemble(invalid.service, Arc::new(Memory::default()))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
}

#[test]
fn direct_assembly_rejects_each_invalid_intake_profile_without_leaking_private_workers() {
    let directory = tempfile::tempdir().unwrap();
    let invalid = Some(crate::intake::Profile {
        version: 1,
        requests_per_tenant: 1,
        body_bytes: 0,
        body_bytes_per_tenant: 0,
    });
    for set in [
        |admission: &mut crate::config::Admission, profile| admission.data_profile = profile,
        |admission: &mut crate::config::Admission, profile| admission.control_profile = profile,
        |admission: &mut crate::config::Admission, profile| admission.recovery_profile = profile,
    ] {
        let mut configuration = prepared(directory.path());
        set(&mut configuration.service.admission, invalid);
        assert_eq!(
            assemble(configuration.service, Arc::new(Memory::default()))
                .err()
                .unwrap()
                .code,
            "CONFIG"
        );
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());
    }
    let mut configuration = prepared(directory.path());
    configuration.service.catalogue = Some(crate::config::CatalogueAdmission {
        workers: 1,
        queued_total: 4,
        queued_per_tenant: 3,
        queued_per_name: 2,
        intake: 2,
        max_body_bytes: 65536,
        timeout_ms: 1000,
        intake_profile: invalid,
    });
    assert_eq!(
        assemble(configuration.service, Arc::new(Memory::default()))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn real_native_hot_session_runs_while_another_database_is_blocked_in_cold_object_io() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use scap_object_store::{Condition, StoreError, Stored};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Mutex};
    use std::time::Instant;

    struct Paused {
        memory: Memory,
        armed: AtomicBool,
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl Objects for Paused {
        fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
            if key.starts_with("scap-object/v1/1/2/10/inc/")
                && self.armed.swap(false, Ordering::SeqCst)
            {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            self.memory.get(key, maximum, deadline)
        }
        fn put(
            &self,
            key: &str,
            bytes: &[u8],
            condition: Condition<'_>,
            deadline: Instant,
        ) -> Result<String, StoreError> {
            self.memory.put(key, bytes, condition, deadline)
        }
    }
    fn receive(
        reply: tokio::sync::oneshot::Receiver<Result<serde_json::Value, Failure>>,
    ) -> serde_json::Value {
        runtime().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_secs(5), reply)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        })
    }
    fn submit(
        state: &HttpState,
        database: u64,
        action: Action,
    ) -> tokio::sync::oneshot::Receiver<Result<serde_json::Value, Failure>> {
        let mut call = call(action);
        call.scope.database.0 = database;
        state.scheduler.submit(principal(), call, until()).unwrap()
    }
    fn query() -> Action {
        Action::Query {
            statements: vec![crate::wire::WireStatement {
                sql: "SELECT x FROM t".into(),
                params: vec![],
            }],
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let (entered, paused) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let objects = Arc::new(Paused {
        memory: Memory::default(),
        armed: AtomicBool::new(false),
        entered,
        release: Mutex::new(wait),
    });
    let (_, state) = assemble(prepared(directory.path()).service, objects.clone()).unwrap();
    for database in [10, 20] {
        receive(submit(
            &state,
            database,
            Action::Create { nonce: Decimal(1) },
        ));
        receive(submit(
            &state,
            database,
            Action::Activate {
                expected_worker_instance: None,
                expected_revision: Decimal(1),
                nonce: Decimal(2),
            },
        ));
        let statements: Vec<_> = ["CREATE TABLE t(x INTEGER)", "INSERT INTO t VALUES (44)"]
            .into_iter()
            .map(|sql| crate::wire::WireStatement {
                sql: sql.into(),
                params: vec![],
            })
            .collect();
        let request =
            scap_object::request(1, 1, 3, &crate::wire::statements(&statements).unwrap()).unwrap();
        receive(submit(
            &state,
            database,
            Action::Execute {
                request: crate::wire::Identity {
                    epoch: Decimal(1),
                    id: Decimal(1),
                    principal: Decimal(3),
                    fingerprint: request.fingerprint,
                },
                statements,
            },
        ));
    }
    objects.memory.calls.lock().unwrap().clear();
    objects.armed.store(true, Ordering::SeqCst);
    let mut cold = submit(&state, 10, Action::Open {});
    paused.recv_timeout(Duration::from_secs(5)).unwrap();
    let hot = receive(submit(&state, 20, query()));
    let result = STANDARD.decode(hot["result"].as_str().unwrap()).unwrap();
    let decoded =
        scap_sql::decode_result(&result, scap_object::options::durable_sql_limits()).unwrap();
    assert_eq!(
        decoded.statements[0].rows,
        vec![vec![scap_sql::Value::Integer(44)]]
    );
    assert_eq!(
        objects
            .memory
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.contains("/1/2/20/"))
            .cloned()
            .collect::<Vec<_>>(),
        ["GET scap-object/v1/1/2/20/head"]
    );
    assert!(matches!(
        cold.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    receive(submit(
        &state,
        10,
        Action::Status {
            expected_worker_instance: None,
        },
    ));
    release.send(()).unwrap();
    receive(cold);
    objects.memory.calls.lock().unwrap().clear();
    assert_eq!(receive(submit(&state, 10, query())), hot);
    assert_eq!(
        *objects.memory.calls.lock().unwrap(),
        ["GET scap-object/v1/1/2/10/head"]
    );
    drop(state);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn enabled_catalogue_has_a_separate_worker_pool_and_rejects_invalid_direct_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = prepared(directory.path());
    configuration.service.catalogue = Some(crate::config::CatalogueAdmission {
        intake_profile: None,
        workers: 1,
        queued_total: 4,
        queued_per_tenant: 3,
        queued_per_name: 2,
        intake: 2,
        max_body_bytes: 65536,
        timeout_ms: 1000,
    });
    let (_, state) = assemble(configuration.service, Arc::new(Memory::default())).unwrap();
    let call=crate::catalogue_wire::parse(br#"{"version":1,"operation":"prepare_create","name":"catalogue","create_operation":"1","expected_name_revision":null,"options":{"quota":{"mode":"default"}}}"#).unwrap();
    let value = state
        .catalogue
        .as_ref()
        .unwrap()
        .scheduler
        .submit(principal(), call, until())
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(value["creation"]["name"], "catalogue");
    drop(state);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
    let mut configuration = prepared(directory.path());
    configuration.service.catalogue = Some(crate::config::CatalogueAdmission {
        intake_profile: None,
        workers: 0,
        queued_total: 4,
        queued_per_tenant: 3,
        queued_per_name: 2,
        intake: 2,
        max_body_bytes: 65536,
        timeout_ms: 1000,
    });
    assert!(assemble(configuration.service, Arc::new(Memory::default())).is_err());
    let mut configuration = prepared(directory.path());
    configuration.service.catalogue = Some(crate::config::CatalogueAdmission {
        intake_profile: None,
        workers: 1,
        queued_total: 4,
        queued_per_tenant: 3,
        queued_per_name: 2,
        intake: 0,
        max_body_bytes: 65536,
        timeout_ms: 1000,
    });
    assert!(assemble(configuration.service, Arc::new(Memory::default())).is_err());
}

#[test]
fn startup_and_listener_failures_do_not_leave_workers_or_connections_running() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = prepared(directory.path());
    configuration.service.admission.active_database_actors = 0;
    assert!(assemble(configuration.service, Arc::new(Memory::default())).is_err());
    let mut configuration = prepared(directory.path());
    configuration.service.cache_directory = directory.path().join("missing");
    assert!(assemble(configuration.service, Arc::new(Memory::default())).is_err());
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
    let mut configuration = prepared(directory.path());
    configuration.s3.endpoint = "bad".into();
    assert_eq!(
        serve(configuration, Box::pin(async {})).unwrap_err().code,
        "CONFIG"
    );
    let backend = startup_s3::Backend::new();
    let mut configuration = prepared(directory.path());
    configuration.s3.endpoint = backend.endpoint();
    serve(configuration, Box::pin(async {})).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut configuration = prepared(directory.path());
    configuration.s3.endpoint = backend.endpoint();
    configuration.service.worker_instance = WorkerInstance::Explicit(101);
    configuration.service.listen = listener.local_addr().unwrap();
    assert_eq!(
        serve(configuration, Box::pin(async {})).unwrap_err().code,
        "LISTEN"
    );
    let (_, state) = assemble(
        prepared(directory.path()).service,
        Arc::new(Memory::default()),
    )
    .unwrap();
    fn failed_runtime() -> std::io::Result<tokio::runtime::Runtime> {
        Err(std::io::Error::other("unit runtime failure"))
    }
    assert_eq!(
        run(
            Assembly {
                address: "127.0.0.1:0".parse().unwrap(),
                worker_instance: 100,
                state,
            },
            crate::transport::Profile::default().checked().unwrap(),
            Box::pin(async {}),
            failed_runtime
        )
        .unwrap_err()
        .code,
        "RUNTIME"
    );
    let (_, mut state) = assemble(
        prepared(directory.path()).service,
        Arc::new(Memory::default()),
    )
    .unwrap();
    Arc::get_mut(&mut state).unwrap().max_body_bytes = 0;
    assert_eq!(
        run(
            Assembly {
                address: "127.0.0.1:0".parse().unwrap(),
                worker_instance: 100,
                state,
            },
            crate::transport::Profile::default().checked().unwrap(),
            Box::pin(async {}),
            runtime
        )
        .unwrap_err()
        .code,
        "CONFIG"
    );
    let mut configuration = prepared(directory.path());
    configuration.service.transport.max_connections = 0;
    assert_eq!(
        serve(configuration, Box::pin(async {})).unwrap_err().code,
        "CONFIG"
    );
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn cli_reads_exactly_one_bounded_configuration_and_reports_only_stable_codes() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("config.json");
    std::fs::write(
        &file,
        serde_json::to_vec(&sample_config(directory.path())).unwrap(),
    )
    .unwrap();
    fn accepted(config: Config) -> Result<(), Failure> {
        assert_eq!(config.version, 1);
        Ok(())
    }
    assert!(start(vec![file.clone().into()], accepted, initialize_allocator).is_ok());
    assert_eq!(
        start(vec![], accepted, initialize_allocator)
            .unwrap_err()
            .code,
        "USAGE"
    );
    assert_eq!(
        start(
            vec![file.clone().into(), file.clone().into()],
            accepted,
            initialize_allocator
        )
        .unwrap_err()
        .code,
        "USAGE"
    );
    assert_eq!(
        start(
            vec![directory.path().join("missing").into()],
            accepted,
            initialize_allocator
        )
        .unwrap_err()
        .code,
        "CONFIG"
    );
    assert_eq!(
        start(
            vec![directory.path().into()],
            accepted,
            initialize_allocator
        )
        .unwrap_err()
        .code,
        "CONFIG"
    );
    std::fs::write(&file, vec![0; 4 * 1024 * 1024 + 2]).unwrap();
    assert_eq!(
        start(vec![file.clone().into()], accepted, initialize_allocator)
            .unwrap_err()
            .code,
        "CONFIG"
    );
    std::fs::write(&file, b"{}").unwrap();
    assert_eq!(entry(vec![file.into()]).unwrap_err().code, "CONFIG");

    let mut config =
        Config::parse(&serde_json::to_vec(&sample_config(directory.path())).unwrap()).unwrap();
    config.version = 2;
    assert_eq!(launch(config).unwrap_err().code, "CONFIG");
    {
        let _credentials = crate::tests::test_credentials();
        let mut config =
            Config::parse(&serde_json::to_vec(&sample_config(directory.path())).unwrap()).unwrap();
        config.s3.endpoint = "bad".into();
        assert_eq!(launch(config).unwrap_err().code, "CONFIG");
    }
    runtime().unwrap().block_on(async {
        assert!(tokio::time::timeout(
            Duration::from_millis(1),
            shutdown(Box::pin(tokio::signal::ctrl_c()))
        )
        .await
        .is_err());
    });
}

#[test]
fn allocator_cli_is_explicit_bounded_and_does_not_launch_a_service() {
    use std::os::unix::ffi::OsStringExt;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("config.json");
    std::fs::write(&file, sample_config(directory.path()).to_string()).unwrap();
    fn no_service(_: Config) -> Result<(), Failure> {
        panic!("initialization must not launch a service")
    }
    fn accepted(config: Config, floor: u64) -> Result<(), Failure> {
        assert_eq!(config.version, 1);
        assert_eq!(floor, 17);
        Ok(())
    }
    assert!(start(
        vec![
            "--init-worker-allocator".into(),
            file.clone().into(),
            "17".into()
        ],
        no_service,
        accepted
    )
    .is_ok());
    for floor in ["", "01", "+1", "-1", "18446744073709551616"] {
        assert_eq!(
            start(
                vec![
                    "--init-worker-allocator".into(),
                    file.clone().into(),
                    floor.into()
                ],
                no_service,
                accepted
            )
            .unwrap_err()
            .code,
            "USAGE"
        );
    }
    assert_eq!(
        start(
            vec![
                "--init-worker-allocator".into(),
                file.clone().into(),
                OsString::from_vec(vec![255])
            ],
            no_service,
            accepted
        )
        .unwrap_err()
        .code,
        "USAGE"
    );
    assert_eq!(
        start(
            vec!["--reset-worker-allocator".into(), file.into(), "17".into()],
            no_service,
            accepted
        )
        .unwrap_err()
        .code,
        "USAGE"
    );
}

#[test]
fn real_startup_adapter_initializes_once_and_restarts_auto_without_config_edits() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    let parse = |value: &serde_json::Value| Config::parse(value.to_string().as_bytes()).unwrap();
    assert_eq!(
        initialize_allocator(parse(&value), 0).unwrap_err().code,
        "CONFIG"
    );
    value["worker_instance"] = serde_json::json!("auto");
    value["version"] = serde_json::json!(2);
    assert_eq!(
        initialize_allocator(parse(&value), 0).unwrap_err().code,
        "CONFIG"
    );
    value["version"] = serde_json::json!(1);
    let _credentials = crate::tests::test_credentials();
    value["s3"]["endpoint"] = serde_json::json!("invalid");
    assert_eq!(
        initialize_allocator(parse(&value), 0).unwrap_err().code,
        "CONFIG"
    );
    let backend = startup_s3::Backend::new();
    value["s3"]["endpoint"] = serde_json::json!(backend.endpoint());
    let config_path = directory.path().join("config.json");
    std::fs::write(&config_path, value.to_string()).unwrap();
    entry(vec![
        "--init-worker-allocator".into(),
        config_path.into(),
        "100".into(),
    ])
    .unwrap();
    assert_eq!(
        initialize_allocator(parse(&value), 0).unwrap_err().code,
        "INSTANCE_ALLOCATOR_EXISTS"
    );
    for _ in 0..2 {
        serve(parse(&value).prepare().unwrap(), Box::pin(async {})).unwrap();
    }
}

#[test]
fn prepared_startup_failure_and_completed_shutdown_signal_are_observable() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = prepared(directory.path());
    config.service.admission.active_database_actors = 0;
    assert_eq!(
        serve(config, Box::pin(async {})).unwrap_err().code,
        "CONFIG"
    );
    runtime().unwrap().block_on(async {
        shutdown(Box::pin(std::future::ready(Ok(())))).await;
        shutdown(Box::pin(std::future::ready(Err(std::io::Error::other(
            "signal registration failed",
        )))))
        .await;
    });
}

#[test]
fn discovery_startup_requires_a_listing_transport_and_validates_the_direct_worker_identity() {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    let mut p = prepared(directory.path()).service;
    p.discovery = Some(PreparedDiscovery::Ready(crate::discovery::tests::codec()));
    assert_eq!(assemble(p, memory.clone()).err().unwrap().code, "CONFIG");
    let mut p = prepared(directory.path()).service;
    p.discovery = Some(PreparedDiscovery::Ready(crate::discovery::tests::codec()));
    p.worker_instance = WorkerInstance::Explicit(0);
    assert_eq!(
        assemble_with_listings(p, memory.clone(), Some(memory.clone()))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    let mut p = prepared(directory.path()).service;
    p.discovery = Some(PreparedDiscovery::Ready(crate::discovery::tests::codec()));
    let (_, state) = assemble_with_listings(p, memory.clone(), Some(memory)).unwrap();
    assert!(state.discovery.is_some());
    drop(state);
}

fn gc_prepared(parent: &std::path::Path) -> Prepared {
    let mut value = prepared(parent);
    value.service.gc_deployment = Some(1);
    value.gc = Some(PreparedGarbage {
        deployment: 1,
        s3: S3Config {
            endpoint: value.s3.endpoint.clone(),
            region: value.s3.region.clone(),
            bucket: value.s3.bucket.clone(),
            access_key: "collector-access".into(),
            secret_key: "collector-secret".into(),
            session_token: None,
            timeout: value.s3.timeout,
            max_object_bytes: value.s3.max_object_bytes,
            allow_http: value.s3.allow_http,
        },
    });
    value
}

#[test]
fn direct_prepared_gc_cannot_rebind_authority_or_silently_enable_delete() {
    let directory = tempfile::tempdir().unwrap();
    let changes: [fn(&mut Prepared); 10] = [
        |p| p.service.gc_deployment = None,
        |p| p.gc.as_mut().unwrap().s3.endpoint = "http://127.0.0.1:8".into(),
        |p| p.gc.as_mut().unwrap().s3.region = "elsewhere".into(),
        |p| p.gc.as_mut().unwrap().s3.bucket = "other-bucket".into(),
        |p| p.gc.as_mut().unwrap().s3.timeout += Duration::from_secs(1),
        |p| p.gc.as_mut().unwrap().s3.allow_http = !p.s3.allow_http,
        |p| p.gc.as_mut().unwrap().s3.max_object_bytes += 1,
        |p| p.gc.as_mut().unwrap().s3.access_key = p.s3.access_key.clone(),
        |p| {
            p.gc.as_mut().unwrap().deployment = 0;
            p.service.gc_deployment = Some(0);
        },
        |p| p.gc.as_mut().unwrap().s3.secret_key.clear(),
    ];
    for change in changes {
        let mut value = gc_prepared(directory.path());
        change(&mut value);
        assert_eq!(
            gc_backend(value.gc, value.service.gc_deployment, &value.s3)
                .err()
                .unwrap()
                .code,
            "CONFIG"
        );
    }
    let value = gc_prepared(directory.path());
    assert_eq!(
        gc_backend(None, value.service.gc_deployment, &value.s3)
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    assert!(gc_backend(value.gc, value.service.gc_deployment, &value.s3)
        .unwrap()
        .is_some());
    let mut missing = gc_prepared(directory.path());
    missing.gc = None;
    assert_eq!(
        serve(missing, Box::pin(async {})).unwrap_err().code,
        "CONFIG"
    );
    // Production construction/drop remains outside its request runtime even when
    // both ordinary and dedicated S3 adapters are present.
    let backend = startup_s3::Backend::new();
    let mut configuration = gc_prepared(directory.path());
    configuration.s3.endpoint = backend.endpoint();
    configuration.gc.as_mut().unwrap().s3.endpoint = backend.endpoint();
    serve(configuration, Box::pin(async {})).unwrap();
}

#[test]
fn startup_claim_is_shared_by_all_public_assembly_paths_and_survives_exit() {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    let (_, state) = assemble(prepared(directory.path()).service, memory.clone()).unwrap();
    // Same backend, a different set of enabled capabilities and different
    // disposable cache directories cannot create a second incarnation.
    let other = tempfile::tempdir().unwrap();
    assert_eq!(
        assemble_with_listings(
            prepared(other.path()).service,
            memory.clone(),
            Some(memory.clone())
        )
        .err()
        .unwrap()
        .code,
        "INSTANCE_REUSED"
    );
    assert!(std::fs::read_dir(other.path()).unwrap().next().is_none());
    drop(state);
    assert_eq!(
        assemble_with_storage(prepared(other.path()).service, memory.clone(), None, None)
            .err()
            .unwrap()
            .code,
        "INSTANCE_REUSED"
    );
    let mut next = prepared(other.path()).service;
    next.worker_instance = WorkerInstance::Explicit(101);
    let (_, replacement) = assemble(next, memory.clone()).unwrap();
    drop(replacement);
    assert_eq!(memory.values.lock().unwrap().len(), 2);
}

#[test]
fn automatic_restart_returns_the_real_identity_before_database_workers_are_built() {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    crate::instance::initialize(memory.as_ref(), 40, until()).unwrap();
    for worker in [41, 42] {
        let mut config = prepared(directory.path()).service;
        config.worker_instance = WorkerInstance::Auto;
        config.discovery = Some(PreparedDiscovery::Automatic {
            master: [1; 32],
            namespace: [2; 32],
        });
        let assembly =
            assemble_identified(config, memory.clone(), Some(memory.clone()), None).unwrap();
        assert_eq!(assembly.worker_instance, worker);
        assert!(assembly.state.discovery.is_some());
        let wrong = assembly
            .state
            .scheduler
            .submit(
                principal(),
                call(Action::Status {
                    expected_worker_instance: Some(Decimal(worker - 1)),
                }),
                until(),
            )
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap_err();
        assert_eq!(wrong.code, "TARGET_MISMATCH");
        drop(assembly);
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());
    }
    let memory = Arc::new(Memory::default());
    let mut config = prepared(directory.path()).service;
    config.worker_instance = WorkerInstance::Auto;
    assert_eq!(
        assemble(config, memory.clone()).err().unwrap().code,
        "INSTANCE_ALLOCATOR_MISSING"
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 1);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn discovery_identity_mismatch_precedes_allocation_and_late_failure_burns_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    for (worker, discovery) in [
        (
            WorkerInstance::Auto,
            PreparedDiscovery::Ready(crate::discovery::tests::codec()),
        ),
        (
            WorkerInstance::Explicit(100),
            PreparedDiscovery::Automatic {
                master: [1; 32],
                namespace: [2; 32],
            },
        ),
    ] {
        let mut config = prepared(directory.path()).service;
        config.worker_instance = worker;
        config.discovery = Some(discovery);
        assert_eq!(
            assemble_identified(config, memory.clone(), Some(memory.clone()), None)
                .err()
                .unwrap()
                .code,
            "CONFIG"
        );
        assert!(memory.calls.lock().unwrap().is_empty());
    }
    fn failed_discovery(
        _: PreparedDiscovery,
        _: u64,
    ) -> Result<Arc<crate::discovery_cursor::CursorCodec>, Failure> {
        Err(Failure::new("UNAVAILABLE"))
    }
    crate::instance::initialize(memory.as_ref(), 0, until()).unwrap();
    let mut config = prepared(directory.path()).service;
    config.worker_instance = WorkerInstance::Auto;
    config.discovery = Some(PreparedDiscovery::Automatic {
        master: [1; 32],
        namespace: [2; 32],
    });
    assert_eq!(
        assemble_using(
            config,
            memory.clone(),
            Some(memory.clone()),
            None,
            crate::catalogue_scheduler::Scheduler::new,
            failed_discovery
        )
        .err()
        .unwrap()
        .code,
        "UNAVAILABLE"
    );
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
    assert_eq!(
        crate::instance::claim(memory.as_ref(), 1, until())
            .unwrap_err()
            .code,
        "INSTANCE_REUSED"
    );
    assert_eq!(
        crate::instance::allocate(memory.as_ref(), until()).unwrap(),
        2
    );
}

#[test]
fn direct_assembly_validates_every_local_profile_before_consuming_an_identity() {
    let directory = tempfile::tempdir().unwrap();
    let changes: &[fn(&mut ServiceConfig)] = &[
        |p| p.transport.max_connections = 0,
        |p| p.output.version = 0,
        |p| p.options.operation_timeout = Duration::ZERO,
        |p| p.admission.active_database_actors = 0,
        |p| p.listen = "0.0.0.0:0".parse().unwrap(),
        |p| p.worker_instance = WorkerInstance::Explicit(0),
        |p| p.cache_directory = "relative".into(),
        |p| p.cache.pages_per_actor = 0,
        |p| p.cache.parallel_recoveries = 0,
        |p| p.cache.parallel_recoveries = 257,
        |p| p.admission.timeout_ms = 0,
        |p| p.admission.recovery_timeout_ms = 0,
        |p| p.admission.recovery_timeout_ms = 604800001,
        |p| p.admission.max_body_bytes = 0,
        |p| p.admission.data_intake = 0,
        |p| p.admission.control_intake = 0,
        |p| p.admission.recovery_intake = 0,
        |p| p.gc_deployment = Some(0),
        |p| p.gc_deployment = Some(1),
        |p| p.discovery = Some(PreparedDiscovery::Ready(crate::discovery::tests::codec())),
    ];
    for change in changes {
        let memory = Arc::new(Memory::default());
        let mut configuration = prepared(directory.path()).service;
        change(&mut configuration);
        assert_eq!(
            assemble(configuration, memory.clone()).err().unwrap().code,
            "CONFIG"
        );
        assert!(memory.calls.lock().unwrap().is_empty());
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());
    }
    let memory = Arc::new(Memory::default());
    let mut configuration = prepared(directory.path()).service;
    configuration.gc_deployment = Some(2);
    assert_eq!(
        assemble_with_storage(
            configuration,
            memory.clone(),
            Some(memory.clone()),
            Some(memory.clone())
        )
        .err()
        .unwrap()
        .code,
        "CONFIG"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
    let memory = Arc::new(Memory::default());
    let mut configuration = prepared(directory.path()).service;
    configuration.cache_directory = directory.path().join("missing");
    assert_eq!(
        assemble(configuration, memory.clone()).err().unwrap().code,
        "CACHE_IO"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
}

#[test]
fn claim_failure_starts_no_service_workers_or_local_cache() {
    for error in [
        scap_object_store::StoreError::Conflict,
        scap_object_store::StoreError::Unknown,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let memory = Arc::new(Memory::default());
        *memory.fail_put.lock().unwrap() = Some(error.clone());
        let expected = if error == scap_object_store::StoreError::Conflict {
            "INSTANCE_REUSED"
        } else {
            "INSTANCE_UNKNOWN"
        };
        assert_eq!(
            assemble(prepared(directory.path()).service, memory.clone())
                .err()
                .unwrap()
                .code,
            expected
        );
        assert_eq!(memory.calls.lock().unwrap().len(), 1);
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());
    }
}

#[test]
fn cache_loss_after_claim_fails_startup_and_does_not_release_the_identity() {
    use scap_object_store::{Condition, StoreError, Stored};

    struct RemoveCache {
        memory: Arc<Memory>,
        path: std::path::PathBuf,
    }
    impl Objects for RemoveCache {
        fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
            let stored = self.memory.get(key, maximum, deadline)?;
            // The directory was valid before the claim. Remove it at the
            // external I/O boundary to exercise a real worker creation error.
            std::fs::remove_dir(&self.path).unwrap();
            Ok(stored)
        }

        fn put(
            &self,
            key: &str,
            bytes: &[u8],
            condition: Condition<'_>,
            deadline: Instant,
        ) -> Result<String, StoreError> {
            self.memory.put(key, bytes, condition, deadline)
        }
    }

    for with_restore in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let cache = parent.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        let memory = Arc::new(Memory::default());
        let backend = Arc::new(RemoveCache {
            memory: memory.clone(),
            path: cache.clone(),
        });
        let mut config = prepared(&cache).service;
        if with_restore {
            let profile: crate::restore::Profile =
                serde_json::from_value(crate::restore::tests::profile()).unwrap();
            config.catalogue = Some(
                serde_json::from_value::<crate::restore::Profile>(crate::restore::tests::profile())
                    .unwrap()
                    .admission,
            );
            config.restore = Some(profile);
        }
        assert_eq!(assemble(config, backend).err().unwrap().code, "CACHE_IO");
        assert!(!cache.exists());
        assert_eq!(memory.calls.lock().unwrap().len(), 2);
        assert_eq!(memory.values.lock().unwrap().len(), 1);
        std::fs::create_dir(&cache).unwrap();
        assert_eq!(
            assemble(prepared(&cache).service, memory.clone())
                .err()
                .unwrap()
                .code,
            "INSTANCE_REUSED"
        );
        let mut next = prepared(&cache).service;
        next.worker_instance = WorkerInstance::Explicit(101);
        let (_, state) = assemble(next, memory).unwrap();
        drop(state);
        assert!(std::fs::read_dir(&cache).unwrap().next().is_none());
    }
}

#[test]
fn catalogue_construction_failure_after_claim_does_not_release_the_identity() {
    fn failed_catalogue(
        limits: crate::catalogue_scheduler::Limits,
        _factory: crate::catalogue_scheduler::Factory,
    ) -> Result<crate::catalogue_scheduler::Scheduler, Failure> {
        // This seam models an OS thread-creation failure after valid admission,
        // without exhausting process-wide resources used by concurrent tests.
        limits.validate().unwrap();
        Err(Failure::new("UNAVAILABLE"))
    }

    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    let mut configuration = prepared(directory.path()).service;
    configuration.catalogue = Some(crate::config::CatalogueAdmission {
        workers: 1,
        queued_total: 4,
        queued_per_tenant: 3,
        queued_per_name: 2,
        intake: 2,
        max_body_bytes: 65536,
        timeout_ms: 1000,
        intake_profile: None,
    });
    assert_eq!(
        assemble_using(
            configuration,
            memory.clone(),
            None,
            None,
            failed_catalogue,
            PreparedDiscovery::bind
        )
        .err()
        .unwrap()
        .code,
        "UNAVAILABLE"
    );
    assert_eq!(memory.calls.lock().unwrap().len(), 2);
    assert_eq!(memory.values.lock().unwrap().len(), 1);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
    assert_eq!(
        assemble(prepared(directory.path()).service, memory)
            .err()
            .unwrap()
            .code,
        "INSTANCE_REUSED"
    );
}

#[test]
fn gc_assembly_requires_exact_capabilities_and_wires_the_collector_into_workers() {
    let directory = tempfile::tempdir().unwrap();
    let memory = Arc::new(Memory::default());
    for (deployment, listing, garbage) in [
        (Some(0), true, true),
        (Some(1), false, true),
        (Some(1), true, false),
        (None, true, true),
    ] {
        let mut value = prepared(directory.path()).service;
        value.gc_deployment = deployment;
        assert_eq!(
            assemble_with_storage(
                value,
                memory.clone(),
                listing.then(|| memory.clone() as Arc<dyn Listings>),
                garbage.then(|| memory.clone() as Arc<dyn Garbage>)
            )
            .err()
            .unwrap()
            .code,
            "CONFIG"
        );
    }
    let (_, state) = assemble_with_storage(
        gc_prepared(directory.path()).service,
        memory.clone(),
        Some(memory.clone()),
        Some(memory.clone()),
    )
    .unwrap();
    let submit = |action| {
        state
            .scheduler
            .submit(principal(), call(action), until())
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap()
    };
    let first = submit(Action::Create { nonce: Decimal(1) });
    let begun = submit(Action::CompactBegin {
        expected_head_serial: Decimal(first["head_serial"].as_str().unwrap().parse().unwrap()),
    });
    let plan = Decimal(
        begun["storage"]["plan"]["serial"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    );
    let aborted = submit(Action::CompactAbort { plan_serial: plan });
    let empty = submit(Action::GcPrepare {
        expected_head_serial: Decimal(aborted["head_serial"].as_str().unwrap().parse().unwrap()),
        generation: Decimal(2),
        after: None,
    });
    assert_eq!(empty["scanned"], 0);
    assert_eq!(empty["exhausted"], true);
    assert!(empty["status"]["storage"]["sweep"].is_null());
    assert!(memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call.starts_with("LIST ")));
    drop(state);
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}
