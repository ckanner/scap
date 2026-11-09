use super::*;
use crate::tests::{call, principal, sample_config, until, Memory};
use crate::wire::{Action, Decimal};

fn prepared(parent: &std::path::Path) -> Prepared {
    std::env::set_var("SCAP_TEST_ACCESS", "access");
    std::env::set_var("SCAP_TEST_SECRET", "secret");
    let prepared = Config::parse(&serde_json::to_vec(&sample_config(parent)).unwrap())
        .unwrap()
        .prepare()
        .unwrap();
    std::env::remove_var("SCAP_TEST_ACCESS");
    std::env::remove_var("SCAP_TEST_SECRET");
    prepared
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
        .submit(principal(), call(Action::Status {}), until())
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
    receive(submit(&state, 10, Action::Status {}));
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
    serve(prepared(directory.path()), Box::pin(async {})).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut configuration = prepared(directory.path());
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
            "127.0.0.1:0".parse().unwrap(),
            state,
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
            "127.0.0.1:0".parse().unwrap(),
            state,
            Box::pin(async {}),
            runtime
        )
        .unwrap_err()
        .code,
        "CONFIG"
    );
    assert_eq!(
        http_result(Err(std::io::Error::other("unit accept failure")))
            .unwrap_err()
            .code,
        "HTTP"
    );
    assert!(http_result(Ok(())).is_ok());
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
    assert!(start(vec![file.clone().into()], accepted).is_ok());
    assert_eq!(start(vec![], accepted).unwrap_err().code, "USAGE");
    assert_eq!(
        start(vec![file.clone().into(), file.clone().into()], accepted)
            .unwrap_err()
            .code,
        "USAGE"
    );
    assert_eq!(
        start(vec![directory.path().join("missing").into()], accepted)
            .unwrap_err()
            .code,
        "CONFIG"
    );
    assert_eq!(
        start(vec![directory.path().into()], accepted)
            .unwrap_err()
            .code,
        "CONFIG"
    );
    std::fs::write(&file, vec![0; 4 * 1024 * 1024 + 2]).unwrap();
    assert_eq!(
        start(vec![file.clone().into()], accepted).unwrap_err().code,
        "CONFIG"
    );
    std::fs::write(&file, b"{}").unwrap();
    assert_eq!(entry(vec![file.into()]), ExitCode::FAILURE);
    assert_eq!(exit(Ok(())), ExitCode::SUCCESS);

    let mut config =
        Config::parse(&serde_json::to_vec(&sample_config(directory.path())).unwrap()).unwrap();
    config.version = 2;
    assert_eq!(launch(config).unwrap_err().code, "CONFIG");
    std::env::set_var("SCAP_TEST_ACCESS", "access");
    std::env::set_var("SCAP_TEST_SECRET", "secret");
    let mut config =
        Config::parse(&serde_json::to_vec(&sample_config(directory.path())).unwrap()).unwrap();
    config.s3.endpoint = "bad".into();
    assert_eq!(launch(config).unwrap_err().code, "CONFIG");
    std::env::remove_var("SCAP_TEST_ACCESS");
    std::env::remove_var("SCAP_TEST_SECRET");
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
    p.discovery = Some(crate::discovery::tests::codec());
    assert_eq!(assemble(p, memory.clone()).err().unwrap().code, "CONFIG");
    let mut p = prepared(directory.path()).service;
    p.discovery = Some(crate::discovery::tests::codec());
    p.worker_instance = 0;
    assert_eq!(
        assemble_with_listings(p, memory.clone(), Some(memory.clone()))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    let mut p = prepared(directory.path()).service;
    p.discovery = Some(crate::discovery::tests::codec());
    let (_, state) = assemble_with_listings(p, memory.clone(), Some(memory)).unwrap();
    assert!(state.discovery.is_some());
    drop(state);
}
