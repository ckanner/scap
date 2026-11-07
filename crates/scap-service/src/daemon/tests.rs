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
fn startup_and_listener_failures_do_not_leave_workers_or_connections_running() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = prepared(directory.path());
    configuration.service.admission.workers = 0;
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
    config.service.admission.workers = 0;
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
