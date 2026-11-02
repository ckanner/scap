use super::*;

#[test]
fn explicit_initialization_and_existing_open_are_distinct() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("config.json");
    std::fs::write(
        &file,
        serde_json::to_vec(&crate::tests::config_json()).unwrap(),
    )
    .unwrap();
    for (args, expected) in [
        (vec![file.as_os_str().to_owned()], StartMode::OpenExisting),
        (
            vec!["--initialize".into(), file.as_os_str().to_owned()],
            StartMode::Initialize,
        ),
    ] {
        command_with(args, |config, mode| {
            assert_eq!(mode, expected);
            assert_eq!(config.cluster_id, 1);
            Ok(())
        })
        .unwrap();
    }
    for args in [
        vec![],
        vec!["--unknown".into(), "path".into()],
        vec!["a".into(), "b".into(), "c".into()],
    ] {
        assert!(command_with(args, |_, _| panic!("invalid arguments cannot start")).is_err());
    }
    assert!(command(Vec::<OsString>::new()).is_err());
    assert!(command_with(vec!["/absent/config.json".into()], |_, _| Ok(())).is_err());
    assert_eq!(
        command(vec![file.as_os_str().to_owned()]).unwrap_err().code,
        "CONFIG_IO"
    );
    assert_eq!(
        command_with(vec![file.as_os_str().to_owned()], |_, _| Err(failure(
            "START_FAILURE"
        )))
        .unwrap_err()
        .code,
        "START_FAILURE"
    );
    std::fs::write(&file, b"{}").unwrap();
    assert!(command_with(vec![file.into_os_string()], |_, _| Ok(())).is_err());
    assert_eq!(
        execute(
            crate::tests::config(),
            StartMode::Initialize,
            Err(std::io::Error::other("injected executor error")),
            Box::pin(async { Ok(()) })
        )
        .unwrap_err()
        .code,
        "EXECUTOR"
    );
    drop(signal());
}

#[test]
fn executor_runs_native_node_and_preserves_shutdown_signal_errors() {
    for failed in [false, true] {
        let fixture = crate::node::tests::Fixture::new();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build();
        let result = execute(
            fixture.config.clone(),
            StartMode::Initialize,
            runtime,
            Box::pin(async move {
                if failed {
                    Err(std::io::Error::other("signal registration unavailable"))
                } else {
                    Ok(())
                }
            }),
        );
        assert_eq!(
            result.err().map(|error| error.code),
            failed.then(|| "SIGNAL".to_owned())
        );
        assert!(fixture.config.data_dir.join("raft").is_dir());
    }
}

#[tokio::test]
async fn interrupt_termination_and_signal_channel_errors_are_explicit() {
    use std::future::{pending, ready};
    assert!(wait_signal(Box::pin(ready(Ok(()))), Box::pin(pending()))
        .await
        .is_ok());
    assert!(wait_signal(
        Box::pin(ready(Err(std::io::Error::other("interrupt")))),
        Box::pin(pending())
    )
    .await
    .is_err());
    assert!(wait_signal(Box::pin(pending()), Box::pin(ready(Some(()))))
        .await
        .is_ok());
    assert!(wait_signal(Box::pin(pending()), Box::pin(ready(None)))
        .await
        .is_err());
    assert!(
        registered_signal(Err(std::io::Error::other("registration")))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_sigterm_is_registered_and_received_without_terminating_the_node_process() {
    use std::task::{Context, Waker};
    let mut signal = Box::pin(signal());
    let mut context = Context::from_waker(Waker::noop());
    assert!(signal.as_mut().poll(&mut context).is_pending());
    // Registration is complete before delivering a signal to this test process.
    // Other processes, including the build runner, are never addressed.
    let status = std::process::Command::new("kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    tokio::time::timeout(std::time::Duration::from_secs(2), signal)
        .await
        .unwrap()
        .unwrap();
}
