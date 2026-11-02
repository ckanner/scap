use std::ffi::OsString;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use scap_service::ServiceError;

use crate::{failure, Config, StartMode};

type SignalFuture<'a> = Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>>;
type TerminationFuture<'a> = Pin<Box<dyn Future<Output = Option<()>> + Send + 'a>>;

pub fn command(args: impl IntoIterator<Item = OsString>) -> Result<(), ServiceError> {
    command_with(args, |config, mode| {
        execute(
            config,
            mode,
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build(),
            Box::pin(signal()),
        )
    })
}

async fn signal() -> std::io::Result<()> {
    registered_signal(tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    ))
    .await
}

async fn registered_signal(
    registered: std::io::Result<tokio::signal::unix::Signal>,
) -> std::io::Result<()> {
    let mut terminate = registered?;
    wait_signal(
        Box::pin(tokio::signal::ctrl_c()),
        Box::pin(terminate.recv()),
    )
    .await
}

async fn wait_signal(
    interrupt: SignalFuture<'_>,
    terminate: TerminationFuture<'_>,
) -> std::io::Result<()> {
    tokio::select! {
        result = interrupt => result,
        result = terminate => result.ok_or_else(|| std::io::Error::other("termination signal closed")),
    }
}

fn command_with(
    args: impl IntoIterator<Item = OsString>,
    start: impl FnOnce(Config, StartMode) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let args: Vec<_> = args.into_iter().take(3).collect();
    let (config, mode) = read_command(&args)?;
    start(config, mode)
}

fn read_command(args: &[OsString]) -> Result<(Config, StartMode), ServiceError> {
    let (mode, path) = arguments(args)?;
    let config = Config::decode(&crate::node::read_file(Path::new(path), 1024 * 1024)?)?;
    Ok((config, mode))
}

fn arguments(args: &[OsString]) -> Result<(StartMode, &OsString), ServiceError> {
    let (mode, path) = match args {
        [path] => (StartMode::OpenExisting, path),
        [flag, path] if flag == "--initialize" => (StartMode::Initialize, path),
        _ => {
            return Err(failure(
                "USAGE: scap-server [--initialize] /absolute/config.json",
            ))
        }
    };
    Ok((mode, path))
}

fn execute(
    config: Config,
    mode: StartMode,
    executor: std::io::Result<tokio::runtime::Runtime>,
    shutdown: SignalFuture<'_>,
) -> Result<(), ServiceError> {
    let executor = executor.map_err(|_| failure("EXECUTOR"))?;
    let result = executor.block_on(async {
        let mut signal_failed = false;
        crate::run(config, mode, async {
            signal_failed = shutdown.await.is_err();
        })
        .await?;
        if signal_failed {
            return Err(failure("SIGNAL"));
        }
        Ok(())
    });
    // A timed-out native I/O join cannot be forcibly cancelled. Do not let
    // Runtime::drop silently replace the explicit node shutdown bound with an
    // unbounded wait; the CLI exits and its process supervisor may terminate it.
    executor.shutdown_timeout(std::time::Duration::from_millis(100));
    result
}

#[cfg(test)]
mod tests;
