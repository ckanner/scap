//! Startup owns runtimes on a plain OS thread; S3 is never dropped in Tokio.

use std::ffi::OsString;
use std::future::Future;
use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use scap_object::Options;
use scap_object_store::{Objects, S3};
use tokio::sync::Semaphore;

use crate::{
    config::{Config, Prepared, ServiceConfig},
    engine::Engine,
    http::{self, CatalogueState, HttpState},
    scheduler::{Factory, Scheduler},
    Failure,
};

pub type Shutdown = std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Build without entering an asynchronous runtime. Cache files and object I/O
/// are created by the worker factory on their own confined worker threads.
pub fn assemble(
    prepared: ServiceConfig,
    objects: Arc<dyn Objects>,
) -> Result<(std::net::SocketAddr, Arc<HttpState>), Failure> {
    let catalogue = match prepared.catalogue {
        Some(admission) => {
            // The scheduler validates queue/worker limits at construction;
            // transport budgets must also hold for this direct entry point.
            admission.validate_transport()?;
            let objects = objects.clone();
            let factory: crate::catalogue_scheduler::Factory = Arc::new(move |_| {
                Ok(Box::new(crate::catalogue::Worker::new(
                    objects.clone(),
                    prepared.worker_instance,
                    Options::default(),
                )))
            });
            Some(CatalogueState {
                scheduler: Arc::new(crate::catalogue_scheduler::Scheduler::new(
                    admission.limits(),
                    factory,
                )?),
                max_body_bytes: admission.max_body_bytes,
                timeout: Duration::from_millis(admission.timeout_ms),
                intake: Arc::new(Semaphore::new(admission.intake)),
            })
        }
        None => None,
    };
    let limits = prepared.admission.limits();
    let recovery = Arc::new(Semaphore::new(prepared.cache.parallel_recoveries));
    let factory: Factory = Arc::new(move |_| {
        Ok(Box::new(Engine::new(
            objects.clone(),
            prepared.worker_instance,
            Options::default(),
            &prepared.cache_directory,
            prepared.cache.sessions_per_worker,
            prepared.cache.pages_per_worker,
            recovery.clone(),
        )?))
    });
    let scheduler = Arc::new(Scheduler::new(limits, factory)?);
    let admission = prepared.admission;
    Ok((
        prepared.listen,
        Arc::new(HttpState {
            auth: prepared.auth,
            scheduler,
            catalogue,
            max_body_bytes: admission.max_body_bytes,
            timeout: Duration::from_millis(admission.timeout_ms),
            recovery_timeout: Duration::from_millis(admission.recovery_timeout_ms),
            intake: Arc::new(Semaphore::new(admission.data_intake)),
            control_intake: Arc::new(Semaphore::new(admission.control_intake)),
            recovery_intake: Arc::new(Semaphore::new(admission.recovery_intake)),
        }),
    ))
}

pub fn serve(prepared: Prepared, shutdown: Shutdown) -> Result<(), Failure> {
    // Construction and final drop remain outside the request runtime. Each S3
    // object owns a separate bounded I/O runtime shared by the worker threads.
    let objects: Arc<dyn Objects> =
        Arc::new(S3::new(prepared.s3).map_err(|_| Failure::new("CONFIG"))?);
    let (address, state) = assemble(prepared.service, objects)?;
    run(address, state, shutdown, runtime)
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

fn run(
    address: std::net::SocketAddr,
    state: Arc<HttpState>,
    shutdown: Shutdown,
    create_runtime: fn() -> std::io::Result<tokio::runtime::Runtime>,
) -> Result<(), Failure> {
    let router = http::router(state.clone())?;
    let runtime = create_runtime().map_err(|_| Failure::new("RUNTIME"))?;
    let outcome = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|_| Failure::new("LISTEN"))?;
        http_result(
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown)
                .await,
        )
    });
    // Drop the request runtime before joining/dropping S3 workers.
    drop(runtime);
    drop(state);
    outcome
}

fn launch(config: Config) -> Result<(), Failure> {
    let prepared = config.prepare()?;
    serve(
        prepared,
        Box::pin(shutdown(Box::pin(tokio::signal::ctrl_c()))),
    )
}

async fn shutdown(signal: std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>) {
    let _ = signal.await;
}

fn http_result(result: std::io::Result<()>) -> Result<(), Failure> {
    result.map_err(|_| Failure::new("HTTP"))
}

fn start(args: Vec<OsString>, launch: fn(Config) -> Result<(), Failure>) -> Result<(), Failure> {
    if args.len() != 1 {
        return Err(Failure::new("USAGE"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&args[0])
        .map_err(|_| Failure::new("CONFIG"))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::new("CONFIG"))?;
    launch(Config::parse(&bytes)?)
}

pub fn entry(args: Vec<OsString>) -> ExitCode {
    exit(start(args, launch))
}

fn exit(result: Result<(), Failure>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scapd: {}", error.code);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
