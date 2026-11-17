//! Startup owns runtimes on a plain OS thread; S3 is never dropped in Tokio.

use std::ffi::OsString;
use std::future::Future;
use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_object_store::{Garbage, GcS3, Listings, Objects, S3Config, S3};
use tokio::sync::Semaphore;

use crate::{
    config::{Config, Prepared, PreparedGarbage, ServiceConfig},
    engine::{Collector, Engine},
    http::{self, CatalogueState, HttpState},
    intake::{Class, Intake},
    scheduler::{Factory, Scheduler},
    Failure,
};

pub type Shutdown = std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Build without entering an asynchronous runtime. Startup permanently claims
/// its configured identity on the supplied authority before starting workers.
pub fn assemble(
    prepared: ServiceConfig,
    objects: Arc<dyn Objects>,
) -> Result<(std::net::SocketAddr, Arc<HttpState>), Failure> {
    assemble_with_listings(prepared, objects, None)
}

/// The same configured backend must provide object authority and candidate
/// listing. Enabling discovery without its transport fails at startup.
pub fn assemble_with_listings(
    prepared: ServiceConfig,
    objects: Arc<dyn Objects>,
    listings: Option<Arc<dyn Listings>>,
) -> Result<(std::net::SocketAddr, Arc<HttpState>), Failure> {
    assemble_with_storage(prepared, objects, listings, None)
}

/// Trusted Rust assembly must bind all capabilities to the same backend.
/// Missing or unexpected collector capability is a startup configuration error.
pub fn assemble_with_storage(
    prepared: ServiceConfig,
    objects: Arc<dyn Objects>,
    listings: Option<Arc<dyn Listings>>,
    garbage: Option<Arc<dyn Garbage>>,
) -> Result<(std::net::SocketAddr, Arc<HttpState>), Failure> {
    prepared.transport.checked()?;
    let output = Arc::new(crate::output::Pool::new(prepared.output)?);
    let options = prepared.options;
    options.validate().map_err(|_| Failure::new("CONFIG"))?;
    let limits = prepared.admission.limits();
    limits.validate()?;
    let admission = &prepared.admission;
    if !prepared.listen.ip().is_loopback()
        || prepared.worker_instance == 0
        || !prepared.cache_directory.is_absolute()
        || prepared.cache.pages_per_actor == 0
        || !(1..=256).contains(&prepared.cache.parallel_recoveries)
        || !(1..=86400000).contains(&admission.timeout_ms)
        || !(admission.timeout_ms..=604800000).contains(&admission.recovery_timeout_ms)
    {
        return Err(Failure::new("CONFIG"));
    }
    scap_object_sqlite::validate_cache_directory(&prepared.cache_directory)
        .map_err(|_| Failure::new("CACHE_IO"))?;
    let intake = Arc::new(Intake::new(
        Class::Data,
        admission.data_intake,
        admission.max_body_bytes,
        admission.data_profile,
    )?);
    let control_intake = Arc::new(Intake::new(
        Class::Control,
        admission.control_intake,
        admission.max_body_bytes,
        admission.control_profile,
    )?);
    let recovery_intake = Arc::new(Intake::new(
        Class::Recovery,
        admission.recovery_intake,
        admission.max_body_bytes,
        admission.recovery_profile,
    )?);
    let catalogue_intake = match &prepared.catalogue {
        Some(admission) => {
            admission.limits().validate()?;
            Some(Arc::new(admission.build_intake()?))
        }
        None => None,
    };
    let collector = match prepared.gc_deployment {
        Some(deployment) => {
            if deployment == 0 {
                return Err(Failure::new("CONFIG"));
            }
            prepared.auth.validate_gc_deployment(deployment)?;
            Some(Collector {
                deployment,
                listings: listings.clone().ok_or_else(|| Failure::new("CONFIG"))?,
                garbage: garbage.ok_or_else(|| Failure::new("CONFIG"))?,
            })
        }
        None => {
            if garbage.is_some() {
                return Err(Failure::new("CONFIG"));
            }
            None
        }
    };
    let discovery = match prepared.discovery {
        Some(codec) => Some(Arc::new(crate::discovery::Discovery::new(
            objects.clone(),
            listings.ok_or_else(|| Failure::new("CONFIG"))?,
            prepared.worker_instance,
            codec,
        )?)),
        None => None,
    };
    // Every local configuration/capability check above precedes this durable
    // effect. There are no service workers or listeners yet. A later runtime,
    // thread or bind failure still consumes the ID; cleanup never releases it.
    crate::instance::claim(
        objects.as_ref(),
        prepared.worker_instance,
        Instant::now() + options.operation_timeout,
    )?;
    let catalogue = match prepared.catalogue {
        Some(admission) => {
            let objects = objects.clone();
            let options = options.clone();
            let factory: crate::catalogue_scheduler::Factory = Arc::new(move |_| {
                Ok(Box::new(crate::catalogue::Worker::new(
                    objects.clone(),
                    prepared.worker_instance,
                    options.clone(),
                )))
            });
            Some(CatalogueState {
                scheduler: Arc::new(crate::catalogue_scheduler::Scheduler::new(
                    admission.limits(),
                    factory,
                )?),
                max_body_bytes: admission.max_body_bytes,
                timeout: Duration::from_millis(admission.timeout_ms),
                intake: catalogue_intake.expect("validated catalogue admission"),
            })
        }
        None => None,
    };
    let recovery = Arc::new(Semaphore::new(prepared.cache.parallel_recoveries));
    let factory: Factory = Arc::new(move |_| {
        Ok(Box::new(
            Engine::new(
                objects.clone(),
                prepared.worker_instance,
                options.clone(),
                &prepared.cache_directory,
                1,
                prepared.cache.pages_per_actor,
                recovery.clone(),
            )?
            .with_collector(collector.clone()),
        ))
    });
    let scheduler = Arc::new(Scheduler::new(limits, factory)?);
    let admission = prepared.admission;
    Ok((
        prepared.listen,
        Arc::new(HttpState {
            auth: prepared.auth,
            scheduler,
            output,
            catalogue,
            discovery,
            max_body_bytes: admission.max_body_bytes,
            timeout: Duration::from_millis(admission.timeout_ms),
            recovery_timeout: Duration::from_millis(admission.recovery_timeout_ms),
            intake,
            control_intake,
            recovery_intake,
        }),
    ))
}

pub fn serve(prepared: Prepared, shutdown: Shutdown) -> Result<(), Failure> {
    // Direct Prepared callers receive the same validation as parsed configs,
    // before S3 clients or any workers are created.
    let transport = prepared.service.transport.checked()?;
    prepared.service.output.checked()?;
    let garbage = gc_backend(prepared.gc, prepared.service.gc_deployment, &prepared.s3)?;
    // Construction and final drop remain outside the request runtime. Each S3
    // object owns a separate bounded I/O runtime shared by the worker threads.
    let backend = Arc::new(S3::new(prepared.s3).map_err(|_| Failure::new("CONFIG"))?);
    let (address, state) =
        assemble_with_storage(prepared.service, backend.clone(), Some(backend), garbage)?;
    run(address, state, transport, shutdown, runtime)
}

fn gc_backend(
    configured: Option<PreparedGarbage>,
    deployment: Option<u64>,
    authority: &S3Config,
) -> Result<Option<Arc<dyn Garbage>>, Failure> {
    match configured {
        Some(gc) => {
            if deployment != Some(gc.deployment)
                || gc.s3.endpoint != authority.endpoint
                || gc.s3.region != authority.region
                || gc.s3.bucket != authority.bucket
                || gc.s3.timeout != authority.timeout
                || gc.s3.allow_http != authority.allow_http
                || gc.s3.max_object_bytes != authority.max_object_bytes
                || gc.s3.access_key == authority.access_key
            {
                return Err(Failure::new("CONFIG"));
            }
            Ok(Some(Arc::new(
                GcS3::new(gc.s3, gc.deployment).map_err(|_| Failure::new("CONFIG"))?,
            )))
        }
        None => {
            if deployment.is_some() {
                return Err(Failure::new("CONFIG"));
            }
            Ok(None)
        }
    }
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
    transport: crate::transport::Limits,
    shutdown: Shutdown,
    create_runtime: fn() -> std::io::Result<tokio::runtime::Runtime>,
) -> Result<(), Failure> {
    let router = http::router(state.clone())?;
    let runtime = create_runtime().map_err(|_| Failure::new("RUNTIME"))?;
    let outcome = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|_| Failure::new("LISTEN"))?;
        crate::transport::serve(listener, router, transport, shutdown).await;
        Ok(())
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
