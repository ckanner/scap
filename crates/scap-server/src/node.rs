use std::fs::{self, File};
use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use axum::{
    http::{header, HeaderValue, StatusCode},
    middleware::map_response,
    response::Response,
    routing::get,
};
use raft::eraftpb::ConfState;
use scap_cell::{CellApplication, CellState, Position};
use scap_cell_client::Client;
use scap_raft_driver::{Driver, DriverConfig};
use scap_raft_rocks::RocksBackend;
use scap_raft_runtime::{
    Clock, Handle, NetworkWorkers, QueueLimits, Runtime, RuntimeConfig, SystemClock,
};
use scap_raft_store::{Identity, Store};
use scap_raft_transport::{
    ClientSecurity, PeerEndpoint, PeerServer, ServerSecurity, TransportLimits,
};
use scap_raft_wire::{certificate_identity, Binding, Policy, Scope};
use scap_service::{Service, ServiceError};
use scap_sql_worker::NativeFactory;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

use crate::archive;
use crate::archive_jobs::{self, Jobs, Supervisor};
use crate::config::{cell_limits, worker_limits, Config};
use crate::failure;
use crate::lanes::{Executor, Lanes};
use crate::listener::Bounded;
use crate::mailbox::{Envelope, Mailbox};
use crate::worker::{LocalPort, Worker};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartMode {
    Initialize,
    OpenExisting,
}

struct Stop {
    stopped: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    handle: scap_raft_runtime::Handle,
    signal: watch::Sender<bool>,
}
impl Stop {
    fn request(&self) {
        self.ready.store(false, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
        self.handle.stop();
        let _ = self.signal.send(true);
    }
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.request();
    }
}

trait System: Sync {
    fn entropy(&self, bytes: &mut [u8]) -> Result<(), getrandom::Error>;
    fn create_directory(&self, path: &Path) -> std::io::Result<()>;
    fn sync_parent(&self, path: &Path) -> std::io::Result<()>;
    fn spawn(
        &self,
        name: &'static str,
        job: Box<dyn FnOnce() + Send>,
    ) -> std::io::Result<thread::JoinHandle<()>>;
}

struct Native;
impl System for Native {
    fn entropy(&self, bytes: &mut [u8]) -> Result<(), getrandom::Error> {
        getrandom::fill(bytes)
    }
    fn create_directory(&self, path: &Path) -> std::io::Result<()> {
        fs::create_dir(path)
    }
    fn sync_parent(&self, path: &Path) -> std::io::Result<()> {
        File::open(path.join("..")).and_then(|parent| parent.sync_all())
    }
    fn spawn(
        &self,
        name: &'static str,
        job: Box<dyn FnOnce() + Send>,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        thread::Builder::new().name(name.into()).spawn(job)
    }
}

type CellDriver = Driver<RocksBackend, CellApplication>;
type CellRuntime = Runtime<CellDriver>;
type ArchiveJobs = Jobs<LocalPort, scap_archive::S3>;
type Shutdown<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Concrete constructors stay at one assembly boundary. The lifecycle owns
/// their returned resources and treats any construction failure identically to
/// a native failure; tests can reject a component before it becomes supervised.
trait Assembly: Sync {
    fn driver(
        &self,
        store: Store<RocksBackend>,
        application: CellApplication,
        boot: u128,
    ) -> Result<CellDriver, ServiceError>;
    fn runtime(
        &self,
        driver: CellDriver,
        policy: Policy,
    ) -> Result<(CellRuntime, Handle), ServiceError>;
    fn client(
        &self,
        config: &Config,
        port: LocalPort,
        clock: Arc<dyn Clock>,
    ) -> Result<Client<LocalPort>, ServiceError>;
    fn archive(
        &self,
        client: Client<LocalPort>,
        objects: Option<scap_archive::S3>,
        max_databases: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<(ArchiveJobs, Supervisor), ServiceError>;
    fn service(
        &self,
        mailbox: Mailbox,
        database: String,
        boot: u128,
    ) -> Result<Service<Mailbox>, ServiceError>;
}

impl Assembly for Native {
    fn driver(
        &self,
        store: Store<RocksBackend>,
        application: CellApplication,
        boot: u128,
    ) -> Result<CellDriver, ServiceError> {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        mapped(
            Driver::new(store, application, driver_config(boot), &logger),
            "DRIVER_CONFIG",
        )
    }
    fn runtime(
        &self,
        driver: CellDriver,
        policy: Policy,
    ) -> Result<(CellRuntime, Handle), ServiceError> {
        mapped(
            Runtime::new(driver, policy, runtime_config(), Arc::new(SystemClock)),
            "RUNTIME_CONFIG",
        )
    }
    fn client(
        &self,
        config: &Config,
        port: LocalPort,
        clock: Arc<dyn Clock>,
    ) -> Result<Client<LocalPort>, ServiceError> {
        mapped(
            Client::new(config.cluster_id, config.cell, cell_limits(), port, clock),
            "CELL_SCOPE",
        )
    }
    fn archive(
        &self,
        client: Client<LocalPort>,
        objects: Option<scap_archive::S3>,
        max_databases: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<(ArchiveJobs, Supervisor), ServiceError> {
        archive_jobs::spawn(client, objects, max_databases, clock)
    }
    fn service(
        &self,
        mailbox: Mailbox,
        database: String,
        boot: u128,
    ) -> Result<Service<Mailbox>, ServiceError> {
        Service::new(mailbox, database, boot, http_limits())
    }
}

/// Keep every native owner joined, including failure after only one owner was
/// started. A dropped run future first stops admission before reclaiming them.
struct Owners {
    stop: Stop,
    threads: Vec<thread::JoinHandle<()>>,
    archive: Option<Supervisor>,
}
impl Owners {
    fn request_stop(&self) {
        self.stop.request();
        if let Some(archive) = &self.archive {
            archive.request_stop();
        }
    }
    fn finish(&mut self) -> Result<(), ServiceError> {
        self.request_stop();
        let mut failed = false;
        for owner in self.threads.drain(..) {
            failed |= owner.join().is_err();
        }
        let archived = self
            .archive
            .take()
            .map(|archive| archive.join())
            .unwrap_or(Ok(()));
        if failed {
            return Err(failure("SHUTDOWN_THREAD"));
        }
        archived
    }
}
impl Drop for Owners {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Assembly errors retain their public boundary without duplicating closure
// implementations for every concrete storage/transport error type.
fn mapped<T, E>(result: Result<T, E>, code: &str) -> Result<T, ServiceError> {
    result.map_err(|_| failure(code))
}

/// Run one configured voter and its leader-owned SQL service. Each deployment
/// uses three independently configured processes and three private directories.
/// Creation is explicit; missing/corrupt existing storage never creates a cell.
pub async fn run(
    config: Config,
    mode: StartMode,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServiceError> {
    run_with(config, mode, Box::pin(shutdown), &Native, &Native).await
}

async fn run_with(
    config: Config,
    mode: StartMode,
    shutdown: Shutdown<'_>,
    system: &dyn System,
    assembly: &dyn Assembly,
) -> Result<(), ServiceError> {
    if config.databases.is_empty() || config.databases.len() > 32 {
        return Err(failure("CONFIG_DATABASE"));
    }
    let boot = boot_id(|bytes| system.entropy(bytes))?;
    let application = mapped(
        CellApplication::new(config.cell, cell_limits()),
        "CELL_CONFIG",
    )?;
    let material = security(&config)?;
    let store = open_store_with(&config, mode, system)?;
    // Acquiring the exclusive RocksDB lock precedes touching writer caches.
    // No other live process may own this node's private data namespace.
    crate::cache::clean_namespace(&config.data_dir.join("writers"))?;
    let driver = assembly.driver(store, application, boot)?;
    let (mut runtime, handle) = assembly.runtime(driver, material.policy)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let (signal, stop_signal) = watch::channel(false);
    let mut owners = Owners {
        stop: Stop {
            stopped: stopped.clone(),
            ready: ready.clone(),
            handle: handle.clone(),
            signal,
        },
        threads: Vec::new(),
        archive: None,
    };
    let http_listener = mapped(TcpListener::bind(config.http_listen).await, "HTTP_BIND")?;
    let peer_listener = mapped(TcpListener::bind(config.peer_listen).await, "PEER_BIND")?;
    let server = mapped(
        PeerServer::new(
            Arc::new(handle.clone()),
            material.server,
            transport_limits(),
        ),
        "PEER_TLS",
    )?;
    let (network, mut sender) = mapped(
        NetworkWorkers::start(
            handle.clone(),
            material.endpoints,
            material.client,
            transport_limits(),
            32,
        ),
        "NETWORK_CONFIG",
    )?;
    let objects = archive::connect(
        config.archive.as_ref(),
        tokio::runtime::Handle::current(),
        |name| std::env::var(name).ok(),
    )?;
    let clock = Arc::new(SystemClock);
    let sql_port = LocalPort {
        handle: handle.clone(),
    };
    let client = assembly.client(&config, sql_port.clone(), clock.clone())?;
    let (cold, archive) =
        assembly.archive(client, objects, config.databases.len(), clock.clone())?;
    owners.archive = Some(archive);
    let (mailbox, receiver) = Mailbox::new(&config.databases, stopped.clone());
    let service = Arc::new(assembly.service(mailbox, config.databases[0].name.clone(), boot)?);
    let readiness = ready.clone();
    let readiness_stopped = stopped.clone();
    let routes = scap_service::router(service)
        .route(
            "/readyz",
            get(move || readiness_response(readiness.clone(), readiness_stopped.clone())),
        )
        .route("/livez", get(|| async { StatusCode::OK }))
        .layer(map_response(close_connection));
    let http_stop = stop_signal.clone();
    let peer_stop = stop_signal;
    let mut http = Task(tokio::spawn(async move {
        axum::serve(Bounded::with_stop(http_listener, http_stop.clone()), routes)
            .with_graceful_shutdown(wait_stop(http_stop))
            .await
    }));
    let mut peer = Task(tokio::spawn(async move {
        server.serve(peer_listener, wait_stop(peer_stop)).await
    }));
    let (raft_complete, mut raft_completed) = oneshot::channel();
    let (sql_complete, mut sql_completed) = oneshot::channel();
    let result = async {
        owners.threads.push(mapped(
            system.spawn(
                "scap-raft",
                Box::new(move || {
                    let result = runtime.run(&mut sender);
                    let _ = raft_complete.send(result);
                }),
            ),
            "RAFT_THREAD",
        )?);
        owners.threads.push(mapped(
            system.spawn(
                "scap-sql",
                Box::new(move || {
                    let result = SqlOwner {
                        config,
                        sql_port,
                        cold,
                        clock,
                        ready,
                        boot,
                    }
                    .run(&receiver, stopped);
                    let _ = sql_complete.send(result);
                }),
            ),
            "SQL_THREAD",
        )?);
        supervise(
            shutdown,
            &mut http.0,
            &mut peer.0,
            &mut raft_completed,
            &mut sql_completed,
            owners.archive.as_mut().unwrap().completed(),
        )
        .await
    }
    .await;
    owners.request_stop();
    let deadline = Instant::now() + Duration::from_secs(5);
    let _ = network.shutdown(deadline).await;
    drain(&mut http.0, deadline).await;
    drain(&mut peer.0, deadline).await;
    // Synchronous disk calls cannot be force-cancelled. Process supervision may
    // terminate a stuck shutdown; an unfinished drain is never a commit ACK.
    let joined = tokio::task::spawn_blocking(move || owners.finish());
    finish_join(joined, deadline).await?;
    result
}

struct SqlOwner {
    config: Config,
    sql_port: LocalPort,
    cold: ArchiveJobs,
    clock: Arc<dyn Clock>,
    ready: Arc<AtomicBool>,
    boot: u128,
}

impl SqlOwner {
    fn run(self, receiver: &dyn Inbox, stopped: Arc<AtomicBool>) -> Result<(), ServiceError> {
        let Self {
            config,
            sql_port,
            cold,
            clock,
            ready,
            boot,
        } = self;
        let lane_config = config.clone();
        let lane_port = sql_port.clone();
        let lane_cold = cold.clone();
        let lane_clock = clock.clone();
        Lanes::new(
            boot,
            stopped.clone(),
            Box::new(move |database, boot| {
                let mut config = lane_config.clone();
                config.databases = vec![database];
                let port = lane_port.clone();
                let cold = lane_cold.clone();
                let clock = lane_clock.clone();
                Box::new(move || {
                    database_worker(config, port, cold, clock, boot)
                        .map(|worker| Box::new(worker) as Box<dyn Executor>)
                })
            }),
        )
        .and_then(|mut lanes| {
            let mut catalog =
                Worker::new(config, sql_port, NativeFactory, cold, clock, ready, boot)?;
            let result = sql_loop(&mut catalog, receiver, stopped, &mut lanes);
            let joined = lanes.finish();
            joined.and(result)
        })
    }
}

/// Per-request deadlines and recovery failures affect only this database's
/// worker. Only the catalogue publishes the node's routing readiness hint.
fn database_worker<P, C>(
    config: Config,
    port: P,
    cold: C,
    clock: Arc<dyn Clock>,
    boot: u128,
) -> Result<Worker<P, NativeFactory, C>, ServiceError>
where
    P: crate::worker::ControlPort,
    C: crate::worker::ColdStorage<P>,
{
    Worker::new(
        config,
        port,
        NativeFactory,
        cold,
        clock,
        Arc::new(AtomicBool::new(false)),
        boot,
    )
}

async fn close_connection(mut response: Response) -> Response {
    // The first HTTP/1 release uses one request per connection. Explicit close
    // prevents pools from racing reuse against the finite connection lifetime.
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

async fn supervise(
    shutdown: impl Future<Output = ()>,
    http: impl Future,
    peer: impl Future,
    raft: impl Future,
    sql: impl Future,
    archive: impl Future,
) -> Result<(), ServiceError> {
    tokio::select! {
        _ = shutdown => Ok(()),
        _ = http => Err(failure("HTTP_STOPPED")),
        _ = peer => Err(failure("PEER_STOPPED")),
        _ = raft => Err(failure("RAFT_STOPPED")),
        _ = sql => Err(failure("SQL_STOPPED")),
        _ = archive => Err(failure("ARCHIVE_STOPPED")),
    }
}

async fn finish_join(
    joined: tokio::task::JoinHandle<Result<(), ServiceError>>,
    deadline: Instant,
) -> Result<(), ServiceError> {
    mapped(
        mapped(
            tokio::time::timeout_at(deadline.into(), joined).await,
            "SHUTDOWN_TIMEOUT",
        )?,
        "SHUTDOWN_THREAD",
    )?
}

async fn drain<T>(task: &mut tokio::task::JoinHandle<T>, deadline: Instant) {
    if !task.is_finished()
        && tokio::time::timeout_at(deadline.into(), &mut *task)
            .await
            .is_err()
    {
        task.abort();
    }
}

async fn readiness_response(ready: Arc<AtomicBool>, stopped: Arc<AtomicBool>) -> StatusCode {
    if !stopped.load(Ordering::Acquire) && ready.load(Ordering::Acquire) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn wait_stop(mut signal: watch::Receiver<bool>) {
    while !*signal.borrow_and_update() {
        if signal.changed().await.is_err() {
            break;
        }
    }
}

trait Inbox {
    fn receive(&self) -> Result<Envelope, mpsc::RecvTimeoutError>;
}

impl Inbox for mpsc::Receiver<Envelope> {
    fn receive(&self) -> Result<Envelope, mpsc::RecvTimeoutError> {
        self.recv_timeout(Duration::from_millis(50))
    }
}

fn sql_loop<P, F, C>(
    catalog: &mut Worker<P, F, C>,
    receiver: &dyn Inbox,
    stopped: Arc<AtomicBool>,
    lanes: &mut Lanes,
) -> Result<(), ServiceError>
where
    P: crate::worker::ControlPort,
    F: scap_sql_worker::EngineFactory<P>,
    C: crate::worker::ColdStorage<P>,
{
    let mut maintenance = Instant::now();
    while !stopped.load(Ordering::Acquire) {
        lanes.reap()?;
        if Instant::now() >= maintenance {
            if let Ok(Some(database)) = catalog.scan() {
                lanes.recover(database)?;
            }
            maintenance = Instant::now() + Duration::from_secs(1);
        }
        match receiver.receive() {
            Ok(envelope) => {
                lanes.dispatch(envelope)?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

pub(crate) fn read_file(path: &Path, max: u64) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(max.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|_| failure("CONFIG_IO"))?;
    if bytes.len() as u64 > max {
        return Err(failure("CONFIG_LIMIT"));
    }
    Ok(bytes)
}

fn boot_id(
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<u128, ServiceError> {
    let mut bytes = [0; 16];
    fill(&mut bytes).map_err(|_| failure("RANDOM_SOURCE"))?;
    let boot = u128::from_le_bytes(bytes);
    if boot == 0 {
        return Err(failure("BOOT_ID"));
    }
    Ok(boot)
}

struct Security {
    policy: Policy,
    server: ServerSecurity,
    client: ClientSecurity,
    endpoints: Vec<PeerEndpoint>,
}

fn security(config: &Config) -> Result<Security, ServiceError> {
    let certificate = read_file(&config.certificate_pem, 16 * 1024)?;
    let key = read_file(&config.private_key_pem, 16 * 1024)?;
    let ca = read_file(&config.ca_pem, 16 * 1024)?;
    let bindings = config
        .peers
        .iter()
        .map(|peer| {
            let der = read_file(&peer.certificate_der, 16 * 1024)?;
            Ok(Binding {
                node_id: peer.node_id,
                fingerprint: certificate_identity(&der, 16 * 1024)
                    .map_err(|_| failure("PEER_CERTIFICATE"))?
                    .fingerprint,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let policy = Policy::new(
        Scope {
            cluster_id: config.cluster_id,
            cell_id: config.cell.cell_id,
            cell_incarnation: config.cell.cell_incarnation,
            node_id: config.node_id,
        },
        config.peers.iter().map(|peer| peer.node_id).collect(),
        bindings,
        scap_raft_wire::Limits {
            max_payload_bytes: 12 * 1024 * 1024,
            max_entries: 1024,
            max_fields: 64 * 1024,
            max_certificate_bytes: 16 * 1024,
            max_bindings: 3,
        },
    )
    .map_err(|_| failure("PEER_POLICY"))?;
    Ok(Security {
        policy,
        server: ServerSecurity {
            certificate_pem: certificate.clone(),
            private_key_pem: key.clone(),
            client_ca_pem: ca.clone(),
        },
        client: ClientSecurity {
            certificate_pem: certificate,
            private_key_pem: key,
            server_ca_pem: ca,
        },
        endpoints: config
            .peers
            .iter()
            .filter(|peer| peer.node_id != config.node_id)
            .map(|peer| PeerEndpoint {
                uri: peer.uri.clone(),
                cluster_id: config.cluster_id,
                node_id: peer.node_id,
            })
            .collect(),
    })
}

fn open_store_with(
    config: &Config,
    mode: StartMode,
    system: &dyn System,
) -> Result<Store<RocksBackend>, ServiceError> {
    let identity = Identity {
        cluster_id: config.cluster_id,
        cell_id: config.cell.cell_id,
        cell_incarnation: config.cell.cell_incarnation,
        node_id: config.node_id,
    };
    let path = config.data_dir.join("raft");
    let limits = scap_raft_store::Limits {
        max_image_bytes: 128 * 1024 * 1024,
        max_entry_bytes: 5 * 1024 * 1024,
        max_entries: 1024,
        max_application_bytes: cell_limits().max_state_bytes as usize,
    };
    match mode {
        StartMode::Initialize => {
            system
                .create_directory(&config.data_dir)
                .map_err(|_| failure("DATA_DIRECTORY"))?;
            system
                .sync_parent(&config.data_dir)
                .map_err(|_| failure("DATA_DIRECTORY_SYNC"))?;
            let backend = RocksBackend::create_new(&path).map_err(|_| failure("STORE_CREATE"))?;
            let mut membership = ConfState::default();
            membership.set_voters(config.peers.iter().map(|peer| peer.node_id).collect());
            let application = CellState::bootstrap(
                config.cell,
                config.administrator_id,
                Position { term: 1, index: 1 },
                cell_limits(),
            )
            .map_err(|_| failure("CELL_GENESIS"))?
            .encode();
            Store::create_new_with_application(backend, identity, membership, limits, application)
                .map_err(|_| failure("STORE_GENESIS"))
        }
        StartMode::OpenExisting => Store::open_existing(
            RocksBackend::open_existing(&path).map_err(|_| failure("STORE_OPEN"))?,
            identity,
            limits,
        )
        .map_err(|_| failure("STORE_IDENTITY")),
    }
}

fn driver_config(boot: u128) -> DriverConfig {
    DriverConfig {
        raft: raft::Config {
            election_tick: 15,
            heartbeat_tick: 2,
            pre_vote: true,
            check_quorum: true,
            read_only_option: raft::ReadOnlyOption::Safe,
            max_size_per_msg: 5 * 1024 * 1024,
            max_inflight_msgs: 16,
            max_uncommitted_size: 16 * 1024 * 1024,
            max_committed_size_per_ready: 5 * 1024 * 1024,
            ..raft::Config::default()
        },
        boot_id: boot,
        max_input_bytes: 12 * 1024 * 1024,
        max_output_messages: 64,
        max_output_bytes: 32 * 1024 * 1024,
        max_pending_reads: 32,
        max_pending_proposals: 32,
        max_pending_proposal_bytes: 32 * 1024 * 1024,
        max_ready_rounds: 32,
    }
}

fn runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        inbox: QueueLimits {
            max_messages: 128,
            max_bytes: 32 * 1024 * 1024,
        },
        requests: QueueLimits {
            max_messages: 32,
            max_bytes: 32 * 1024 * 1024,
        },
        max_pending_deliveries: 128,
        max_pending_delivery_bytes: 32 * 1024 * 1024,
        max_pending_reads: 32,
        max_pending_proposals: 32,
        max_result_bytes: 16 * 1024,
        max_view_bytes: 8 * 1024 * 1024,
        max_poll_rounds: 64,
        tick_interval: Duration::from_millis(100),
        delivery_timeout: Duration::from_secs(2),
        max_inbound_age: Duration::from_secs(10),
    }
}

fn transport_limits() -> TransportLimits {
    TransportLimits {
        max_wire_bytes: 13 * 1024 * 1024,
        max_connections: 64,
        max_inflight_requests: 32,
        max_streams_per_connection: 4,
        max_header_bytes: 8192,
        handshake_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(2),
        max_connection_age: Duration::from_secs(30),
        connection_grace: Duration::from_secs(2),
    }
}

fn http_limits() -> scap_service::Limits {
    scap_service::Limits {
        max_body_bytes: 1024 * 1024,
        max_response_bytes: 512 * 1024,
        max_pipeline_requests: 128,
        max_cached_statements: 64,
        max_cached_sql_bytes: 64 * 1024,
        max_inflight: 32,
        max_token_bytes: 4096,
        max_timeout: Duration::from_secs(10),
        sql: worker_limits().sqlite.sql,
    }
}

#[cfg(test)]
pub(crate) mod tests;
