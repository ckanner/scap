use super::*;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) struct Fixture {
    pub config: Config,
    pub directory: tempfile::TempDir,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::tests::config();
        config.data_dir = directory.path().join("data");
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        config.ca_pem = directory.path().join("ca.pem");
        fs::write(&config.ca_pem, ca.pem()).unwrap();
        for peer in &mut config.peers {
            let endpoint = PeerEndpoint {
                uri: peer.uri.clone(),
                cluster_id: config.cluster_id,
                node_id: peer.node_id,
            };
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![endpoint.server_name()]).unwrap();
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ];
            let certificate = params.signed_by(&key, &ca, &ca_key).unwrap();
            peer.certificate_der = directory.path().join(format!("peer-{}.der", peer.node_id));
            fs::write(&peer.certificate_der, certificate.der()).unwrap();
            if peer.node_id == config.node_id {
                config.certificate_pem = directory.path().join("server.pem");
                config.private_key_pem = directory.path().join("server-key.pem");
                fs::write(&config.certificate_pem, certificate.pem()).unwrap();
                fs::write(&config.private_key_pem, key.serialize_pem()).unwrap();
            }
        }
        Self { config, directory }
    }
}

fn free_addresses() -> (std::net::SocketAddr, std::net::SocketAddr) {
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    (first.local_addr().unwrap(), second.local_addr().unwrap())
}

async fn http_ready(address: std::net::SocketAddr) {
    http_response(address, "/readyz", 503).await;
}

async fn http_response(address: std::net::SocketAddr, path: &str, status: u16) {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    // One voter cannot invent a quorum or advertise SQL readiness.
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{response}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("\r\nconnection: close\r\n"),
        "{response}"
    );
}

async fn bind_after_cancellation(address: std::net::SocketAddr, deadline: Instant) -> TcpListener {
    tokio::time::timeout_at(deadline.into(), async {
        loop {
            match TcpListener::bind(address).await {
                Ok(listener) => return listener,
                // Dropping run aborts its server tasks; their listener drops
                // complete when those tasks are next polled by the runtime.
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("cannot observe release of {address}: {error}"),
            }
        }
    })
    .await
    .expect("cancelled node retained a listener past the shutdown observation deadline")
}

struct Faults {
    entropy: bool,
    directory: Option<&'static str>,
    thread: Option<&'static str>,
    panic: bool,
    skip: bool,
    active: Arc<AtomicUsize>,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            entropy: false,
            directory: None,
            thread: None,
            panic: false,
            skip: false,
            active: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl System for Faults {
    fn entropy(&self, bytes: &mut [u8]) -> Result<(), getrandom::Error> {
        if self.entropy {
            Err(getrandom::Error::UNSUPPORTED)
        } else {
            Native.entropy(bytes)
        }
    }
    fn create_directory(&self, path: &Path) -> std::io::Result<()> {
        if self.directory == Some("create") {
            return Err(std::io::Error::other("injected mkdir"));
        }
        Native.create_directory(path)?;
        if self.directory == Some("raft") {
            fs::create_dir(path.join("raft"))?;
        }
        Ok(())
    }
    fn sync_parent(&self, path: &Path) -> std::io::Result<()> {
        if self.directory == Some("sync") {
            return Err(std::io::Error::other("injected fsync"));
        }
        Native.sync_parent(path)
    }
    fn spawn(
        &self,
        name: &'static str,
        job: Box<dyn FnOnce() + Send>,
    ) -> std::io::Result<thread::JoinHandle<()>> {
        let selected = self.thread == Some(name);
        if selected && !self.panic && !self.skip {
            return Err(std::io::Error::other("injected thread admission"));
        }
        let active = self.active.clone();
        let panic = selected && self.panic;
        let skip = selected && self.skip;
        Native.spawn(
            name,
            Box::new(move || {
                struct Active(Arc<AtomicUsize>);
                impl Drop for Active {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                active.fetch_add(1, Ordering::AcqRel);
                let _active = Active(active);
                assert!(!panic, "injected owner panic");
                if !skip {
                    job();
                }
            }),
        )
    }
}

struct RejectAssembly(&'static str);
impl Assembly for RejectAssembly {
    fn driver(
        &self,
        store: Store<RocksBackend>,
        application: CellApplication,
        boot: u128,
    ) -> Result<CellDriver, ServiceError> {
        if self.0 == "DRIVER_CONFIG" {
            return Err(failure(self.0));
        }
        Native.driver(store, application, boot)
    }
    fn runtime(
        &self,
        driver: CellDriver,
        policy: Policy,
    ) -> Result<(CellRuntime, Handle), ServiceError> {
        if self.0 == "RUNTIME_CONFIG" {
            return Err(failure(self.0));
        }
        Native.runtime(driver, policy)
    }
    fn client(
        &self,
        config: &Config,
        port: LocalPort,
        clock: Arc<dyn Clock>,
    ) -> Result<Client<LocalPort>, ServiceError> {
        if self.0 == "CELL_SCOPE" {
            return Err(failure(self.0));
        }
        Native.client(config, port, clock)
    }
    fn archive(
        &self,
        client: Client<LocalPort>,
        objects: Option<scap_archive::S3>,
        max_databases: usize,
        clock: Arc<dyn Clock>,
    ) -> Result<(ArchiveJobs, Supervisor), ServiceError> {
        if self.0 == "ARCHIVE_SPAWN" {
            return Err(failure(self.0));
        }
        Native.archive(client, objects, max_databases, clock)
    }
    fn service(
        &self,
        mailbox: Mailbox,
        database: String,
        boot: u128,
    ) -> Result<Service<Mailbox>, ServiceError> {
        if self.0 == "SERVICE_CONFIG" {
            return Err(failure(self.0));
        }
        Native.service(mailbox, database, boot)
    }
}

#[test]
fn bounded_configuration_reads_and_boot_identity_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config");
    assert_eq!(read_file(&path, 10).unwrap_err().code, "CONFIG_IO");
    fs::write(&path, b"123").unwrap();
    assert_eq!(read_file(&path, 3).unwrap(), b"123");
    assert_eq!(read_file(&path, u64::MAX).unwrap(), b"123");
    assert_eq!(read_file(temp.path(), 3).unwrap_err().code, "CONFIG_IO");
    assert_eq!(read_file(&path, 2).unwrap_err().code, "CONFIG_LIMIT");
    assert_eq!(boot_id(|_| Ok(())).unwrap_err().code, "BOOT_ID");
    assert_eq!(
        boot_id(|_| Err(getrandom::Error::UNSUPPORTED))
            .unwrap_err()
            .code,
        "RANDOM_SOURCE"
    );
    assert_ne!(boot_id(getrandom::fill).unwrap(), 0);
    for byte in [0, 1, 2] {
        assert_eq!(
            boot_id(|bytes| {
                if byte == 2 {
                    return Err(getrandom::Error::UNSUPPORTED);
                }
                bytes.fill(byte);
                Ok(())
            })
            .is_ok(),
            byte == 1
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_assembly_never_keeps_partial_listeners_workers_or_store_lock() {
    for code in [
        "DRIVER_CONFIG",
        "RUNTIME_CONFIG",
        "CELL_SCOPE",
        "ARCHIVE_SPAWN",
        "SERVICE_CONFIG",
    ] {
        let fixture = Fixture::new();
        let result = run_with(
            fixture.config.clone(),
            StartMode::Initialize,
            Box::pin(async {}),
            &Native,
            &RejectAssembly(code),
        )
        .await;
        assert_eq!(result.unwrap_err().code, code);
        drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
    }
    let fixture = Fixture::new();
    let faults = Faults {
        entropy: true,
        ..Faults::default()
    };
    assert_eq!(
        run_with(
            fixture.config.clone(),
            StartMode::Initialize,
            Box::pin(async {}),
            &faults,
            &Native
        )
        .await
        .unwrap_err()
        .code,
        "RANDOM_SOURCE"
    );
    assert!(!fixture.config.data_dir.exists());
    assert_eq!(
        run(fixture.config.clone(), StartMode::OpenExisting, async {})
            .await
            .unwrap_err()
            .code,
        "STORE_OPEN"
    );
    assert!(!fixture.config.data_dir.exists());
    let mut config = fixture.config.clone();
    config.archive = Some(crate::ArchiveConfig {
        endpoint: "https://s3.example.test".into(),
        region: "unit".into(),
        bucket: "unit".into(),
        access_key_env: "=".into(),
        secret_key_env: "=".into(),
        allow_http: false,
    });
    assert_eq!(
        run(config.clone(), StartMode::Initialize, async {})
            .await
            .unwrap_err()
            .code,
        "ARCHIVE_CREDENTIAL"
    );
    drop(open_store_with(&config, StartMode::OpenExisting, &Native).unwrap());
}

#[test]
fn explicit_storage_creation_never_replaces_or_repairs_existing_authority() {
    let fixture = Fixture::new();
    let cfg = &fixture.config;
    assert_eq!(
        open_store_with(cfg, StartMode::OpenExisting, &Native)
            .err()
            .unwrap()
            .code,
        "STORE_OPEN"
    );
    assert!(!cfg.data_dir.exists());
    let store = open_store_with(cfg, StartMode::Initialize, &Native).unwrap();
    let before = store.view().unwrap().application.clone();
    assert_eq!(
        open_store_with(cfg, StartMode::Initialize, &Native)
            .err()
            .unwrap()
            .code,
        "DATA_DIRECTORY"
    );
    assert_eq!(
        open_store_with(cfg, StartMode::OpenExisting, &Native)
            .err()
            .unwrap()
            .code,
        "STORE_OPEN"
    );
    drop(store);
    let store = open_store_with(cfg, StartMode::OpenExisting, &Native).unwrap();
    assert_eq!(store.view().unwrap().application, before);
    drop(store);
    let mut wrong = cfg.clone();
    wrong.node_id = 2;
    assert_eq!(
        open_store_with(&wrong, StartMode::OpenExisting, &Native)
            .err()
            .unwrap()
            .code,
        "STORE_IDENTITY"
    );
    fs::write(
        cfg.data_dir.join("raft/CURRENT"),
        b"corrupt-manifest-pointer\n",
    )
    .unwrap();
    assert_eq!(
        open_store_with(cfg, StartMode::OpenExisting, &Native)
            .err()
            .unwrap()
            .code,
        "STORE_OPEN"
    );
    assert_eq!(
        fs::read(cfg.data_dir.join("raft/CURRENT")).unwrap(),
        b"corrupt-manifest-pointer\n"
    );
    for (stage, code) in [
        ("create", "DATA_DIRECTORY"),
        ("sync", "DATA_DIRECTORY_SYNC"),
        ("raft", "STORE_CREATE"),
    ] {
        let fixture = Fixture::new();
        let faults = Faults {
            directory: Some(stage),
            ..Faults::default()
        };
        assert_eq!(
            open_store_with(&fixture.config, StartMode::Initialize, &faults)
                .err()
                .unwrap()
                .code,
            code
        );
    }
    for (genesis, code) in [(true, "CELL_GENESIS"), (false, "STORE_GENESIS")] {
        let mut fixture = Fixture::new();
        if genesis {
            fixture.config.administrator_id = 0;
        } else {
            fixture.config.cluster_id = 0;
        }
        assert_eq!(
            open_store_with(&fixture.config, StartMode::Initialize, &Native)
                .err()
                .unwrap()
                .code,
            code
        );
        assert!(fixture.config.data_dir.join("raft").is_dir());
    }
}

#[test]
fn pinned_security_requires_every_local_material_and_exact_peer_scope() {
    let fixture = Fixture::new();
    let material = security(&fixture.config).unwrap();
    assert_eq!(material.endpoints.len(), 2);
    assert!(material
        .endpoints
        .iter()
        .all(|peer| peer.node_id != fixture.config.node_id));
    for field in 0..4 {
        let mut config = fixture.config.clone();
        let missing = fixture.directory.path().join("absent");
        match field {
            0 => config.certificate_pem = missing,
            1 => config.private_key_pem = missing,
            2 => config.ca_pem = missing,
            _ => config.peers[0].certificate_der = missing,
        }
        assert_eq!(security(&config).err().unwrap().code, "CONFIG_IO");
    }
    let mut config = fixture.config.clone();
    config.cluster_id = 0;
    assert_eq!(security(&config).err().unwrap().code, "PEER_POLICY");
    fs::write(&fixture.config.peers[0].certificate_der, b"invalid DER").unwrap();
    assert_eq!(
        security(&fixture.config).err().unwrap().code,
        "PEER_CERTIFICATE"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_assembly_opens_serves_and_joins_before_reopening_existing_store() {
    let mut fixture = Fixture::new();
    (fixture.config.http_listen, fixture.config.peer_listen) = free_addresses();
    let http = fixture.config.http_listen;
    let peer = fixture.config.peer_listen;
    run(fixture.config.clone(), StartMode::Initialize, async {
        // This shutdown future is first polled by supervise after assembly.
        http_ready(http).await;
        http_response(http, "/livez", 200).await;
        http_response(http, "/db/alpha/v1/status", 401).await;
        http_response(http, "/missing", 404).await;
        http_ready(http).await;
    })
    .await
    .unwrap();
    // Both native owner threads have released their storage and sockets.
    drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
    drop(TcpListener::bind(http).await.unwrap());
    drop(TcpListener::bind(peer).await.unwrap());
    run(fixture.config.clone(), StartMode::OpenExisting, async {})
        .await
        .unwrap();
    drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
    let limits = driver_config(9);
    assert!(limits.raft.pre_vote && limits.raft.check_quorum);
    assert_eq!(limits.raft.read_only_option, raft::ReadOnlyOption::Safe);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_errors_fail_closed_and_partial_thread_start_is_joined() {
    for size in [0, 33] {
        let mut config = crate::tests::config();
        config.databases.resize(size, config.databases[0].clone());
        assert_eq!(
            run(config, StartMode::Initialize, async {})
                .await
                .unwrap_err()
                .code,
            "CONFIG_DATABASE"
        );
    }
    let mut config = crate::tests::config();
    config.cell.cell_id = 0;
    assert_eq!(
        run(config, StartMode::Initialize, async {})
            .await
            .unwrap_err()
            .code,
        "CELL_CONFIG"
    );
    for (case, expected) in [
        (0, "HTTP_BIND"),
        (1, "PEER_BIND"),
        (2, "PEER_TLS"),
        (3, "NETWORK_CONFIG"),
        (4, "CACHE_NAMESPACE"),
    ] {
        let mut fixture = Fixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut mode = StartMode::Initialize;
        match case {
            0 => fixture.config.http_listen = listener.local_addr().unwrap(),
            1 => fixture.config.peer_listen = listener.local_addr().unwrap(),
            2 => fs::write(&fixture.config.private_key_pem, b"invalid private key").unwrap(),
            3 => fixture.config.peers[1].uri = "http://127.0.0.1:1".into(),
            _ => {
                drop(open_store_with(&fixture.config, StartMode::Initialize, &Native).unwrap());
                let namespace = fixture.config.data_dir.join("writers");
                fs::create_dir(&namespace).unwrap();
                fs::write(namespace.join("unknown"), b"preserve").unwrap();
                mode = StartMode::OpenExisting;
            }
        }
        assert_eq!(
            run(fixture.config.clone(), mode, async {})
                .await
                .unwrap_err()
                .code,
            expected
        );
        drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
    }
    for (name, panic, skip, expected) in [
        ("scap-raft", false, false, "RAFT_THREAD"),
        ("scap-sql", false, false, "SQL_THREAD"),
        ("scap-raft", true, false, "SHUTDOWN_THREAD"),
        ("scap-sql", false, true, "SQL_STOPPED"),
    ] {
        let fixture = Fixture::new();
        let faults = Faults {
            thread: Some(name),
            panic,
            skip,
            ..Faults::default()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_with(
                fixture.config.clone(),
                StartMode::Initialize,
                Box::pin(std::future::pending()),
                &faults,
                &Native,
            ),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().code, expected);
        assert_eq!(faults.active.load(Ordering::Acquire), 0);
        drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
    }
}

#[tokio::test]
async fn supervision_identifies_every_exit_and_bounded_join_never_hides_failure() {
    async fn selected(actual: usize, selected: usize) {
        if actual != selected {
            std::future::pending::<()>().await;
        }
    }
    for (case, expected) in [
        (0, None),
        (1, Some("HTTP_STOPPED")),
        (2, Some("PEER_STOPPED")),
        (3, Some("RAFT_STOPPED")),
        (4, Some("SQL_STOPPED")),
        (5, Some("ARCHIVE_STOPPED")),
    ] {
        let result = supervise(
            selected(case, 0),
            selected(case, 1),
            selected(case, 2),
            selected(case, 3),
            selected(case, 4),
            selected(case, 5),
        )
        .await;
        assert_eq!(
            result.err().map(|error| error.code),
            expected.map(str::to_owned)
        );
    }
    assert!(finish_join(
        tokio::spawn(async { Ok(()) }),
        Instant::now() + Duration::from_secs(1)
    )
    .await
    .is_ok());
    let joined = tokio::spawn(async { Err(failure("OWNER_FAILURE")) });
    assert_eq!(
        finish_join(joined, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap_err()
            .code,
        "OWNER_FAILURE"
    );
    let joined: tokio::task::JoinHandle<Result<(), ServiceError>> = tokio::spawn(async {
        panic!("injected join panic");
    });
    assert_eq!(
        finish_join(joined, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap_err()
            .code,
        "SHUTDOWN_THREAD"
    );
    let joined = tokio::spawn(std::future::pending::<Result<(), ServiceError>>());
    let abort = joined.abort_handle();
    assert_eq!(
        finish_join(joined, Instant::now()).await.unwrap_err().code,
        "SHUTDOWN_TIMEOUT"
    );
    abort.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_run_reclaims_tasks_native_owners_and_exclusive_store_lock() {
    let mut fixture = Fixture::new();
    (fixture.config.http_listen, fixture.config.peer_listen) = free_addresses();
    let config = fixture.config.clone();
    let (release, released) = oneshot::channel();
    let (entered, entering) = oneshot::channel();
    let (started, mut startup) = oneshot::channel();
    let task = tokio::spawn(async move {
        entered.send(()).unwrap();
        released.await.unwrap();
        run(config, StartMode::Initialize, async {
            // Reaching supervise proves both listeners and owner threads exist.
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        })
        .await
    });
    entering.await.unwrap();
    // Deliberately hold startup: scheduling the task is not a readiness signal.
    assert_eq!(
        startup.try_recv().unwrap_err(),
        oneshot::error::TryRecvError::Empty
    );
    release.send(()).unwrap();
    startup
        .await
        .expect("node exited before reaching supervise");
    http_ready(fixture.config.http_listen).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let deadline = Instant::now() + Duration::from_secs(1);
    drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
    let http = bind_after_cancellation(fixture.config.http_listen, deadline).await;
    let peer = bind_after_cancellation(fixture.config.peer_listen, deadline).await;
    drop((http, peer));
}

#[test]
fn sql_loop_processes_one_bound_envelope_then_observes_channel_close() {
    use crate::worker::tests::{Port, TestClock};
    use scap_service::{Backend, Call, Mode};
    struct Disabled;
    impl crate::worker::ColdStorage<Port> for Disabled {
        fn hydrate(
            &mut self,
            _: &mut Client<Port>,
            _: &scap_cell_client::RequestContext,
            _: &scap_cell::DatabaseView,
            _: u128,
        ) -> Result<(), ServiceError> {
            Err(failure("ARCHIVE_UNAVAILABLE"))
        }
        fn archive(
            &mut self,
            _: &mut Client<Port>,
            _: &scap_cell_client::RequestContext,
            _: &scap_cell::DatabaseView,
            _: u128,
            _: u128,
        ) -> Result<bool, ServiceError> {
            Ok(false)
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::tests::config();
    config.data_dir = directory.path().to_owned();
    fs::create_dir(directory.path().join("writers")).unwrap();
    let port = Port::new(&config);
    let clock = Arc::new(TestClock::new());
    let ready = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let (mailbox, receiver) = Mailbox::new(&config.databases, stopped.clone());
    let response = mailbox.execute(Call {
        context: crate::tests::context("alpha", 17),
        mode: Mode::Write,
        statements: vec![crate::tests::sql("SELECT 42")],
    });
    drop(mailbox);
    let mut worker = Worker::new(config, port, NativeFactory, Disabled, clock, ready, 5).unwrap();
    struct Scripted(
        std::cell::RefCell<std::collections::VecDeque<Result<Envelope, mpsc::RecvTimeoutError>>>,
    );
    impl Inbox for Scripted {
        fn receive(&self) -> Result<Envelope, mpsc::RecvTimeoutError> {
            self.0.borrow_mut().pop_front().unwrap()
        }
    }
    let scripted = Scripted(std::cell::RefCell::new(
        [
            Ok(receiver.recv().unwrap()),
            Err(mpsc::RecvTimeoutError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected),
        ]
        .into(),
    ));
    sql_loop(&mut worker, &scripted, stopped);
    assert!(scripted.0.borrow().is_empty());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert_eq!(
        runtime.block_on(response).unwrap().statements[0].rows,
        vec![vec![scap_sql::Value::Integer(42)]]
    );
    let (_sender, receiver) = mpsc::sync_channel(1);
    sql_loop(&mut worker, &receiver, Arc::new(AtomicBool::new(true)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_closes_an_accepted_incomplete_body_and_releases_the_connection() {
    let mut fixture = Fixture::new();
    (fixture.config.http_listen, fixture.config.peer_listen) = free_addresses();
    let (stop, stopped) = oneshot::channel();
    let (started, startup) = oneshot::channel();
    let config = fixture.config.clone();
    let node = tokio::spawn(run(config, StartMode::Initialize, async {
        started.send(()).unwrap();
        let _ = stopped.await;
    }));
    startup
        .await
        .expect("node exited before reaching supervise");
    let mut slow = tokio::net::TcpStream::connect(fixture.config.http_listen)
        .await
        .unwrap();
    let header = format!("POST /db/alpha/v2/pipeline HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 100000\r\nConnection: keep-alive\r\n\r\n{{", crate::tests::TOKEN);
    slow.write_all(header.as_bytes()).await.unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), slow.read(&mut byte))
            .await
            .is_err()
    );
    http_ready(fixture.config.http_listen).await;
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), node)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut remaining = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(1), slow.read_to_end(&mut remaining))
        .await
        .unwrap();
    if let Err(error) = closed {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    drop(open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap());
}

#[tokio::test]
async fn readiness_stop_and_drain_are_bounded() {
    let ready = Arc::new(AtomicBool::new(false));
    assert_eq!(
        readiness_response(ready.clone()).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    ready.store(true, Ordering::Release);
    assert_eq!(readiness_response(ready).await, StatusCode::OK);
    let (sender, receiver) = watch::channel(false);
    let wait = tokio::spawn(wait_stop(receiver));
    sender.send(true).unwrap();
    wait.await.unwrap();
    let (sender, receiver) = watch::channel(false);
    drop(sender);
    wait_stop(receiver).await;
    let mut done = tokio::spawn(async {});
    tokio::task::yield_now().await;
    drain(&mut done, Instant::now()).await;
    let mut waiting = tokio::spawn(std::future::pending::<()>());
    drain(&mut waiting, Instant::now()).await;
    assert!(waiting.await.is_err());
    let mut finishing = tokio::spawn(async {
        tokio::task::yield_now().await;
    });
    drain(&mut finishing, Instant::now() + Duration::from_secs(1)).await;
}
