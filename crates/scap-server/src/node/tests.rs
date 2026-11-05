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
        Self::with_config(crate::tests::config())
    }

    fn with_config(mut config: Config) -> Self {
        let directory = tempfile::tempdir().unwrap();
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
    environment: std::collections::BTreeMap<String, String>,
    join_expiry: Option<usize>,
    clock_reads: AtomicUsize,
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
            environment: Default::default(),
            join_expiry: None,
            clock_reads: AtomicUsize::new(0),
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
    fn now(&self) -> Instant {
        let call = self.clock_reads.fetch_add(1, Ordering::Relaxed) + 1;
        if self.join_expiry == Some(call) {
            Native.now() + Duration::from_secs(6)
        } else {
            Native.now()
        }
    }
    fn environment(&self, name: &str) -> Option<String> {
        self.environment.get(name).cloned()
    }
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

fn fourth_peer() -> Config {
    let mut config = crate::tests::config();
    config.peers.push(crate::PeerConfig {
        node_id: 4,
        uri: "https://127.0.0.1:30104".into(),
        certificate_der: "/tmp/scap-server-unit/4.der".into(),
    });
    config
}

#[test]
fn join_is_explicit_fresh_and_never_creates_an_additional_voter() {
    let bootstrap = Fixture::new();
    assert_eq!(
        open_store_with(&bootstrap.config, StartMode::Join, &Native)
            .err()
            .unwrap()
            .code,
        "CONFIG_START_MODE"
    );
    assert!(!bootstrap.config.data_dir.exists());
    let original = open_store_with(&bootstrap.config, StartMode::Initialize, &Native).unwrap();
    let genesis = original.view().unwrap().application.clone();
    let mut config = fourth_peer();
    config.node_id = 4;
    let joiner = Fixture::with_config(config);
    assert_eq!(
        open_store_with(&joiner.config, StartMode::Initialize, &Native)
            .err()
            .unwrap()
            .code,
        "CONFIG_START_MODE"
    );
    assert!(!joiner.config.data_dir.exists());
    let store = open_store_with(&joiner.config, StartMode::Join, &Native).unwrap();
    assert_eq!(store.view().unwrap().conf_state.voters, vec![1, 2, 3]);
    assert_eq!(store.view().unwrap().application, genesis);
    let application = CellApplication::new(joiner.config.cell, cell_limits()).unwrap();
    let mut driver = Native.driver(store, application, 8001).unwrap();
    assert!(!driver.status().unwrap().is_voter);
    assert!(driver.campaign().is_err());
    drop(driver);
    let store = open_store_with(&joiner.config, StartMode::OpenExisting, &Native).unwrap();
    assert_eq!(store.view().unwrap().conf_state.voters, vec![1, 2, 3]);
    drop(store);
    assert_eq!(
        open_store_with(&joiner.config, StartMode::Join, &Native)
            .err()
            .unwrap()
            .code,
        "DATA_DIRECTORY"
    );
}

#[test]
fn reopening_checks_durable_application_binding_and_immutable_administrator() {
    use scap_raft_driver::Application;
    let fixture = Fixture::new();
    let mut store = open_store_with(&fixture.config, StartMode::Initialize, &Native).unwrap();
    let mut corrupt = store.view().unwrap().clone();
    corrupt.application.clear();
    assert_eq!(
        validate_application(&fixture.config, &corrupt)
            .unwrap_err()
            .code,
        "STORE_APPLICATION"
    );
    let entry = raft::eraftpb::Entry {
        term: 1,
        index: 2,
        ..Default::default()
    };
    let hard = raft::eraftpb::HardState {
        term: 1,
        commit: 2,
        ..Default::default()
    };
    let mut application = CellApplication::new(fixture.config.cell, cell_limits()).unwrap();
    let bytes = application
        .apply(
            &store.view().unwrap().application,
            std::slice::from_ref(&entry),
        )
        .unwrap();
    let members = store.view().unwrap().conf_state.clone();
    store
        .persist_ready(std::slice::from_ref(&entry), Some(&hard), None)
        .unwrap();
    store
        .apply_committed(2, &[entry], &bytes, &members)
        .unwrap();
    drop(store);
    let mut wrong = fixture.config.clone();
    wrong.administrator_id += 1;
    assert_eq!(
        open_store_with(&wrong, StartMode::OpenExisting, &Native)
            .err()
            .unwrap()
            .code,
        "STORE_ADMINISTRATOR"
    );
    let store = open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap();
    assert_eq!(store.view().unwrap().applied, 2);
}

#[test]
fn open_existing_reads_genuine_v2_hot_and_cold_applications_without_reinitializing() {
    for (fixture, index, cold) in [
        (
            include_str!("../../../scap-cell/test-fixtures/server-hot-v2.hex"),
            9,
            false,
        ),
        (
            include_str!("../../../scap-cell/test-fixtures/server-cold-v2.hex"),
            10,
            true,
        ),
    ] {
        let mut config = crate::tests::config();
        config.cell = scap_cell::CellIdentity {
            cell_id: 7,
            cell_incarnation: 8,
        };
        config.administrator_id = 12;
        let fixture_directory = Fixture::with_config(config);
        let config = &fixture_directory.config;
        let hex: String = fixture.split_whitespace().collect();
        let legacy: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(legacy[8], 2);
        assert_eq!(genesis(config, cell_limits()).unwrap().application[8], 2);
        let mut store = open_store_with(config, StartMode::Initialize, &Native).unwrap();
        let entries: Vec<_> = (2..=index)
            .map(|index| raft::eraftpb::Entry {
                term: 1,
                index,
                ..Default::default()
            })
            .collect();
        let hard = raft::eraftpb::HardState {
            term: 1,
            commit: index,
            ..Default::default()
        };
        store.persist_ready(&entries, Some(&hard), None).unwrap();
        let members = store.view().unwrap().conf_state.clone();
        store
            .apply_committed(index, &entries, &legacy, &members)
            .unwrap();
        drop(store);

        let store = open_store_with(config, StartMode::OpenExisting, &Native).unwrap();
        assert_eq!(store.view().unwrap().application, legacy);
        assert_eq!(store.view().unwrap().applied, index);
        assert_eq!(store.view().unwrap().conf_state, members);
        let state = CellState::decode_bound(
            &store.view().unwrap().application,
            config.cell,
            Position { term: 1, index },
            cell_limits(),
        )
        .unwrap();
        assert_eq!(state.bootstrap_administrator(), 12);
        let database = state.database(9).unwrap();
        assert_eq!(database.revision, 2);
        assert_eq!(database.cold, cold);
        assert_eq!(database.archive.unwrap().revision, 2);
        let admission = scap_cell::Admission {
            principal_id: 12,
            credential_id: 13,
            admission_id: 14,
            auth_epoch: 1,
            request_epoch: 1,
        };
        assert!(matches!(
            state.lookup(database.identity, admission, 101, [1; 32]).unwrap(),
            scap_cell::Lookup::Committed { result, .. } if result == [1, 0, 255]
        ));
        assert!(matches!(
            state
                .lookup(database.identity, admission, 103, [3; 32])
                .unwrap(),
            scap_cell::Lookup::Cancelled { .. }
        ));
        assert_eq!(state.physical_history_version(), 2);
        assert_eq!(state.encode(), legacy);
        drop(store);
        let mut wrong = config.clone();
        wrong.administrator_id += 1;
        assert_eq!(
            open_store_with(&wrong, StartMode::OpenExisting, &Native)
                .err()
                .unwrap()
                .code,
            "STORE_ADMINISTRATOR"
        );
    }
}

#[test]
fn initialize_and_join_genesis_remain_exactly_the_genuine_legacy_application() {
    let mut config = crate::tests::config();
    config.cell = scap_cell::CellIdentity {
        cell_id: 7,
        cell_incarnation: 8,
    };
    config.administrator_id = 12;
    let hex: String = include_str!("../../../scap-cell/test-fixtures/server-genesis-v2.hex")
        .split_whitespace()
        .collect();
    let original: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(original[8], 2);
    let bootstrap = genesis(&config, cell_limits()).unwrap();
    assert_eq!(bootstrap.application, original);
    // The candidate node ID is excluded from the shared genesis: replaying an
    // old committed suffix must see the same pre-activation budget and bytes.
    config.node_id = 4;
    let candidate = genesis(&config, cell_limits()).unwrap();
    assert_eq!(candidate.application, bootstrap.application);
    assert_eq!(candidate.membership, bootstrap.membership);
    assert_eq!(candidate.digest, bootstrap.digest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joining_node_requires_fresh_leader_permission_before_any_data_or_listener() {
    let bootstrap = Fixture::new();
    assert_eq!(
        run(bootstrap.config.clone(), StartMode::Join, async {})
            .await
            .unwrap_err()
            .code,
        "CONFIG_START_MODE"
    );
    assert!(!bootstrap.config.data_dir.exists());
    let mut config = fourth_peer();
    config.node_id = 4;
    let mut fixture = Fixture::with_config(config);
    (fixture.config.http_listen, fixture.config.peer_listen) = free_addresses();
    assert_eq!(
        run_with(
            fixture.config.clone(),
            StartMode::Join,
            Box::pin(async {}),
            &Faults::default(),
            &Native
        )
        .await
        .unwrap_err()
        .code,
        "JOIN_MANAGEMENT_URL"
    );
    assert!(!fixture.config.data_dir.exists());
    let available = TcpListener::bind(fixture.config.http_listen).await.unwrap();
    drop(available);
    let mut view = crate::join::tests::view(&fixture.config);
    view["membership"]["conf_state"]["learners"] = serde_json::json!([4]);
    let (endpoint, owner) = crate::join::tests::server(200, view);
    let mut system = Faults::default();
    system
        .environment
        .insert("SCAP_JOIN_MANAGEMENT_URL".into(), endpoint);
    system
        .environment
        .insert("SCAP_MANAGEMENT_TOKEN".into(), "join-unit-secret".into());
    assert_eq!(
        run_with(
            fixture.config.clone(),
            StartMode::Join,
            Box::pin(async {}),
            &system,
            &Native
        )
        .await
        .unwrap_err()
        .code,
        "JOIN_ID_REUSED"
    );
    owner.join().unwrap();
    assert!(!fixture.config.data_dir.exists());
    let (endpoint, owner) =
        crate::join::tests::server(200, crate::join::tests::view(&fixture.config));
    system
        .environment
        .insert("SCAP_JOIN_MANAGEMENT_URL".into(), endpoint);
    run_with(
        fixture.config.clone(),
        StartMode::Join,
        Box::pin(async { http_ready(fixture.config.http_listen).await }),
        &system,
        &Native,
    )
    .await
    .unwrap();
    owner.join().unwrap();
    assert!(fixture.config.data_dir.join("raft").is_dir());
    let store = open_store_with(&fixture.config, StartMode::OpenExisting, &Native).unwrap();
    assert_eq!(store.view().unwrap().conf_state.voters, vec![1, 2, 3]);
    let _ = Native.environment("SCAP_UNIT_ENVIRONMENT_BOUNDARY");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_deadline_is_rechecked_before_storage_listeners_and_service_start() {
    for phase in 1..=3 {
        let mut config = fourth_peer();
        config.node_id = 4;
        let mut fixture = Fixture::with_config(config);
        (fixture.config.http_listen, fixture.config.peer_listen) = free_addresses();
        let (endpoint, owner) =
            crate::join::tests::server(200, crate::join::tests::view(&fixture.config));
        let mut system = Faults {
            join_expiry: Some(phase),
            ..Faults::default()
        };
        system
            .environment
            .insert("SCAP_JOIN_MANAGEMENT_URL".into(), endpoint);
        system
            .environment
            .insert("SCAP_MANAGEMENT_TOKEN".into(), "join-unit-secret".into());
        assert_eq!(
            run_with(
                fixture.config.clone(),
                StartMode::Join,
                Box::pin(async {}),
                &system,
                &Native
            )
            .await
            .unwrap_err()
            .code,
            "JOIN_EXPIRED"
        );
        owner.join().unwrap();
        assert_eq!(fixture.config.data_dir.exists(), phase > 1);
        assert_eq!(system.clock_reads.load(Ordering::Relaxed), phase);
        let http = TcpListener::bind(fixture.config.http_listen).await.unwrap();
        let peer = TcpListener::bind(fixture.config.peer_listen).await.unwrap();
        drop((http, peer));
    }
}

#[test]
fn pinned_security_requires_every_local_material_and_exact_peer_scope() {
    let fixture = Fixture::new();
    let material = security(&fixture.config).unwrap();
    assert!(!material.policy.allows_membership_changes());
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

#[test]
fn membership_transport_is_enabled_only_by_explicit_management_or_a_larger_pool() {
    let mut fixture = Fixture::new();
    fixture.config.management = Some(crate::ManagementConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        token_digest: [7; 32],
    });
    assert!(security(&fixture.config)
        .unwrap()
        .policy
        .allows_membership_changes());
    let fixture = Fixture::with_config(fourth_peer());
    let material = security(&fixture.config).unwrap();
    assert!(material.policy.allows_membership_changes());
    assert_eq!(material.endpoints.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_listener_is_separate_authenticated_and_owned_until_shutdown() {
    let mut fixture = Fixture::new();
    (fixture.config.http_listen, fixture.config.peer_listen) = free_addresses();
    let (management, _) = free_addresses();
    fixture.config.management = Some(crate::ManagementConfig {
        listen: management,
        token_digest: [7; 32],
    });
    run(fixture.config.clone(), StartMode::Initialize, async {
        http_response(management, crate::management::PATH, 401).await;
        http_response(fixture.config.http_listen, crate::management::PATH, 404).await;
    })
    .await
    .unwrap();
    let listener = TcpListener::bind(management).await.unwrap();
    drop(listener);

    let mut fixture = Fixture::new();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    fixture.config.management = Some(crate::ManagementConfig {
        listen: occupied.local_addr().unwrap(),
        token_digest: [7; 32],
    });
    assert_eq!(
        run(fixture.config, StartMode::Initialize, async {})
            .await
            .unwrap_err()
            .code,
        "MANAGEMENT_BIND"
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
        // Exercise the actual lazy native lane assembly with an authenticated
        // request. One isolated voter must still reject it as NOT_LEADER.
        let mut stream = tokio::net::TcpStream::connect(http).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /db/alpha/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                    crate::tests::TOKEN
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("NOT_LEADER"), "{response}");
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
        (6, Some("MANAGEMENT_STOPPED")),
    ] {
        let result = supervise(
            selected(case, 0),
            selected(case, 1),
            selected(case, 2),
            selected(case, 3),
            selected(case, 4),
            selected(case, 5),
            selected(case, 6),
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

struct Disabled;
impl<P: crate::worker::ControlPort> crate::worker::ColdStorage<P> for Disabled {
    type RecoveryGuard = ();

    fn recovery_guard(
        &mut self,
        _: scap_cell::DatabaseIdentity,
        _: &scap_cell_client::RequestContext,
    ) -> Result<Self::RecoveryGuard, ServiceError> {
        Ok(())
    }

    fn hydrate(
        &mut self,
        _: &mut Client<P>,
        _: &scap_cell_client::RequestContext,
        _: &scap_cell::DatabaseView,
        _: u128,
    ) -> Result<(), ServiceError> {
        Err(failure("ARCHIVE_UNAVAILABLE"))
    }
    fn archive(
        &mut self,
        _: &mut Client<P>,
        _: &scap_cell_client::RequestContext,
        _: &scap_cell::DatabaseView,
        _: u128,
        _: u128,
    ) -> Result<bool, ServiceError> {
        Ok(false)
    }
}

#[test]
fn sql_loop_processes_one_bound_envelope_then_observes_channel_close() {
    use crate::worker::tests::{Port, TestClock};
    use scap_service::{Backend, Call, Mode};
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
    let lane_config = config.clone();
    let mut lanes = Lanes::new(
        5,
        stopped.clone(),
        Box::new(move |database, boot| {
            let mut config = lane_config.clone();
            config.databases = vec![database];
            Box::new(move || {
                let port = Port::new(&config);
                Worker::new(
                    config,
                    port,
                    NativeFactory,
                    Disabled,
                    Arc::new(TestClock::new()),
                    Arc::new(AtomicBool::new(false)),
                    boot,
                )
                .map(|worker| Box::new(worker) as Box<dyn Executor>)
            })
        }),
    )
    .unwrap();
    let test_config = config.clone();
    let catalogue_port = port.clone();
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
    sql_loop(&mut worker, &scripted, stopped, &mut lanes).unwrap();
    assert!(scripted.0.borrow().is_empty());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert_eq!(
        runtime.block_on(response).unwrap().statements[0].rows,
        vec![vec![scap_sql::Value::Integer(42)]]
    );
    let (_sender, receiver) = mpsc::sync_channel(1);
    sql_loop(
        &mut worker,
        &receiver,
        Arc::new(AtomicBool::new(true)),
        &mut lanes,
    )
    .unwrap();
    lanes.finish().unwrap();

    // A persisted unsuspended owner requires automatic recovery even when no
    // client happens to arrive. The dispatcher delegates that work to a lane.
    let view = catalogue_port.effects.borrow().state.database(3).unwrap();
    let outcome = catalogue_port.apply(scap_cell::Command {
        control_revision: view.control_revision,
        cell: test_config.cell,
        database: view.identity,
        admission: scap_cell::Admission {
            principal_id: test_config.administrator_id,
            credential_id: test_config.service_credential_id,
            admission_id: 5000,
            auth_epoch: view.auth_epoch,
            request_epoch: 1,
        },
        kind: scap_cell::CommandKind::ClaimOwner {
            operation_id: 5001,
            expected_epoch: view.owner.epoch,
            worker_instance_id: 6000,
        },
    });
    assert!(matches!(
        outcome.outcome,
        scap_cell::Outcome::ControlApplied(_)
    ));
    let disconnected = Scripted(std::cell::RefCell::new(
        [Err(mpsc::RecvTimeoutError::Disconnected)].into(),
    ));
    sql_loop(
        &mut worker,
        &disconnected,
        Arc::new(AtomicBool::new(false)),
        &mut lanes,
    )
    .unwrap();
    lanes.finish().unwrap();

    fn reject_spawn(_: Box<dyn FnOnce() + Send>) -> std::io::Result<thread::JoinHandle<()>> {
        Err(std::io::Error::other("injected SQL lane admission failure"))
    }
    let refused = || {
        Lanes::with_spawn(
            7,
            Arc::new(AtomicBool::new(false)),
            Box::new(|_, _| Box::new(|| Err(failure("TEST_BUILD")))),
            1,
            reject_spawn,
        )
        .unwrap()
    };
    let mut failed = refused();
    // The original dispatcher surfaces a recovery spawn failure, rather than
    // leaving an apparently running service with no owner or retry boundary.
    assert_eq!(
        sql_loop(
            &mut worker,
            &disconnected,
            Arc::new(AtomicBool::new(false)),
            &mut failed
        )
        .unwrap_err()
        .code,
        "SQL_LANE_SPAWN"
    );

    catalogue_port.effects.borrow_mut().leader = false;
    let (mailbox, received) =
        Mailbox::new(&test_config.databases, Arc::new(AtomicBool::new(false)));
    let response = mailbox.execute(Call {
        context: crate::tests::context("alpha", 7000),
        mode: Mode::Write,
        statements: vec![crate::tests::sql("SELECT 7")],
    });
    let request = Scripted(std::cell::RefCell::new(
        [Ok(received.recv().unwrap())].into(),
    ));
    let mut failed = refused();
    assert_eq!(
        sql_loop(
            &mut worker,
            &request,
            Arc::new(AtomicBool::new(false)),
            &mut failed
        )
        .unwrap_err()
        .code,
        "SQL_LANE_SPAWN"
    );
    assert_eq!(
        runtime.block_on(response).unwrap_err().code,
        "COMMIT_UNKNOWN"
    );

    struct Polling(Instant);
    impl Inbox for Polling {
        fn receive(&self) -> Result<Envelope, mpsc::RecvTimeoutError> {
            assert!(
                Instant::now() < self.0,
                "failed SQL lane was not supervised"
            );
            thread::sleep(Duration::from_millis(1));
            Err(mpsc::RecvTimeoutError::Timeout)
        }
    }
    let mut failed = Lanes::new(
        8,
        Arc::new(AtomicBool::new(false)),
        Box::new(|_, _| Box::new(|| Err(failure("TEST_BUILD")))),
    )
    .unwrap();
    failed.recover(test_config.databases[0].clone()).unwrap();
    assert_eq!(
        sql_loop(
            &mut worker,
            &Polling(Instant::now() + Duration::from_secs(2)),
            Arc::new(AtomicBool::new(false)),
            &mut failed,
        )
        .unwrap_err()
        .code,
        "TEST_BUILD"
    );
}

#[test]
fn sql_owner_assembly_rejects_invalid_scope_and_boot_before_opening_an_engine() {
    for case in 0..3 {
        let (_runtime, sql_port) = crate::local::tests::runtime(false);
        let mut config = crate::tests::config();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let client = Native
            .client(&config, sql_port.clone(), clock.clone())
            .unwrap();
        let (cold, supervisor) = archive_jobs::spawn::<_, scap_archive::S3>(
            client,
            None,
            config.databases.len(),
            clock.clone(),
        )
        .unwrap();
        if case == 1 {
            config.cluster_id += 1;
        }
        let owner = SqlOwner {
            config,
            sql_port,
            cold,
            clock,
            ready: Arc::new(AtomicBool::new(false)),
            boot: if case == 0 { 0 } else { 1 },
        };
        let (_sender, receiver) = mpsc::sync_channel(1);
        let result = owner.run(&receiver, Arc::new(AtomicBool::new(true)));
        match case {
            0 => assert_eq!(result.unwrap_err().code, "SQL_LANE_CONFIG"),
            1 => assert_eq!(result.unwrap_err().code, "CELL_SCOPE"),
            _ => result.unwrap(),
        }
        supervisor.join().unwrap();
    }
}

#[test]
fn only_catalogue_checks_publish_node_readiness_across_lane_errors_and_successes() {
    use crate::worker::tests::{Port, TestClock};
    use scap_service::Backend;

    let config = crate::tests::config();
    let port = Port::new(&config);
    let clock = Arc::new(TestClock::new());
    let ready = Arc::new(AtomicBool::new(false));
    let mut catalog = Worker::new(
        config.clone(),
        port.clone(),
        NativeFactory,
        Disabled,
        clock.clone(),
        ready.clone(),
        80,
    )
    .unwrap();
    assert!(catalog.scan().unwrap().is_none());
    assert!(ready.load(Ordering::Acquire));
    // Exercise the production lane constructor; it owns a private readiness
    // cell, while the catalogue above owns the HTTP routing hint.
    let mut lane =
        database_worker(config.clone(), port.clone(), Disabled, clock.clone(), 81).unwrap();
    let (mailbox, receiver) = Mailbox::new(&config.databases, Arc::new(AtomicBool::new(false)));
    {
        let mut status = |id| {
            let response = mailbox.status(crate::tests::context("alpha", id));
            let envelope = receiver.recv().unwrap();
            let result = lane.request(envelope.request);
            drop(response);
            result
        };
        // A fresh lane observes its first term without clearing catalogue readiness.
        assert!(matches!(
            status(1).unwrap(),
            crate::worker::Reply::Status(_)
        ));
        assert!(ready.load(Ordering::Acquire));
        port.effects.borrow_mut().status_error = true;
        assert_eq!(status(2).err().unwrap().code, "UNAVAILABLE");
        assert!(ready.load(Ordering::Acquire));
        port.effects.borrow_mut().status_error = false;
    }

    let next_read = port.effects.borrow().reads + 1;
    port.effects.borrow_mut().read_error = Some(next_read);
    assert_eq!(lane.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    assert!(ready.load(Ordering::Acquire));
    port.effects.borrow_mut().read_error = None;

    // Actual catalogue leadership loss withdraws the hint. A later successful
    // lane check cannot publish node readiness on the catalogue's behalf.
    port.effects.borrow_mut().leader = false;
    assert_eq!(catalog.scan().unwrap_err().code, "NOT_LEADER");
    assert!(!ready.load(Ordering::Acquire));
    port.effects.borrow_mut().leader = true;
    lane.tick().unwrap();
    assert!(!ready.load(Ordering::Acquire));
    catalog.scan().unwrap();
    assert!(ready.load(Ordering::Acquire));

    let response = mailbox.status(crate::tests::context("alpha", 3));
    let mut envelope = receiver.recv().unwrap();
    envelope.request.context.deadline = clock.now().unwrap().instant;
    assert_eq!(
        lane.request(envelope.request).err().unwrap().code,
        "COMMIT_UNKNOWN"
    );
    assert!(ready.load(Ordering::Acquire));
    drop(response);
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
    let stopped = Arc::new(AtomicBool::new(false));
    assert_eq!(
        readiness_response(ready.clone(), stopped.clone()).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    ready.store(true, Ordering::Release);
    assert_eq!(
        readiness_response(ready.clone(), stopped.clone()).await,
        StatusCode::OK
    );
    // Even a catalogue completion racing shutdown cannot advertise readiness.
    stopped.store(true, Ordering::Release);
    assert_eq!(
        readiness_response(ready, stopped).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
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
