use std::fs;
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use scap_archive::{Error, Objects, S3Config, S3};
use scap_cell::Admission;
use scap_cell_client::RequestContext;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Mini,
    Separate,
}

impl Mode {
    fn environment() -> Self {
        match std::env::var_os("SCAP_SEAWEEDFS_MODE") {
            None => Self::Mini,
            Some(value) if value == "mini" => Self::Mini,
            Some(value) if value == "separate" => Self::Separate,
            Some(_) => panic!("SCAP_SEAWEEDFS_MODE must be mini or separate"),
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Mini => "mini; one upstream process",
            Self::Separate => "separate; master, volume, filer, s3; explicit loopback TCP",
        }
    }
}

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn context() -> RequestContext {
    RequestContext {
        admission: Admission {
            principal_id: 1,
            credential_id: 2,
            admission_id: 3,
            auth_epoch: 1,
            request_epoch: 1,
        },
        deadline: Instant::now() + Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

struct Backend {
    executable: PathBuf,
    directory: PathBuf,
    config: PathBuf,
    ports: [u16; 8],
    mode: Mode,
    children: Vec<(&'static str, Child)>,
    runtime: tokio::runtime::Runtime,
    evidence: Vec<String>,
}

impl Backend {
    fn new(name: &str) -> Self {
        let executable = std::env::var_os("SCAP_SEAWEEDFS_BIN")
            .map(PathBuf::from)
            .expect("set SCAP_SEAWEEDFS_BIN to the verified SeaweedFS 4.51 binary");
        let version = Command::new(&executable).arg("version").output().unwrap();
        assert!(version.status.success());
        assert!(String::from_utf8_lossy(&version.stdout)
            .contains("4.51 153ab668c99731a6d29492bf6c61d0b4fa701101"));
        let directory = std::env::temp_dir().join(format!(
            "scap-archive-s3-{name}-{}-{}",
            std::process::id(),
            port()
        ));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("s3-test-identity.json");
        fs::write(&config, br#"{"identities":[{"name":"scap-test","credentials":[{"accessKey":"scap-test-key","secretKey":"scap-test-secret"}],"actions":["Admin","Read","Write","List","Tagging"]}]}"#).unwrap();
        let mode = Mode::environment();
        let mut used = std::collections::BTreeSet::new();
        let mut backend = Self {
            executable,
            directory,
            config,
            ports: std::array::from_fn(|_| loop {
                let candidate = port();
                if used.insert(candidate) {
                    break candidate;
                }
            }),
            mode,
            children: Vec::new(),
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
            evidence: vec![format!(
                "SeaweedFS 4.51 153ab668c99731a6d29492bf6c61d0b4fa701101; {}",
                mode.description()
            )],
        };
        backend.start();
        backend
    }
    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports[6])
    }
    fn store(&self) -> S3 {
        self.store_with_secret("scap-test-secret")
    }
    fn store_with_secret(&self, secret: &str) -> S3 {
        S3::new(
            S3Config {
                endpoint: self.endpoint(),
                region: "us-east-1".into(),
                bucket: "scap-test".into(),
                access_key: "scap-test-key".into(),
                secret_key: secret.into(),
                session_token: None,
                allow_http: true,
                max_object_bytes: 65536,
                request_timeout: Duration::from_millis(800),
            },
            self.runtime.handle().clone(),
        )
        .unwrap()
    }
    fn launch(&mut self, name: &'static str, mut command: Command) {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join(format!("{name}.log")))
            .unwrap();
        self.children.push((
            name,
            command
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        ));
    }
    fn start_mini(&mut self) {
        let mut command = Command::new(&self.executable);
        command
            .arg("mini")
            .arg(format!("-dir={}", self.directory.display()))
            .arg("-ip=127.0.0.1")
            .arg("-ip.bind=127.0.0.1")
            .arg("-admin.ui=false")
            .arg("-webdav=false")
            .arg("-s3.port.iceberg=0")
            .arg("-s3.port.lance=0")
            .arg("-volume.max=2")
            .arg("-master.volumeSizeLimitMB=64")
            .arg("-bucket=scap-test")
            .arg(format!("-s3.config={}", self.config.display()));
        for (key, port) in [
            "master.port",
            "master.port.grpc",
            "volume.port",
            "volume.port.grpc",
            "filer.port",
            "filer.port.grpc",
            "s3.port",
            "s3.port.grpc",
        ]
        .into_iter()
        .zip(self.ports)
        {
            command.arg(format!("-{key}={port}"));
        }
        self.launch("seaweedfs", command);
    }
    fn start_separate(&mut self) {
        // Upstream component processes use explicit HTTP/gRPC TCP addresses.
        // No Unix-socket permission or upstream implementation is changed.
        let master = format!("127.0.0.1:{}.{}", self.ports[0], self.ports[1]);
        let filer = format!("127.0.0.1:{}.{}", self.ports[4], self.ports[5]);
        for (index, name) in ["master", "volume", "filer", "s3"].into_iter().enumerate() {
            let directory = self.directory.join(name);
            fs::create_dir_all(&directory).unwrap();
            let mut command = Command::new(&self.executable);
            command
                .arg(name)
                .args(["-ip=127.0.0.1", "-ip.bind=127.0.0.1"])
                .arg(format!("-port={}", self.ports[index * 2]))
                .arg(format!("-port.grpc={}", self.ports[index * 2 + 1]));
            match name {
                "master" => {
                    command.arg(format!("-mdir={}", directory.display())).args([
                        "-peers=none",
                        "-telemetry=false",
                        "-volumeSizeLimitMB=64",
                    ]);
                }
                "volume" => {
                    command
                        .arg(format!("-dir={}", directory.display()))
                        .arg(format!("-master={master}"))
                        .arg("-max=2");
                }
                "filer" => {
                    command
                        .arg(format!("-defaultStoreDir={}", directory.display()))
                        .arg(format!("-master={master}"));
                }
                "s3" => {
                    command
                        .arg(format!("-filer={filer}"))
                        .arg(format!("-config={}", self.config.display()))
                        .args(["-port.iceberg=0", "-port.lance=0"]);
                }
                _ => unreachable!(),
            }
            self.launch(name, command);
        }
    }
    fn ensure_bucket(&self) -> bool {
        let request = |head| {
            let mut command = Command::new("curl");
            command.args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "1",
                "--noproxy",
                "*",
                "--aws-sigv4",
                "aws:amz:us-east-1:s3",
                "--user",
                "scap-test-key:scap-test-secret",
            ]);
            if head {
                command.arg("--head");
            } else {
                command.args(["-X", "PUT", "--data-binary", ""]);
            }
            command
                .arg(format!("{}/scap-test", self.endpoint()))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        };
        request(true) || request(false)
    }
    fn start(&mut self) {
        assert!(self.children.is_empty());
        match self.mode {
            Mode::Mini => self.start_mini(),
            Mode::Separate => self.start_separate(),
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut store = self.store();
        loop {
            for (name, child) in &mut self.children {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!(
                        "S3 component {name} exited {status}; inspect {}",
                        self.directory.join(format!("{name}.log")).display()
                    );
                }
            }
            if (self.mode == Mode::Mini || self.ensure_bucket())
                && store.put("startup/readiness", b"ready", &context()).is_ok()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "S3 startup failed; inspect component logs in {}",
                self.directory.display()
            );
            thread::sleep(Duration::from_millis(100));
        }
        self.evidence.push(format!(
            "SeaweedFS backend ready through production signed conditional PUT; processes={}",
            self.children.len()
        ));
    }
    fn kill(&mut self) {
        assert!(!self.children.is_empty());
        let count = self.children.len();
        for (name, child) in &mut self.children {
            assert!(
                child.try_wait().unwrap().is_none(),
                "S3 component {name} exited before the injected fault"
            );
        }
        for (_, child) in self.children.iter_mut().rev() {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            #[cfg(unix)]
            assert_eq!(status.signal(), Some(9));
            #[cfg(not(unix))]
            assert!(!status.success());
        }
        self.children.clear();
        self.evidence.push(format!(
            "All S3 backend processes SIGKILL completed; processes={count}"
        ));
    }
    fn finish(&mut self, name: &str) {
        self.evidence.push("verification passed".into());
        let directory = std::env::var_os("SCAP_ARCHIVE_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.directory.join("evidence"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(format!("{name}.log")),
            self.evidence.join("\n"),
        )
        .unwrap();
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        while let Some((_, mut child)) = self.children.pop() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn signed_conditional_put_never_overwrites_and_exact_bytes_survive_process_restart() {
    let mut backend = Backend::new("immutable-restart");
    let mut store = backend.store();
    let original: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
    store
        .put("immutable/object", &original, &context())
        .unwrap();
    store
        .put("immutable/object", b"different replacement", &context())
        .unwrap();
    assert_eq!(
        store
            .get("immutable/object", original.len() as u32, &context())
            .unwrap(),
        original
    );
    backend.evidence.push(
        "If-None-Match:* rejected a different replacement; HEAD/GET preserved original bytes"
            .into(),
    );
    assert_eq!(
        store.get("immutable/object", 16, &context()),
        Err(Error::TooLarge)
    );
    assert_eq!(
        backend
            .store_with_secret("incorrect-secret")
            .get("immutable/object", 65536, &context()),
        Err(Error::Object)
    );
    backend
        .evidence
        .push("bounded HEAD and wrong signed credentials were rejected".into());
    backend.kill();
    assert!(store.get("immutable/object", 65536, &context()).is_err());
    backend.start();
    let mut store = backend.store();
    assert_eq!(
        store.get("immutable/object", 65536, &context()).unwrap(),
        original
    );
    backend.evidence.push(
        "new S3 process reopened the same directory and returned byte-identical object".into(),
    );
    backend.finish("immutable-restart");
}

#[test]
fn expired_upload_during_outage_preserves_existing_objects_without_creating_new_data() {
    let mut backend = Backend::new("orphan-outage");
    let mut store = backend.store();
    store
        .put("published/older", b"authoritative object", &context())
        .unwrap();
    store
        .put("orphan/newer", b"uploaded but unpublished", &context())
        .unwrap();
    assert_eq!(
        store.get("published/older", 128, &context()).unwrap(),
        b"authoritative object"
    );
    backend.kill();
    let mut expired = context();
    expired.deadline = Instant::now();
    assert_eq!(
        store.put("orphan/never", b"late", &expired),
        Err(Error::Unknown)
    );
    backend.start();
    let mut store = backend.store();
    assert_eq!(
        store.get("published/older", 128, &context()).unwrap(),
        b"authoritative object"
    );
    assert_eq!(
        store.get("orphan/newer", 128, &context()).unwrap(),
        b"uploaded but unpublished"
    );
    assert!(store.get("orphan/never", 128, &context()).is_err());
    backend.evidence.push("original key survived outage; expired upload produced no object; separate uploaded keys retained independent bytes".into());
    backend.finish("orphan-outage");
}
