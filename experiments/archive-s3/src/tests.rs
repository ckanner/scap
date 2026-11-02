use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use scap_archive::{Error, Objects, S3Config, S3};
use scap_cell::Admission;
use scap_cell_client::RequestContext;

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
    child: Option<Child>,
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
        let mut backend = Self {
            executable,
            directory,
            config,
            ports: std::array::from_fn(|_| port()),
            child: None,
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
            evidence: Vec::new(),
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
    fn start(&mut self) {
        assert!(self.child.is_none());
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join("seaweedfs.log"))
            .unwrap();
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
        self.child = Some(
            command
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut store = self.store();
        loop {
            if store.put("startup/readiness", b"ready", &context()).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "S3 startup failed; inspect {}",
                self.directory.join("seaweedfs.log").display()
            );
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "S3 exited {status}: {}",
                    fs::read_to_string(self.directory.join("seaweedfs.log")).unwrap()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.evidence
            .push("SeaweedFS process ready through signed conditional PUT".into());
    }
    fn kill(&mut self) {
        let mut child = self.child.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        self.evidence.push("S3 process SIGKILL completed".into());
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
        if let Some(mut child) = self.child.take() {
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
    assert!(store.get("orphan/never", 128, &context()).is_err());
    backend.evidence.push("original key survived outage; expired upload produced no object; separate uploaded keys retained independent bytes".into());
    backend.finish("orphan-outage");
}
