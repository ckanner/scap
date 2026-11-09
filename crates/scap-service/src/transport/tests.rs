use super::*;
use std::future::{poll_fn, Future};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;

struct Inputs {
    receiver: mpsc::UnboundedReceiver<DuplexStream>,
    accepted: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl Listener for Inputs {
    type Io = DuplexStream;
    type Addr = ();

    async fn accept(&mut self) -> (DuplexStream, ()) {
        let stream = self.receiver.recv().await.expect("test input remains open");
        self.accepted.fetch_add(1, Ordering::SeqCst);
        (stream, ())
    }

    fn local_addr(&self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Inputs {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct Running {
    inputs: mpsc::UnboundedSender<DuplexStream>,
    accepted: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(profile: Profile, router: Router) -> Self {
        let (inputs, receiver) = mpsc::unbounded_channel();
        let accepted = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let listener = Inputs {
            receiver,
            accepted: accepted.clone(),
            dropped: dropped.clone(),
        };
        let (stop, signal) = oneshot::channel();
        let task = tokio::spawn(serve(
            listener,
            router,
            profile.checked().unwrap(),
            Box::pin(async {
                let _ = signal.await;
            }),
        ));
        Self {
            inputs,
            accepted,
            dropped,
            stop: Some(stop),
            task,
        }
    }

    fn connect(&self, capacity: usize) -> DuplexStream {
        let (client, server) = tokio::io::duplex(capacity);
        self.inputs.send(server).unwrap();
        client
    }

    fn signal(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
    }

    async fn finish(mut self) {
        self.signal();
        self.task.await.unwrap();
        assert!(self.dropped.load(Ordering::SeqCst));
    }
}

fn router() -> Router {
    Router::new().route("/", get(|| async { "ok" }))
}

async fn turns() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

async fn pending_read(stream: &mut DuplexStream) -> bool {
    let mut byte = [0];
    let read = stream.read(&mut byte);
    let mut read = std::pin::pin!(read);
    poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_pending())).await
}

async fn headers(stream: &mut DuplexStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 4096);
    }
    bytes
}

async fn closed_response(stream: &mut DuplexStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    bytes
}

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: unit\r\nConnection: close\r\n\r\n";

#[test]
fn versioned_profile_validates_every_limit_before_building_hyper() {
    let profile = Profile::default();
    assert_eq!(
        profile,
        Profile {
            version: 1,
            max_connections: 128,
            max_headers: 64,
            max_header_bytes: 16384,
            max_buffer_bytes: 32768,
            header_timeout_ms: 5000,
        }
    );
    assert!(profile.checked().is_ok());
    let changes: &[fn(&mut Profile)] = &[
        |p| p.version = 0,
        |p| p.max_connections = 0,
        |p| p.max_connections = 4097,
        |p| p.max_headers = 0,
        |p| p.max_headers = 257,
        |p| p.max_header_bytes = 0,
        |p| p.max_header_bytes = 65537,
        |p| p.max_buffer_bytes = 8191,
        |p| p.max_buffer_bytes = 1048577,
        |p| p.max_buffer_bytes = 8192,
        |p| p.header_timeout_ms = 0,
        |p| p.header_timeout_ms = 60001,
    ];
    for change in changes {
        let mut invalid = profile;
        change(&mut invalid);
        assert_eq!(invalid.checked().unwrap_err().code, "CONFIG");
    }
    assert!(Profile {
        max_connections: 1,
        max_headers: 1,
        max_header_bytes: 1,
        max_buffer_bytes: 8192,
        header_timeout_ms: 1,
        ..profile
    }
    .checked()
    .is_ok());
    assert!(Profile {
        max_connections: 4096,
        max_headers: 256,
        max_header_bytes: 65536,
        max_buffer_bytes: 1048576,
        header_timeout_ms: 60000,
        ..profile
    }
    .checked()
    .is_ok());
}

#[tokio::test(start_paused = true)]
async fn saturation_stops_accept_and_completed_tasks_are_reaped_before_more_work() {
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new([Semaphore::new(0), Semaphore::new(0)]);
    let next = Arc::new(AtomicUsize::new(0));
    let app = router().route(
        "/wait",
        get({
            let entered = entered.clone();
            let release = release.clone();
            move || {
                let entered = entered.clone();
                let release = release.clone();
                let index = next.fetch_add(1, Ordering::SeqCst);
                async move {
                    entered.add_permits(1);
                    release[index].acquire().await.unwrap().forget();
                    "done"
                }
            }
        }),
    );
    let server = Running::start(
        Profile {
            max_connections: 2,
            ..Profile::default()
        },
        app,
    );
    let mut first = server.connect(4096);
    first
        .write_all(b"GET /wait HTTP/1.1\r\nHost: unit\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    entered.acquire().await.unwrap().forget();
    let mut second = server.connect(4096);
    second
        .write_all(b"GET /wait HTTP/1.1\r\nHost: unit\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    entered.acquire().await.unwrap().forget();
    let mut queued = server.connect(4096);
    queued.write_all(REQUEST).await.unwrap();
    turns().await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    assert!(pending_read(&mut queued).await);
    release[0].add_permits(1);
    assert!(closed_response(&mut first).await.ends_with(b"done"));
    assert!(closed_response(&mut queued).await.ends_with(b"ok"));
    assert_eq!(server.accepted.load(Ordering::SeqCst), 3);
    assert!(pending_read(&mut second).await);
    for _ in 0..8 {
        let mut stream = server.connect(4096);
        stream.write_all(REQUEST).await.unwrap();
        assert!(closed_response(&mut stream).await.ends_with(b"ok"));
    }
    release[1].add_permits(1);
    assert!(closed_response(&mut second).await.ends_with(b"done"));
    server.finish().await;
}

#[tokio::test(start_paused = true)]
async fn first_and_keepalive_headers_have_absolute_nonrenewing_deadlines() {
    let profile = Profile {
        header_timeout_ms: 100,
        ..Profile::default()
    };
    let server = Running::start(profile, router());
    let mut first = server.connect(4096);
    first.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
    turns().await;
    tokio::time::advance(Duration::from_millis(80)).await;
    assert!(pending_read(&mut first).await);
    first.write_all(b" u").await.unwrap();
    turns().await;
    tokio::time::advance(Duration::from_millis(21)).await;
    let response = closed_response(&mut first).await;
    assert!(!response.starts_with(b"HTTP/1.1 200"));

    let mut second = server.connect(4096);
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: unit\r\n\r\n")
        .await
        .unwrap();
    assert!(headers(&mut second).await.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 2];
    second.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ok");
    second.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
    turns().await;
    tokio::time::advance(Duration::from_millis(101)).await;
    assert!(!closed_response(&mut second)
        .await
        .starts_with(b"HTTP/1.1 200"));
    server.finish().await;
}

#[tokio::test(start_paused = true)]
async fn header_byte_and_count_boundaries_are_checked_by_the_actual_parser() {
    let server = Running::start(
        Profile {
            max_header_bytes: 128,
            ..Profile::default()
        },
        router(),
    );
    let prefix = "GET / HTTP/1.1\r\nHost: unit\r\nConnection: close\r\nX-Pad: ";
    for (size, status) in [(128, b"HTTP/1.1 200"), (129, b"HTTP/1.1 431")] {
        let request = format!("{prefix}{}\r\n\r\n", "x".repeat(size - prefix.len() - 4));
        assert_eq!(request.len(), size);
        let mut stream = server.connect(4096);
        stream.write_all(request.as_bytes()).await.unwrap();
        assert!(closed_response(&mut stream).await.starts_with(status));
    }
    server.finish().await;
    let server = Running::start(
        Profile {
            max_headers: 2,
            ..Profile::default()
        },
        router(),
    );
    for (request, status) in [
        (REQUEST, b"HTTP/1.1 200"),
        (
            b"GET / HTTP/1.1\r\nHost: unit\r\nConnection: close\r\nX: y\r\n\r\n".as_slice(),
            b"HTTP/1.1 431",
        ),
    ] {
        let mut stream = server.connect(4096);
        stream.write_all(request).await.unwrap();
        assert!(closed_response(&mut stream).await.starts_with(status));
    }
    server.finish().await;
}

#[tokio::test(start_paused = true)]
async fn chunked_trailers_share_the_header_size_limit() {
    let app = Router::new().route(
        "/",
        axum::routing::post(|body: Body| async {
            match axum::body::to_bytes(body, 4096).await {
                Ok(_) => StatusCode::OK,
                Err(_) => StatusCode::BAD_REQUEST,
            }
        }),
    );
    let server = Running::start(
        Profile {
            max_header_bytes: 128,
            ..Profile::default()
        },
        app,
    );
    for (trailer, status) in [
        ("X: y".to_owned(), b"HTTP/1.1 200"),
        (format!("X: {}", "x".repeat(128)), b"HTTP/1.1 400"),
    ] {
        let mut stream = server.connect(4096);
        stream.write_all(format!("POST / HTTP/1.1\r\nHost: unit\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n{trailer}\r\n\r\n").as_bytes()).await.unwrap();
        assert!(closed_response(&mut stream).await.starts_with(status));
    }
    server.finish().await;
}

#[tokio::test(start_paused = true)]
async fn h2_and_failed_connections_do_not_dispatch_or_leak_slots() {
    async fn panicking() -> &'static str {
        panic!("unit connection panic")
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/",
            get({
                let calls = calls.clone();
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { "ok" }
                }
            }),
        )
        .route("/panic", get(panicking));
    let server = Running::start(
        Profile {
            max_connections: 1,
            ..Profile::default()
        },
        app,
    );
    let mut h2 = server.connect(4096);
    h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    let response = closed_response(&mut h2).await;
    assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 400"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut failed = server.connect(4096);
    failed
        .write_all(b"GET /panic HTTP/1.1\r\nHost: unit\r\n\r\n")
        .await
        .unwrap();
    assert!(closed_response(&mut failed).await.is_empty());
    drop(server.connect(4096));
    let mut healthy = server.connect(4096);
    healthy.write_all(REQUEST).await.unwrap();
    assert!(closed_response(&mut healthy).await.ends_with(b"ok"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.finish().await;
}

struct TrackedBytes {
    bytes: Vec<u8>,
    dropped: Arc<AtomicUsize>,
}

impl AsRef<[u8]> for TrackedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for TrackedBytes {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_retains_queued_bytes_until_the_slow_response_drains() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let app = Router::new().route(
        "/",
        get({
            let dropped = dropped.clone();
            move || {
                let dropped = dropped.clone();
                async move {
                    Body::from(Bytes::from_owner(TrackedBytes {
                        bytes: vec![b'x'; 65536],
                        dropped,
                    }))
                }
            }
        }),
    );
    let mut server = Running::start(Profile::default(), app);
    let mut stream = server.connect(128);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: unit\r\n\r\n")
        .await
        .unwrap();
    assert!(headers(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    turns().await;
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "transport must retain the Bytes owner, not flatten its payload"
    );
    server.signal();
    turns().await;
    assert!(server.dropped.load(Ordering::SeqCst));
    assert!(
        !server.task.is_finished(),
        "active response must drain before graceful shutdown returns"
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(closed_response(&mut stream).await, vec![b'x'; 65536]);
    server.task.await.unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn shutdown_without_connections_or_with_idle_keepalive_finishes() {
    Running::start(Profile::default(), router()).finish().await;
    let server = Running::start(Profile::default(), router());
    let mut stream = server.connect(4096);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: unit\r\n\r\n")
        .await
        .unwrap();
    assert!(headers(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 2];
    stream.read_exact(&mut body).await.unwrap();
    server.finish().await;
    assert!(closed_response(&mut stream).await.is_empty());
}
