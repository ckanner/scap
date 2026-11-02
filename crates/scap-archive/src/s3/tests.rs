use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap()
}
fn config(endpoint: String) -> S3Config {
    S3Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "scap-test".into(),
        access_key: "unit-access".into(),
        secret_key: "unit-secret".into(),
        session_token: None,
        allow_http: true,
        max_object_bytes: 4096,
        request_timeout: Duration::from_secs(1),
    }
}
struct Reply {
    status: u16,
    size: usize,
    body: Vec<u8>,
    delay: Duration,
}
fn reply(status: u16, size: usize, body: &[u8]) -> Reply {
    Reply {
        status,
        size,
        body: body.into(),
        delay: Duration::ZERO,
    }
}
fn server(
    replies: Vec<Reply>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> (String, thread::JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&requests);
    let handle = thread::spawn(move || {
        for response in replies {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut block = [0u8; 8192];
            loop {
                let n = socket.read(&mut block).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&block[..n]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let size = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                    if request.len() >= end + 4 + size {
                        capture.lock().unwrap().push(headers);
                        break;
                    }
                }
            }
            if let Some(cancel) = &cancel {
                cancel.store(true, Ordering::Release);
            }
            thread::sleep(response.delay);
            let headers = format!("HTTP/1.1 {} Test\r\nContent-Length: {}\r\nETag: \"unit-etag\"\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n\r\n", response.status, response.size);
            let _ = socket.write_all(headers.as_bytes());
            let _ = socket.write_all(&response.body);
        }
    });
    (endpoint, handle, requests)
}

#[test]
fn actual_signed_http_put_head_get_and_existing_create_never_overwrite() {
    let runtime = runtime();
    let (endpoint, server, requests) = server(
        vec![
            reply(200, 0, b""),
            reply(200, 3, b""),
            reply(200, 3, b"abc"),
            reply(412, 0, b""),
        ],
        None,
    );
    let mut cfg = config(endpoint);
    cfg.session_token = Some("unit-session".into());
    let mut s3 = S3::new(cfg, runtime.handle().clone()).unwrap();
    let context = crate::tests::context();
    s3.put("path/abc", b"abc", &context).unwrap();
    assert_eq!(s3.clone().get("path/abc", 3, &context).unwrap(), b"abc");
    s3.put("path/abc", b"abc", &context).unwrap();
    server.join().unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests.iter() {
        assert!(request.contains("authorization: aws4-hmac-sha256"));
        assert!(request.contains("x-amz-security-token: unit-session"));
    }
    assert!(requests[0].contains("if-none-match: *"));
    assert!(requests[3].contains("if-none-match: *"));
    assert!(requests[1].starts_with("head /scap-test/path/abc"));
    assert!(requests[2].starts_with("get /scap-test/path/abc"));
}

#[test]
fn explicit_configuration_rejects_ambient_credentials_and_insecure_urls() {
    let runtime = runtime();
    for index in 0..14 {
        let mut cfg = config("http://127.0.0.1:1".into());
        match index {
            0 => cfg.endpoint = "not a URL".into(),
            1 => cfg.endpoint = "ftp://host".into(),
            2 => cfg.endpoint = "https:///".into(),
            3 => cfg.endpoint = "https://user@host".into(),
            4 => cfg.endpoint = "https://:password@host".into(),
            5 => cfg.endpoint = "https://host?secret=yes".into(),
            6 => cfg.endpoint = "https://host#fragment".into(),
            7 => cfg.allow_http = false,
            8 => cfg.region.clear(),
            9 => cfg.bucket.clear(),
            10 => cfg.access_key.clear(),
            11 => cfg.secret_key.clear(),
            12 => cfg.max_object_bytes = 0,
            _ => cfg.request_timeout = Duration::ZERO,
        }
        assert!(
            matches!(S3::new(cfg, runtime.handle().clone()), Err(Error::Invalid)),
            "config {index}"
        );
    }
    let mut cfg = config("https://localhost".into());
    cfg.allow_http = false;
    assert!(S3::new(cfg, runtime.handle().clone()).is_ok());
    assert!(matches!(
        S3::build(
            config("https://localhost".into()),
            runtime.handle().clone(),
            |_| Err(object_store::Error::Generic {
                store: "injected builder failure",
                source: "unavailable transport".into()
            })
        ),
        Err(Error::Object)
    ));
}

#[test]
fn sizes_paths_cancellation_and_absolute_deadlines_are_checked_before_io() {
    let runtime = runtime();
    let mut s3 = S3::new(
        config("http://127.0.0.1:1".into()),
        runtime.handle().clone(),
    )
    .unwrap();
    let mut context = crate::tests::context();
    assert_eq!(
        s3.put("key", &vec![0; 4097], &context),
        Err(Error::TooLarge)
    );
    assert_eq!(s3.get("key", 4097, &context), Err(Error::TooLarge));
    assert_eq!(s3.put("../bad", b"x", &context), Err(Error::Invalid));
    assert_eq!(s3.get("../bad", 1, &context), Err(Error::Invalid));
    context.cancelled.store(true, Ordering::Release);
    assert_eq!(s3.put("key", b"x", &context), Err(Error::Unknown));
    context.cancelled.store(false, Ordering::Release);
    context.deadline = Instant::now();
    assert_eq!(s3.get("key", 1, &context), Err(Error::Unknown));
}

#[test]
fn network_errors_oversized_headers_and_short_bodies_are_not_success() {
    let runtime = runtime();
    for index in 0..6 {
        let replies = match index {
            0 => vec![reply(403, 0, b"")],
            1 => vec![reply(404, 0, b"")],
            2 => vec![reply(200, 5, b"")],
            3 => vec![reply(200, 3, b""), reply(500, 0, b"")],
            4 => vec![reply(200, 3, b""), reply(200, 5, b"abcde")],
            _ => vec![reply(200, 3, b""), reply(200, 3, b"ab")],
        };
        let (endpoint, server, _) = server(replies, None);
        let mut s3 = S3::new(config(endpoint), runtime.handle().clone()).unwrap();
        let context = crate::tests::context();
        let result = if index == 0 {
            s3.put("key", b"abc", &context).map(|()| Vec::new())
        } else {
            s3.get("key", 3, &context)
        };
        let expected = if matches!(index, 2 | 4) {
            Error::TooLarge
        } else {
            Error::Object
        };
        assert_eq!(result, Err(expected), "case {index}");
        server.join().unwrap();
    }
}

#[test]
fn timeout_and_cancellation_after_io_keep_original_budget() {
    let runtime = runtime();
    for get in [false, true] {
        let mut delayed = reply(200, 0, b"");
        delayed.delay = Duration::from_millis(100);
        let (endpoint, server, _) = server(vec![delayed], None);
        let mut s3 = S3::new(config(endpoint), runtime.handle().clone()).unwrap();
        let mut context = crate::tests::context();
        context.deadline = Instant::now() + Duration::from_millis(20);
        let result = if get {
            s3.get("key", 1, &context).map(|_| ())
        } else {
            s3.put("key", b"x", &context)
        };
        assert_eq!(result, Err(Error::Unknown));
        server.join().unwrap();
    }
    for get in [false, true] {
        let context = crate::tests::context();
        let replies = if get {
            vec![reply(200, 1, b""), reply(200, 1, b"x")]
        } else {
            vec![reply(200, 0, b"")]
        };
        let (endpoint, server, _) = server(replies, Some(context.cancelled.clone()));
        let mut s3 = S3::new(config(endpoint), runtime.handle().clone()).unwrap();
        let result = if get {
            s3.get("key", 1, &context).map(|_| ())
        } else {
            s3.put("key", b"x", &context)
        };
        assert_eq!(result, Err(Error::Unknown));
        server.join().unwrap();
    }
}

#[test]
fn streaming_collection_checks_every_chunk_and_propagates_errors() {
    let runtime = runtime();
    let chunks: Vec<object_store::Result<bytes::Bytes>> =
        vec![Ok(vec![1, 2].into()), Ok(vec![3, 4].into())];
    assert_eq!(
        runtime.block_on(collect(futures_util::stream::iter(chunks).boxed(), 3)),
        Err(Error::TooLarge)
    );
    let chunks: Vec<object_store::Result<bytes::Bytes>> =
        vec![Err(object_store::Error::NotSupported {
            source: "unsupported".into(),
        })];
    assert_eq!(
        runtime.block_on(collect(futures_util::stream::iter(chunks).boxed(), 3)),
        Err(Error::Object)
    );
    assert_eq!(
        runtime.block_on(collect(
            futures_util::stream::empty::<object_store::Result<bytes::Bytes>>().boxed(),
            0
        )),
        Ok(Vec::new())
    );
}
