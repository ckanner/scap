use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;

pub(crate) fn config(endpoint: impl Into<String>) -> S3Config {
    S3Config {
        endpoint: endpoint.into(),
        region: "us-east-1".into(),
        bucket: "scap-unit".into(),
        access_key: "unit-access".into(),
        secret_key: "unit-secret".into(),
        session_token: None,
        timeout: Duration::from_secs(2),
        max_object_bytes: 4096,
        allow_http: true,
    }
}

pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

pub(crate) struct Reply {
    pub status: u16,
    pub declared_size: usize,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub delay: Duration,
    pub location: Option<String>,
}

pub(crate) fn reply(status: u16, body: &[u8]) -> Reply {
    Reply {
        status,
        declared_size: body.len(),
        body: body.to_vec(),
        etag: Some("\"unit-version\"".into()),
        delay: Duration::ZERO,
        location: None,
    }
}

type CapturedRequests = Arc<Mutex<Vec<String>>>;

/// A deterministic response transport, not an S3 correctness implementation.
/// Real object-store and process fault contracts execute separately.
pub(crate) fn transport(replies: Vec<Reply>) -> (String, thread::JoinHandle<()>, CapturedRequests) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&requests);
    let handle = thread::spawn(move || {
        for response in replies {
            let bound = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < bound, "expected one request");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut block = [0; 8192];
                let count = socket.read(&mut block).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&block[..count]);
                assert!(request.len() < 65536);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
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
            thread::sleep(response.delay);
            let mut headers = format!(
                "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n",
                response.status, response.declared_size
            );
            if let Some(etag) = response.etag {
                headers.push_str(&format!("ETag: {etag}\r\n"));
            }
            if let Some(location) = response.location {
                headers.push_str(&format!("Location: {location}\r\n"));
            }
            headers.push_str("\r\n");
            let _ = socket.write_all(headers.as_bytes());
            let _ = socket.write_all(&response.body);
        }
    });
    (endpoint, handle, requests)
}

/// A timeout may happen before the client has sent complete HTTP headers. Keep
/// accepted sockets silent until the caller finishes, rather than requiring a
/// complete request from an operation whose original deadline may already have
/// elapsed. Closing the signal on panic also stops the owned fixture thread.
fn stalled_transport() -> (
    String,
    thread::JoinHandle<usize>,
    std::sync::mpsc::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let mut sockets = Vec::new();
        loop {
            let finished = !matches!(
                stopped.recv_timeout(Duration::from_millis(1)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            );
            // Drain connections already queued at completion as well. No HTTP
            // response is emitted, and no early EOF is treated as a fixture bug.
            loop {
                match listener.accept() {
                    Ok((socket, _)) => {
                        sockets.push(socket);
                        assert!(sockets.len() <= 1, "one HTTP attempt per call");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("{error}"),
                }
            }
            if finished {
                break;
            }
        }
        sockets.len()
    });
    (endpoint, server, stop)
}

#[test]
fn signed_single_get_keeps_its_etag_and_writes_keep_exact_conditions() {
    let (endpoint, server, capture) = transport(vec![
        reply(200, b"abc"),
        reply(200, b""),
        reply(200, b""),
        reply(200, b""),
    ]);
    let mut settings = config(endpoint);
    settings.session_token = Some("unit-session".into());
    let s3 = S3::new(settings).unwrap();
    let original = s3.get("scope/HEAD", 3, deadline()).unwrap();
    assert_eq!(original.bytes, b"abc");
    assert_eq!(original.etag, "\"unit-version\"");
    assert_eq!(
        s3.clone().put(
            "scope/HEAD",
            b"next",
            Condition::Match(&original.etag),
            deadline()
        ),
        Ok(original.etag)
    );
    assert!(s3
        .put("scope/blob", b"", Condition::Absent, deadline())
        .is_ok());
    assert_eq!(s3.get("scope/empty", 0, deadline()).unwrap().bytes, b"");
    server.join().unwrap();
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("get /scap-unit/scope/head "));
    assert!(requests[1].starts_with("put /scap-unit/scope/head "));
    assert!(requests[1].contains("if-match: \"unit-version\""));
    assert!(requests[2].contains("if-none-match: *"));
    for request in requests.iter() {
        assert!(request.contains("authorization: aws4-hmac-sha256"));
        assert!(request.contains("x-amz-security-token: unit-session"));
        assert!(!request.starts_with("head "));
        assert!(!request.contains("list-type"));
    }
}

#[test]
fn configuration_and_construction_fail_closed_without_ambient_credentials() {
    for index in 0..16 {
        let mut settings = config("http://127.0.0.1:1");
        match index {
            0 => settings.endpoint = "not a url".into(),
            1 => settings.endpoint = "ftp://host/".into(),
            2 => settings.endpoint = "https://user@host/".into(),
            3 => settings.endpoint = "https://:secret@host/".into(),
            4 => settings.endpoint = "https://host/?x=1".into(),
            5 => settings.endpoint = "https://host/#part".into(),
            6 => settings.endpoint = "https://host/prefix".into(),
            7 => settings.allow_http = false,
            8 => settings.region.clear(),
            9 => settings.bucket.clear(),
            10 => settings.access_key.clear(),
            11 => settings.secret_key.clear(),
            12 => settings.session_token = Some(String::new()),
            13 => settings.max_object_bytes = 0,
            14 => settings.timeout = Duration::ZERO,
            _ => settings.endpoint = "https:///".into(),
        }
        assert!(
            matches!(S3::new(settings), Err(StoreError::Invalid)),
            "case {index}"
        );
    }
    let mut settings = config("https://example.invalid");
    settings.allow_http = false;
    assert!(S3::new(settings).is_ok());
    assert!(matches!(
        S3::build(
            config("https://example.invalid"),
            |_| Err(object_store::Error::Generic {
                store: "test",
                source: "injected construction failure".into(),
            }),
            runtime,
        ),
        Err(StoreError::Invalid)
    ));
    assert!(matches!(
        S3::build(
            config("https://example.invalid"),
            AmazonS3Builder::build,
            || { Err(std::io::Error::other("injected runtime failure")) }
        ),
        Err(StoreError::Invalid)
    ));
    let runtime = runtime().unwrap();
    let guard = runtime.enter();
    assert!(matches!(
        S3::new(config("https://example.invalid")),
        Err(StoreError::Invalid)
    ));
    drop(guard);
}

#[test]
fn input_limits_paths_etags_and_deadlines_precede_any_io() {
    let s3 = S3::new(config("http://127.0.0.1:1")).unwrap();
    assert_eq!(s3.get("key", 4097, deadline()), Err(StoreError::Budget));
    assert_eq!(
        s3.put("key", &[0; 4097], Condition::Absent, deadline()),
        Err(StoreError::Budget)
    );
    for key in ["", "../bad", "/prefix", "trailing/", "key\0"] {
        assert_eq!(
            s3.get(key, 1, deadline()),
            Err(StoreError::Invalid),
            "{key:?}"
        );
    }
    assert_eq!(
        s3.get(&"k".repeat(1025), 1, deadline()),
        Err(StoreError::Invalid)
    );
    assert_eq!(s3.get("key", 1, Instant::now()), Err(StoreError::Unknown));
    assert_eq!(
        s3.put("key", b"x", Condition::Absent, Instant::now()),
        Err(StoreError::Unknown)
    );
    for etag in [
        "",
        "*",
        "has space",
        "plain",
        "\"unterminated",
        "no-begin\"",
        "W/\"weak\"",
        "\"a\",\"b\"",
        "\"contains space\"",
        "\"bad\u{7f}\"",
        "\"é\"",
        "bad\r\nheader",
        "bad\u{7f}",
        "é",
    ] {
        assert_eq!(
            s3.put("key", b"x", Condition::Match(etag), deadline()),
            Err(StoreError::Invalid),
            "{etag:?}"
        );
    }
    assert_eq!(
        s3.put("key", b"x", Condition::Match(&"x".repeat(1025)), deadline()),
        Err(StoreError::Invalid)
    );
    let other_runtime = runtime().unwrap();
    let guard = other_runtime.enter();
    assert_eq!(s3.get("key", 1, deadline()), Err(StoreError::Invalid));
    drop(guard);
}

#[test]
fn definite_preconditions_and_uncertain_statuses_remain_distinct() {
    let cases = [
        (412, Condition::Absent, StoreError::Conflict),
        (412, Condition::Match("\"old\""), StoreError::Conflict),
        (409, Condition::Absent, StoreError::Unknown),
        (409, Condition::Match("\"old\""), StoreError::Unknown),
        (500, Condition::Absent, StoreError::Unknown),
        (500, Condition::Match("\"old\""), StoreError::Unknown),
        (403, Condition::Absent, StoreError::Unknown),
        (404, Condition::Absent, StoreError::Unknown),
        (404, Condition::Match("\"old\""), StoreError::Conflict),
        (304, Condition::Absent, StoreError::Unknown),
    ];
    let (endpoint, server, capture) =
        transport(cases.iter().map(|case| reply(case.0, b"")).collect());
    let s3 = S3::new(config(endpoint)).unwrap();
    for (status, condition, expected) in &cases {
        assert_eq!(
            s3.put("key", b"x", *condition, deadline()),
            Err(expected.clone()),
            "status {status} condition {condition:?}"
        );
    }
    server.join().unwrap();
    assert_eq!(
        capture.lock().unwrap().len(),
        cases.len(),
        "one HTTP attempt per call"
    );
}

#[test]
fn read_failures_and_missing_put_tokens_never_become_success() {
    let mut missing = reply(200, b"abc");
    missing.etag = None;
    let mut invalid = reply(200, b"abc");
    invalid.etag = Some("*".into());
    let mut short = reply(200, b"ab");
    short.declared_size = 3;
    let replies = vec![
        reply(404, b""),
        reply(500, b""),
        reply(412, b""),
        reply(200, b"abcd"),
        missing,
        invalid,
        short,
    ];
    let (endpoint, server, _) = transport(replies);
    let s3 = S3::new(config(endpoint)).unwrap();
    for expected in [
        StoreError::Missing,
        StoreError::Unknown,
        StoreError::Unknown,
        StoreError::Limit,
        StoreError::Corrupt,
        StoreError::Corrupt,
        StoreError::Unknown,
    ] {
        assert_eq!(s3.get("key", 3, deadline()), Err(expected));
    }
    server.join().unwrap();
    let mut missing = reply(200, b"");
    missing.etag = None;
    let mut invalid = reply(200, b"");
    invalid.etag = Some("*".into());
    let (endpoint, server, _) = transport(vec![missing, invalid]);
    let s3 = S3::new(config(endpoint)).unwrap();
    for _ in 0..2 {
        assert_eq!(
            s3.put("key", b"x", Condition::Absent, deadline()),
            Err(StoreError::Unknown)
        );
    }
    server.join().unwrap();
}

#[test]
fn operation_and_transport_timeouts_keep_the_original_outcome_unknown() {
    for put in [false, true] {
        let (endpoint, server, stop) = stalled_transport();
        let s3 = S3::new(config(endpoint)).unwrap();
        let bound = Instant::now() + Duration::from_millis(20);
        let result = if put {
            s3.put("key", b"x", Condition::Absent, bound).map(|_| ())
        } else {
            s3.get("key", 3, bound).map(|_| ())
        };
        assert_eq!(result, Err(StoreError::Unknown));
        stop.send(()).unwrap();
        assert!(server.join().unwrap() <= 1);
    }
    let (endpoint, server, stop) = stalled_transport();
    let mut settings = config(endpoint);
    settings.timeout = Duration::from_millis(20);
    let s3 = S3::new(settings).unwrap();
    assert_eq!(s3.get("key", 1, deadline()), Err(StoreError::Unknown));
    stop.send(()).unwrap();
    assert!(server.join().unwrap() <= 1);
    assert_eq!(
        s3.execute(Instant::now() + Duration::from_millis(5), async {
            thread::sleep(Duration::from_millis(20));
            Ok(())
        }),
        Err(StoreError::Unknown)
    );
}

fn object(size: u64, chunks: Vec<object_store::Result<bytes::Bytes>>) -> GetResult {
    GetResult {
        payload: object_store::GetResultPayload::Stream(futures_util::stream::iter(chunks).boxed()),
        meta: object_store::ObjectMeta {
            location: Path::from("key"),
            last_modified: std::time::SystemTime::UNIX_EPOCH.into(),
            size,
            e_tag: Some("\"opaque-token\"".into()),
            version: None,
        },
        range: 0..size,
        attributes: Default::default(),
        extensions: Default::default(),
    }
}

#[test]
fn body_collection_checks_complete_range_size_and_every_stream_chunk() {
    let runtime = runtime().unwrap();
    let mut partial = object(3, vec![]);
    partial.range = 1..3;
    assert_eq!(
        runtime.block_on(read_object(partial, 3)),
        Err(StoreError::Corrupt)
    );
    assert_eq!(
        runtime.block_on(read_object(object(3, vec![Ok(b"ab".as_slice().into())]), 3)),
        Err(StoreError::Corrupt)
    );
    assert_eq!(
        runtime.block_on(read_object(
            object(
                3,
                vec![Ok(b"ab".as_slice().into()), Ok(b"cd".as_slice().into())]
            ),
            3
        )),
        Err(StoreError::Limit)
    );
    assert_eq!(
        runtime.block_on(read_object(
            object(
                3,
                vec![Err(object_store::Error::NotSupported {
                    source: "injected stream failure".into()
                })]
            ),
            3
        )),
        Err(StoreError::Unknown)
    );
    assert_eq!(
        runtime.block_on(read_object(
            object(
                3,
                vec![Ok(b"ab".as_slice().into()), Ok(b"c".as_slice().into())]
            ),
            3
        )),
        Ok(Stored {
            bytes: b"abc".to_vec(),
            etag: "\"opaque-token\"".into()
        })
    );
}
