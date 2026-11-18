use super::*;
use crate::tests::{config, deadline, reply, transport};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PREFIX: &str = "scap-object/v1/1/2/3/inc/4/gen/5/storage/6/objects/";
const HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const EMPTY: &[u8] =
    b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
const NO_LOCK: &[u8] =
    b"<Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>none</Message></Error>";

fn ready_replies() -> Vec<crate::tests::Reply> {
    vec![reply(200, EMPTY), reply(404, NO_LOCK)]
}

#[derive(Debug)]
struct TimedReply {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
}

#[derive(Debug)]
struct TimedRequest {
    method: Method,
    uri: String,
    headers: HeaderMap,
}

type TimedRequests = Arc<Mutex<Vec<TimedRequest>>>;

#[derive(Debug)]
struct TimedTransport {
    replies: Mutex<VecDeque<TimedReply>>,
    requests: TimedRequests,
    completed: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl object_store::client::HttpService for TimedTransport {
    async fn call(
        &self,
        request: HttpRequest,
    ) -> Result<object_store::client::HttpResponse, object_store::client::HttpError> {
        self.requests.lock().unwrap().push(TimedRequest {
            method: request.method().clone(),
            uri: request.uri().to_string(),
            headers: request.headers().clone(),
        });
        let response = self.replies.lock().unwrap().pop_front().unwrap();
        tokio::time::sleep(response.delay).await;
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(http::Response::builder()
            .status(response.status)
            .body(response.body.into())
            .unwrap())
    }
}

/// Deterministic async timeout effects, separate from the real HTTP fixtures.
/// The caller still supplies one original std::Instant. Only Tokio's timer is
/// paused, so preflight and DELETE/GET share that exact deadline without a TCP
/// scheduling race. This does not freeze std::Instant's post-completion guard.
fn timed_store(replies: Vec<crate::tests::Reply>) -> (GcS3, TimedRequests, Arc<AtomicUsize>) {
    let mut store = GcS3::new(config("http://127.0.0.1:1"), 1).unwrap();
    store.inner.runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    store.client = HttpClient::new(TimedTransport {
        replies: Mutex::new(
            replies
                .into_iter()
                .map(|value| TimedReply {
                    status: value.status,
                    body: value.body,
                    delay: value.delay,
                })
                .collect(),
        ),
        requests: Arc::clone(&requests),
        completed: Arc::clone(&completed),
    });
    (store, requests, completed)
}

fn delayed_preflight() -> Vec<crate::tests::Reply> {
    let mut replies = ready_replies();
    for response in &mut replies {
        response.delay = Duration::from_millis(250);
    }
    replies
}

#[test]
fn signed_gc_capability_and_conditional_delete_use_exact_single_requests() {
    let mut replies = ready_replies();
    replies.extend([
        reply(204, b""),
        reply(412, b"<Error><Code>PreconditionFailed</Code></Error>"),
        reply(404, b"<Error><Code>NoSuchKey</Code></Error>"),
    ]);
    let (endpoint, server, capture) = transport(replies);
    let mut settings = config(endpoint);
    settings.session_token = Some("gc-session".into());
    let store = GcS3::new(settings, 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    assert_eq!(
        batch.delete(HASH, "\"original\""),
        Ok(DeleteOutcome::Applied)
    );
    assert_eq!(
        batch.delete(HASH, "\"original\""),
        Ok(DeleteOutcome::Conflict)
    );
    assert_eq!(
        batch.delete(HASH, "\"original\""),
        Ok(DeleteOutcome::Missing)
    );
    server.join().unwrap();
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("get /scap-unit?versioning "));
    assert!(requests[1].starts_with("get /scap-unit?object-lock "));
    for request in requests.iter() {
        assert!(request.contains("authorization: aws4-hmac-sha256"));
        assert!(request.contains("x-amz-security-token: gc-session"));
        assert!(!request.contains("versionid="));
        assert!(!request.contains("bypass-governance"));
    }
    for request in &requests[2..] {
        assert!(request.starts_with(&format!("delete /scap-unit/{PREFIX}{HASH} ")));
        assert!(request.contains("if-match: \"original\""));
        assert!(request.contains("signedheaders=host;if-match;"));
    }
}

#[test]
fn preflight_denials_never_issue_a_delete_or_alias_a_missing_bucket() {
    let cases: Vec<(Vec<crate::tests::Reply>,GcError)>=vec![
        (vec![reply(403,b"denied")],GcError::Denied),
        (vec![reply(404,b"<Error><Code>NoSuchBucket</Code></Error>")],GcError::Unknown),
        (vec![reply(200,b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>")],GcError::Unsupported),
        (vec![reply(200,b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Suspended</Status></VersioningConfiguration>")],GcError::Unsupported),
        (vec![reply(200,b"invalid")],GcError::Corrupt),
        (vec![reply(200,EMPTY),reply(200,b"<ObjectLockConfiguration/>")],GcError::Unsupported),
        (vec![reply(200,EMPTY),reply(404,b"<Error><Code>NoSuchBucket</Code></Error>")],GcError::Unsupported),
        (vec![reply(200,EMPTY),reply(404,b"invalid")],GcError::Corrupt),
        (vec![reply(200,EMPTY),reply(403,b"denied")],GcError::Denied),
        (vec![reply(200,EMPTY),reply(500,b"error")],GcError::Unknown),
    ];
    for (replies, expected) in cases {
        let count = replies.len();
        let (endpoint, server, capture) = transport(replies);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        assert!(matches!(store.begin_batch(PREFIX,deadline()),Err(error) if error==expected));
        server.join().unwrap();
        let requests = capture.lock().unwrap();
        assert_eq!(requests.len(), count);
        assert!(requests.iter().all(|request| request.starts_with("get ")));
    }
}

#[test]
fn batch_bounds_errors_and_original_deadline_do_not_retry_deletes() {
    let mut replies = ready_replies();
    replies.extend((0..MAX_DELETE_BATCH).map(|_| reply(204, b"")));
    let (endpoint, server, capture) = transport(replies);
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    for _ in 0..MAX_DELETE_BATCH {
        assert_eq!(batch.delete(HASH, "\"x\""), Ok(DeleteOutcome::Applied));
    }
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Limit));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 34);
    for (status, body, expected) in [
        (409, b"conflict".as_slice(), GcError::Unknown),
        (500, b"error", GcError::Unknown),
        (200, b"", GcError::Unknown),
        (
            404,
            b"<Error><Code>NoSuchBucket</Code></Error>",
            GcError::Unknown,
        ),
        (403, b"denied", GcError::Denied),
    ] {
        let mut replies = ready_replies();
        replies.push(reply(status, body));
        let (endpoint, server, capture) = transport(replies);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
        assert_eq!(batch.delete(HASH, "\"x\""), Err(expected));
        assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Limit));
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 3);
    }
    let (endpoint, server, capture) = transport(ready_replies());
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    batch.deadline = Instant::now();
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Unknown));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 2);
}

#[test]
fn configuration_and_fixed_prefix_validation_precede_any_io() {
    for case in 0..9 {
        let mut settings = config("http://127.0.0.1:1");
        match case {
            0 => settings.bucket = "UPPER".into(),
            1 => settings.bucket = "aa".into(),
            2 => settings.bucket = "a".repeat(64),
            3 => settings.bucket = "bucket--zone--x-s3".into(),
            4 => settings.access_key = "a\nb".into(),
            5 => settings.region = "a\nb".into(),
            6 => settings.session_token = Some("a\nb".into()),
            7 => settings.endpoint = "bad".into(),
            _ => settings.endpoint = "http://host/path".into(),
        }
        assert!(
            matches!(GcS3::new(settings, 1), Err(GcError::Invalid)),
            "case {case}"
        );
    }
    assert!(matches!(
        GcS3::new(config("http://127.0.0.1:1"), 0),
        Err(GcError::Invalid)
    ));
    assert!(matches!(
        GcS3::build(config("http://127.0.0.1:1"), 1, |_| Err(GcError::Invalid)),
        Err(GcError::Invalid)
    ));
    let store = GcS3::new(config("http://127.0.0.1:1"), 1).unwrap();
    let mut bad = vec![
        String::new(),
        "a".repeat(961),
        PREFIX.trim_end_matches('/').into(),
        PREFIX.replace("scap-object", "other"),
        PREFIX.replace("v1", "v2"),
        PREFIX.replace("inc/", "other/"),
        PREFIX.replace("gen/", "other/"),
        PREFIX.replace("storage/", "other/"),
        PREFIX.replace("objects/", "head/"),
        format!("{PREFIX}x"),
    ];
    for value in ["0", "01", "+1", "-1", "one", "18446744073709551616", "2"] {
        bad.push(PREFIX.replacen("v1/1/", &format!("v1/{value}/"), 1));
    }
    for value in bad {
        assert!(
            matches!(store.begin_batch(&value, deadline()), Err(GcError::Invalid)),
            "{value}"
        );
    }
    assert!(valid_prefix(PREFIX, 1));
    assert!(valid_prefix(
        "scap-object/v1/18446744073709551615/2/3/inc/4/gen/5/storage/6/objects/",
        u64::MAX
    ));
    assert!(matches!(
        store.begin_batch(PREFIX, Instant::now()),
        Err(GcError::Unknown)
    ));
    assert!(matches!(
        store.begin_batch(PREFIX, deadline()),
        Err(GcError::Unknown)
    ));
    let runtime = crate::runtime().unwrap();
    let guard = runtime.enter();
    assert!(matches!(
        store.begin_batch(PREFIX, deadline()),
        Err(GcError::Invalid)
    ));
    drop(guard);
}

#[test]
fn invalid_hashes_and_etags_cannot_escape_the_payload_namespace() {
    let (endpoint, server, capture) = transport(ready_replies());
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    for hash in [
        "".into(),
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        format!("/{}", "a".repeat(63)),
        format!("../{}", "a".repeat(61)),
    ] {
        assert_eq!(batch.delete(&hash, "\"x\""), Err(GcError::Invalid));
    }
    for etag in ["*", "x", "W/\"x\"", "\"a\nb\"", "\"a\"b\""] {
        assert_eq!(batch.delete(HASH, etag), Err(GcError::Invalid));
    }
    let runtime = crate::runtime().unwrap();
    let guard = runtime.enter();
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Invalid));
    drop(guard);
    assert_eq!(batch.remaining, MAX_DELETE_BATCH);
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 2);
}

#[test]
fn truncated_large_redirected_and_late_responses_stay_unknown() {
    let mut short = reply(200, EMPTY);
    short.declared_size += 1;
    let mut redirect = reply(301, b"");
    redirect.location = Some("http://127.0.0.1:1/".into());
    for response in [
        short,
        redirect,
        reply(200, &vec![b' '; MAX_GC_RESPONSE_BYTES + 1]),
    ] {
        let (endpoint, server, capture) = transport(vec![response]);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        assert!(matches!(
            store.begin_batch(PREFIX, deadline()),
            Err(GcError::Unknown)
        ));
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 1);
    }
    let mut replies = delayed_preflight();
    let mut late = reply(204, b"");
    late.delay = Duration::from_secs(2);
    replies.push(late);
    let (store, capture, completed) = timed_store(replies);
    let original = deadline();
    let mut batch = store.begin_batch(PREFIX, original).unwrap();
    assert_eq!(batch.deadline, original);
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Unknown));
    assert_eq!(batch.deadline, original);
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Limit));
    assert_eq!(completed.load(Ordering::SeqCst), 2);
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[1].method, Method::GET);
    assert_eq!(requests[2].method, Method::DELETE);
    assert_eq!(
        requests[2].uri,
        format!("http://127.0.0.1:1/scap-unit/{PREFIX}{HASH}")
    );
    assert_eq!(requests[2].headers[http::header::IF_MATCH], "\"x\"");
    assert!(requests
        .iter()
        .all(|request| request.headers[http::header::AUTHORIZATION]
            .to_str()
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 ")));
}

#[test]
fn unexpected_version_metadata_and_malformed_delete_results_are_uncertain() {
    for name in ["x-amz-version-id", "x-amz-delete-marker"] {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static("null"));
        assert_eq!(
            deletion(Response {
                status: 204,
                headers,
                bytes: vec![]
            }),
            Err(GcError::Unknown)
        );
    }
    for (status, body) in [(204, b"body".as_slice()), (404, b"invalid")] {
        assert_eq!(
            deletion(Response {
                status,
                headers: HeaderMap::new(),
                bytes: body.to_vec()
            }),
            Err(GcError::Unknown)
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
    assert_eq!(
        deletion(Response {
            status: 204,
            headers,
            bytes: vec![]
        }),
        Err(GcError::Unknown)
    );
    assert_eq!(
        deletion(Response {
            status: 204,
            headers: HeaderMap::new(),
            bytes: vec![]
        }),
        Ok(DeleteOutcome::Applied)
    );
}

#[test]
fn preflight_timeout_does_not_create_a_batch_after_the_original_deadline() {
    let mut delayed = reply(200, EMPTY);
    delayed.delay = Duration::from_secs(3);
    let (store, capture, completed) = timed_store(vec![delayed]);
    let original = deadline();
    assert!(matches!(
        store.begin_batch(PREFIX, original),
        Err(GcError::Unknown)
    ));
    assert_eq!(capture.lock().unwrap().len(), 1);
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}

#[test]
fn wall_clock_guard_rejects_a_ready_future_finishing_after_the_original_deadline() {
    let store = GcS3::new(config("http://127.0.0.1:1"), 1).unwrap();
    let original = deadline();
    let mut completed = false;
    assert_eq!(
        store.execute(original, async {
            // A synchronous completion can hold its poll past Tokio's timer.
            // Keep the original real clock guard independently exercised; no
            // paused timer or renewed deadline stands in for this check.
            std::thread::sleep(original.saturating_duration_since(Instant::now()));
            assert!(Instant::now() >= original);
            completed = true;
            Ok(())
        }),
        Err(GcError::Unknown)
    );
    assert!(completed);
}

#[test]
fn lock_and_delete_transport_errors_cannot_become_complete_backend_results() {
    let mut lock = reply(404, NO_LOCK);
    lock.declared_size += 1;
    let (endpoint, server, capture) = transport(vec![reply(200, EMPTY), lock]);
    let store = GcS3::new(config(endpoint), 1).unwrap();
    assert!(matches!(
        store.begin_batch(PREFIX, deadline()),
        Err(GcError::Unknown)
    ));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 2);

    let mut deletion = reply(500, b"incomplete error response");
    deletion.declared_size += 1;
    let mut replies = ready_replies();
    replies.push(deletion);
    let (endpoint, server, capture) = transport(replies);
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Unknown));
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Limit));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 3);
}

#[derive(Debug)]
struct UnavailableCredentials(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl object_store::client::CredentialProvider for UnavailableCredentials {
    type Credential = object_store::aws::AwsCredential;

    async fn get_credential(&self) -> object_store::Result<Arc<Self::Credential>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(object_store::Error::Generic {
            store: "unit credentials",
            source: "credential provider unavailable".into(),
        })
    }
}

#[derive(Debug)]
struct UnexpectedTransport(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl object_store::client::HttpService for UnexpectedTransport {
    async fn call(
        &self,
        _request: HttpRequest,
    ) -> Result<object_store::client::HttpResponse, object_store::client::HttpError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(object_store::client::HttpError::new(
            object_store::client::HttpErrorKind::Connect,
            std::io::Error::other("transport must not be reached"),
        ))
    }
}

#[test]
fn request_validation_and_credential_failure_precede_transport() {
    let credentials = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let mut store = GcS3::new(config("http://127.0.0.1:1"), 1).unwrap();
    store.inner.store = object_store::aws::AmazonS3Builder::new()
        .with_bucket_name("scap-unit")
        .with_region("us-east-1")
        .with_endpoint("http://127.0.0.1:1")
        .with_allow_http(true)
        .with_credentials(Arc::new(UnavailableCredentials(Arc::clone(&credentials))))
        .build()
        .unwrap()
        .into();
    store.client = HttpClient::new(UnexpectedTransport(Arc::clone(&requests)));
    assert!(matches!(
        store.inner.runtime.block_on(store.request(
            Method::GET,
            "",
            Some("versioning"),
            Some("\n")
        )),
        Err(GcError::Invalid)
    ));
    assert_eq!(credentials.load(Ordering::SeqCst), 0);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert!(matches!(
        store.begin_batch(PREFIX, deadline()),
        Err(GcError::Unknown)
    ));
    assert_eq!(credentials.load(Ordering::SeqCst), 1);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[test]
fn signing_failure_is_unknown_before_any_delete_is_sent() {
    fn signer(
        request: &mut HttpRequest,
        credential: &object_store::aws::AwsCredential,
        region: &str,
    ) -> object_store::Result<()> {
        if request.method() == Method::DELETE {
            return Err(object_store::Error::Generic {
                store: "unit signing",
                source: "signer unavailable".into(),
            });
        }
        authorize(request, credential, region)
    }

    let (endpoint, server, capture) = transport(ready_replies());
    let mut store = GcS3::new(config(endpoint), 1).unwrap();
    store.authorization = signer;
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    assert_eq!(batch.delete(HASH, "\"original\""), Err(GcError::Unknown));
    assert_eq!(batch.delete(HASH, "\"original\""), Err(GcError::Limit));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 2);
}

#[test]
fn garbage_capability_inspects_one_full_candidate_and_keeps_its_original_etag() {
    let mut replies = ready_replies();
    replies.push(reply(200, b"original object bytes"));
    replies.extend(ready_replies());
    replies.push(reply(404, b"<Error><Code>NoSuchKey</Code></Error>"));
    replies.extend(ready_replies());
    replies.push(reply(204, b""));
    let (endpoint, server, capture) = transport(replies);
    let store: Box<dyn Garbage> = Box::new(GcS3::new(config(endpoint), 1).unwrap());
    let candidate = store.inspect(PREFIX, HASH, deadline()).unwrap();
    assert_eq!(
        candidate,
        GcCandidate::Present {
            etag: "\"unit-version\"".into()
        }
    );
    assert_eq!(
        store.inspect(PREFIX, HASH, deadline()),
        Ok(GcCandidate::Missing)
    );
    let GcCandidate::Present { etag } = candidate else {
        panic!("original GET must identify its exact version");
    };
    assert_eq!(
        store.delete(PREFIX, HASH, &etag, deadline()),
        Ok(DeleteOutcome::Applied)
    );
    server.join().unwrap();
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 9);
    for index in [2, 5] {
        assert!(requests[index].starts_with(&format!("get /scap-unit/{PREFIX}{HASH} ")));
        assert!(!requests[index].contains("range:"));
        assert!(!requests[index].contains("if-match:"));
    }
    assert!(requests[8].starts_with(&format!("delete /scap-unit/{PREFIX}{HASH} ")));
    assert!(requests[8].contains("if-match: \"unit-version\""));
    assert!(requests
        .iter()
        .all(|r| r.contains("authorization: aws4-hmac-sha256")));
}

#[test]
fn candidate_uncertainty_never_becomes_absence_or_an_eligible_new_etag() {
    let mut missing_etag = reply(200, b"ok");
    missing_etag.etag = None;
    let mut invalid_etag = reply(200, b"ok");
    invalid_etag.etag = Some("weak".into());
    let mut short = reply(200, b"short");
    short.declared_size += 1;
    let mut redirect = reply(307, b"");
    redirect.location = Some("http://127.0.0.1:1/".into());
    for (response, expected) in [
        (missing_etag, GcError::Unknown),
        (invalid_etag, GcError::Unknown),
        (short, GcError::Unknown),
        (redirect, GcError::Unknown),
        (reply(200, &[0; 4097]), GcError::Unknown),
        (
            reply(404, b"<Error><Code>NoSuchBucket</Code></Error>"),
            GcError::Unknown,
        ),
        (reply(404, b"not complete S3 XML"), GcError::Unknown),
        (
            reply(404, &vec![0; MAX_GC_RESPONSE_BYTES + 1]),
            GcError::Unknown,
        ),
        (reply(206, b"partial"), GcError::Unknown),
        (reply(403, b"denied"), GcError::Denied),
        (reply(409, b"conflict"), GcError::Unknown),
        (reply(500, b"failed"), GcError::Unknown),
    ] {
        let mut replies = ready_replies();
        replies.push(response);
        let (endpoint, server, capture) = transport(replies);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        assert_eq!(store.inspect(PREFIX, HASH, deadline()), Err(expected));
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 3);
    }
}

#[test]
fn garbage_capability_rejects_bad_namespace_inputs_and_keeps_original_deadlines() {
    let store = GcS3::new(config("http://127.0.0.1:1"), 1).unwrap();
    assert_eq!(
        store.inspect(PREFIX, "bad", deadline()),
        Err(GcError::Invalid)
    );
    assert_eq!(
        store.inspect("other/", HASH, deadline()),
        Err(GcError::Invalid)
    );
    assert_eq!(
        store.inspect(PREFIX, HASH, Instant::now()),
        Err(GcError::Unknown)
    );
    assert_eq!(
        store.delete(PREFIX, "bad", "\"x\"", deadline()),
        Err(GcError::Invalid)
    );
    assert_eq!(
        store.delete(PREFIX, HASH, "*", deadline()),
        Err(GcError::Invalid)
    );
    assert_eq!(
        store.delete("other/", HASH, "\"x\"", deadline()),
        Err(GcError::Invalid)
    );
    assert_eq!(
        store.delete(PREFIX, HASH, "\"x\"", Instant::now()),
        Err(GcError::Unknown)
    );
    let runtime = crate::runtime().unwrap();
    let guard = runtime.enter();
    assert_eq!(
        store.inspect(PREFIX, HASH, deadline()),
        Err(GcError::Invalid)
    );
    drop(guard);

    for delete in [false, true] {
        let (endpoint, server, capture) = transport(vec![reply(403, b"preflight denied")]);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        if delete {
            assert_eq!(
                store.delete(PREFIX, HASH, "\"x\"", deadline()),
                Err(GcError::Denied)
            );
        } else {
            assert_eq!(
                store.inspect(PREFIX, HASH, deadline()),
                Err(GcError::Denied)
            );
        }
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 1);
    }

    let mut late = reply(200, b"complete but too late");
    late.delay = Duration::from_secs(2);
    let mut replies = delayed_preflight();
    replies.push(late);
    let (store, capture, completed) = timed_store(replies);
    let original = deadline();
    assert_eq!(store.inspect(PREFIX, HASH, original), Err(GcError::Unknown));
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].method, Method::GET);
    assert_eq!(
        requests[2].uri,
        format!("http://127.0.0.1:1/scap-unit/{PREFIX}{HASH}")
    );
    assert_eq!(completed.load(Ordering::SeqCst), 2);
}

fn candidate_response() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::ETAG, HeaderValue::from_static("\"original\""));
    headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("3"));
    Response {
        status: 200,
        headers,
        bytes: b"abc".to_vec(),
    }
}

#[test]
fn candidate_requires_one_exact_version_and_a_complete_unencoded_unversioned_body() {
    for name in [
        "x-amz-version-id",
        "x-amz-delete-marker",
        "content-range",
        "content-encoding",
    ] {
        let mut response = candidate_response();
        response
            .headers
            .insert(name, HeaderValue::from_static("unexpected"));
        assert_eq!(candidate(response), Err(GcError::Unknown));
    }
    let mut response = candidate_response();
    response
        .headers
        .append(http::header::ETAG, HeaderValue::from_static("\"second\""));
    assert_eq!(candidate(response), Err(GcError::Unknown));
    let mut response = candidate_response();
    response.headers.insert(
        http::header::ETAG,
        HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    assert_eq!(candidate(response), Err(GcError::Unknown));
    let mut response = candidate_response();
    response.headers.remove(http::header::CONTENT_LENGTH);
    assert_eq!(candidate(response), Err(GcError::Unknown));
    for value in [
        b"invalid".as_slice(),
        b"4",
        b"\xff",
        b"184467440737095516160",
    ] {
        let mut response = candidate_response();
        response.headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_bytes(value).unwrap(),
        );
        assert_eq!(candidate(response), Err(GcError::Unknown));
    }
    assert_eq!(
        candidate(candidate_response()),
        Ok(GcCandidate::Present {
            etag: "\"original\"".into()
        })
    );
}
