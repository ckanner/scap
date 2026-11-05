use super::*;
use crate::tests::{limits, EmptyBackend};
use crate::{
    BackendFuture, DatabaseStatus, Environment, Outcome, OutcomeAction, RequestPosition,
    RequestTerminal,
};
use scap_sql::{StatementResult, TransactionResult};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tower::ServiceExt;

struct TestEnvironment {
    now: Instant,
    wall: Result<u64, ServiceError>,
    offset: AtomicU64,
}
impl Environment for TestEnvironment {
    fn now(&self) -> Instant {
        self.now + Duration::from_millis(self.offset.load(Ordering::Relaxed))
    }
    fn unix_millis(&self) -> Result<u64, ServiceError> {
        self.wall.clone()
    }
}

fn environment() -> Arc<TestEnvironment> {
    Arc::new(TestEnvironment {
        now: Instant::now(),
        wall: Ok(1000),
        offset: AtomicU64::new(0),
    })
}

struct BackendState {
    contexts: Mutex<Vec<RequestContext>>,
    modes: Mutex<Vec<Mode>>,
    actions: Mutex<Vec<OutcomeAction>>,
    rotations: Mutex<Vec<u64>>,
    pending: AtomicBool,
    error: Mutex<Option<ServiceError>>,
    outcome: Mutex<Outcome>,
    advance: Option<Arc<TestEnvironment>>,
}

#[derive(Clone)]
struct TestBackend(Arc<BackendState>);
impl TestBackend {
    fn new() -> Self {
        Self(Arc::new(BackendState {
            contexts: Mutex::new(Vec::new()),
            modes: Mutex::new(Vec::new()),
            actions: Mutex::new(Vec::new()),
            rotations: Mutex::new(Vec::new()),
            pending: AtomicBool::new(false),
            error: Mutex::new(None),
            outcome: Mutex::new(Outcome::Unknown),
            advance: None,
        }))
    }
}

impl Backend for TestBackend {
    fn status(&self, context: RequestContext) -> BackendFuture<DatabaseStatus> {
        self.0.contexts.lock().unwrap().push(context);
        let error = self.0.error.lock().unwrap().clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(DatabaseStatus {
                    revision: u64::MAX,
                    request_epoch: u64::MAX,
                    retained_requests: u64::MAX,
                    unacknowledged_requests: u64::MAX,
                    retired_revision: u64::MAX,
                    base_revision: u64::MAX,
                    tail_entries: u64::MAX,
                    tail_bytes: u64::MAX,
                    suspended: true,
                    cold: true,
                    owner_active: false,
                    archived_revision: Some(u64::MAX),
                }),
            }
        })
    }
    fn execute(&self, call: Call) -> BackendFuture<TransactionResult> {
        self.0.contexts.lock().unwrap().push(call.context);
        self.0.modes.lock().unwrap().push(call.mode);
        if let Some(environment) = &self.0.advance {
            environment.offset.store(1000, Ordering::Relaxed);
        }
        let result = TransactionResult {
            statements: call
                .statements
                .iter()
                .map(|_| StatementResult {
                    columns: vec![],
                    rows: vec![],
                    affected_rows: 0,
                    last_insert_rowid: 0,
                })
                .collect(),
        };
        let pending = self.0.pending.load(Ordering::Relaxed);
        let error = self.0.error.lock().unwrap().clone();
        Box::pin(async move {
            if pending {
                std::future::pending::<()>().await;
            }
            match error {
                Some(error) => Err(error),
                None => Ok(result),
            }
        })
    }
    fn outcome(&self, call: OutcomeCall) -> BackendFuture<Outcome> {
        assert_eq!(call.statements[0].sql, "SELECT 1");
        self.0.contexts.lock().unwrap().push(call.context);
        self.0.actions.lock().unwrap().push(call.action);
        let result = self.0.outcome.lock().unwrap().clone();
        let error = self.0.error.lock().unwrap().clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(result),
            }
        })
    }
    fn rotate(&self, call: RotateCall) -> BackendFuture<u64> {
        self.0.contexts.lock().unwrap().push(call.context);
        self.0.rotations.lock().unwrap().push(call.expected_epoch);
        let error = self.0.error.lock().unwrap().clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(call.expected_epoch + 1),
            }
        })
    }
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer token"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers
}

fn request(path: &str, body: Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::from(body.to_string()))
        .unwrap();
    *request.headers_mut() = headers();
    request
}

fn execute_body() -> Value {
    json!({"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}},{"type":"close"}]})
}

async fn decode(response: Response) -> (StatusCode, Value, HeaderMap) {
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, 100_000).await.unwrap();
    (
        parts.status,
        serde_json::from_slice(&bytes).unwrap(),
        parts.headers,
    )
}

#[test]
fn admission_validates_headers_scope_ids_and_original_deadline() {
    let environment = environment();
    let service =
        Service::with_environment(EmptyBackend, "db".into(), 1, limits(), environment.clone())
            .unwrap();
    let (context, mode) = service
        .context("other".into(), None, &headers(), true)
        .unwrap();
    assert_eq!(context.database, "other");
    assert_eq!(context.credential, "token");
    assert_eq!(mode, Mode::Write);
    assert_eq!(context.deadline, environment.now + limits().max_timeout);
    let id = "00000000000000000000000000000001";
    let mut input = headers();
    input.insert("x-scap-request-id", HeaderValue::from_static(id));
    input.insert("x-scap-mode", HeaderValue::from_static("read"));
    input.insert("x-scap-deadline-unix-ms", HeaderValue::from_static("1050"));
    let (context, mode) = service
        .context("db".into(), Some(id), &input, true)
        .unwrap();
    assert_eq!(context.request_id, 1);
    assert_eq!(context.request_epoch, 1);
    assert_eq!(
        context.deadline,
        environment.now + Duration::from_millis(50)
    );
    assert_eq!(mode, Mode::Read);
    input.insert("x-scap-mode", HeaderValue::from_static("write"));
    input.insert("x-scap-deadline-unix-ms", HeaderValue::from_static("9000"));
    assert_eq!(
        service
            .context("db".into(), None, &input, true)
            .unwrap()
            .0
            .deadline,
        environment.now + limits().max_timeout
    );
    let mut invalids = Vec::new();
    for (key, value) in [
        ("authorization", ""),
        ("authorization", "Basic token"),
        ("authorization", "Bearer "),
        ("content-type", "text/plain"),
        ("x-scap-request-id", "bad"),
        ("x-scap-request-epoch", "bad"),
        ("x-scap-request-epoch", "0"),
        ("x-scap-request-epoch", "18446744073709551616"),
        ("x-scap-mode", "stale"),
        ("x-scap-deadline-unix-ms", "bad"),
        ("x-scap-deadline-unix-ms", "1000"),
        ("x-scap-deadline-unix-ms", "999"),
    ] {
        let mut h = headers();
        h.insert(key, HeaderValue::from_str(value).unwrap());
        invalids.push(h);
    }
    let mut long = headers();
    long.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", "x".repeat(129))).unwrap(),
    );
    invalids.push(long);
    let mut absent = headers();
    absent.remove("authorization");
    invalids.push(absent);
    let mut absent = headers();
    absent.remove("content-type");
    invalids.push(absent);
    let mut duplicate = headers();
    duplicate.append("authorization", HeaderValue::from_static("Bearer token"));
    invalids.push(duplicate);
    let mut bytes = headers();
    bytes.insert("authorization", HeaderValue::from_bytes(&[0xff]).unwrap());
    invalids.push(bytes);
    for invalid in invalids {
        assert!(service.context("db".into(), None, &invalid, true).is_err());
    }
    for key in [
        "content-type",
        "x-scap-request-id",
        "x-scap-request-epoch",
        "x-scap-mode",
        "x-scap-deadline-unix-ms",
    ] {
        let mut input = headers();
        input.append(key, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(service.context("db".into(), None, &input, true).is_err());
    }
    assert!(service
        .context("/bad".into(), None, &headers(), true)
        .is_err());
    assert!(service
        .context(
            "db".into(),
            Some("00000000000000000000000000000002"),
            &input,
            true
        )
        .is_err());
    assert_eq!(
        service
            .context("db".into(), Some(id), &headers(), true)
            .unwrap()
            .0
            .request_id,
        1
    );
    service.next_id.store(u64::MAX, Ordering::Relaxed);
    assert!(service
        .context("db".into(), None, &headers(), true)
        .is_err());
    let bad_clock = Arc::new(TestEnvironment {
        now: Instant::now(),
        wall: Err(invalid("clock")),
        offset: AtomicU64::new(0),
    });
    let bad_service =
        Service::with_environment(EmptyBackend, "db".into(), 1, limits(), bad_clock).unwrap();
    assert!(bad_service
        .context("db".into(), None, &input, true)
        .is_err());
}

#[tokio::test]
async fn status_is_authenticated_bounded_and_does_not_call_sql() {
    let backend = TestBackend::new();
    let router = router(Arc::new(
        Service::new(backend.clone(), "db".into(), 1, limits()).unwrap(),
    ));
    let input = || {
        Request::builder()
            .method("GET")
            .uri("/db/db/v1/status")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap()
    };
    let (status, value, headers) = decode(router.clone().oneshot(input()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value,
        json!({"revision":u64::MAX.to_string(),"request_epoch":u64::MAX.to_string(),"retained_requests":u64::MAX.to_string(),"unacknowledged_requests":u64::MAX.to_string(),"retired_revision":u64::MAX.to_string(),"base_revision":u64::MAX.to_string(),"tail_entries":u64::MAX.to_string(),"tail_bytes":u64::MAX.to_string(),"suspended":true,"cold":true,"owner_active":false,"archived_revision":u64::MAX.to_string()})
    );
    assert_eq!(headers["cache-control"], "no-store");
    assert!(backend.0.modes.lock().unwrap().is_empty());
    assert!(backend.0.contexts.lock().unwrap()[0]
        .cancelled
        .load(Ordering::Acquire));
    let mut body = input();
    *body.body_mut() = Body::from("unexpected");
    assert_eq!(
        router.clone().oneshot(body).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut no_auth = input();
    no_auth.headers_mut().remove("authorization");
    assert_eq!(
        router.clone().oneshot(no_auth).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    *backend.0.error.lock().unwrap() = Some(ServiceError::new("UNAUTHORIZED", "denied"));
    assert_eq!(
        router.oneshot(input()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let router = super::router(Arc::new(
        Service::new(EmptyBackend, "db".into(), 1, limits()).unwrap(),
    ));
    let (_, value, _) = decode(router.oneshot(input()).await.unwrap()).await;
    assert_eq!(value["archived_revision"], Value::Null);
    assert_eq!(value["base_revision"], "0");
    assert_eq!(value["tail_entries"], "0");
    assert_eq!(value["tail_bytes"], "0");
    assert_eq!(value["request_epoch"], "1");
    assert_eq!(value["retained_requests"], "0");
    assert_eq!(value["unacknowledged_requests"], "0");
    assert_eq!(value["retired_revision"], "0");
}

#[tokio::test]
async fn actual_axum_routes_forward_only_validated_calls_and_cancel_on_completion() {
    let backend = TestBackend::new();
    let service = Arc::new(Service::new(backend.clone(), "default".into(), 1, limits()).unwrap());
    let router = router(service);
    let (status, value, headers) = decode(
        router
            .clone()
            .oneshot(request("/v2/pipeline", execute_body()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["results"][0]["response"]["type"], "execute");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["x-scap-request-id"].to_str().unwrap().len(), 32);
    assert_eq!(headers["x-scap-request-epoch"], "1");
    let mut input = request("/db/second/v2/pipeline", execute_body());
    input
        .headers_mut()
        .insert("x-scap-mode", HeaderValue::from_static("read"));
    input.headers_mut().insert(
        "x-scap-request-epoch",
        HeaderValue::from_static("18446744073709551615"),
    );
    assert_eq!(
        router.clone().oneshot(input).await.unwrap().status(),
        StatusCode::OK
    );
    let contexts = backend.0.contexts.lock().unwrap();
    assert_eq!(contexts[0].database, "default");
    assert_eq!(contexts[1].database, "second");
    assert_eq!(contexts[1].request_epoch, u64::MAX);
    assert!(contexts
        .iter()
        .all(|context| context.cancelled.load(Ordering::Acquire)));
    assert_ne!(contexts[0].request_id, contexts[1].request_id);
    assert_eq!(
        *backend.0.modes.lock().unwrap(),
        vec![Mode::Write, Mode::Read]
    );
}

#[tokio::test]
async fn outcome_is_explicit_and_requires_the_original_statements() {
    let backend = TestBackend::new();
    let router = router(Arc::new(
        Service::new(backend.clone(), "default".into(), 1, limits()).unwrap(),
    ));
    let path = "/db/db/v1/requests/00000000000000000000000000000001";
    for (action, outcome, state) in [
        ("lookup", Outcome::Unknown, "unknown"),
        (
            "resolve_or_cancel",
            Outcome::Cancelled {
                position: RequestPosition { term: 2, index: 3 },
                acknowledged: false,
            },
            "cancelled",
        ),
    ] {
        *backend.0.outcome.lock().unwrap() = outcome;
        let (status, value, _) = decode(
            router
                .clone()
                .oneshot(request(
                    path,
                    json!({"action":action,"statements":[{"sql":"SELECT 1"}]}),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["state"], state);
    }
    assert_eq!(
        *backend.0.actions.lock().unwrap(),
        vec![OutcomeAction::Lookup, OutcomeAction::ResolveOrCancel]
    );
    assert!(backend
        .0
        .contexts
        .lock()
        .unwrap()
        .iter()
        .all(|context| context.request_id == 1));
    let invalid = router
        .clone()
        .oneshot(request(path, json!({"action":"lookup","statements":[]})))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    *backend.0.error.lock().unwrap() = Some(ServiceError::new("UNAUTHORIZED", "no access"));
    let invalid = router
        .oneshot(request(
            path,
            json!({"action":"lookup","statements":[{"sql":"SELECT 1"}]}),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn acknowledgement_routes_the_original_epoch_and_terminal_proof_without_sql() {
    let backend = TestBackend::new();
    *backend.0.outcome.lock().unwrap() = Outcome::Acknowledged;
    let router = router(Arc::new(
        Service::new(backend.clone(), "db".into(), 1, limits()).unwrap(),
    ));
    let path = "/db/db/v1/requests/00000000000000000000000000000001";
    let mut input = request(
        path,
        json!({"action":"acknowledge","statements":[{"sql":"SELECT 1"}],"expected":{"state":"committed","sequence":"8"}}),
    );
    input
        .headers_mut()
        .insert("x-scap-request-epoch", HeaderValue::from_static("7"));
    let (status, value, headers) = decode(router.clone().oneshot(input).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, json!({"state":"acknowledged"}));
    assert_eq!(headers["x-scap-request-epoch"], "7");
    assert_eq!(backend.0.contexts.lock().unwrap()[0].request_epoch, 7);
    assert_eq!(
        *backend.0.actions.lock().unwrap(),
        vec![OutcomeAction::Acknowledge {
            expected: RequestTerminal::Committed { sequence: 8 }
        }]
    );
    assert!(backend.0.modes.lock().unwrap().is_empty());
    *backend.0.outcome.lock().unwrap() = Outcome::Retired { current_epoch: 8 };
    let mut input = request(
        path,
        json!({"action":"lookup","statements":[{"sql":"SELECT 1"}]}),
    );
    input
        .headers_mut()
        .insert("x-scap-request-epoch", HeaderValue::from_static("7"));
    let (_, value, headers) = decode(router.oneshot(input).await.unwrap()).await;
    assert_eq!(value, json!({"state":"retired","current_epoch":"8"}));
    assert_eq!(headers["x-scap-request-epoch"], "7");
}

#[tokio::test]
async fn rotation_is_explicit_matches_the_original_epoch_and_propagates_backend_denials() {
    let backend = TestBackend::new();
    let router = router(Arc::new(
        Service::new(backend.clone(), "db".into(), 1, limits()).unwrap(),
    ));
    let path = "/db/db/v1/request-epoch";
    let input = || {
        let mut input = request(path, json!({"action":"rotate","expected_epoch":"7"}));
        input
            .headers_mut()
            .insert("x-scap-request-epoch", HeaderValue::from_static("7"));
        input
    };
    let (status, value, headers) = decode(router.clone().oneshot(input()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, json!({"state":"rotated","request_epoch":"8"}));
    assert_eq!(headers["x-scap-request-epoch"], "7");
    assert_eq!(*backend.0.rotations.lock().unwrap(), vec![7]);
    assert_eq!(backend.0.contexts.lock().unwrap()[0].request_epoch, 7);
    assert!(backend.0.contexts.lock().unwrap()[0]
        .cancelled
        .load(Ordering::Acquire));
    assert!(backend.0.modes.lock().unwrap().is_empty());
    assert!(backend.0.actions.lock().unwrap().is_empty());
    let mismatch = request(path, json!({"action":"rotate","expected_epoch":"7"}));
    assert_eq!(
        router.clone().oneshot(mismatch).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let malformed = request(path, json!({"action":"lookup","expected_epoch":"1"}));
    assert_eq!(
        router.clone().oneshot(malformed).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(backend.0.rotations.lock().unwrap().len(), 1);
    *backend.0.error.lock().unwrap() = Some(ServiceError::new("UNAUTHORIZED", "admin required"));
    assert_eq!(
        router.oneshot(input()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let router = super::router(Arc::new(
        Service::new(EmptyBackend, "db".into(), 1, limits()).unwrap(),
    ));
    let (_, value, _) = decode(
        router
            .oneshot(request(
                path,
                json!({"action":"rotate","expected_epoch":"1"}),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(value["request_epoch"], "2");
}

#[tokio::test]
async fn malformed_and_oversized_requests_have_no_sql_effects() {
    let backend = TestBackend::new();
    let service = Arc::new(Service::new(backend.clone(), "default".into(), 1, limits()).unwrap());
    let router = router(service.clone());
    let mut no_auth = request("/v2/pipeline", execute_body());
    no_auth.headers_mut().remove("authorization");
    assert_eq!(
        router.clone().oneshot(no_auth).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    for body in ["bad json".to_owned(), "x".repeat(4097)] {
        let mut input = request("/v2/pipeline", execute_body());
        *input.body_mut() = Body::from(body);
        assert_eq!(
            router.clone().oneshot(input).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        router
            .clone()
            .oneshot(request(
                "/v2/pipeline",
                json!({"baton":"old","requests":[]})
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let _first = service.permits.acquire().await.unwrap();
    let _second = service.permits.acquire().await.unwrap();
    assert_eq!(
        router
            .oneshot(request("/v2/pipeline", execute_body()))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(backend.0.contexts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn timed_out_and_abandoned_requests_cancel_without_retry() {
    let backend = TestBackend::new();
    backend.0.pending.store(true, Ordering::Relaxed);
    let mut limits = limits();
    limits.max_timeout = Duration::from_millis(5);
    let router = router(Arc::new(
        Service::new(backend.clone(), "db".into(), 1, limits).unwrap(),
    ));
    let (status, value, _) = decode(
        router
            .oneshot(request("/v2/pipeline", execute_body()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(value["code"], "COMMIT_UNKNOWN");
    assert_eq!(backend.0.contexts.lock().unwrap().len(), 1);
    assert!(backend.0.contexts.lock().unwrap()[0]
        .cancelled
        .load(Ordering::Acquire));
    let backend = TestBackend::new();
    backend.0.pending.store(true, Ordering::Relaxed);
    let router = super::router(Arc::new(
        Service::new(backend.clone(), "db".into(), 1, crate::tests::limits()).unwrap(),
    ));
    let running = tokio::spawn(async move {
        router
            .oneshot(request("/v2/pipeline", execute_body()))
            .await
    });
    while backend.0.contexts.lock().unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
    running.abort();
    let _ = running.await;
    assert!(backend.0.contexts.lock().unwrap()[0]
        .cancelled
        .load(Ordering::Acquire));
}

#[tokio::test]
async fn absolute_deadline_is_rechecked_after_a_completed_backend_future() {
    let environment = environment();
    let mut backend = TestBackend::new();
    Arc::get_mut(&mut backend.0).unwrap().advance = Some(environment.clone());
    let router = router(Arc::new(
        Service::with_environment(backend, "db".into(), 1, limits(), environment).unwrap(),
    ));
    let (status, value, _) = decode(
        router
            .oneshot(request("/v2/pipeline", execute_body()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(value["code"], "COMMIT_UNKNOWN");
}

#[tokio::test]
async fn response_limits_and_error_codes_never_claim_a_rollback() {
    let response = bounded_response(json!({"large":"x".repeat(100)}), (1, 4), 10);
    let (status, value, _) = decode(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value["code"], "COMMITTED_RESULT_UNAVAILABLE");
    for (code, status) in [
        ("UNAUTHORIZED", 401),
        ("INVALID_REQUEST", 400),
        ("UNSUPPORTED_FEATURE", 400),
        ("EXPIRED", 408),
        ("COMMIT_UNKNOWN", 504),
        ("NOT_LEADER", 503),
        ("OVERLOADED", 503),
        ("COMMITTED_RESULT_UNAVAILABLE", 503),
        ("SQL_ERROR", 422),
    ] {
        let (actual, value, headers) =
            decode(error_response(ServiceError::new(code, "message"), None)).await;
        assert_eq!(actual.as_u16(), status);
        assert_eq!(value["code"], code);
        assert!(!headers.contains_key("x-scap-request-id"));
    }
    let backend = TestBackend::new();
    *backend.0.error.lock().unwrap() = Some(ServiceError::new("COMMIT_UNKNOWN", "unknown"));
    let router = router(Arc::new(
        Service::new(backend, "db".into(), 1, limits()).unwrap(),
    ));
    let (status, value, _) = decode(
        router
            .oneshot(request("/v2/pipeline", execute_body()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["results"][0]["error"]["code"], "COMMIT_UNKNOWN");
}
