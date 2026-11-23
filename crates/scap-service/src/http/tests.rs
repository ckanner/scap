use super::*;
use crate::auth::Credential;
use crate::scheduler::{Factory, Limits, Worker};
use crate::tests::principal;
use crate::wire::{Call, Decimal};
use axum::http::{HeaderValue, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tower::ServiceExt;

struct Echo;
impl Worker for Echo {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        match call.scope.database.0 {
            8 => Err(Failure::new("DENIED")),
            9 => panic!("unit worker response loss"),
            10 => {
                std::thread::sleep(Duration::from_millis(50));
                Ok(json!("late"))
            }
            _ => Ok(json!({"served":call.action.admission()})),
        }
    }

    fn execute_budgeted(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        _: &mut crate::output::OutputContext,
    ) -> Result<Value, Failure> {
        // This fixture only creates fixed small scalar/status values.
        self.execute(principal, call, deadline)
    }
}
pub(super) fn state() -> Arc<HttpState> {
    let token = "a".repeat(32);
    let auth = Authenticator::new(vec![Credential {
        sha256: format!("{:x}", Sha256::digest(&token)),
        deployment: Decimal(1),
        tenant: Decimal(2),
        principal: Decimal(3),
        provision: true,
        deployment_inventory: false,
    }])
    .unwrap();
    let factory: Factory = Arc::new(|_| Ok(Box::new(Echo)));
    let scheduler = Arc::new(
        Scheduler::new(
            Limits {
                active_database_actors: 4,
                active_database_actors_per_tenant: 4,
                actor_idle_timeout: Duration::from_secs(60),
                control_workers: 1,
                queued_total: 8,
                queued_per_tenant: 6,
                queued_per_database: 4,
                reserved_controls: 1,
            },
            factory,
        )
        .unwrap(),
    );
    Arc::new(HttpState {
        resource_diagnostics: false,
        auth,
        scheduler,
        output: Arc::new(crate::output::Pool::new(crate::output::Profile::default()).unwrap()),
        catalogue: None,
        restore: None,
        discovery: None,
        max_body_bytes: 4096,
        timeout: Duration::from_millis(500),
        recovery_timeout: Duration::from_secs(2),
        intake: Arc::new(Intake::new(Class::Data, 1, 4096, None).unwrap()),
        control_intake: Arc::new(Intake::new(Class::Control, 1, 4096, None).unwrap()),
        recovery_intake: Arc::new(Intake::new(Class::Recovery, 1, 4096, None).unwrap()),
    })
}
pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn body(operation: &str, database: u64) -> String {
    let mut value = json!({"version":1,"scope":{"deployment":"1","tenant":"2","database":database.to_string(),"incarnation":"1","generation":"1"},"operation":operation});
    if operation == "query" {
        value["statements"] = json!([]);
    }
    value.to_string()
}
pub(super) fn request(operation: &str, database: u64) -> Request {
    let class = match operation {
        "open" | "activate" => "recovery",
        "query" | "execute" | "create" => "data",
        _ => "control",
    };
    Request::builder()
        .method(Method::POST)
        .uri("/v1")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("content-type", "application/json")
        .header("x-scap-admission", class)
        .body(Body::from(body(operation, database)))
        .unwrap()
}
pub(super) async fn decoded(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 100000).await.unwrap()).unwrap()
}

#[test]
fn diagnostics_are_opt_in_after_authentication_and_do_not_change_error_envelopes() {
    for enabled in [false, true] {
        let mut state = state();
        Arc::get_mut(&mut state).unwrap().resource_diagnostics = enabled;
        let app = router(state.clone()).unwrap();
        runtime().block_on(async {
            let held = state.intake.acquire(&principal()).unwrap();
            let mut unauthenticated = request("query", 3);
            unauthenticated.headers_mut().remove("authorization");
            let response = app.clone().oneshot(unauthenticated).await.unwrap();
            assert!(!response.headers().contains_key(rejection::HEADER));
            assert_eq!(decoded(response).await["error"]["code"], "UNAUTHENTICATED");
            let mut invalid = request("query", 3);
            invalid
                .headers_mut()
                .insert("x-scap-admission", HeaderValue::from_static("invalid"));
            let response = app.clone().oneshot(invalid).await.unwrap();
            assert!(!response.headers().contains_key(rejection::HEADER));
            assert_eq!(decoded(response).await["error"]["code"], "INVALID");
            let mut admitted_identity = request("query", 3);
            *admitted_identity.body_mut() = Body::from("not parsed at this gate");
            let response = app.clone().oneshot(admitted_identity).await.unwrap();
            drop(held);
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response
                    .headers()
                    .get(rejection::HEADER)
                    .map(|header| header.to_str().unwrap()),
                if enabled {
                    Some("v=1;reason=intake_data_requests_global;used=1;limit=1;requested=1")
                } else {
                    None
                }
            );
            assert!(response.extensions().get::<Rejection>().is_none());
            assert_eq!(
                decoded(response).await,
                wire::failed(&Failure::new("BACKPRESSURE"))
            );
            let response = app.clone().oneshot(request("query", 3)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response.headers().contains_key(rejection::HEADER));
            drop(response);
            let mut invalid = request("query", 3);
            *invalid.body_mut() = Body::from("invalid JSON");
            let response = app.clone().oneshot(invalid).await.unwrap();
            assert!(!response.headers().contains_key(rejection::HEADER));
            assert_eq!(decoded(response).await["error"]["code"], "INVALID");
        });
    }
}

#[test]
fn authentication_precedes_intake_and_headers_are_unambiguous() {
    let state = state();
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(decoded(health).await["status"], "alive");
        let permit = state.intake.acquire(&principal()).unwrap();
        for mode in 0..3 {
            let mut req = request("query", 3);
            match mode {
                0 => {
                    req.headers_mut().remove("authorization");
                }
                1 => {
                    req.headers_mut().append(
                        "authorization",
                        HeaderValue::from_static("Bearer duplicate"),
                    );
                }
                _ => {
                    req.headers_mut()
                        .insert("authorization", HeaderValue::from_bytes(&[255]).unwrap());
                }
            }
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(decoded(response).await["error"]["code"], "UNAUTHENTICATED");
        }
        assert_eq!(
            app.clone()
                .oneshot(request("query", 3))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Reserved control intake remains usable while all data permits are held.
        assert_eq!(
            decoded(app.clone().oneshot(request("status", 3)).await.unwrap()).await["value"]
                ["served"],
            "control"
        );
        drop(permit);
        for mode in 0..5 {
            let mut req = request("query", 3);
            match mode {
                0 => {
                    req.headers_mut()
                        .insert("x-scap-admission", HeaderValue::from_static("bad"));
                }
                1 => {
                    req.headers_mut()
                        .append("x-scap-admission", HeaderValue::from_static("data"));
                }
                2 => {
                    req.headers_mut().remove("content-type");
                }
                3 => {
                    req.headers_mut()
                        .append("content-type", HeaderValue::from_static("application/json"));
                }
                _ => {
                    req.headers_mut()
                        .insert("x-scap-admission", HeaderValue::from_static("control"));
                }
            }
            assert_eq!(
                decoded(app.clone().oneshot(req).await.unwrap()).await["error"]["code"],
                "INVALID"
            );
        }
        let mut req = request("query", 3);
        req.headers_mut().remove("x-scap-admission");
        assert_eq!(
            decoded(app.clone().oneshot(req).await.unwrap()).await["value"]["served"],
            "data"
        );
        let permit = state.recovery_intake.acquire(&principal()).unwrap();
        assert_eq!(
            app.clone()
                .oneshot(request("open", 3))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(permit);
        assert_eq!(
            decoded(app.clone().oneshot(request("open", 3)).await.unwrap()).await["value"]
                ["served"],
            "recovery"
        );
    });
}

#[test]
fn complete_response_body_keeps_its_intake_reservation_until_consumed_or_dropped() {
    runtime().block_on(async {
        for consume in [true, false] {
            let state = state();
            let slots = state.intake.clone();
            let app = router(state.clone()).unwrap();
            let response = app.clone().oneshot(request("query", 3)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(slots.available_permits(), 0);
            assert_eq!(
                app.clone()
                    .oneshot(request("query", 3))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::TOO_MANY_REQUESTS
            );
            // Sending a reply can wake HTTP before the Job drops its lease.
            // Join actual workers while the complete response is still owned.
            drop(app);
            drop(state);
            assert_eq!(slots.available_permits(), 0);
            if consume {
                assert_eq!(decoded(response).await["ok"], true);
            } else {
                drop(response);
            }
            assert_eq!(slots.available_permits(), 1);
        }
        let slots = Arc::new(Intake::new(Class::Data, 1, 4096, None).unwrap());
        let permit = slots.acquire(&principal()).unwrap();
        let mut body = ReservedBody {
            inner: Body::from("abc"),
            reservation: Arc::new(permit),
        };
        assert_eq!(body.size_hint().exact(), Some(3));
        assert!(!body.is_end_stream());
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.into_data().unwrap(), "abc");
        assert!(body.is_end_stream());
        assert!(
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                .await
                .is_none()
        );
    });
}

#[test]
fn outgoing_response_bytes_keep_each_admission_reserved_after_body_drop() {
    runtime().block_on(async {
        for operation in ["query", "status", "open"] {
            let state = state();
            let slots = match operation {
                "query" => state.intake.clone(),
                "status" => state.control_intake.clone(),
                _ => state.recovery_intake.clone(),
            };
            let app = router(state.clone()).unwrap();
            let response = app.clone().oneshot(request(operation, 3)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = response.into_body();
            let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                .await
                .unwrap()
                .unwrap();
            let bytes = frame.into_data().unwrap();
            assert!(body.is_end_stream());
            // Hyper may drop the body immediately after this last frame while
            // retaining the frame bytes in a connection's pending write queue.
            drop(body);
            let cloned = bytes.clone();
            let sliced = bytes.slice(1..bytes.len() - 1);
            drop(bytes);
            assert_eq!(slots.available_permits(), 0);
            assert_eq!(
                app.clone()
                    .oneshot(request(operation, 3))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::TOO_MANY_REQUESTS
            );
            // Leave only the response-byte owners before checking the final
            // refund; a received reply alone does not prove Job destruction.
            drop(app);
            drop(state);
            assert_eq!(slots.available_permits(), 0);
            drop(cloned);
            assert_eq!(slots.available_permits(), 0);
            drop(sliced);
            assert_eq!(slots.available_permits(), 1);
        }
    });
}

type FrameState = Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>>;

struct FrameBody(std::collections::VecDeque<FrameState>);

impl HttpBody for FrameBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0.pop_front().unwrap_or(Poll::Ready(None))
    }
}

#[test]
fn reservations_preserve_pending_empty_data_trailer_and_end_frames_without_copying() {
    use http_body::Frame;
    let slots = Arc::new(Semaphore::new(1));
    let first = Bytes::from(vec![0, 1, 2, 255]);
    let second = Bytes::from(vec![3, 4, 5, 254]);
    let pointers = [first.as_ptr(), second.as_ptr()];
    let mut trailers = HeaderMap::new();
    trailers.insert("x-scap-test", HeaderValue::from_static("unchanged"));
    let mut body = ReservedBody {
        inner: Body::new(FrameBody(
            [
                Poll::Pending,
                Poll::Ready(Some(Ok(Frame::data(Bytes::new())))),
                Poll::Ready(Some(Ok(Frame::data(first)))),
                Poll::Ready(Some(Ok(Frame::data(second)))),
                Poll::Ready(Some(Ok(Frame::trailers(trailers.clone())))),
            ]
            .into(),
        )),
        reservation: Arc::new(slots.clone().try_acquire_owned().unwrap()),
    };
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(Pin::new(&mut body).poll_frame(&mut context).is_pending());
    assert_eq!(slots.available_permits(), 0);
    let mut data = Vec::new();
    for _ in 0..3 {
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut context) else {
            panic!("expected an unchanged data frame");
        };
        data.push(frame.into_data().unwrap());
    }
    assert!(data[0].is_empty());
    assert_eq!(&data[1][..], &[0, 1, 2, 255]);
    assert_eq!(&data[2][..], &[3, 4, 5, 254]);
    assert_eq!([data[1].as_ptr(), data[2].as_ptr()], pointers);
    let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut context) else {
        panic!("expected unchanged trailers");
    };
    assert_eq!(frame.into_trailers().unwrap(), trailers);
    assert!(matches!(
        Pin::new(&mut body).poll_frame(&mut context),
        Poll::Ready(None)
    ));
    drop(body);
    assert_eq!(slots.available_permits(), 0);
    drop(data.pop());
    assert_eq!(slots.available_permits(), 0);
    drop(data.pop());
    assert_eq!(slots.available_permits(), 0);
    drop(data);
    assert_eq!(slots.available_permits(), 1);
}

#[test]
fn response_error_preserves_emitted_bytes_and_releases_unemitted_reservations() {
    use http_body::Frame;
    let slots = Arc::new(Semaphore::new(1));
    let mut body = ReservedBody {
        inner: Body::new(FrameBody(
            [
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"partial"))))),
                Poll::Ready(Some(Err(std::io::Error::other("injected body failure")))),
            ]
            .into(),
        )),
        reservation: Arc::new(slots.clone().try_acquire_owned().unwrap()),
    };
    let mut context = Context::from_waker(std::task::Waker::noop());
    let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut context) else {
        panic!("expected data before the failure");
    };
    let bytes = frame.into_data().unwrap();
    let Poll::Ready(Some(Err(error))) = Pin::new(&mut body).poll_frame(&mut context) else {
        panic!("expected the original body error");
    };
    assert_eq!(error.to_string(), "injected body failure");
    drop(body);
    assert_eq!(&bytes[..], b"partial");
    assert_eq!(slots.available_permits(), 0);
    drop(bytes);
    assert_eq!(slots.available_permits(), 1);

    let body = ReservedBody {
        inner: Body::from(vec![42; 1024]),
        reservation: Arc::new(slots.clone().try_acquire_owned().unwrap()),
    };
    assert_eq!(slots.available_permits(), 0);
    drop(body);
    assert_eq!(slots.available_permits(), 1);
}

#[test]
fn parse_and_worker_failures_preserve_error_codes_without_retry() {
    let state = state();
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        for bytes in [
            "not json".to_owned(),
            "a".repeat(4097),
            body("query", 3).replace("\"version\":1", "\"version\":2"),
        ] {
            let mut req = request("query", 3);
            *req.body_mut() = Body::from(bytes);
            assert_eq!(
                decoded(app.clone().oneshot(req).await.unwrap()).await["ok"],
                false
            );
        }
        let mut req = request("status", 3);
        *req.body_mut() =
            Body::from(body("status", 3).replace("\"tenant\":\"2\"", "\"tenant\":\"4\""));
        assert_eq!(
            decoded(app.clone().oneshot(req).await.unwrap()).await["error"]["code"],
            "DENIED"
        );
        assert_eq!(
            decoded(app.clone().oneshot(request("status", 8)).await.unwrap()).await["error"]
                ["code"],
            "DENIED"
        );
        drop(app);
        drop(state);
        let state = self::state();
        let app = router(state.clone()).unwrap();
        assert_eq!(
            decoded(app.clone().oneshot(request("status", 9)).await.unwrap()).await["error"]
                ["code"],
            "UNKNOWN"
        );
        // A panicking Job drops its sender before its lease and the control
        // lane's exit guard. An unreserved queued job observes that guard's
        // closure without borrowing the still-releasing HTTP intake slot.
        let barrier = state.scheduler.submit(
            principal(),
            wire::parse(body("status", 3).as_bytes()).unwrap(),
            crate::tests::until(),
        );
        let unavailable = match barrier {
            Ok(receiver) => receiver.await.unwrap().unwrap_err(),
            Err(error) => error,
        };
        assert_eq!(unavailable.code, "UNAVAILABLE");
        assert_eq!(
            decoded(app.clone().oneshot(request("status", 3)).await.unwrap()).await["error"]
                ["code"],
            "UNAVAILABLE"
        );
    });
}

pub(super) struct PendingBody;
impl HttpBody for PendingBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Poll::Pending
    }
}

#[test]
fn body_and_response_timeouts_use_one_original_deadline_and_never_claim_rollback() {
    let mut state = state();
    Arc::get_mut(&mut state).unwrap().timeout = Duration::from_millis(20);
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        let mut req = request("query", 3);
        *req.body_mut() = Body::new(PendingBody);
        assert_eq!(
            decoded(app.clone().oneshot(req).await.unwrap()).await["error"]["code"],
            "DEADLINE"
        );
        // A separate entered/release handshake proves UNKNOWN only after
        // the worker has actually started; upload expiry is DEADLINE.
        // An explicit recovery may outlive the ordinary deadline; it must use
        // the separate configured budget from the same receive instant.
        assert_eq!(
            decoded(app.oneshot(request("open", 10)).await.unwrap()).await["value"],
            "late"
        );
    });
}

#[test]
fn invalid_state_is_rejected_and_all_failure_classes_have_stable_statuses() {
    for set in [
        |s: &mut HttpState| s.max_body_bytes = 0,
        |s: &mut HttpState| s.timeout = Duration::ZERO,
        |s: &mut HttpState| s.timeout = Duration::from_secs(86401),
        |s: &mut HttpState| s.recovery_timeout = Duration::ZERO,
        |s: &mut HttpState| s.recovery_timeout = Duration::from_secs(604801),
        |s: &mut HttpState| {
            s.intake = Arc::new(Intake::new(Class::Catalogue, 1, 4096, None).unwrap())
        },
        |s: &mut HttpState| {
            s.control_intake = Arc::new(Intake::new(Class::Catalogue, 1, 4096, None).unwrap())
        },
        |s: &mut HttpState| {
            s.recovery_intake = Arc::new(Intake::new(Class::Catalogue, 1, 4096, None).unwrap())
        },
    ] {
        let mut value = state();
        set(Arc::get_mut(&mut value).unwrap());
        assert!(router(value).is_err());
    }
    for (code, status) in [
        ("UNAUTHENTICATED", 401),
        ("DENIED", 403),
        ("NOT_FOUND", 404),
        ("INVALID", 400),
        ("VERSION", 400),
        ("LIMIT", 413),
        ("BACKPRESSURE", 429),
        ("RECOVERY_BUSY", 429),
        ("UNKNOWN", 503),
        ("UNAVAILABLE", 503),
        ("DEADLINE", 503),
        ("COMMITTED_BUT_UNAVAILABLE", 503),
        ("CONFLICT", 409),
    ] {
        assert_eq!(failure(Failure::new(code)).status().as_u16(), status);
    }
}

#[test]
fn parsing_cannot_extend_an_expired_upload_budget_into_recovery() {
    let bytes = body("open", 3);
    assert_eq!(
        parse_before(bytes.as_bytes(), Instant::now())
            .unwrap_err()
            .code,
        "DEADLINE"
    );
    assert_eq!(
        parse_before(bytes.as_bytes(), Instant::now() + Duration::from_secs(1))
            .unwrap()
            .action
            .admission(),
        "recovery"
    );
    assert_eq!(
        parse_before(b"malformed", Instant::now() + Duration::from_secs(1))
            .unwrap_err()
            .code,
        "INVALID"
    );
}

#[test]
fn maintenance_requests_cannot_claim_the_wrong_intake_class() {
    let state = state();
    let app = router(state).unwrap();
    runtime().block_on(async {
        for (operation, fields, class) in [
            (
                "compact_begin",
                json!({"expected_head_serial":"1"}),
                "control",
            ),
            ("compact_copy", json!({"plan_serial":"2"}), "recovery"),
            ("compact_promote", json!({"plan_serial":"2"}), "control"),
            ("compact_abort", json!({"plan_serial":"2"}), "control"),
            (
                "gc_prepare",
                json!({"expected_head_serial":"3","generation":"1","after":null}),
                "recovery",
            ),
            ("gc_resume", json!({"batch_serial":"4"}), "recovery"),
        ] {
            let mut value: Value = serde_json::from_str(&body(operation, 3)).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            for supplied in [class, "data"] {
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("/v1")
                    .header("authorization", format!("Bearer {}", "a".repeat(32)))
                    .header("content-type", "application/json")
                    .header("x-scap-admission", supplied)
                    .body(Body::from(value.to_string()))
                    .unwrap();
                let response = app.clone().oneshot(request).await.unwrap();
                if supplied == class {
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(decoded(response).await["value"]["served"], class);
                } else {
                    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                    assert_eq!(decoded(response).await["error"]["code"], "INVALID");
                }
            }
        }
    });
}
