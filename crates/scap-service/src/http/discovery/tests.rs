use super::*;
use crate::discovery::tests::{codec, discovery, seed};
use crate::http::tests::{decoded, runtime, state};
use crate::tests::{principal, Memory};
use axum::http::{HeaderValue, Method};
use tower::ServiceExt;

fn request(operation: &str) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/discovery")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("content-type", "application/json")
        .header("x-scap-admission", "discovery")
        .body(Body::from(
            json!({"version":1,"operation":operation,"cursor":null}).to_string(),
        ))
        .unwrap()
}
fn enabled() -> Arc<HttpState> {
    let memory = Arc::new(Memory::default());
    seed(memory.clone(), 2, 1);
    let mut state = state();
    Arc::get_mut(&mut state).unwrap().discovery = Some(discovery(memory));
    state
}

#[test]
fn enabled_discovery_is_authenticated_and_has_independent_bounded_response_lifetime() {
    runtime().block_on(async {
        assert_eq!(
            decoded(
                router(state())
                    .unwrap()
                    .oneshot(request("list_names"))
                    .await
                    .unwrap()
            )
            .await["error"]["code"],
            "UNAVAILABLE"
        );
        let state = enabled();
        let app = router(state.clone()).unwrap();
        let scan = state.discovery.as_ref().unwrap();
        let held = scan.admission.acquire(&principal()).unwrap();
        let mut unauth = request("list_names");
        unauth.headers_mut().remove("authorization");
        assert_eq!(
            decoded(app.clone().oneshot(unauth).await.unwrap()).await["error"]["code"],
            "UNAUTHENTICATED"
        );
        assert_eq!(
            decoded(app.clone().oneshot(request("list_names")).await.unwrap()).await["error"]
                ["code"],
            "BACKPRESSURE"
        );
        drop(held);
        let data = state.intake.acquire(&principal()).unwrap();
        let control = state.control_intake.acquire(&principal()).unwrap();
        let recovery = state.recovery_intake.acquire(&principal()).unwrap();
        let response = app.clone().oneshot(request("list_names")).await.unwrap();
        assert!(scan.admission.acquire(&principal()).is_err());
        assert_eq!(
            decoded(response).await["value"]["names"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        drop(scan.admission.acquire(&principal()).unwrap());
        drop((data, control, recovery));
        assert_eq!(
            decoded(
                app.clone()
                    .oneshot(request("deployment_inventory"))
                    .await
                    .unwrap()
            )
            .await["error"]["code"],
            "DENIED"
        );
        for mode in 0..4 {
            let mut req = request("list_names");
            match mode {
                0 => {
                    req.headers_mut().remove("x-scap-admission");
                }
                1 => {
                    req.headers_mut()
                        .insert("x-scap-admission", HeaderValue::from_static("catalogue"));
                }
                2 => {
                    req.headers_mut()
                        .append("x-scap-admission", HeaderValue::from_static("discovery"));
                }
                _ => {
                    req.headers_mut().remove("content-type");
                }
            }
            assert_eq!(
                decoded(app.clone().oneshot(req).await.unwrap()).await["error"]["code"],
                "INVALID"
            );
        }
        for (body, code) in [
            ("broken".into(), "INVALID"),
            ("x".repeat(scan::MAX_BODY_BYTES + 1), "LIMIT"),
            (
                json!({"version":2,"operation":"list_names","cursor":null}).to_string(),
                "VERSION",
            ),
            (
                json!({"version":1,"operation":"list_names","cursor":"tampered"}).to_string(),
                "CURSOR_INVALID",
            ),
        ] {
            let mut req = request("list_names");
            *req.body_mut() = Body::from(body);
            assert_eq!(
                decoded(app.clone().oneshot(req).await.unwrap()).await["error"]["code"],
                code
            );
        }
    });
}

#[test]
fn blocking_panic_and_expired_body_are_explicit_failures_without_leaked_admission() {
    struct PanicList;
    impl scap_object_store::Listings for PanicList {
        fn list_page(
            &self,
            _: &scap_object_store::ListRequest<'_>,
            _: Instant,
        ) -> Result<scap_object_store::ListPage, scap_object_store::ListError> {
            panic!("injected discovery task loss")
        }
    }
    let discovery = Arc::new(
        scan::Discovery::new(
            Arc::new(Memory::default()),
            Arc::new(PanicList),
            100,
            codec(),
        )
        .unwrap(),
    );
    runtime().block_on(async {
        let reservation = discovery.admission.acquire(&principal()).unwrap();
        let result = admitted(
            discovery.clone(),
            principal(),
            reservation,
            Instant::now() + scan::TIMEOUT,
            request("list_names"),
        )
        .await;
        assert_eq!(decoded(result).await["error"]["code"], "UNAVAILABLE");
        let reservation = discovery.admission.acquire(&principal()).unwrap();
        let mut req = request("list_names");
        *req.body_mut() = Body::new(crate::http::tests::PendingBody);
        assert_eq!(
            decoded(
                admitted(
                    discovery.clone(),
                    principal(),
                    reservation,
                    Instant::now() + Duration::from_millis(1),
                    req
                )
                .await
            )
            .await["error"]["code"],
            "DEADLINE"
        );
        drop(discovery.admission.acquire(&principal()).unwrap());
    });
}

#[test]
fn timed_out_request_retains_its_scan_slot_until_the_plain_worker_finishes() {
    use std::sync::{mpsc, Mutex};
    struct SlowList {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl scap_object_store::Listings for SlowList {
        fn list_page(
            &self,
            _: &scap_object_store::ListRequest<'_>,
            _: Instant,
        ) -> Result<scap_object_store::ListPage, scap_object_store::ListError> {
            assert!(tokio::runtime::Handle::try_current().is_err());
            // Deliberately ignore the earlier read deadline to prove that the
            // outer HTTP timeout cannot release a still-running port call.
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Ok(scap_object_store::ListPage {
                entries: vec![],
                end: scap_object_store::ListEnd::Exhausted,
                response_bytes: 128,
            })
        }
    }
    let (entered, started) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let d = Arc::new(
        scan::Discovery::new(
            Arc::new(Memory::default()),
            Arc::new(SlowList {
                entered,
                release: Mutex::new(held),
            }),
            100,
            codec(),
        )
        .unwrap(),
    );
    runtime().block_on(async {
        let lease = d.admission.acquire(&principal()).unwrap();
        let response = admitted(
            d.clone(),
            principal(),
            lease,
            Instant::now() + Duration::from_secs(2),
            request("list_names"),
        )
        .await;
        assert_eq!(decoded(response).await["error"]["code"], "DEADLINE");
        started.try_recv().unwrap();
        assert_eq!(
            d.admission.acquire(&principal()).err().unwrap().code,
            "BACKPRESSURE"
        );
        release.send(()).unwrap();
    });
    drop(d);
}

#[test]
fn invalid_worker_reservation_is_reported_without_touching_the_backend() {
    let memory = Arc::new(Memory::default());
    let d = discovery(memory.clone());
    let unrelated = scan::Admission::default().acquire(&principal()).unwrap();
    runtime().block_on(async {
        let response = admitted(
            d,
            principal(),
            unrelated,
            Instant::now() + Duration::from_secs(1),
            request("list_names"),
        )
        .await;
        assert_eq!(decoded(response).await["error"]["code"], "INVALID");
    });
    assert!(memory.calls.lock().unwrap().is_empty());
}
