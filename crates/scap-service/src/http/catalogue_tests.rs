use super::tests::{decoded, request, runtime, state, PendingBody};
use super::*;
use crate::catalogue_scheduler::{Factory, Limits, Scheduler, Worker};
use crate::catalogue_wire::Call;
use axum::http::{HeaderValue, Method};
use serde_json::Value;
use tower::ServiceExt;

struct Echo;
impl Worker for Echo {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        match call.action.name() {
            Some("denied") => Err(Failure::new("DENIED")),
            Some("panic") => panic!("injected directory loss"),
            Some("late") => {
                std::thread::sleep(Duration::from_millis(30));
                Ok(json!("late"))
            }
            _ => Ok(json!({"name":call.action.name()})),
        }
    }
}
fn enabled() -> Arc<HttpState> {
    let mut state = state();
    let factory: Factory = Arc::new(|_| Ok(Box::new(Echo)));
    Arc::get_mut(&mut state).unwrap().catalogue = Some(CatalogueState {
        scheduler: Arc::new(
            Scheduler::new(
                Limits {
                    workers: 1,
                    queued_total: 4,
                    queued_per_tenant: 3,
                    queued_per_name: 2,
                },
                factory,
            )
            .unwrap(),
        ),
        max_body_bytes: 2048,
        timeout: Duration::from_millis(500),
        intake: Arc::new(Semaphore::new(1)),
    });
    state
}
fn directory(name: &str) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/catalogue")
        .header("authorization", format!("Bearer {}", "a".repeat(32)))
        .header("content-type", "application/json")
        .header("x-scap-admission", "catalogue")
        .body(Body::from(
            json!({"version":1,"operation":"resolve_name","name":name}).to_string(),
        ))
        .unwrap()
}

#[test]
fn catalogue_is_explicitly_enabled_authenticated_and_never_borrows_database_capacity() {
    runtime().block_on(async {
        let app = router(state()).unwrap();
        assert_eq!(
            decoded(app.oneshot(directory("x")).await.unwrap()).await["error"]["code"],
            "UNAVAILABLE"
        );
        let state = enabled();
        let app = router(state.clone()).unwrap();
        let slots = state.catalogue.as_ref().unwrap().intake.clone();
        let permit = slots.clone().try_acquire_owned().unwrap();
        let mut unauth = directory("x");
        unauth.headers_mut().remove("authorization");
        assert_eq!(
            decoded(app.clone().oneshot(unauth).await.unwrap()).await["error"]["code"],
            "UNAUTHENTICATED"
        );
        assert_eq!(
            decoded(app.clone().oneshot(directory("x")).await.unwrap()).await["error"]["code"],
            "BACKPRESSURE"
        );
        for (operation, class) in [
            ("query", "data"),
            ("status", "control"),
            ("open", "recovery"),
        ] {
            assert_eq!(
                decoded(app.clone().oneshot(request(operation, 3)).await.unwrap()).await["value"]
                    ["served"],
                class
            );
        }
        drop(permit);
        let data = state.intake.clone().try_acquire_owned().unwrap();
        let control = state.control_intake.clone().try_acquire_owned().unwrap();
        let recovery = state.recovery_intake.clone().try_acquire_owned().unwrap();
        let response = app.clone().oneshot(directory("exact É")).await.unwrap();
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(decoded(response).await["value"]["name"], "exact É");
        assert_eq!(slots.available_permits(), 1);
        drop((data, control, recovery));
        for mode in 0..4 {
            let mut req = directory("x");
            match mode {
                0 => {
                    req.headers_mut().remove("x-scap-admission");
                }
                1 => {
                    req.headers_mut()
                        .insert("x-scap-admission", HeaderValue::from_static("control"));
                }
                2 => {
                    req.headers_mut()
                        .append("x-scap-admission", HeaderValue::from_static("catalogue"));
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
    });
}

#[test]
fn malformed_denied_lost_and_expired_directory_responses_keep_their_exact_semantics() {
    let state = enabled();
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        for (body,code) in [("broken".to_owned(),"INVALID"),("x".repeat(2049),"LIMIT"),(json!({"version":2,"operation":"resolve_name","name":"x"}).to_string(),"VERSION"),
            (json!({"version":1,"operation":"resume_create","creation":{"creator":"9","operation":"1","name":"x","scope":{"deployment":"1","tenant":"2","database":"3","incarnation":"4","generation":"5"},"expected_name_revision":null}}).to_string(),"DENIED")] {
            let mut req=directory("x");*req.body_mut()=Body::from(body);
            assert_eq!(decoded(app.clone().oneshot(req).await.unwrap()).await["error"]["code"],code);
        }
        assert_eq!(decoded(app.clone().oneshot(directory("denied")).await.unwrap()).await["error"]["code"],"DENIED");
        assert_eq!(decoded(app.clone().oneshot(directory("panic")).await.unwrap()).await["error"]["code"],"UNKNOWN");
    });
    let mut state = enabled();
    Arc::get_mut(&mut state)
        .unwrap()
        .catalogue
        .as_mut()
        .unwrap()
        .timeout = Duration::from_millis(2);
    let app = router(state).unwrap();
    runtime().block_on(async {
        let mut pending = directory("x");
        *pending.body_mut() = Body::new(PendingBody);
        assert_eq!(
            decoded(app.clone().oneshot(pending).await.unwrap()).await["error"]["code"],
            "DEADLINE"
        );
        assert_eq!(
            decoded(app.oneshot(directory("late")).await.unwrap()).await["error"]["code"],
            "UNKNOWN"
        );
    });
    let bytes = json!({"version":1,"operation":"resolve_name","name":"x"}).to_string();
    assert_eq!(
        parse_catalogue_before(bytes.as_bytes(), Instant::now())
            .unwrap_err()
            .code,
        "DEADLINE"
    );
}

#[test]
fn invalid_direct_directory_state_cannot_open_an_unbounded_route() {
    for set in [
        |s: &mut CatalogueState| s.max_body_bytes = 0,
        |s: &mut CatalogueState| s.max_body_bytes = 65537,
        |s: &mut CatalogueState| s.timeout = Duration::ZERO,
        |s: &mut CatalogueState| s.timeout = Duration::from_secs(86401),
        |s: &mut CatalogueState| s.intake = Arc::new(Semaphore::new(0)),
        |s: &mut CatalogueState| s.intake = Arc::new(Semaphore::new(4097)),
    ] {
        let mut state = enabled();
        set(Arc::get_mut(&mut state)
            .unwrap()
            .catalogue
            .as_mut()
            .unwrap());
        assert!(router(state).is_err());
    }
}
