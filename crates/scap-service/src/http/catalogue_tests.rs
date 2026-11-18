use super::tests::{decoded, request, runtime, state, PendingBody};
use super::*;
use crate::catalogue_scheduler::{Factory, Limits, Scheduler, Worker};
use crate::catalogue_wire::Call;
use crate::tests::principal;
use axum::http::{HeaderValue, Method};
use serde_json::Value;
use tower::ServiceExt;

struct Echo;
impl Worker for Echo {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        match call.action.name() {
            Some("denied") => Err(Failure::new("DENIED")),
            Some("panic") => panic!("injected directory loss"),
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
        intake: Arc::new(Intake::new(Class::Catalogue, 1, 2048, None).unwrap()),
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

fn restore_request() -> Request {
    let mut request = directory("restore");
    request
        .headers_mut()
        .insert("x-scap-admission", HeaderValue::from_static("recovery"));
    *request.body_mut() = Body::from(
        json!({"version":1,"operation":"resume_restore", "reference":{
        "descriptor_hash":"a".repeat(64),
        "creation":crate::catalogue_wire::creation(&crate::tests::named_creation("restore", 8))}})
        .to_string(),
    );
    request
}

fn restore_enabled(factory: Factory) -> Arc<HttpState> {
    let mut state = enabled();
    Arc::get_mut(&mut state).unwrap().restore = Some(RestoreState {
        pool: CatalogueState {
            scheduler: Arc::new(
                Scheduler::new_recovery(
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
            timeout: Duration::from_millis(100),
            intake: Arc::new(Intake::new(Class::Recovery, 1, 2048, None).unwrap()),
        },
        timeout: Duration::from_millis(500),
    });
    state
}

#[test]
fn restore_copy_uses_its_own_pool_and_rejects_misclassified_calls() {
    runtime().block_on(async {
        let disabled = router(enabled()).unwrap();
        assert_eq!(
            decoded(disabled.oneshot(restore_request()).await.unwrap()).await["error"]["code"],
            "UNAVAILABLE"
        );
        let state = restore_enabled(Arc::new(|_| Ok(Box::new(Echo))));
        let app = router(state.clone()).unwrap();
        let permit = state
            .restore
            .as_ref()
            .unwrap()
            .pool
            .intake
            .acquire(&principal())
            .unwrap();
        assert_eq!(
            decoded(app.clone().oneshot(restore_request()).await.unwrap()).await["error"]["code"],
            "BACKPRESSURE"
        );
        assert_eq!(
            decoded(
                app.clone()
                    .oneshot(directory("inspect remains live"))
                    .await
                    .unwrap()
            )
            .await["value"]["name"],
            "inspect remains live"
        );
        drop(permit);
        let mut wrong = restore_request();
        wrong
            .headers_mut()
            .insert("x-scap-admission", HeaderValue::from_static("catalogue"));
        assert_eq!(
            decoded(app.clone().oneshot(wrong).await.unwrap()).await["error"]["code"],
            "INVALID"
        );
        let mut wrong = directory("restore");
        wrong
            .headers_mut()
            .insert("x-scap-admission", HeaderValue::from_static("recovery"));
        assert_eq!(
            decoded(app.clone().oneshot(wrong).await.unwrap()).await["error"]["code"],
            "INVALID"
        );
        let reply = app.oneshot(restore_request()).await.unwrap();
        drop(state);
        assert_eq!(decoded(reply).await["value"]["name"], "restore");
    });
}

#[test]
fn direct_restore_state_rejects_invalid_limits_and_wrong_intake_before_routing() {
    for mode in 0..8 {
        let mut state = restore_enabled(Arc::new(|_| Ok(Box::new(Echo))));
        let state_mut = Arc::get_mut(&mut state).unwrap();
        let restore = state_mut.restore.as_mut().unwrap();
        match mode {
            0 => state_mut.catalogue = None,
            1 => restore.pool.max_body_bytes = 0,
            2 => restore.pool.max_body_bytes = 65537,
            3 => restore.pool.timeout = Duration::ZERO,
            4 => restore.pool.timeout = Duration::from_secs(86401),
            5 => restore.timeout = Duration::ZERO,
            6 => restore.timeout = Duration::from_secs(604801),
            _ => {
                restore.pool.intake =
                    Arc::new(Intake::new(Class::Catalogue, 1, 2048, None).unwrap())
            }
        }
        assert_eq!(router(state).err().unwrap().code, "CONFIG");
    }
}

#[test]
fn restore_execution_uses_long_budget_but_upload_keeps_short_budget() {
    struct Slow;
    impl Worker for Slow {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            std::thread::sleep(Duration::from_millis(250));
            Ok(json!("copied"))
        }
    }
    let mut state = restore_enabled(Arc::new(|_| Ok(Box::new(Slow))));
    Arc::get_mut(&mut state)
        .unwrap()
        .restore
        .as_mut()
        .unwrap()
        .pool
        .timeout = Duration::from_millis(100);
    runtime().block_on(async {
        let app = router(state).unwrap();
        assert_eq!(
            decoded(app.clone().oneshot(restore_request()).await.unwrap()).await["value"],
            "copied"
        );
        let mut pending = restore_request();
        *pending.body_mut() = Body::new(PendingBody);
        assert_eq!(
            decoded(app.oneshot(pending).await.unwrap()).await["error"]["code"],
            "DEADLINE"
        );
    });
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
        let permit = slots.acquire(&principal()).unwrap();
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
        // A reply does not establish that the database Job has dropped its
        // lease. Join this phase before reserving all database classes anew.
        drop(app);
        drop(state);
        let state = enabled();
        let app = router(state.clone()).unwrap();
        let slots = state.catalogue.as_ref().unwrap().intake.clone();
        let data = state.intake.acquire(&principal()).unwrap();
        let control = state.control_intake.acquire(&principal()).unwrap();
        let recovery = state.recovery_intake.acquire(&principal()).unwrap();
        let response = app.clone().oneshot(directory("exact É")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(app);
        drop(state);
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(decoded(response).await["value"]["name"], "exact É");
        assert_eq!(slots.available_permits(), 1);
        drop((data, control, recovery));
        let app = router(enabled()).unwrap();
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
        // Independent worker errors do not depend on a prior Job having
        // destroyed its lease merely because its reply has been consumed.
        for (name, code) in [("denied", "DENIED"), ("panic", "UNKNOWN")] {
            let isolated = router(enabled()).unwrap();
            assert_eq!(decoded(isolated.oneshot(directory(name)).await.unwrap()).await["error"]["code"],code);
        }
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
        // The worker-started UNKNOWN case has an explicit entered/release
        // handshake in catalogue_job_retains_intake_after_http_timeout.
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
        |s: &mut CatalogueState| {
            s.intake = Arc::new(Intake::new(Class::Data, 1, 2048, None).unwrap())
        },
        |s: &mut CatalogueState| {
            s.intake = Arc::new(Intake::new(Class::Catalogue, 1, 2049, None).unwrap())
        },
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

#[test]
fn catalogue_upload_accounting_panic_stops_before_parsing_and_retains_response_ownership() {
    let state = enabled();
    let app = router(state.clone()).unwrap();
    let pool = state.catalogue.as_ref().unwrap().intake.clone();
    runtime().block_on(async {
        let mut input = directory("must-not-dispatch");
        *input.body_mut() = super::intake_tests::poisoned_upload(pool.clone());
        let response = app.oneshot(input).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(pool.available_permits(), 0);
        assert_eq!(decoded(response).await["error"]["code"], "UNAVAILABLE");
        assert_eq!(pool.available_permits(), 1);
        assert_eq!(
            pool.acquire(&principal()).err().unwrap().code,
            "UNAVAILABLE"
        );
    });
}

#[test]
fn catalogue_dispatch_cannot_borrow_another_class_or_reuse_its_reservation() {
    let state = enabled();
    let catalogue = state.catalogue.as_ref().unwrap();
    let call = || crate::catalogue_wire::Call {
        version: 1,
        action: crate::catalogue_wire::Action::ResolveName {
            name: "once".into(),
        },
    };
    let data = state.intake.acquire(&principal()).unwrap();
    assert_eq!(
        catalogue
            .scheduler
            .submit_reserved(principal(), call(), crate::tests::until(), data)
            .err()
            .unwrap()
            .code,
        "DENIED"
    );
    assert_eq!(state.intake.available_permits(), 1);
    let reservation = catalogue.intake.acquire(&principal()).unwrap();
    let result = catalogue
        .scheduler
        .submit_reserved(
            principal(),
            call(),
            crate::tests::until(),
            reservation.clone(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(result["name"], "once");
    assert_eq!(
        catalogue
            .scheduler
            .submit_reserved(
                principal(),
                call(),
                crate::tests::until(),
                reservation.clone()
            )
            .err()
            .unwrap()
            .code,
        "INVALID"
    );
    let intake = catalogue.intake.clone();
    drop(reservation);
    // A delivered reply can wake us before the worker drops its Job lease.
    // Joining the scheduler establishes actual completion without a sleep.
    drop(state);
    assert_eq!(intake.available_permits(), 1);
}

#[test]
fn catalogue_job_retains_intake_after_http_timeout_until_actual_worker_completion() {
    use std::sync::{Condvar, Mutex};
    struct Gate {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        released: Mutex<bool>,
        changed: Condvar,
    }
    struct Guard(Arc<Gate>);
    impl Drop for Guard {
        fn drop(&mut self) {
            *self.0.released.lock().unwrap() = true;
            self.0.changed.notify_all();
        }
    }
    struct Blocked(Arc<Gate>);
    impl Worker for Blocked {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            if let Some(entered) = self.0.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let mut released = self.0.released.lock().unwrap();
            while !*released {
                released = self.0.changed.wait(released).unwrap();
            }
            Ok(json!("complete"))
        }
    }
    let (entered, ready) = tokio::sync::oneshot::channel();
    let gate = Arc::new(Gate {
        entered: Mutex::new(Some(entered)),
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let worker_gate = gate.clone();
    let factory: Factory = Arc::new(move |_| Ok(Box::new(Blocked(worker_gate.clone()))));
    let mut state = enabled();
    let catalogue = Arc::get_mut(&mut state)
        .unwrap()
        .catalogue
        .as_mut()
        .unwrap();
    catalogue.scheduler = Arc::new(
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
    );
    catalogue.timeout = Duration::from_millis(100);
    let app = router(state.clone()).unwrap();
    let guard = Guard(gate);
    runtime().block_on(async {
        let task = tokio::spawn(app.clone().oneshot(directory("blocked")));
        tokio::time::timeout(Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decoded(task.await.unwrap().unwrap()).await["error"]["code"],
            "UNKNOWN"
        );
        let pool = &state.catalogue.as_ref().unwrap().intake;
        assert_eq!(pool.available_permits(), 0);
        assert_eq!(
            app.clone()
                .oneshot(directory("second"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            decoded(app.oneshot(request("status", 3)).await.unwrap()).await["ok"],
            true
        );
        drop(guard);
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    });
}
