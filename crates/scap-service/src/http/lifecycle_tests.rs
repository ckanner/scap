use super::tests::{decoded, request, runtime, state};
use super::*;
use crate::lifecycle_export::{tests::profile, Diagnostics};
use std::future::poll_fn;
use tower::ServiceExt;

fn observed_state() -> Arc<HttpState> {
    let mut state = state();
    let diagnostics = Arc::new(Diagnostics::new(&profile()).unwrap());
    let owned = Arc::get_mut(&mut state).unwrap();
    owned.intake = Arc::new(
        Intake::new(Class::Data, 1, 4096, None)
            .unwrap()
            .with_lifecycle(diagnostics.registry.clone(), crate::lifecycle::Lane::Data)
            .unwrap(),
    );
    owned.lifecycle_diagnostics = Some(diagnostics);
    state
}

fn snapshot(state: &HttpState) -> serde_json::Value {
    serde_json::to_value(
        state
            .lifecycle_diagnostics
            .as_ref()
            .unwrap()
            .registry
            .snapshot(),
    )
    .unwrap()
}

#[test]
fn http_readiness_and_final_bytes_are_independent_from_worker_return() {
    use crate::scheduler::{Factory, Limits, Worker};
    use std::sync::{mpsc, Condvar, Mutex};
    struct Paused {
        started: mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (lock, changed) = &*self.0;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }
    }
    impl Worker for Paused {
        fn execute(
            &mut self,
            _: &Principal,
            _: crate::wire::Call,
            _: Instant,
        ) -> Result<serde_json::Value, Failure> {
            self.started.send(()).unwrap();
            let (lock, changed) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = changed.wait(released).unwrap();
            }
            Ok(json!("finished once"))
        }
        fn execute_budgeted(
            &mut self,
            principal: &Principal,
            call: crate::wire::Call,
            deadline: Instant,
            _: &mut crate::output::OutputContext,
        ) -> Result<serde_json::Value, Failure> {
            self.execute(principal, call, deadline)
        }
    }
    let mut state = observed_state();
    let (started, entering) = mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let owned = Arc::get_mut(&mut state).unwrap();
    let factory: Factory = {
        let release = release.clone();
        Arc::new(move |_| {
            Ok(Box::new(Paused {
                started: started.clone(),
                release: release.clone(),
            }))
        })
    };
    owned.scheduler = Arc::new(
        Scheduler::new(
            Limits {
                active_database_actors: 1,
                active_database_actors_per_tenant: 1,
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
    owned.timeout = Duration::from_millis(20);
    let app = router(state.clone()).unwrap();
    let _cleanup = ReleaseOnDrop(release.clone());
    runtime().block_on(async {
        let running = tokio::spawn(app.oneshot(request("query", 3)));
        tokio::task::yield_now().await;
        entering.recv_timeout(Duration::from_secs(2)).unwrap();
        let response = running.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(snapshot(&state)["lanes"][0]["active"], "1");
        assert_eq!(state.intake.available_permits(), 0);
        let (lock, changed) = &*release;
        *lock.lock().unwrap() = true;
        changed.notify_all();
        assert_eq!(decoded(response).await["error"]["code"], "UNKNOWN");
        let deadline = Instant::now() + Duration::from_secs(2);
        while snapshot(&state)["lanes"][0]["active"] != "0" {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let final_state = snapshot(&state);
        assert_eq!(final_state["valid"], true);
        assert_eq!(final_state["lanes"][0]["acquired"], "1");
        assert_eq!(final_state["lanes"][0]["released"], "1");
        for interval in final_state["lanes"][0]["intervals"].as_array().unwrap() {
            assert_eq!(interval["completed"], "1");
            assert_eq!(interval["censored"], "0");
        }
        assert_eq!(state.intake.available_permits(), 1);
    });
}

#[test]
fn diagnostic_total_hold_ends_at_the_final_original_response_slice() {
    runtime().block_on(async {
        let state = observed_state();
        let response = router(state.clone())
            .unwrap()
            .oneshot(request("query", 3))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let bytes = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let clone = bytes.clone();
        let slice = bytes.slice(1..2);
        drop((body, bytes, clone));
        assert_eq!(snapshot(&state)["lanes"][0]["active"], "1");
        assert_eq!(snapshot(&state)["lanes"][0]["released"], "0");
        assert_eq!(state.intake.available_permits(), 0);
        drop(slice);
        let snapshot = snapshot(&state);
        assert_eq!(snapshot["valid"], true);
        assert_eq!(snapshot["lanes"][0]["active"], "0");
        assert_eq!(snapshot["lanes"][0]["released"], "1");
        assert_eq!(snapshot["lanes"][0]["intervals"][7]["completed"], "1");
        assert_eq!(state.intake.available_permits(), 1);
    });
}

fn diagnostic_request(token: char) -> Request {
    Request::builder()
        .uri("/diagnostics/lifecycle")
        .header(
            "authorization",
            format!("Bearer {}", token.to_string().repeat(32)),
        )
        .body(Body::empty())
        .unwrap()
}

#[test]
fn export_is_disabled_by_default_and_rejects_ordinary_and_duplicate_bearers() {
    runtime().block_on(async {
        let mut state = state();
        let app = router(state.clone()).unwrap();
        assert_eq!(
            app.oneshot(diagnostic_request('d')).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let diagnostics = Arc::new(Diagnostics::new(&profile()).unwrap());
        Arc::get_mut(&mut state).unwrap().lifecycle_diagnostics = Some(diagnostics);
        let app = router(state.clone()).unwrap();
        let mut duplicate = diagnostic_request('d');
        duplicate.headers_mut().append(
            "authorization",
            format!("Bearer {}", "d".repeat(32)).parse().unwrap(),
        );
        for input in [
            diagnostic_request('a'),
            Request::builder()
                .uri("/diagnostics/lifecycle")
                .body(Body::empty())
                .unwrap(),
            duplicate,
        ] {
            assert_eq!(
                app.clone().oneshot(input).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
        let response = app.clone().oneshot(diagnostic_request('d')).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        let _: serde_json::Value = decoded(response).await;
        let mut ordinary = request("status", 3);
        ordinary.headers_mut().insert(
            "authorization",
            format!("Bearer {}", "d".repeat(32)).parse().unwrap(),
        );
        assert_eq!(
            app.oneshot(ordinary).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    });
}

#[test]
fn exported_body_frame_clone_and_nonempty_slice_hold_the_only_response_credit() {
    runtime().block_on(async {
        let mut state = state();
        Arc::get_mut(&mut state).unwrap().lifecycle_diagnostics =
            Some(Arc::new(Diagnostics::new(&profile()).unwrap()));
        let app = router(state).unwrap();
        let response = app.clone().oneshot(diagnostic_request('d')).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            app.clone()
                .oneshot(diagnostic_request('d'))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let mut body = response.into_body();
        let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        let bytes = frame.into_data().unwrap();
        let clone = bytes.clone();
        let slice = bytes.slice(1..2);
        drop((body, bytes));
        assert_eq!(
            app.clone()
                .oneshot(diagnostic_request('d'))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(clone);
        assert_eq!(
            app.clone()
                .oneshot(diagnostic_request('d'))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(slice);
        let response = app.oneshot(diagnostic_request('d')).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(to_bytes(
            response.into_body(),
            crate::lifecycle_export::MAX_RESPONSE_BYTES
        )
        .await
        .is_ok());
    });
}
