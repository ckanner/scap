use super::tests::{decoded, request, runtime, state};
use super::*;
use crate::auth::Credential;
use crate::intake::Profile;
use crate::scheduler::{Factory, Limits, Worker};
use crate::tests::{call as native_call, principal, until};
use crate::wire::{Action, Call, Decimal};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use tower::ServiceExt;

fn authenticated_state(total: usize, profile: Option<Profile>) -> Arc<HttpState> {
    let mut state = state();
    let owned = Arc::get_mut(&mut state).unwrap();
    owned.auth = Authenticator::new(
        [('a', 2, 3), ('b', 2, 4), ('c', 3, 3)]
            .into_iter()
            .map(|(token, tenant, principal)| Credential {
                sha256: format!("{:x}", Sha256::digest(token.to_string().repeat(32))),
                deployment: Decimal(1),
                tenant: Decimal(tenant),
                principal: Decimal(principal),
                provision: true,
                deployment_inventory: false,
            })
            .collect(),
    )
    .unwrap();
    owned.intake = Arc::new(Intake::new(Class::Data, total, 4096, profile).unwrap());
    state
}

fn credential(mut request: Request, token: char) -> Request {
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", token.to_string().repeat(32))
            .parse()
            .unwrap(),
    );
    if token == 'c' {
        let value = json!({"version":1,"scope":{"deployment":"1","tenant":"3","database":"3","incarnation":"1","generation":"1"},"operation":"query","statements":[]});
        *request.body_mut() = Body::from(value.to_string());
    }
    request
}

struct CountedPending(Arc<AtomicUsize>);
impl HttpBody for CountedPending {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

struct PoisonedUpload {
    pool: Arc<Intake>,
    bytes: Option<Bytes>,
}

impl HttpBody for PoisonedUpload {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.bytes.take().map(|bytes| {
            crate::intake::tests::poison_accounting(&self.pool);
            Ok(http_body::Frame::data(bytes))
        }))
    }
}

pub(super) fn poisoned_upload(pool: Arc<Intake>) -> Body {
    Body::new(PoisonedUpload {
        pool,
        // Accounting failure must be reported before even trying to parse
        // this body, and must never fall through to worker dispatch.
        bytes: Some(Bytes::from_static(b"not JSON")),
    })
}

#[test]
fn accounting_owner_panic_during_body_read_fails_before_parse_and_releases_the_last_response() {
    for operation in ["query", "status", "open"] {
        let state = state();
        let app = router(state.clone()).unwrap();
        let pool = match operation {
            "status" => state.control_intake.clone(),
            "open" => state.recovery_intake.clone(),
            _ => state.intake.clone(),
        };
        runtime().block_on(async {
            let mut input = request(operation, 3);
            *input.body_mut() = poisoned_upload(pool.clone());
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
}

#[test]
fn authenticated_tenant_quota_is_reserved_before_polling_any_request_body() {
    let state = authenticated_state(3, None);
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        let first_polls = Arc::new(AtomicUsize::new(0));
        let mut first = request("query", 3);
        *first.body_mut() = Body::new(CountedPending(first_polls.clone()));
        let mut first = Box::pin(app.clone().oneshot(first));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(first.as_mut().poll(&mut context).is_pending());
        assert_eq!(first_polls.load(Ordering::SeqCst), 1);
        assert_eq!(state.intake.available_permits(), 2);

        let rejected_polls = Arc::new(AtomicUsize::new(0));
        let mut same_tenant_other_principal = credential(request("query", 3), 'b');
        *same_tenant_other_principal.body_mut() = Body::new(CountedPending(rejected_polls.clone()));
        let response = app
            .clone()
            .oneshot(same_tenant_other_principal)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rejected_polls.load(Ordering::SeqCst), 0);
        drop(response);

        let other_polls = Arc::new(AtomicUsize::new(0));
        let mut other = credential(request("query", 3), 'c');
        *other.body_mut() = Body::new(CountedPending(other_polls.clone()));
        let mut other = Box::pin(app.clone().oneshot(other));
        assert!(other.as_mut().poll(&mut context).is_pending());
        assert_eq!(other_polls.load(Ordering::SeqCst), 1);
        assert_eq!(state.intake.available_permits(), 1);
        assert_eq!(
            decoded(app.oneshot(request("status", 3)).await.unwrap()).await["ok"],
            true
        );
        drop((first, other));
        assert_eq!(state.intake.available_permits(), 3);
    });
}

#[test]
fn completed_body_read_refunds_unused_extent_while_responses_remain_owned() {
    let state = authenticated_state(
        3,
        Some(Profile {
            version: 1,
            requests_per_tenant: 2,
            body_bytes: 5120,
            body_bytes_per_tenant: 5120,
        }),
    );
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        let first = app.clone().oneshot(request("query", 3)).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(state.intake.available_permits(), 2);
        // Without the post-read refund, two 4096-byte reservations cannot
        // fit in the global 5120-byte pool while the first response is held.
        let second = app
            .oneshot(credential(request("query", 3), 'c'))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(state.intake.available_permits(), 1);
        let slots = state.intake.clone();
        // A response wakeup is not a worker destruction barrier.
        drop(state);
        drop(first);
        assert_eq!(slots.available_permits(), 2);
        drop(second);
        assert_eq!(slots.available_permits(), 3);
    });
}

struct Gate {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: Mutex<bool>,
    changed: Condvar,
    executions: AtomicUsize,
}

impl Gate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct GatedWorker(Arc<Gate>);
impl Worker for GatedWorker {
    fn execute(
        &mut self,
        _: &Principal,
        call: Call,
        _: Instant,
    ) -> Result<serde_json::Value, Failure> {
        self.0.executions.fetch_add(1, Ordering::SeqCst);
        if call.scope.database.0 == 10 {
            if let Some(entered) = self.0.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let mut released = self.0.released.lock().unwrap();
            while !*released {
                released = self.0.changed.wait(released).unwrap();
            }
        }
        Ok(json!({"completed":true}))
    }

    fn execute_budgeted(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        _: &mut crate::output::OutputContext,
    ) -> Result<serde_json::Value, Failure> {
        // The bounded fixture reply is covered by the acquired base credit.
        self.execute(principal, call, deadline)
    }
}

fn gated(
    total: usize,
) -> (
    Arc<HttpState>,
    Arc<Gate>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (entered, ready) = tokio::sync::oneshot::channel();
    let gate = Arc::new(Gate {
        entered: Mutex::new(Some(entered)),
        released: Mutex::new(false),
        changed: Condvar::new(),
        executions: AtomicUsize::new(0),
    });
    let worker_gate = gate.clone();
    let factory: Factory = Arc::new(move |_| Ok(Box::new(GatedWorker(worker_gate.clone()))));
    let mut state = state();
    let owned = Arc::get_mut(&mut state).unwrap();
    owned.scheduler = Arc::new(
        Scheduler::new(
            Limits {
                active_database_actors: 2,
                active_database_actors_per_tenant: 2,
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
    owned.timeout = Duration::from_millis(100);
    owned.recovery_timeout = Duration::from_millis(100);
    owned.intake = Arc::new(
        Intake::new(
            Class::Data,
            total,
            4096,
            Some(Profile {
                version: 1,
                requests_per_tenant: total,
                body_bytes: total * 4096,
                body_bytes_per_tenant: total * 4096,
            }),
        )
        .unwrap(),
    );
    (state, gate, ready)
}

async fn wait_free(pool: &Arc<Intake>, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while pool.available_permits() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn worker_retains_each_intake_after_http_deadline_and_response_bytes_are_dropped() {
    for operation in ["query", "status", "open"] {
        let (state, gate, entered) = gated(1);
        let app = router(state.clone()).unwrap();
        let _release = ReleaseOnDrop(gate.clone());
        let pool = match operation {
            "status" => state.control_intake.clone(),
            "open" => state.recovery_intake.clone(),
            _ => state.intake.clone(),
        };
        let output = state.output.clone();
        runtime().block_on(async {
            let task = tokio::spawn(app.clone().oneshot(request(operation, 10)));
            tokio::time::timeout(Duration::from_secs(2), entered)
                .await
                .unwrap()
                .unwrap();
            let response = task.await.unwrap().unwrap();
            assert_eq!(decoded(response).await["error"]["code"], "UNKNOWN");
            assert_eq!(pool.available_permits(), 0);
            let bytes = crate::output::BASE_BYTES;
            assert_eq!(
                crate::output::tests::usage(&output),
                if operation == "query" {
                    (bytes, 0, 1)
                } else {
                    (0, bytes, 1)
                }
            );
            assert_eq!(
                app.oneshot(request(operation, 3)).await.unwrap().status(),
                StatusCode::TOO_MANY_REQUESTS
            );
            gate.release();
            wait_free(&pool, 1).await;
            assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
        });
        drop(state);
        assert_eq!(crate::output::tests::usage(&output), (0, 0, 0));
    }
}

#[test]
fn queued_cancellation_keeps_its_lease_until_the_worker_actually_discards_the_job() {
    let (state, gate, entered) = gated(2);
    let output = state.output.clone();
    let app = router(state.clone()).unwrap();
    let _release = ReleaseOnDrop(gate.clone());
    runtime().block_on(async {
        let first = tokio::spawn(app.clone().oneshot(request("query", 10)));
        tokio::time::timeout(Duration::from_secs(2), entered)
            .await
            .unwrap()
            .unwrap();
        let second = app.oneshot(request("query", 10)).await.unwrap();
        assert_eq!(decoded(second).await["error"]["code"], "UNKNOWN");
        assert_eq!(
            decoded(first.await.unwrap().unwrap()).await["error"]["code"],
            "UNKNOWN"
        );
        assert_eq!(state.intake.available_permits(), 0);
        assert_eq!(
            crate::output::tests::usage(&output),
            (2 * crate::output::BASE_BYTES, 0, 1)
        );
        gate.release();
        wait_free(&state.intake, 2).await;
        assert_eq!(gate.executions.load(Ordering::SeqCst), 1);
    });
    drop(state);
    assert_eq!(crate::output::tests::usage(&output), (0, 0, 0));
}

#[test]
fn scheduler_refuses_reusing_or_reclassifying_a_http_reservation() {
    let state = state();
    let reservation = state.intake.acquire(&principal()).unwrap();
    assert_eq!(
        state
            .scheduler
            .submit_encoded(
                principal(),
                native_call(Action::Status {
                    expected_worker_instance: None
                }),
                until(),
                reservation.clone(),
                state.output.acquire(&principal(), true).unwrap(),
            )
            .err()
            .unwrap()
            .code,
        "DENIED"
    );
    let result = state
        .scheduler
        .submit_encoded(
            principal(),
            native_call(Action::Query { statements: vec![] }),
            until(),
            reservation.clone(),
            state.output.acquire(&principal(), false).unwrap(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.bytes).unwrap()["value"]["served"],
        "data"
    );
    assert_eq!(
        state
            .scheduler
            .submit_encoded(
                principal(),
                native_call(Action::Query { statements: vec![] }),
                until(),
                reservation.clone(),
                state.output.acquire(&principal(), false).unwrap(),
            )
            .err()
            .unwrap()
            .code,
        "INVALID"
    );
    let slots = state.intake.clone();
    drop(state);
    drop(reservation);
    assert_eq!(slots.available_permits(), 1);
}
