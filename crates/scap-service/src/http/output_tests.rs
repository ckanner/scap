use super::tests::{decoded, request, runtime, state};
use super::*;
use crate::auth::Credential;
use crate::output::{
    tests::{receipt, small_pool, usage},
    OutputContext, Pool, BASE_BYTES,
};
use crate::scheduler::{Limits, Worker};
use crate::wire::{Call, Decimal};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[derive(Clone, Copy)]
enum Mode {
    Small,
    Large,
    Unknown,
    HeadFault,
    Committed,
}

struct Budgeted {
    mode: Mode,
    calls: Arc<AtomicUsize>,
}

impl Worker for Budgeted {
    fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
        panic!("HTTP must call the explicitly budgeted capability")
    }

    fn execute_budgeted(
        &mut self,
        _: &Principal,
        _: Call,
        _: Instant,
        output: &mut OutputContext,
    ) -> Result<Value, Failure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            Mode::Small => Ok(json!({"small":true})),
            Mode::Large => {
                let result = output.base64(&[7; 4096])?;
                Ok(Value::Object(Map::from_iter([(
                    "result".into(),
                    Value::String(result),
                )])))
            }
            Mode::Unknown => Err(Failure::new("UNKNOWN")),
            Mode::HeadFault => {
                // Fault-inject a violation of the internal fixed metadata
                // shape after a possible HEAD effect. It must close the
                // reply, never invent a retryable LIMIT or rollback proof.
                output.head_result();
                Ok(Value::String("x".repeat(4096)))
            }
            Mode::Committed => {
                output.committed(receipt());
                let result = output
                    .base64(&[7; 2048])
                    .map_err(|_| output.committed_unavailable())?;
                Ok(wire::committed(output.receipt(), result))
            }
        }
    }
}

fn fixture(pool: Arc<Pool>, mode: Mode) -> (Arc<HttpState>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut state = state();
    let owned = Arc::get_mut(&mut state).unwrap();
    owned.output = pool;
    owned.intake = Arc::new(Intake::new(Class::Data, 4, 4096, None).unwrap());
    owned.scheduler = Arc::new(
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
            Arc::new(move |_| {
                Ok(Box::new(Budgeted {
                    mode,
                    calls: observed.clone(),
                }))
            }),
        )
        .unwrap(),
    );
    (state, calls)
}

#[test]
fn output_admission_is_per_authenticated_tenant_before_job_and_protects_small_controls() {
    let pool = small_pool(2 * BASE_BYTES, BASE_BYTES);
    let (mut state, calls) = fixture(pool.clone(), Mode::Small);
    Arc::get_mut(&mut state).unwrap().auth = Authenticator::new(
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
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        let first = app.clone().oneshot(request("query", 3)).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let mut foreign_scope = request("query", 3);
        *foreign_scope.body_mut() = Body::from(
            json!({"version":1,"scope":{"deployment":"1",
            "tenant":"3","database":"3","incarnation":"1","generation":"1"},
            "operation":"query","statements":[]})
            .to_string(),
        );
        let denied = app.clone().oneshot(foreign_scope).await.unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(decoded(denied).await["error"]["code"], "DENIED");
        let mut same_tenant = request("query", 3);
        same_tenant.headers_mut().insert(
            "authorization",
            format!("Bearer {}", "b".repeat(32)).parse().unwrap(),
        );
        let rejected = app.clone().oneshot(same_tenant).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(decoded(rejected).await["error"]["code"], "BACKPRESSURE");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut other_tenant = request("query", 3);
        other_tenant.headers_mut().insert(
            "authorization",
            format!("Bearer {}", "c".repeat(32)).parse().unwrap(),
        );
        *other_tenant.body_mut() = Body::from(
            json!({"version":1,"scope":{"deployment":"1",
            "tenant":"3","database":"3","incarnation":"1","generation":"1"},
            "operation":"query","statements":[]})
            .to_string(),
        );
        let other = app.clone().oneshot(other_tenant).await.unwrap();
        assert_eq!(other.status(), StatusCode::OK);
        let control = app.clone().oneshot(request("status", 3)).await.unwrap();
        assert_eq!(control.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        drop(app);
        drop(state); // join every worker before asserting exact final refunds
        assert_eq!(usage(&pool), (2 * BASE_BYTES, BASE_BYTES, 2));
        drop((first, other, control));
        assert_eq!(usage(&pool), (0, 0, 0));
    });
}

#[test]
fn outgoing_large_frame_clones_keep_full_json_capacity_after_body_and_worker_drop() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let (state, _) = fixture(pool.clone(), Mode::Large);
    let intake = state.intake.clone();
    let app = router(state.clone()).unwrap();
    runtime().block_on(async {
        let response = app.clone().oneshot(request("query", 3)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let bytes = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let full_capacity = bytes.len();
        assert_eq!(full_capacity, base64::encoded_len(4096, true).unwrap() + 33);
        let cloned = bytes.clone();
        let sliced = bytes.slice(1..2);
        drop((body, bytes, app, state));
        assert_eq!(usage(&pool), (BASE_BYTES + full_capacity, 0, 1));
        assert_eq!(intake.available_permits(), 3);
        drop(cloned);
        assert_eq!(usage(&pool), (BASE_BYTES + full_capacity, 0, 1));
        drop(sliced);
        assert_eq!(usage(&pool), (0, 0, 0));
        assert_eq!(intake.available_permits(), 4);
    });
}

#[test]
fn real_http_finalizer_preserves_unknown_commit_proof_and_head_effect_uncertainty() {
    for (mode, shared, operation, status, code) in [
        (
            Mode::Unknown,
            BASE_BYTES,
            "query",
            StatusCode::SERVICE_UNAVAILABLE,
            "UNKNOWN",
        ),
        (
            Mode::HeadFault,
            0,
            "status",
            StatusCode::SERVICE_UNAVAILABLE,
            "UNKNOWN",
        ),
        (
            Mode::Committed,
            BASE_BYTES + 3000,
            "query",
            StatusCode::SERVICE_UNAVAILABLE,
            "COMMITTED_BUT_UNAVAILABLE",
        ),
        (
            Mode::Large,
            BASE_BYTES + 6000,
            "query",
            StatusCode::PAYLOAD_TOO_LARGE,
            "LIMIT",
        ),
    ] {
        let pool = small_pool(shared, shared);
        let (state, executions) = fixture(pool.clone(), mode);
        let app = router(state.clone()).unwrap();
        runtime().block_on(async {
            let response = app.clone().oneshot(request(operation, 3)).await.unwrap();
            assert_eq!(response.status(), status);
            drop(app);
            drop(state);
            let value = decoded(response).await;
            assert_eq!(value["error"]["code"], code);
            if code == "COMMITTED_BUT_UNAVAILABLE" {
                assert_eq!(value["error"]["receipt"], wire::receipt(&receipt()));
            } else {
                assert!(value["error"].get("receipt").is_none());
            }
            assert_eq!(executions.load(Ordering::SeqCst), 1);
            assert_eq!(usage(&pool), (0, 0, 0));
        });
    }
}
