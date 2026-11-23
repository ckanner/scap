use super::*;
use crate::tests::{call, principal, until};
use crate::wire::{Action, Decimal, Identity};
use serde_json::json;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;
use std::thread::ThreadId;

pub(crate) fn limits() -> Limits {
    Limits {
        active_database_actors: 2,
        active_database_actors_per_tenant: 2,
        actor_idle_timeout: Duration::from_secs(60),
        control_workers: 1,
        queued_total: 32,
        queued_per_tenant: 16,
        queued_per_database: 8,
        reserved_controls: 2,
    }
}

fn job(
    tenant: u64,
    database: u64,
    id: u64,
    priority: bool,
) -> (Job, oneshot::Receiver<Result<Value, Failure>>) {
    let mut principal = principal();
    principal.tenant = tenant;
    let action = if priority {
        Action::Lookup {
            request: Identity {
                epoch: Decimal(1),
                id: Decimal(id),
                principal: Decimal(3),
                fingerprint: "a".repeat(64),
            },
        }
    } else {
        Action::Create { nonce: Decimal(id) }
    };
    let mut call = call(action);
    call.scope.tenant.0 = tenant;
    call.scope.database.0 = database;
    let key = scap_object::format::head_key(&call.scope.native().unwrap());
    let (reply, receiver) = oneshot::channel();
    (
        Job {
            _reservation: None,
            output: None,
            _output_hold: None,
            principal,
            call,
            key,
            deadline: until(),
            reply: Reply::Value(reply),
        },
        receiver,
    )
}

fn label(job: Job) -> (u64, u64, u64) {
    let id = match job.call.action {
        Action::Create { nonce } => nonce.0,
        Action::Lookup { request } => request.id.0,
        _ => unreachable!(),
    };
    (job.principal.tenant, job.call.scope.database.0, id)
}

fn data(database: u64, action: Action) -> Call {
    let mut call = call(action);
    call.scope.database.0 = database;
    call
}

fn query(database: u64) -> Call {
    data(database, Action::Query { statements: vec![] })
}

fn receive(receiver: oneshot::Receiver<Result<Value, Failure>>) -> Result<Value, Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), receiver)
                .await
                .unwrap()
                .unwrap()
        })
}

fn encoded_job(
    pool: &Arc<crate::output::Pool>,
    deadline: Instant,
) -> (Job, oneshot::Receiver<crate::output::Reply>) {
    let (mut job, old) = job(2, 3, 1, false);
    drop(old);
    let output = pool.acquire(&job.principal, false).unwrap();
    let hold = output.work_hold();
    let (sender, receiver) = oneshot::channel();
    job.deadline = deadline;
    job.reply = Reply::Encoded(sender);
    job.output = Some(output);
    job._output_hold = Some(hold);
    (job, receiver)
}

fn diagnostic_intake(
    registry: &Arc<crate::lifecycle::Registry>,
    class: crate::intake::Class,
    lane: crate::lifecycle::Lane,
) -> Arc<crate::intake::Intake> {
    Arc::new(
        crate::intake::Intake::new(class, 8, 4096, None)
            .unwrap()
            .with_lifecycle(registry.clone(), lane)
            .unwrap(),
    )
}

fn diagnostic_lease(intake: &Arc<crate::intake::Intake>) -> Arc<crate::intake::Lease> {
    let lease = intake.acquire(&principal()).unwrap();
    lease.shrink_body(0).unwrap();
    lease
}

#[test]
fn lifecycle_tracks_the_original_enqueue_and_invocation_in_all_scheduler_lanes() {
    use crate::intake::Class;
    use crate::lifecycle::{Lane, Registry};
    use crate::output::{tests::small_pool, BASE_BYTES};

    struct BudgetEcho;
    impl Worker for BudgetEcho {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            unreachable!("the original output context must be retained")
        }
        fn execute_budgeted(
            &mut self,
            _: &Principal,
            _: Call,
            _: Instant,
            _: &mut crate::output::OutputContext,
        ) -> Result<Value, Failure> {
            Ok(json!(true))
        }
    }
    let registry = Arc::new(Registry::new());
    let intake = diagnostic_intake(&registry, Class::Data, Lane::Data);
    let controls = diagnostic_intake(&registry, Class::Control, Lane::Control);
    let output = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let scheduler = Scheduler::with_read_pool(
        limits(),
        Some(ReadPool {
            workers: 1,
            active_per_tenant: 1,
            active_per_database: 1,
        }),
        Arc::new(|_| Ok(Box::new(BudgetEcho))),
    )
    .unwrap();
    for call in [
        data(10, Action::Create { nonce: Decimal(1) }),
        data(10, Action::Create { nonce: Decimal(2) }),
        data(
            10,
            Action::Status {
                expected_worker_instance: None,
            },
        ),
        query(10),
    ] {
        let control = call.action.admission() == "control";
        let lease = diagnostic_lease(if control { &controls } else { &intake });
        let reply = scheduler
            .submit_encoded(
                principal(),
                call,
                until(),
                lease,
                output.acquire(&principal(), control).unwrap(),
            )
            .unwrap()
            .blocking_recv()
            .unwrap();
        assert_eq!(reply.status, axum::http::StatusCode::OK);
    }
    drop(scheduler);
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    for (index, count) in [(0, 3), (1, 1)] {
        let lane = snapshot.lanes[index];
        assert_eq!(
            (lane.acquired.0, lane.released.0, lane.active.0),
            (count, count, 0)
        );
        for interval in [0, 1, 2, 3, 4, 5, 7] {
            assert_eq!(lane.intervals[interval].distribution.completed.0, count);
        }
        assert_eq!(lane.intervals[6].distribution.not_reached.0, count);
    }
}

#[test]
fn lifecycle_does_not_turn_claim_or_rejected_admission_into_enqueue() {
    use crate::intake::Class;
    use crate::lifecycle::{Lane, Registry};
    use crate::output::{tests::small_pool, BASE_BYTES};
    let registry = Arc::new(Registry::new());
    let intake = diagnostic_intake(&registry, Class::Data, Lane::Data);
    let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let scheduler = Scheduler::new(limits(), factory()).unwrap();
    for (deadline, wrong_output, closed, expected) in [
        (until(), true, false, "DENIED"),
        (Instant::now(), false, false, "DEADLINE"),
        (until(), false, true, "UNAVAILABLE"),
    ] {
        if closed {
            scheduler.shared.close();
        }
        let error = scheduler
            .submit_encoded(
                principal(),
                query(3),
                deadline,
                diagnostic_lease(&intake),
                pool.acquire(&principal(), wrong_output).unwrap(),
            )
            .err()
            .unwrap();
        assert_eq!(error.code, expected);
    }
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    let lane = snapshot.lanes[0];
    assert_eq!((lane.acquired.0, lane.released.0, lane.active.0), (3, 3, 0));
    assert_eq!(lane.intervals[1].distribution.censored.0, 3);
    for interval in [2, 3, 4, 5, 6] {
        assert_eq!(lane.intervals[interval].distribution.not_reached.0, 3);
    }
}

#[test]
fn lifecycle_keeps_skipped_invocations_separate_from_failure_encoding() {
    use crate::intake::Class;
    use crate::lifecycle::{Lane, Registry};
    use crate::output::{tests::small_pool, BASE_BYTES};
    let registry = Arc::new(Registry::new());
    let intake = diagnostic_intake(&registry, Class::Data, Lane::Data);
    let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let mut worker = SingleWorker::new(Box::new(Echo::new(0)));
    for kind in ["disconnected", "expired", "closed"] {
        let (mut job, receiver) = encoded_job(&pool, until());
        job._reservation = Some(diagnostic_lease(&intake));
        job.enqueued();
        match kind {
            "disconnected" => {
                drop(receiver);
                worker.execute(job);
            }
            "expired" => {
                job.deadline = Instant::now();
                worker.execute(job);
                assert!(receiver.blocking_recv().is_err());
            }
            _ => {
                job.fail(Failure::new("UNAVAILABLE"));
                assert_eq!(
                    receiver.blocking_recv().unwrap().status,
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                );
            }
        }
    }
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    let lane = snapshot.lanes[0];
    assert_eq!(lane.released.0, 3);
    assert_eq!(lane.intervals[2].distribution.censored.0, 3);
    assert_eq!(lane.intervals[3].distribution.not_reached.0, 3);
    assert_eq!(lane.intervals[4].distribution.completed.0, 2);
    assert_eq!(lane.intervals[4].distribution.not_reached.0, 1);
    assert_eq!(lane.intervals[5].distribution.completed.0, 2);
}

#[test]
fn lifecycle_records_the_actual_encoding_return_for_limit_cbu_and_no_reply() {
    use crate::intake::Class;
    use crate::lifecycle::{Lane, Registry};
    use crate::output::{
        tests::{receipt, small_pool},
        BASE_BYTES,
    };
    let registry = Arc::new(Registry::new());
    let intake = diagnostic_intake(&registry, Class::Data, Lane::Data);
    let pool = small_pool(2 * BASE_BYTES, BASE_BYTES);
    for (committed, expired) in [(false, false), (true, false), (false, true)] {
        let lease = diagnostic_lease(&intake);
        let mut context = pool.acquire(&principal(), false).unwrap();
        if committed {
            context.committed(receipt());
        }
        let value = crate::output::OwnedValue::new(Ok(json!("x".repeat(4 * BASE_BYTES))), context);
        let (sender, receiver) = oneshot::channel();
        finish_encoded(
            sender,
            value,
            if expired { Instant::now() } else { until() },
            Some(&lease),
        );
        if expired {
            assert!(receiver.blocking_recv().is_err());
        } else {
            let reply = receiver.blocking_recv().unwrap();
            let envelope: Value = serde_json::from_slice(&reply.bytes).unwrap();
            assert_eq!(
                envelope["error"]["code"],
                if committed {
                    "COMMITTED_BUT_UNAVAILABLE"
                } else {
                    "LIMIT"
                }
            );
        }
        drop(lease);
    }
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    let lane = snapshot.lanes[0];
    assert_eq!(lane.intervals[3].distribution.not_reached.0, 3);
    assert_eq!(lane.intervals[4].distribution.completed.0, 3);
    assert_eq!(lane.intervals[5].distribution.completed.0, 3);
    assert_eq!(lane.active.0, 0);
}

#[test]
fn shutdown_releases_queue_locks_before_the_last_lease_aggregates() {
    use crate::intake::Class;
    use crate::lifecycle::{Lane, Registry};
    for lane in ["actor", "control", "reader", "all"] {
        let registry = Arc::new(Registry::new());
        let intake = diagnostic_intake(&registry, Class::Data, Lane::Data);
        let (mut pending, receiver) = job(2, 3, 1, false);
        pending._reservation = Some(diagnostic_lease(&intake));
        pending.enqueued();
        let key = pending.key.clone();
        let mut state = State {
            closed: false,
            actors: BTreeMap::new(),
            controls: vec![Control::default()],
            readers: Readers {
                live: 1,
                ..Readers::default()
            },
            usage: Usage::default(),
        };
        state.usage.add(&pending);
        match lane {
            "actor" | "all" => {
                let mut jobs = DatabaseQueue::default();
                jobs.push(pending);
                state.actors.insert(
                    key.clone(),
                    Actor {
                        slot: 0,
                        tenant: (1, 2),
                        phase: Phase::Running,
                        jobs,
                        changed: Arc::new(Condvar::new()),
                        thread: None,
                    },
                );
            }
            "control" => state.controls[0].queue.push(pending),
            _ => state.readers.queue.push(pending),
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            reaping: Condvar::new(),
        });
        let guard = crate::lifecycle::tests::hold_aggregation(&registry);
        let closing = shared.clone();
        let thread = std::thread::spawn(move || match lane {
            "actor" => closing.close_actor(&key),
            "control" => closing.close_control(0),
            "reader" => closing.close_reader(),
            _ => closing.close(),
        });
        let result = receiver.blocking_recv().unwrap();
        let observed = shared
            .state
            .try_lock()
            .map(|state| {
                let closed = match lane {
                    "actor" => state.actors.values().next().unwrap().phase == Phase::Draining,
                    "control" => state.controls[0].closed,
                    "reader" => state.readers.closed,
                    _ => state.closed,
                };
                (closed, state.usage.all.total)
            })
            .ok();
        // Unblock aggregation before assertions so a regression cannot leave
        // a thread stranded while the test unwinds.
        drop(guard);
        thread.join().unwrap();
        assert_eq!(result.unwrap_err().code, "UNAVAILABLE");
        assert_eq!(observed, Some((true, 0)), "{lane}");
        assert_eq!(intake.available_permits(), 8);
        assert_eq!(registry.snapshot().lanes[0].released.0, 1);
    }
}

#[test]
fn encoded_jobs_validate_identity_and_never_fall_back_to_an_unbudgeted_worker() {
    use crate::intake::{Class, Intake};
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    struct Unmetered(Arc<AtomicUsize>);
    impl Worker for Unmetered {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!("legacy"))
        }
    }
    let executions = Arc::new(AtomicUsize::new(0));
    let count = executions.clone();
    let scheduler = Scheduler::new(
        limits(),
        Arc::new(move |_| Ok(Box::new(Unmetered(count.clone())))),
    )
    .unwrap();
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let intake = Arc::new(Intake::new(Class::Data, 4, 4096, None).unwrap());
    let output = pool.acquire(&principal(), true).unwrap();
    assert_eq!(
        scheduler
            .submit_encoded(
                principal(),
                query(3),
                until(),
                intake.acquire(&principal()).unwrap(),
                output
            )
            .err()
            .unwrap()
            .code,
        "DENIED"
    );
    let mut other = principal();
    other.tenant += 1;
    assert_eq!(
        scheduler
            .submit_encoded(
                principal(),
                query(3),
                until(),
                intake.acquire(&principal()).unwrap(),
                pool.acquire(&other, false).unwrap()
            )
            .err()
            .unwrap()
            .code,
        "DENIED"
    );
    let controls = Arc::new(Intake::new(Class::Control, 1, 4096, None).unwrap());
    assert_eq!(
        scheduler
            .submit_encoded(
                principal(),
                query(3),
                until(),
                controls.acquire(&principal()).unwrap(),
                pool.acquire(&principal(), false).unwrap()
            )
            .err()
            .unwrap()
            .code,
        "DENIED"
    );
    assert_eq!(usage(&pool), (0, 0, 0));
    let reply = scheduler
        .submit_encoded(
            principal(),
            query(3),
            until(),
            intake.acquire(&principal()).unwrap(),
            pool.acquire(&principal(), false).unwrap(),
        )
        .unwrap()
        .blocking_recv()
        .unwrap();
    assert_eq!(reply.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.bytes).unwrap()["error"]["code"],
        "UNAVAILABLE"
    );
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert_eq!(send(&scheduler, query(3)).unwrap(), "legacy");
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    scheduler.shared.close();
    assert_eq!(
        scheduler
            .submit_encoded(
                principal(),
                query(3),
                until(),
                intake.acquire(&principal()).unwrap(),
                pool.acquire(&principal(), false).unwrap()
            )
            .err()
            .unwrap()
            .code,
        "UNAVAILABLE"
    );
    drop(scheduler);
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(reply);
    assert_eq!(usage(&pool), (0, 0, 0));
    assert_eq!(intake.available_permits(), 4);
}

#[test]
fn expired_admission_never_allocates_an_actor_or_retains_output_and_intake() {
    use crate::intake::{Class, Intake};
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    let created = Arc::new(AtomicUsize::new(0));
    let observed = created.clone();
    let actor_limit = limits().active_database_actors;
    let scheduler = Scheduler::new(
        limits(),
        Arc::new(move |index| {
            if index < actor_limit {
                observed.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Box::new(Echo::new(index)))
        }),
    )
    .unwrap();
    for action in [
        Action::Query { statements: vec![] },
        Action::Open {},
        Action::Lookup {
            request: Identity {
                epoch: Decimal(1),
                id: Decimal(1),
                principal: Decimal(3),
                fingerprint: "a".repeat(64),
            },
        },
        Action::Cancel {
            request: Identity {
                epoch: Decimal(1),
                id: Decimal(1),
                principal: Decimal(3),
                fingerprint: "a".repeat(64),
            },
        },
    ] {
        assert_eq!(
            scheduler
                .submit(principal(), data(10, action), Instant::now())
                .unwrap_err()
                .code,
            "DEADLINE"
        );
    }
    let pool = small_pool(2 * BASE_BYTES, 2 * BASE_BYTES);
    let intake = Arc::new(Intake::new(Class::Data, 4, 4096, None).unwrap());
    assert_eq!(
        scheduler
            .submit_encoded(
                principal(),
                query(10),
                Instant::now(),
                intake.acquire(&principal()).unwrap(),
                pool.acquire(&principal(), false).unwrap(),
            )
            .err()
            .unwrap()
            .code,
        "DEADLINE"
    );
    assert_eq!(usage(&pool), (0, 0, 0));
    assert_eq!(intake.available_permits(), 4);
    assert_eq!(created.load(Ordering::SeqCst), 0);
    {
        let state = lock(&scheduler.shared.state);
        assert!(state.actors.is_empty());
        assert_eq!(state.usage.all.total, 0);
        assert!(state.usage.tenants.is_empty() && state.usage.databases.is_empty());
    }
    send(&scheduler, query(10)).unwrap();
    assert_eq!(created.load(Ordering::SeqCst), 1);
}

#[test]
fn admission_mutex_wait_cannot_extend_the_original_request_deadline() {
    let scheduler = Arc::new(Scheduler::new(limits(), factory()).unwrap());
    let state = lock(&scheduler.shared.state);
    let deadline = Instant::now() + Duration::from_secs(1);
    let request = scheduler.clone();
    let (entered, started) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        entered.send(()).unwrap();
        request.submit(principal(), query(10), deadline)
    });
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    drop(state);
    assert_eq!(thread.join().unwrap().unwrap_err().code, "DEADLINE");
    let state = lock(&scheduler.shared.state);
    assert!(state.actors.is_empty());
    assert_eq!(state.usage.all.total, 0);
}

#[test]
fn queued_expiration_and_response_loss_release_only_their_owned_output() {
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    let pool = small_pool(2 * BASE_BYTES, 2 * BASE_BYTES);
    let mut worker = SingleWorker::new(Box::new(Echo::new(0)));
    let (job, receiver) = encoded_job(&pool, until());
    drop(receiver);
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    worker.execute(job);
    assert_eq!(usage(&pool), (0, 0, 0));
    let (job, receiver) = encoded_job(&pool, Instant::now());
    worker.execute(job);
    assert!(receiver.blocking_recv().is_err());
    assert_eq!(usage(&pool), (0, 0, 0));
    let (job, receiver) = encoded_job(&pool, until());
    job.fail(Failure::new("UNAVAILABLE"));
    let reply = receiver.blocking_recv().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.bytes).unwrap()["error"]["code"],
        "UNAVAILABLE"
    );
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(reply);
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn send_boundary_uses_the_original_deadline_and_drops_failed_channel_backing() {
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    let pool = small_pool(2 * BASE_BYTES, 2 * BASE_BYTES);
    let before = Instant::now();
    let deadline = before + Duration::from_secs(5);
    for (closed, now) in [(false, before), (false, deadline), (true, before)] {
        let output = pool.acquire(&principal(), false).unwrap();
        let reply = crate::output::OwnedValue::new(Ok(json!(1)), output)
            .finish(deadline)
            .unwrap();
        let (sender, receiver) = oneshot::channel();
        let receiver = if closed {
            drop(receiver);
            None
        } else {
            Some(receiver)
        };
        send_before(sender, reply, deadline, now);
        if let Some(receiver) = receiver {
            let delivered = receiver.blocking_recv();
            assert_eq!(delivered.is_ok(), now < deadline);
            drop(delivered);
        }
        assert_eq!(usage(&pool), (0, 0, 0));
    }
}

fn send(scheduler: &Scheduler, call: Call) -> Result<Value, Failure> {
    receive(scheduler.submit(principal(), call, until()).unwrap())
}

/// Rc deliberately makes this Worker !Send; it is constructed and dropped
/// inside its actor. Both the type and thread assertions protect confinement.
struct Echo {
    index: usize,
    owner: ThreadId,
    local: Rc<()>,
}
impl Echo {
    fn new(index: usize) -> Self {
        Self {
            index,
            owner: std::thread::current().id(),
            local: Rc::new(()),
        }
    }
}
impl Worker for Echo {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        assert_eq!(self.owner, std::thread::current().id());
        assert_eq!(Rc::strong_count(&self.local), 1);
        Ok(json!({"worker":self.index,"database":call.scope.database.0}))
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        assert_eq!(self.owner, std::thread::current().id());
    }
}
fn factory() -> Factory {
    Arc::new(|index| Ok(Box::new(Echo::new(index))))
}

fn read_profile() -> ReadPool {
    ReadPool {
        workers: 2,
        active_per_tenant: 2,
        active_per_database: 2,
    }
}

#[test]
fn read_pool_is_explicit_bounded_and_validated_before_worker_creation() {
    let enabled = read_profile();
    enabled.validate(limits()).unwrap();
    let mut invalid = limits();
    invalid.control_workers = 0;
    assert_eq!(enabled.validate(invalid).unwrap_err().code, "CONFIG");
    for change in [
        |v: &mut ReadPool| v.workers = 0,
        |v: &mut ReadPool| v.workers = 253,
        |v: &mut ReadPool| v.active_per_tenant = 0,
        |v: &mut ReadPool| v.active_per_tenant = 3,
        |v: &mut ReadPool| v.active_per_database = 0,
        |v: &mut ReadPool| v.active_per_database = 3,
    ] {
        let mut profile = enabled;
        change(&mut profile);
        assert_eq!(
            error(Scheduler::with_read_pool(
                limits(),
                Some(profile),
                factory()
            )),
            "CONFIG"
        );
    }
    let scheduler = Scheduler::with_read_pool(limits(), None, factory()).unwrap();
    assert_eq!(send(&scheduler, query(3)).unwrap()["worker"], 0);
    assert!(scheduler.readers.is_empty());
    let scheduler = Scheduler::with_read_pool(limits(), Some(enabled), factory()).unwrap();
    assert!(
        send(&scheduler, query(3)).unwrap()["worker"]
            .as_u64()
            .unwrap()
            >= 3
    );
    assert!(lock(&scheduler.shared.state).actors.is_empty());
}

#[test]
fn read_pool_partial_startup_and_thread_failures_clean_up_started_workers() {
    fn fail_reader(name: &str, task: Task) -> std::io::Result<JoinHandle<()>> {
        if name == "scap-query" {
            fail_spawn(name, task)
        } else {
            spawn(name, task)
        }
    }
    assert_eq!(
        error(Scheduler::with_read_spawner(
            limits(),
            Some(read_profile()),
            factory(),
            fail_reader,
        )),
        "UNAVAILABLE"
    );
    for panic in [false, true] {
        let factory: Factory = Arc::new(move |index| {
            if index == 4 {
                assert!(!panic, "controlled reader startup panic");
                Err(Failure::new("STARTUP"))
            } else {
                Ok(Box::new(Echo::new(index)))
            }
        });
        assert_eq!(
            error(Scheduler::with_read_pool(
                limits(),
                Some(read_profile()),
                factory
            )),
            if panic { "UNAVAILABLE" } else { "STARTUP" }
        );
    }
}

#[test]
fn eligible_read_queue_rotates_tenants_and_databases_without_losing_blocked_jobs() {
    let mut queue = Queue::default();
    assert!(queue.pop_eligible(|_, _| true).is_none());
    for (tenant, database, id) in [(1, 1, 1), (1, 1, 2), (1, 2, 3), (2, 1, 4)] {
        queue.push(job(tenant, database, id, false).0);
    }
    assert!(queue.pop_eligible(|_, _| false).is_none());
    assert_eq!(
        label(queue.pop_eligible(|tenant, _| tenant.1 == 2).unwrap()),
        (2, 1, 4)
    );
    let blocked = job(1, 1, 9, false).0.key;
    assert_eq!(
        label(queue.pop_eligible(|_, key| key != blocked).unwrap()),
        (1, 2, 3)
    );
    assert_eq!(label(queue.pop_eligible(|_, _| true).unwrap()), (1, 1, 1));
    assert_eq!(label(queue.pop_eligible(|_, _| true).unwrap()), (1, 1, 2));
    assert!(queue.pop().is_none());
}

type ReadStarted = (u64, u64, usize);
type ReadFixture = (
    Factory,
    mpsc::Receiver<ReadStarted>,
    Vec<mpsc::SyncSender<()>>,
);

fn read_blocking_factory(workers: usize) -> ReadFixture {
    struct BlockRead {
        echo: Echo,
        entered: mpsc::SyncSender<ReadStarted>,
        wait: Arc<Mutex<mpsc::Receiver<()>>>,
    }
    impl Worker for BlockRead {
        fn execute(
            &mut self,
            principal: &Principal,
            call: Call,
            deadline: Instant,
        ) -> Result<Value, Failure> {
            if matches!(call.action, Action::Query { .. }) {
                self.entered
                    .send((principal.tenant, call.scope.database.0, self.echo.index))
                    .unwrap();
                lock(&self.wait)
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            self.echo.execute(principal, call, deadline)
        }
    }
    let (entered, started) = mpsc::sync_channel(16);
    let mut releases = Vec::new();
    let waits: Vec<_> = (0..workers)
        .map(|_| {
            let (release, wait) = mpsc::sync_channel(8);
            releases.push(release);
            Arc::new(Mutex::new(wait))
        })
        .collect();
    let factory: Factory = Arc::new(move |index| {
        if index < 3 {
            Ok(Box::new(Echo::new(index)))
        } else {
            Ok(Box::new(BlockRead {
                echo: Echo::new(index),
                entered: entered.clone(),
                wait: waits[index - 3].clone(),
            }))
        }
    });
    (factory, started, releases)
}

fn started(reads: &mpsc::Receiver<ReadStarted>) -> ReadStarted {
    reads.recv_timeout(Duration::from_secs(5)).unwrap()
}

fn finish_reads(scheduler: &Scheduler) {
    let state = lock(&scheduler.shared.state);
    let changed = state.readers.changed.clone();
    let (state, timeout) = changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| {
            !state.readers.tenants.is_empty()
        })
        .unwrap();
    assert!(!timeout.timed_out());
    assert!(state.readers.databases.is_empty());
}

#[test]
fn same_database_reads_overlap_while_writer_and_control_workers_remain_available() {
    let (factory, entered, release) = read_blocking_factory(2);
    let scheduler = Scheduler::with_read_pool(limits(), Some(read_profile()), factory).unwrap();
    let first = scheduler.submit(principal(), query(10), until()).unwrap();
    let second = scheduler.submit(principal(), query(10), until()).unwrap();
    let one = started(&entered);
    let two = started(&entered);
    assert_ne!(one.2, two.2);
    assert_eq!((one.1, two.1), (10, 10));
    assert!(lock(&scheduler.shared.state).actors.is_empty());
    assert_eq!(
        send(&scheduler, data(10, Action::Create { nonce: Decimal(1) })).unwrap()["worker"],
        0
    );
    assert_eq!(
        send(
            &scheduler,
            data(
                10,
                Action::Status {
                    expected_worker_instance: None
                }
            )
        )
        .unwrap()["worker"],
        2
    );
    let queued = scheduler.submit(principal(), query(10), until()).unwrap();
    let queued_again = scheduler.submit(principal(), query(10), until()).unwrap();
    // Both native workers are parked before either queued request is offered.
    // Starting the third call must retain the fourth in the real Readers::pop
    // queue, independently of which worker wins an unblocked thread race.
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 2);
    release[one.2 - 3].send(()).unwrap();
    let three = started(&entered);
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 1);
    release[two.2 - 3].send(()).unwrap();
    let four = started(&entered);
    assert_eq!((three.1, four.1), (10, 10));
    assert_ne!(three.2, four.2);
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
    release[three.2 - 3].send(()).unwrap();
    release[four.2 - 3].send(()).unwrap();
    for receiver in [first, second, queued, queued_again] {
        receive(receiver).unwrap();
    }
    finish_reads(&scheduler);
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
}

#[test]
fn active_read_caps_preserve_other_databases_and_other_tenants() {
    for tenant_cap in [1, 2] {
        let (factory, entered, release) = read_blocking_factory(2);
        let profile = ReadPool {
            active_per_tenant: tenant_cap,
            active_per_database: 1,
            ..read_profile()
        };
        let scheduler = Scheduler::with_read_pool(limits(), Some(profile), factory).unwrap();
        let first = scheduler.submit(principal(), query(10), until()).unwrap();
        let one = started(&entered);
        let blocked = scheduler
            .submit(
                principal(),
                query(if tenant_cap == 1 { 11 } else { 10 }),
                until(),
            )
            .unwrap();
        let mut other = principal();
        if tenant_cap == 1 {
            other.tenant += 1;
        }
        let mut other_call = query(20);
        other_call.scope.tenant.0 = other.tenant;
        let third = scheduler.submit(other, other_call, until()).unwrap();
        let two = started(&entered);
        assert_eq!(two.1, 20);
        assert_eq!(lock(&scheduler.shared.state).usage.all.total, 1);
        release[one.2 - 3].send(()).unwrap();
        let three = started(&entered);
        assert_eq!(three.1, if tenant_cap == 1 { 11 } else { 10 });
        release[two.2 - 3].send(()).unwrap();
        release[three.2 - 3].send(()).unwrap();
        for receiver in [first, blocked, third] {
            receive(receiver).unwrap();
        }
        finish_reads(&scheduler);
    }
}

#[test]
fn read_pool_shutdown_drains_queued_work_and_joins_the_running_query() {
    let (factory, entered, release) = read_blocking_factory(1);
    let profile = ReadPool {
        workers: 1,
        active_per_tenant: 1,
        active_per_database: 1,
    };
    let scheduler = Scheduler::with_read_pool(limits(), Some(profile), factory).unwrap();
    let first = scheduler.submit(principal(), query(10), until()).unwrap();
    started(&entered);
    let queued = scheduler.submit(principal(), query(10), until()).unwrap();
    let shared = scheduler.shared.clone();
    let (done, completed) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        drop(scheduler);
        done.send(()).unwrap();
    });
    assert_eq!(receive(queued).unwrap_err().code, "UNAVAILABLE");
    assert_eq!(lock(&shared.state).readers.tenants.len(), 1);
    assert!(matches!(
        completed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release[0].send(()).unwrap();
    receive(first).unwrap();
    completed.recv_timeout(Duration::from_secs(5)).unwrap();
    thread.join().unwrap();
    assert!(lock(&shared.state).readers.tenants.is_empty());
}

#[test]
fn failed_reader_keeps_active_reservations_until_native_drop_and_never_reroutes() {
    struct PanicRead {
        entered: mpsc::SyncSender<()>,
        panic_now: mpsc::Receiver<()>,
        dropping: mpsc::SyncSender<()>,
        cleanup: mpsc::Receiver<()>,
    }
    impl Worker for PanicRead {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            self.entered.send(()).unwrap();
            self.panic_now.recv_timeout(Duration::from_secs(5)).unwrap();
            panic!("controlled running query panic");
        }
    }
    impl Drop for PanicRead {
        fn drop(&mut self) {
            self.dropping.send(()).unwrap();
            self.cleanup.recv_timeout(Duration::from_secs(5)).unwrap();
        }
    }
    let (entered, started) = mpsc::sync_channel(1);
    let (panic_now, panic_receiver) = mpsc::sync_channel(1);
    let (dropping, drop_started) = mpsc::sync_channel(1);
    let (cleanup, cleanup_receiver) = mpsc::sync_channel(1);
    let source = Arc::new(Mutex::new(Some((panic_receiver, cleanup_receiver))));
    let factory: Factory = Arc::new(move |index| {
        if index < 3 {
            return Ok(Box::new(Echo::new(index)));
        }
        let (panic_now, cleanup) = lock(&source).take().unwrap();
        Ok(Box::new(PanicRead {
            entered: entered.clone(),
            panic_now,
            dropping: dropping.clone(),
            cleanup,
        }))
    });
    let profile = ReadPool {
        workers: 1,
        active_per_tenant: 1,
        active_per_database: 1,
    };
    let scheduler = Scheduler::with_read_pool(limits(), Some(profile), factory).unwrap();
    let first = scheduler.submit(principal(), query(10), until()).unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let pending = scheduler.submit(principal(), query(10), until()).unwrap();
    panic_now.send(()).unwrap();
    drop_started.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(lock(&scheduler.shared.state).readers.tenants.len(), 1);
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 1);
    cleanup.send(()).unwrap();
    assert_eq!(receive(pending).unwrap_err().code, "UNAVAILABLE");
    assert!(first.blocking_recv().is_err());
    assert_eq!(
        scheduler
            .submit(principal(), query(10), until())
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
    finish_reads(&scheduler);
    assert!(lock(&scheduler.shared.state).actors.is_empty());
}

#[test]
fn single_request_panic_keeps_intake_and_output_until_worker_cleanup_in_every_lane() {
    use crate::intake::{Class, Intake};
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };

    struct PanicBudgeted {
        held: Option<String>,
        entered: mpsc::SyncSender<()>,
        panic_now: mpsc::Receiver<()>,
        dropping: mpsc::SyncSender<()>,
        cleanup: mpsc::Receiver<()>,
    }
    impl Worker for PanicBudgeted {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            unreachable!("encoded work must stay budgeted")
        }

        fn execute_budgeted(
            &mut self,
            _: &Principal,
            _: Call,
            _: Instant,
            output: &mut crate::output::OutputContext,
        ) -> Result<Value, Failure> {
            // Retain a genuinely charged output allocation in the worker, so
            // early refund is observable while its backing is still alive.
            self.held = Some(output.base64(b"abc").unwrap());
            self.entered.send(()).unwrap();
            self.panic_now.recv_timeout(Duration::from_secs(5)).unwrap();
            panic!("controlled single-request worker failure");
        }
    }
    impl Drop for PanicBudgeted {
        fn drop(&mut self) {
            let _ = self.dropping.send(());
            let _ = self.cleanup.recv_timeout(Duration::from_secs(5));
        }
    }

    for (lane, index) in [("actor", 0), ("control", 2), ("reader", 3)] {
        for disconnected in [false, true] {
            let registry = Arc::new(crate::lifecycle::Registry::new());
            let (entered, started) = mpsc::sync_channel(1);
            let (panic_now, panic_receiver) = mpsc::sync_channel(1);
            let (dropping, drop_started) = mpsc::sync_channel(1);
            let (cleanup, cleanup_receiver) = mpsc::sync_channel(1);
            let source = Arc::new(Mutex::new(Some((panic_receiver, cleanup_receiver))));
            let factory: Factory = Arc::new(move |slot| {
                if slot != index {
                    return Ok(Box::new(Echo::new(slot)));
                }
                let (panic_now, cleanup) = lock(&source).take().unwrap();
                Ok(Box::new(PanicBudgeted {
                    held: None,
                    entered: entered.clone(),
                    panic_now,
                    dropping: dropping.clone(),
                    cleanup,
                }))
            });
            let scheduler = Scheduler::with_read_pool(
                limits(),
                Some(ReadPool {
                    workers: 1,
                    active_per_tenant: 1,
                    active_per_database: 1,
                }),
                factory,
            )
            .unwrap();
            let control = lane == "control";
            let intake = Arc::new(
                Intake::new(
                    if control { Class::Control } else { Class::Data },
                    1,
                    4096,
                    None,
                )
                .unwrap()
                .with_lifecycle(
                    registry.clone(),
                    if control {
                        crate::lifecycle::Lane::Control
                    } else {
                        crate::lifecycle::Lane::Data
                    },
                )
                .unwrap(),
            );
            let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
            let call = match lane {
                "actor" => data(10, Action::Create { nonce: Decimal(1) }),
                "control" => data(
                    10,
                    Action::Status {
                        expected_worker_instance: None,
                    },
                ),
                _ => query(10),
            };
            let receiver = scheduler
                .submit_encoded(
                    principal(),
                    call,
                    until(),
                    diagnostic_lease(&intake),
                    pool.acquire(&principal(), control).unwrap(),
                )
                .unwrap();
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut receiver = Some(receiver);
            if disconnected {
                drop(receiver.take());
            }
            panic_now.send(()).unwrap();
            drop_started.recv_timeout(Duration::from_secs(5)).unwrap();
            // Observe during the blocked native/cache destructor, then unblock
            // it before asserting so a red regression cannot strand a thread.
            let permits_during_cleanup = intake.available_permits();
            let output_during_cleanup = usage(&pool);
            let read_credits_during_cleanup = lock(&scheduler.shared.state).readers.tenants.len();
            let diagnostic_during_cleanup = registry.snapshot();
            cleanup.send(()).unwrap();
            drop(scheduler);
            if let Some(receiver) = receiver {
                assert!(receiver.blocking_recv().is_err());
            }
            assert_eq!(
                permits_during_cleanup, 0,
                "{lane}, disconnected={disconnected}: intake refunded before worker cleanup"
            );
            assert_eq!(
                output_during_cleanup.0 + output_during_cleanup.1,
                BASE_BYTES + 4,
                "{lane}, disconnected={disconnected}: output refunded before worker cleanup"
            );
            assert_eq!(read_credits_during_cleanup, usize::from(lane == "reader"));
            assert_eq!(intake.available_permits(), 1);
            assert_eq!(usage(&pool), (0, 0, 0));
            let lane_index = usize::from(control);
            assert_eq!(diagnostic_during_cleanup.lanes[lane_index].active.0, 1);
            assert_eq!(diagnostic_during_cleanup.lanes[lane_index].released.0, 0);
            let snapshot = registry.snapshot();
            assert!(snapshot.valid);
            let observed = snapshot.lanes[lane_index];
            assert_eq!((observed.active.0, observed.released.0), (0, 1));
            assert_eq!(observed.intervals[2].distribution.completed.0, 1);
            assert_eq!(observed.intervals[3].distribution.censored.0, 1);
            assert_eq!(observed.intervals[4].distribution.not_reached.0, 1);
            assert_eq!(observed.intervals[5].distribution.not_reached.0, 1);
        }
    }
}
fn fail_spawn(_: &str, _: Task) -> std::io::Result<JoinHandle<()>> {
    Err(std::io::Error::other("unit spawn fault"))
}
fn fail_reaper_spawn(name: &str, task: Task) -> std::io::Result<JoinHandle<()>> {
    if name == "scap-reaper" {
        fail_spawn(name, task)
    } else {
        spawn(name, task)
    }
}
fn error(result: Result<Scheduler, Failure>) -> &'static str {
    match result {
        Ok(_) => panic!("accepted invalid scheduler"),
        Err(error) => error.code,
    }
}

#[test]
fn every_scheduler_capacity_is_explicit_and_validated_before_spawning() {
    for change in [
        |v: &mut Limits| v.active_database_actors = 0,
        |v: &mut Limits| v.active_database_actors = 256,
        |v: &mut Limits| v.active_database_actors_per_tenant = 0,
        |v: &mut Limits| v.active_database_actors_per_tenant = 3,
        |v: &mut Limits| v.actor_idle_timeout = Duration::ZERO,
        |v: &mut Limits| v.actor_idle_timeout = Duration::from_secs(86401),
        |v: &mut Limits| v.control_workers = 0,
        |v: &mut Limits| v.control_workers = 255,
        |v: &mut Limits| v.queued_total = 0,
        |v: &mut Limits| v.queued_total = 65537,
        |v: &mut Limits| v.queued_per_tenant = 0,
        |v: &mut Limits| v.queued_per_tenant = 33,
        |v: &mut Limits| v.queued_per_database = 0,
        |v: &mut Limits| v.queued_per_database = 17,
        |v: &mut Limits| v.reserved_controls = 0,
        |v: &mut Limits| v.reserved_controls = 8,
    ] {
        let mut value = limits();
        change(&mut value);
        assert_eq!(error(Scheduler::new(value, factory())), "CONFIG");
    }
    assert_eq!(
        error(Scheduler::with_spawner(limits(), factory(), fail_spawn)),
        "UNAVAILABLE"
    );
    assert_eq!(
        error(Scheduler::with_spawner(
            limits(),
            factory(),
            fail_reaper_spawn
        )),
        "UNAVAILABLE"
    );
    assert_eq!(
        error(Scheduler::new(
            limits(),
            Arc::new(|_| Err(Failure::new("STARTUP")))
        )),
        "STARTUP"
    );
    assert_eq!(
        error(Scheduler::new(
            limits(),
            Arc::new(|_| panic!("factory fault"))
        )),
        "UNAVAILABLE"
    );
    let mut value = limits();
    value.control_workers = 2;
    assert_eq!(
        error(Scheduler::new(
            value,
            Arc::new(|index| {
                if index == 3 {
                    Err(Failure::new("PARTIAL"))
                } else {
                    Ok(Box::new(Echo::new(index)))
                }
            })
        )),
        "PARTIAL"
    );
}

#[test]
fn controls_rotate_tenants_and_databases_and_priority_bursts_do_not_starve_sql() {
    let mut queue = Queue::default();
    assert!(queue.pop().is_none());
    for (tenant, database, id) in [(1, 1, 1), (1, 1, 2), (1, 2, 3), (2, 1, 4), (2, 2, 5)] {
        queue.push(job(tenant, database, id, true).0);
    }
    let ordered: Vec<_> = std::iter::from_fn(|| queue.pop().map(label)).collect();
    assert_eq!(
        ordered,
        [(1, 1, 1), (2, 1, 4), (1, 2, 3), (2, 2, 5), (1, 1, 2)]
    );
    let mut queue = DatabaseQueue::default();
    for id in 1..=4 {
        queue.push(job(1, 1, id, true).0);
    }
    queue.push(job(1, 1, 5, false).0);
    assert!(!queue.empty());
    assert_eq!(
        std::iter::from_fn(|| queue.pop().map(|job| label(job).2)).collect::<Vec<_>>(),
        [1, 2, 3, 5, 4]
    );
    assert!(queue.empty());
    for id in 1..=5 {
        queue.push(job(1, 1, id, true).0);
    }
    assert_eq!(
        std::iter::from_fn(|| queue.pop().map(|job| label(job).2)).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
}

fn admit(usage: &mut Usage, job: &Job) -> Result<(), Failure> {
    usage.check(job, limits())?;
    usage.add(job);
    Ok(())
}

#[test]
fn queue_diagnostics_capture_charged_credits_at_the_first_failing_partition() {
    use crate::tests::assert_budget;
    for (budget, scope, control, maximum) in [
        (Budget::QueueDatabaseData, 0, false, 6),
        (Budget::QueueDatabaseTotal, 0, true, 8),
        (Budget::QueueTenantData, 1, false, 14),
        (Budget::QueueTenantTotal, 1, true, 16),
        (Budget::QueueGlobalData, 2, false, 30),
        (Budget::QueueGlobalTotal, 2, true, 32),
    ] {
        let mut usage = Usage::default();
        let mut charged = Vec::new();
        for index in 0..maximum {
            let tenant = if scope == 2 { index + 1 } else { 1 };
            let database = if scope == 1 { index / 6 + 1 } else { 1 };
            let admitted = job(tenant, database, index + 1, control).0;
            admit(&mut usage, &admitted).unwrap();
            charged.push(admitted);
        }
        let rejected = job(1, 1, maximum + 1, control).0;
        let error = usage.check(&rejected, limits()).unwrap_err();
        assert_budget(&error, budget, maximum, maximum, 1);
        for admitted in charged {
            usage.remove(&admitted);
        }
        assert_eq!(usage.all.total, 0);
        assert_budget(&error, budget, maximum, maximum, 1);
    }
}

#[test]
fn queue_budgets_are_global_across_lanes_and_recovery_cannot_take_control_reservations() {
    let mut usage = Usage::default();
    let mut jobs = Vec::new();
    for id in 1..=6 {
        let (job, _) = job(1, 1, id, false);
        admit(&mut usage, &job).unwrap();
        jobs.push(job);
    }
    assert_eq!(
        admit(&mut usage, &job(1, 1, 7, false).0).unwrap_err().code,
        "BACKPRESSURE"
    );
    let mut recovery = job(1, 1, 7, false).0;
    recovery.call.action = Action::Open {};
    assert_eq!(
        admit(&mut usage, &recovery).unwrap_err().code,
        "BACKPRESSURE"
    );
    for id in 7..=8 {
        let (job, _) = job(1, 1, id, true);
        admit(&mut usage, &job).unwrap();
        jobs.push(job);
    }
    assert!(admit(&mut usage, &job(1, 1, 9, true).0).is_err());
    for id in 1..=8 {
        let (job, _) = job(1, 2, id, true);
        admit(&mut usage, &job).unwrap();
        jobs.push(job);
    }
    assert!(admit(&mut usage, &job(1, 3, 1, true).0).is_err());
    for job in jobs {
        usage.remove(&job);
    }
    assert_eq!(usage.all.total, 0);
    assert!(usage.tenants.is_empty() && usage.databases.is_empty());
    for id in 0..14 {
        admit(&mut usage, &job(1, id / 6 + 1, id + 1, false).0).unwrap();
    }
    assert!(admit(&mut usage, &job(1, 4, 15, false).0).is_err());
    admit(&mut usage, &job(1, 4, 15, true).0).unwrap();
    admit(&mut usage, &job(1, 4, 16, true).0).unwrap();
    let mut usage = Usage::default();
    for id in 1..=30 {
        admit(&mut usage, &job(id, 1, 1, false).0).unwrap();
    }
    assert!(admit(&mut usage, &job(31, 1, 1, false).0).is_err());
    admit(&mut usage, &job(31, 1, 1, true).0).unwrap();
    admit(&mut usage, &job(32, 1, 1, true).0).unwrap();
    assert!(admit(&mut usage, &job(33, 1, 1, true).0).is_err());
}

struct Blocking {
    echo: Echo,
    entered: mpsc::SyncSender<()>,
    wait: Arc<Mutex<mpsc::Receiver<()>>>,
    calls: Arc<AtomicUsize>,
}
impl Worker for Blocking {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(call.action, Action::Open {}) {
            self.entered.send(()).unwrap();
            lock(&self.wait)
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        self.echo.execute(principal, call, deadline)
    }
}

fn blocking_factory() -> (
    Factory,
    mpsc::Receiver<()>,
    mpsc::SyncSender<()>,
    Arc<AtomicUsize>,
) {
    let (entered, started) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(wait));
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let factory: Factory = Arc::new(move |index| {
        Ok(Box::new(Blocking {
            echo: Echo::new(index),
            entered: entered.clone(),
            wait: wait.clone(),
            calls: count.clone(),
        }))
    });
    (factory, started, release, calls)
}

#[test]
fn cold_database_does_not_block_a_warm_database_and_capacity_does_not_block_controls() {
    let (factory, entered, release, _) = blocking_factory();
    let scheduler = Scheduler::new(limits(), factory).unwrap();
    let warm = send(&scheduler, query(20)).unwrap();
    let cold = scheduler
        .submit(principal(), data(10, Action::Open {}), until())
        .unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut same_database = scheduler.submit(principal(), query(10), until()).unwrap();
    assert!(matches!(
        same_database.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(send(&scheduler, query(20)).unwrap(), warm);
    crate::tests::assert_budget(
        &scheduler
            .submit(principal(), query(30), until())
            .unwrap_err(),
        Budget::ActorsGlobal,
        2,
        2,
        1,
    );
    assert_eq!(
        send(
            &scheduler,
            data(
                30,
                Action::Status {
                    expected_worker_instance: None
                }
            )
        )
        .unwrap()["worker"],
        2
    );
    release.send(()).unwrap();
    assert_eq!(
        receive(cold).unwrap()["worker"],
        receive(same_database).unwrap()["worker"]
    );
    assert_eq!(lock(&scheduler.shared.state).actors.len(), 2);
}

#[test]
fn per_tenant_actor_cap_preserves_slots_for_other_tenants() {
    let mut value = limits();
    value.active_database_actors_per_tenant = 1;
    let scheduler = Scheduler::new(value, factory()).unwrap();
    send(&scheduler, query(10)).unwrap();
    crate::tests::assert_budget(
        &scheduler
            .submit(principal(), query(20), until())
            .unwrap_err(),
        Budget::ActorsTenant,
        1,
        1,
        1,
    );
    let mut other = principal();
    other.tenant = 7;
    let mut call = query(20);
    call.scope.tenant.0 = 7;
    receive(scheduler.submit(other, call, until()).unwrap()).unwrap();
    send(&scheduler, query(10)).unwrap();
    assert_eq!(lock(&scheduler.shared.state).actors.len(), 2);
}

#[test]
fn concurrent_first_calls_share_one_starting_actor_without_holding_the_registry_lock() {
    let (entered, started) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(wait));
    let created = Arc::new(AtomicUsize::new(0));
    let count = created.clone();
    let factory: Factory = Arc::new(move |index| {
        if index < 2 {
            count.fetch_add(1, Ordering::SeqCst);
            entered.send(()).unwrap();
            lock(&wait).recv_timeout(Duration::from_secs(5)).unwrap();
        }
        Ok(Box::new(Echo::new(index)))
    });
    let mut value = limits();
    value.queued_total = 64;
    value.queued_per_tenant = 32;
    value.queued_per_database = 10;
    let scheduler = Arc::new(Scheduler::new(value, factory).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|generation| {
            let scheduler = scheduler.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut call = query(10);
                call.scope.generation.0 = generation + 1;
                scheduler.submit(principal(), call, until()).unwrap()
            })
        })
        .collect();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let replies: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(created.load(Ordering::SeqCst), 1);
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 8);
    crate::tests::assert_budget(
        &scheduler
            .submit(principal(), query(10), until())
            .unwrap_err(),
        Budget::QueueDatabaseData,
        8,
        8,
        1,
    );
    send(
        &scheduler,
        data(
            10,
            Action::Status {
                expected_worker_instance: None,
            },
        ),
    )
    .unwrap();
    release.send(()).unwrap();
    for reply in replies {
        assert_eq!(receive(reply).unwrap()["worker"], 0);
    }
    assert_eq!(lock(&scheduler.shared.state).actors.len(), 1);
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
}

#[test]
fn deadlines_abandoned_waiters_and_shutdown_do_not_replay_jobs() {
    let (factory, entered, release, calls) = blocking_factory();
    let scheduler = Scheduler::new(limits(), factory).unwrap();
    let first = scheduler
        .submit(principal(), data(10, Action::Open {}), until())
        .unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let cancelled = scheduler.submit(principal(), query(10), until()).unwrap();
    drop(cancelled);
    let deadline = Instant::now() + Duration::from_secs(1);
    let expired = scheduler.submit(principal(), query(10), deadline).unwrap();
    let queued = scheduler.submit(principal(), query(10), until()).unwrap();
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    release.send(()).unwrap();
    receive(first).unwrap();
    assert_eq!(receive(expired).unwrap_err().code, "DEADLINE");
    receive(queued).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let first = scheduler
        .submit(principal(), data(10, Action::Open {}), until())
        .unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let pending = scheduler.submit(principal(), query(10), until()).unwrap();
    scheduler.shared.close();
    assert_eq!(receive(pending).unwrap_err().code, "UNAVAILABLE");
    assert_eq!(
        scheduler
            .submit(principal(), query(10), until())
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
    release.send(()).unwrap();
    receive(first).unwrap();
    let mut invalid = query(10);
    invalid.scope.database.0 = 0;
    assert_eq!(
        scheduler
            .submit(principal(), invalid, until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    let mut denied = principal();
    denied.tenant = 7;
    assert_eq!(
        scheduler
            .submit(denied, query(10), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
}

struct SlowDrop {
    echo: Echo,
    entered: mpsc::SyncSender<()>,
    wait: mpsc::Receiver<()>,
}
impl Worker for SlowDrop {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.echo.execute(principal, call, deadline)
    }
}
impl Drop for SlowDrop {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.wait.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

fn wait_retired(scheduler: &Scheduler) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut state = lock(&scheduler.shared.state);
    while !state.actors.is_empty() {
        assert!(Instant::now() < deadline);
        state = scheduler
            .shared
            .reaping
            .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

#[test]
fn idle_actor_exits_without_new_requests_and_draining_slots_wait_for_native_drop() {
    let (entered, dropped) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(Some(wait)));
    let created = Arc::new(AtomicUsize::new(0));
    let count = created.clone();
    let factory: Factory = Arc::new(move |index| {
        if index == 0 {
            count.fetch_add(1, Ordering::SeqCst);
            if let Some(wait) = lock(&wait).take() {
                return Ok(Box::new(SlowDrop {
                    echo: Echo::new(index),
                    entered: entered.clone(),
                    wait,
                }));
            }
        }
        Ok(Box::new(Echo::new(index)))
    });
    let mut value = limits();
    value.active_database_actors = 1;
    value.active_database_actors_per_tenant = 1;
    value.actor_idle_timeout = Duration::from_millis(10);
    let scheduler = Scheduler::new(value, factory).unwrap();
    send(&scheduler, query(10)).unwrap();
    dropped.recv_timeout(Duration::from_secs(5)).unwrap();
    // No submit was needed to reach Drop. Neither same HEAD nor another HEAD
    // can reuse the still-live native owner; controls remain independent.
    let draining = scheduler
        .submit(principal(), query(10), until())
        .unwrap_err();
    assert_eq!(draining.code, "BACKPRESSURE");
    assert_eq!(
        draining.rejection(),
        Some(crate::rejection::Rejection::Source(Source::ActorDraining))
    );
    assert_eq!(
        scheduler
            .submit(principal(), query(20), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(
        send(
            &scheduler,
            data(
                10,
                Action::Status {
                    expected_worker_instance: None
                }
            )
        )
        .unwrap()["worker"],
        1
    );
    release.send(()).unwrap();
    wait_retired(&scheduler);
    send(&scheduler, query(10)).unwrap();
    assert_eq!(created.load(Ordering::SeqCst), 2);
}

struct ThreadExitGate {
    entered: mpsc::SyncSender<()>,
    wait: mpsc::Receiver<()>,
}
impl Drop for ThreadExitGate {
    fn drop(&mut self) {
        // Never panic inside a TLS destructor, even if the assertion thread
        // has already failed. The caller checks the gated ordering directly.
        let _ = self.entered.send(());
        let _ = self.wait.recv_timeout(Duration::from_secs(5));
    }
}
thread_local! {
    static THREAD_EXIT: std::cell::RefCell<Option<ThreadExitGate>> = const { std::cell::RefCell::new(None) };
}

#[test]
fn first_request_never_joins_thread_local_cleanup_and_old_slots_stay_reserved() {
    let (entered, exiting) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(Some(wait)));
    let factory: Factory = Arc::new(move |index| {
        if index == 0 {
            if let Some(wait) = lock(&wait).take() {
                THREAD_EXIT.with(|slot| {
                    *slot.borrow_mut() = Some(ThreadExitGate {
                        entered: entered.clone(),
                        wait,
                    });
                });
            }
        }
        Ok(Box::new(Echo::new(index)))
    });
    let mut value = limits();
    value.actor_idle_timeout = Duration::from_millis(100);
    let scheduler = Scheduler::new(value, factory).unwrap();
    send(&scheduler, query(10)).unwrap();
    exiting.recv_timeout(Duration::from_secs(5)).unwrap();
    // This is the FIRST submit after the actor's main function returned.
    // It must not inherit TLS join work on the HTTP/request thread.
    let first = std::thread::scope(|scope| {
        let (sent, submitted) = mpsc::sync_channel(1);
        let scheduler = &scheduler;
        scope.spawn(move || {
            sent.send(scheduler.submit(
                principal(),
                data(
                    10,
                    Action::Status {
                        expected_worker_instance: None,
                    },
                ),
                until(),
            ))
            .unwrap();
        });
        submitted
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap()
    });
    receive(first).unwrap();
    send(&scheduler, query(20)).unwrap();
    send(&scheduler, query(20)).unwrap();
    let draining = scheduler
        .submit(principal(), query(10), until())
        .unwrap_err();
    assert_eq!(draining.code, "BACKPRESSURE");
    assert_eq!(
        draining.rejection(),
        Some(crate::rejection::Rejection::Source(Source::ActorDraining))
    );
    crate::tests::assert_budget(
        &scheduler
            .submit(principal(), query(30), until())
            .unwrap_err(),
        Budget::ActorsGlobal,
        2,
        2,
        1,
    );
    send(
        &scheduler,
        data(
            10,
            Action::Status {
                expected_worker_instance: None,
            },
        ),
    )
    .unwrap();
    release.send(()).unwrap();
    wait_retired(&scheduler);
    send(&scheduler, query(10)).unwrap();
}

#[test]
fn actor_start_failures_release_reservations_and_do_not_disable_control_workers() {
    let mut scheduler = Scheduler::new(limits(), factory()).unwrap();
    scheduler.spawn = fail_spawn;
    assert_eq!(
        scheduler
            .submit(principal(), query(10), until())
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
    assert!(lock(&scheduler.shared.state).actors.is_empty());
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
    send(
        &scheduler,
        data(
            10,
            Action::Status {
                expected_worker_instance: None,
            },
        ),
    )
    .unwrap();
    scheduler.spawn = spawn;
    scheduler.factory = Arc::new(|_| Err(Failure::new("FACTORY")));
    assert_eq!(send(&scheduler, query(10)).unwrap_err().code, "UNAVAILABLE");
    wait_retired(&scheduler);
    scheduler.factory = Arc::new(|_| panic!("actor factory panic"));
    assert_eq!(send(&scheduler, query(10)).unwrap_err().code, "UNAVAILABLE");
    wait_retired(&scheduler);
    scheduler.factory = factory();
    send(&scheduler, query(10)).unwrap();
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
}

struct PanicWorker {
    entered: mpsc::SyncSender<()>,
    wait: Arc<Mutex<mpsc::Receiver<()>>>,
}
impl Worker for PanicWorker {
    fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
        self.entered.send(()).unwrap();
        lock(&self.wait)
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        panic!("unit execute failure")
    }
}

#[test]
fn control_panic_fails_pending_jobs_and_actor_panic_never_replays_them() {
    for control in [false, true] {
        let (entered, started) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let wait = Arc::new(Mutex::new(wait));
        let factory: Factory = Arc::new(move |index| {
            if (index == 2) == control {
                Ok(Box::new(PanicWorker {
                    entered: entered.clone(),
                    wait: wait.clone(),
                }))
            } else {
                Ok(Box::new(Echo::new(index)))
            }
        });
        let mut scheduler = Scheduler::new(limits(), factory).unwrap();
        let make = || {
            if control {
                data(
                    10,
                    Action::Status {
                        expected_worker_instance: None,
                    },
                )
            } else {
                query(10)
            }
        };
        let first = scheduler.submit(principal(), make(), until()).unwrap();
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let pending = scheduler.submit(principal(), make(), until()).unwrap();
        release.send(()).unwrap();
        assert!(first.blocking_recv().is_err());
        assert_eq!(receive(pending).unwrap_err().code, "UNAVAILABLE");
        assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
        if control {
            assert!(scheduler.controls.remove(0).join().is_err());
            assert_eq!(
                scheduler
                    .submit(principal(), make(), until())
                    .unwrap_err()
                    .code,
                "UNAVAILABLE"
            );
            send(&scheduler, query(20)).unwrap();
        } else {
            wait_retired(&scheduler);
            send(
                &scheduler,
                data(
                    10,
                    Action::Status {
                        expected_worker_instance: None,
                    },
                ),
            )
            .unwrap();
        }
    }
}

#[test]
fn shutdown_drains_control_work_and_poisoned_registry_can_close_waiting_threads() {
    let (entered, started) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(wait));
    let blocked: Factory = Arc::new(move |_| {
        Ok(Box::new(PanicWorker {
            entered: entered.clone(),
            wait: wait.clone(),
        }))
    });
    let scheduler = Scheduler::new(limits(), blocked).unwrap();
    let first = scheduler
        .submit(
            principal(),
            data(
                10,
                Action::Status {
                    expected_worker_instance: None,
                },
            ),
            until(),
        )
        .unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let reply = scheduler
        .submit(
            principal(),
            data(
                10,
                Action::Status {
                    expected_worker_instance: None,
                },
            ),
            until(),
        )
        .unwrap();
    scheduler.shared.close();
    assert_eq!(receive(reply).unwrap_err().code, "UNAVAILABLE");
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
    release.send(()).unwrap();
    assert!(first.blocking_recv().is_err());
    drop(scheduler);

    let scheduler = Scheduler::new(limits(), factory()).unwrap();
    send(&scheduler, query(10)).unwrap();
    let shared = scheduler.shared.clone();
    let _ = std::thread::spawn(move || {
        let _guard = lock(&shared.state);
        panic!("unit registry poison");
    })
    .join();
    send(&scheduler, query(10)).unwrap();
    send(
        &scheduler,
        data(
            10,
            Action::Status {
                expected_worker_instance: None,
            },
        ),
    )
    .unwrap();
}
