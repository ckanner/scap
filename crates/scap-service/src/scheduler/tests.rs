use super::*;
use crate::tests::{call, principal, until};
use crate::wire::{Action, Decimal, Identity};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub(crate) fn limits() -> Limits {
    Limits {
        workers: 1,
        control_workers: 1,
        queued_per_worker: 32,
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
    let (reply, receiver) = oneshot::channel();
    (
        Job {
            principal,
            call,
            deadline: until(),
            reply,
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

#[test]
fn queues_rotate_tenants_and_databases_and_bounded_controls_do_not_starve_sql() {
    let mut queue = Queue::default();
    assert!(queue.pop().is_none());
    for (tenant, database, id) in [(1, 1, 1), (1, 1, 2), (1, 2, 3), (2, 1, 4), (2, 2, 5)] {
        queue
            .push(job(tenant, database, id, false).0, limits())
            .unwrap();
    }
    let ordered: Vec<_> = std::iter::from_fn(|| queue.pop().map(label)).collect();
    assert_eq!(
        ordered,
        [(1, 1, 1), (2, 1, 4), (1, 2, 3), (2, 2, 5), (1, 1, 2)]
    );
    for id in 1..=4 {
        queue.push(job(1, 1, id, true).0, limits()).unwrap();
    }
    queue.push(job(1, 1, 5, false).0, limits()).unwrap();
    assert_eq!(
        std::iter::from_fn(|| queue.pop().map(|job| label(job).2)).collect::<Vec<_>>(),
        vec![1, 2, 3, 5, 4]
    );
    let mut bad = job(1, 1, 1, false).0;
    bad.call.scope.database.0 = 0;
    assert_eq!(queue.push(bad, limits()).unwrap_err().code, "INVALID");
    assert!(queue.groups.is_empty());
    queue.closed = true;
    assert_eq!(
        queue
            .push(job(1, 1, 1, false).0, limits())
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
}

#[test]
fn worker_tenant_and_database_caps_preserve_control_reservations() {
    let mut queue = Queue::default();
    for id in 1..=6 {
        queue.push(job(1, 1, id, false).0, limits()).unwrap();
    }
    assert_eq!(
        queue
            .push(job(1, 1, 7, false).0, limits())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    for id in 7..=8 {
        queue.push(job(1, 1, id, true).0, limits()).unwrap();
    }
    assert!(queue.push(job(1, 1, 9, true).0, limits()).is_err());
    for id in 1..=8 {
        queue.push(job(1, 2, id, true).0, limits()).unwrap();
    }
    assert!(queue.push(job(1, 3, 1, true).0, limits()).is_err());

    let mut queue = Queue::default();
    for id in 0..14 {
        queue
            .push(job(1, id / 6 + 1, id + 1, false).0, limits())
            .unwrap();
    }
    assert!(queue.push(job(1, 4, 15, false).0, limits()).is_err());
    queue.push(job(1, 4, 15, true).0, limits()).unwrap();
    queue.push(job(1, 4, 16, true).0, limits()).unwrap();

    let mut queue = Queue::default();
    for id in 1..=30 {
        queue.push(job(id, 1, 1, false).0, limits()).unwrap();
    }
    assert!(queue.push(job(31, 1, 1, false).0, limits()).is_err());
    queue.push(job(31, 1, 1, true).0, limits()).unwrap();
    queue.push(job(32, 1, 1, true).0, limits()).unwrap();
    assert!(queue.push(job(33, 1, 1, true).0, limits()).is_err());
}

struct Echo(usize);
impl Worker for Echo {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        if matches!(call.action, Action::Open {}) {
            panic!("unit worker fault");
        }
        Ok(json!({"worker":self.0,"database":call.scope.database.0}))
    }
}
fn factory() -> Factory {
    Arc::new(|index| Ok(Box::new(Echo(index))))
}
fn error(scheduler: Result<Scheduler, Failure>) -> &'static str {
    match scheduler {
        Ok(_) => panic!("accepted invalid scheduler"),
        Err(error) => error.code,
    }
}

#[test]
fn startup_limits_partial_failure_and_panicked_workers_fail_closed() {
    for set in [
        |v: &mut Limits| v.workers = 0,
        |v: &mut Limits| v.workers = 257,
        |v: &mut Limits| v.control_workers = 0,
        |v: &mut Limits| v.control_workers = 256,
        |v: &mut Limits| v.queued_per_worker = 0,
        |v: &mut Limits| v.queued_per_tenant = 0,
        |v: &mut Limits| v.queued_per_tenant = 33,
        |v: &mut Limits| v.queued_per_database = 0,
        |v: &mut Limits| v.queued_per_database = 17,
        |v: &mut Limits| v.reserved_controls = 0,
        |v: &mut Limits| v.reserved_controls = 8,
    ] {
        let mut value = limits();
        set(&mut value);
        assert_eq!(error(Scheduler::new(value, factory())), "CONFIG");
    }
    assert_eq!(
        error(Scheduler::new(
            limits(),
            Arc::new(|index| if index == 0 {
                Ok(Box::new(Echo(0)))
            } else {
                Err(Failure::new("STARTUP"))
            })
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
    fn fail(_: Task) -> std::io::Result<JoinHandle<()>> {
        Err(std::io::Error::other("unit spawn fault"))
    }
    assert_eq!(
        error(Scheduler::with_spawner(limits(), factory(), fail)),
        "UNAVAILABLE"
    );
    let mut scheduler = Scheduler::new(limits(), factory()).unwrap();
    assert!(scheduler
        .submit(principal(), call(Action::Open {}), until())
        .unwrap()
        .blocking_recv()
        .is_err());
    // The request sender drops before the worker's outer close guard during
    // unwinding. Join observes that final close; response loss alone does not.
    assert!(scheduler.threads.remove(0).join().is_err());
    // The failed data lane is closed, while the reserved control lane still runs.
    assert_eq!(
        scheduler
            .submit(
                principal(),
                call(Action::Query { statements: vec![] }),
                until()
            )
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
    assert_eq!(
        scheduler
            .submit(principal(), call(Action::Status {}), until())
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap()["worker"],
        1
    );
}

#[test]
fn deadlines_cancelled_waiters_and_shutdown_do_not_replay_calls() {
    let (started, entered) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let waits = Arc::new(Mutex::new(Some(wait)));
    let calls = Arc::new(AtomicUsize::new(0));
    struct Blocking {
        entered: mpsc::SyncSender<()>,
        wait: mpsc::Receiver<()>,
        calls: Arc<AtomicUsize>,
    }
    impl Worker for Blocking {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.send(()).unwrap();
                self.wait.recv().unwrap();
            }
            Ok(json!({"done":true}))
        }
    }
    let count = calls.clone();
    let scheduler = Scheduler::new(
        limits(),
        Arc::new(move |index| {
            if index == 0 {
                Ok(Box::new(Blocking {
                    entered: started.clone(),
                    wait: waits.lock().unwrap().take().unwrap(),
                    calls: count.clone(),
                }))
            } else {
                Ok(Box::new(Echo(index)))
            }
        }),
    )
    .unwrap();
    let first = scheduler
        .submit(
            principal(),
            call(Action::Query { statements: vec![] }),
            until(),
        )
        .unwrap();
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let cancelled = scheduler
        .submit(
            principal(),
            call(Action::Query { statements: vec![] }),
            until(),
        )
        .unwrap();
    drop(cancelled);
    let expired = scheduler
        .submit(
            principal(),
            call(Action::Query { statements: vec![] }),
            Instant::now(),
        )
        .unwrap();
    let queued = scheduler
        .submit(
            principal(),
            call(Action::Query { statements: vec![] }),
            until(),
        )
        .unwrap();
    // Control completion is independent of the blocked data worker.
    assert_eq!(
        scheduler
            .submit(principal(), call(Action::Status {}), until())
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap()["worker"],
        1
    );
    release.send(()).unwrap();
    first.blocking_recv().unwrap().unwrap();
    assert_eq!(
        expired.blocking_recv().unwrap().unwrap_err().code,
        "DEADLINE"
    );
    queued.blocking_recv().unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let mut invalid = call(Action::Status {});
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
            .submit(denied, call(Action::Status {}), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
}

#[test]
fn closed_and_poisoned_lanes_wake_waiters_and_discard_pending_work() {
    let lane = Arc::new(Lane::default());
    let (job, reply) = job(1, 1, 1, false);
    lane.queue.lock().unwrap().push(job, limits()).unwrap();
    lane.close();
    assert_eq!(
        reply.blocking_recv().unwrap().unwrap_err().code,
        "UNAVAILABLE"
    );
    assert!(lane.next().is_none());

    let lane = Arc::new(Lane::default());
    let poison = lane.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poison.queue.lock().unwrap();
        panic!("unit mutex poison");
    })
    .join();
    // next() recovers initial poison, and Condvar recovers poison after wake.
    let waiter = lane.clone();
    let (started, started_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        started.send(()).unwrap();
        waiter.next()
    });
    started_rx.recv().unwrap();
    // Allow the waiter to reach Condvar; this isn't used to infer a database
    // outcome. If it hasn't waited yet, the next loop handles the closed flag.
    std::thread::sleep(Duration::from_millis(10));
    lane.close();
    assert!(thread.join().unwrap().is_none());
}

#[test]
fn submit_recovers_a_poisoned_queue_without_duplicate_execution() {
    let scheduler = Scheduler::new(limits(), factory()).unwrap();
    let lane = scheduler.lanes[1].clone();
    let other = lane.clone();
    let _ = std::thread::spawn(move || {
        let _guard = other.queue.lock().unwrap();
        panic!("unit poison");
    })
    .join();
    let result = scheduler
        .submit(principal(), call(Action::Status {}), until())
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    assert_eq!(result["worker"], 1);
}

#[test]
fn control_only_queue_continues_after_the_burst_limit_without_starving_an_empty_sql_queue() {
    let mut queue = Queue::default();
    for id in 1..=5 {
        queue.push(job(1, 1, id, true).0, limits()).unwrap();
    }
    assert_eq!(
        std::iter::from_fn(|| queue.pop().map(|job| label(job).2)).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
}
