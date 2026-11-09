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
            principal,
            call,
            key,
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
    assert_eq!(
        scheduler
            .submit(principal(), query(30), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(
        send(&scheduler, data(30, Action::Status {})).unwrap()["worker"],
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
    assert_eq!(
        scheduler
            .submit(principal(), query(20), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
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
    assert_eq!(
        scheduler
            .submit(principal(), query(10), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    send(&scheduler, data(10, Action::Status {})).unwrap();
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
    let expired = scheduler
        .submit(principal(), query(10), Instant::now())
        .unwrap();
    let queued = scheduler.submit(principal(), query(10), until()).unwrap();
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
    assert_eq!(
        scheduler
            .submit(principal(), query(10), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(
        scheduler
            .submit(principal(), query(20), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(
        send(&scheduler, data(10, Action::Status {})).unwrap()["worker"],
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
            sent.send(scheduler.submit(principal(), data(10, Action::Status {}), until()))
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
    assert_eq!(
        scheduler
            .submit(principal(), query(10), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(
        scheduler
            .submit(principal(), query(30), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    send(&scheduler, data(10, Action::Status {})).unwrap();
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
    send(&scheduler, data(10, Action::Status {})).unwrap();
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
                data(10, Action::Status {})
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
            send(&scheduler, data(10, Action::Status {})).unwrap();
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
        .submit(principal(), data(10, Action::Status {}), until())
        .unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let reply = scheduler
        .submit(principal(), data(10, Action::Status {}), until())
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
    send(&scheduler, data(10, Action::Status {})).unwrap();
}
