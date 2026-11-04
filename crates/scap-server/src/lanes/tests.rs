use super::*;
use scap_service::{Backend, BackendFuture, Call, Mode};
use scap_sql::TransactionResult;
use std::sync::atomic::AtomicUsize;

use crate::mailbox::Mailbox;
use crate::tests::{config, context, sql};

fn database(id: u128) -> DatabaseConfig {
    let mut database = config().databases.remove(0);
    database.identity.database_id = id;
    database.name = format!("db-{id}");
    database
}

fn envelope(id: u128, request: u128) -> (Envelope, BackendFuture<TransactionResult>) {
    let db = database(id);
    let (mailbox, receive) =
        Mailbox::new(std::slice::from_ref(&db), Arc::new(AtomicBool::new(false)));
    let response = mailbox.execute(Call {
        context: context(&db.name, request),
        mode: Mode::Write,
        statements: vec![sql("SELECT 1")],
    });
    (receive.recv().unwrap(), response)
}

fn result() -> Reply {
    Reply::Sql(TransactionResult { statements: vec![] })
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(Instant::now() < deadline, "lane did not make progress");
        thread::sleep(Duration::from_millis(1));
    }
}

#[derive(Default)]
struct Effects {
    births: Mutex<Vec<(u128, u128)>>,
    requests: Mutex<Vec<(u128, u128)>>,
    dropped: AtomicUsize,
    ticks: AtomicUsize,
    keep_active: AtomicBool,
    started: AtomicUsize,
    released: AtomicBool,
    block_database: u128,
    fail_build: bool,
    panic_build: bool,
    block_drop_database: u128,
    dropping: AtomicUsize,
    release_drop: AtomicBool,
    panic_drop: bool,
}

struct TestExecutor {
    database: u128,
    effects: Arc<Effects>,
}

impl Executor for TestExecutor {
    fn tick(&mut self) {
        self.effects.ticks.fetch_add(1, Ordering::AcqRel);
    }
    fn request(&mut self, request: Request) -> Result<Reply, ServiceError> {
        assert_eq!(request.database.identity.database_id, self.database);
        self.effects.started.fetch_add(1, Ordering::AcqRel);
        if self.database == self.effects.block_database {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !self.effects.released.load(Ordering::Acquire) {
                if request.context.cancelled.load(Ordering::Acquire) {
                    return Err(failure("COMMIT_UNKNOWN"));
                }
                assert!(Instant::now() < deadline, "test failed to release SQL lane");
                thread::sleep(Duration::from_millis(1));
            }
        }
        self.effects
            .requests
            .lock()
            .push((self.database, request.request_id));
        Ok(result())
    }
    fn dormant(&self) -> bool {
        !self.effects.keep_active.load(Ordering::Acquire)
    }
}

impl Drop for TestExecutor {
    fn drop(&mut self) {
        if self.database == self.effects.block_drop_database {
            self.effects.dropping.fetch_add(1, Ordering::AcqRel);
            wait_until(|| self.effects.release_drop.load(Ordering::Acquire));
            assert!(!self.effects.panic_drop, "injected native close panic");
        }
        self.effects.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

fn prepare(effects: Arc<Effects>) -> Prepare {
    Box::new(move |database, boot| {
        let effects = effects.clone();
        Box::new(move || {
            assert!(!effects.panic_build, "injected lane panic");
            if effects.fail_build {
                return Err(failure("TEST_BUILD"));
            }
            effects
                .births
                .lock()
                .push((database.identity.database_id, boot));
            Ok(Box::new(TestExecutor {
                database: database.identity.database_id,
                effects,
            }) as Box<dyn Executor>)
        })
    })
}

fn lanes(effects: Arc<Effects>) -> Lanes {
    Lanes::new(123, Arc::new(AtomicBool::new(false)), prepare(effects)).unwrap()
}

#[tokio::test]
async fn queue_retirement_is_atomic_with_dispatch_and_stop_cancels_owned_work() {
    let queue = Queue::new();
    let (first, response) = envelope(1, 1);
    let active = first.request.context.cancelled.clone();
    assert!(queue.send(first).is_none());
    let Next::Request(first) = queue.next(true) else {
        panic!("queued work wins over retirement");
    };
    let (second, queued) = envelope(1, 2);
    let pending = second.request.context.cancelled.clone();
    assert!(queue.send(second).is_none());
    queue.stop();
    assert!(active.load(Ordering::Acquire));
    assert!(pending.load(Ordering::Acquire));
    assert!(matches!(queue.next(false), Next::Stop));
    assert_eq!(queued.await.unwrap_err().code, "COMMIT_UNKNOWN");
    drop(first);
    assert_eq!(response.await.unwrap_err().code, "COMMIT_UNKNOWN");
    queue.stop();

    let empty = Queue::new();
    assert!(matches!(empty.next(false), Next::Poll));
    assert!(matches!(empty.next(true), Next::Stop));
    let (late, response) = envelope(1, 3);
    let returned = empty
        .send(late)
        .expect("retirement preserves admitted work");
    assert_eq!(returned.request.request_id, 3);
    assert!(!returned.request.context.cancelled.load(Ordering::Acquire));
    assert!(empty.state.lock().pending.is_empty());
    drop(returned);
    assert_eq!(response.await.unwrap_err().code, "COMMIT_UNKNOWN");
}

#[tokio::test]
async fn per_lane_queue_is_bounded_and_preserves_fifo() {
    let queue = Queue::new();
    let mut responses = Vec::new();
    for id in 1..=MAX_DATABASE_QUEUED as u128 {
        let (request, response) = envelope(1, id);
        assert!(queue.send(request).is_none());
        responses.push(response);
    }
    let (overflow, response) = envelope(1, 99);
    assert!(queue.send(overflow).is_none());
    assert_eq!(response.await.unwrap_err().code, "OVERLOADED");
    for id in 1..=MAX_DATABASE_QUEUED as u128 {
        let Next::Request(request) = queue.next(true) else {
            panic!("lost queued request");
        };
        assert_eq!(request.request.request_id, id);
        queue.complete();
        assert!(request.reply.send(Ok(result())).is_ok());
    }
    assert!(matches!(queue.next(true), Next::Stop));
    for response in responses {
        assert!(response.await.is_ok());
    }
}

#[tokio::test]
async fn slow_database_does_not_block_another_and_each_lane_executes_in_order() {
    let effects = Arc::new(Effects {
        block_database: 1,
        ..Effects::default()
    });
    let mut lanes = lanes(effects.clone());
    assert!(lanes.lanes.is_empty()); // no configured cold DB gets a thread
    let (first, first_reply) = envelope(1, 11);
    lanes.dispatch(first).unwrap();
    wait_until(|| effects.started.load(Ordering::Acquire) == 1);
    let (second, second_reply) = envelope(1, 12);
    lanes.dispatch(second).unwrap();
    let (other, other_reply) = envelope(2, 21);
    lanes.dispatch(other).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), other_reply)
        .await
        .unwrap()
        .is_ok());
    assert_eq!(*effects.requests.lock(), vec![(2, 21)]);
    assert!(!effects.released.load(Ordering::Acquire));
    effects.released.store(true, Ordering::Release);
    first_reply.await.unwrap();
    second_reply.await.unwrap();
    assert_eq!(*effects.requests.lock(), vec![(2, 21), (1, 11), (1, 12)]);
    wait_until(|| {
        lanes.reap().unwrap();
        lanes.lanes.is_empty()
    });
    assert_eq!(effects.dropped.load(Ordering::Acquire), 2);
    let old = effects.births.lock()[0].1;
    let (new, response) = envelope(1, 13);
    lanes.dispatch(new).unwrap();
    response.await.unwrap();
    lanes.finish().unwrap();
    let births = effects.births.lock();
    assert_eq!(births.len(), 3);
    assert_ne!(old, births[2].1); // no retired writer boot/operation ID reuse
    assert_eq!(effects.dropped.load(Ordering::Acquire), 3);
    assert!(lanes.lanes.is_empty());
}

#[tokio::test]
async fn retirement_handoff_preserves_fifo_and_capacity_without_overlapping_native_owners() {
    let effects = Arc::new(Effects {
        block_drop_database: 1,
        ..Effects::default()
    });
    let mut lanes = Lanes::with_spawn(
        1,
        Arc::new(AtomicBool::new(false)),
        prepare(effects.clone()),
        2,
        native_spawn,
    )
    .unwrap();
    let (first, first_reply) = envelope(1, 11);
    lanes.dispatch(first).unwrap();
    first_reply.await.unwrap();
    // The empty queue has closed, but the old native owner is still in Drop.
    wait_until(|| effects.dropping.load(Ordering::Acquire) == 1);
    let old_boot = effects.births.lock()[0].1;
    let (next, next_reply) = envelope(1, 12);
    let deadline = next.request.context.deadline;
    let cancelled = next.request.context.cancelled.clone();
    lanes.dispatch(next).unwrap();
    let (last, last_reply) = envelope(1, 13);
    lanes.dispatch(last).unwrap();
    let pending = &lanes.lanes[&1].deferred.0;
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].request.context.deadline, deadline);
    assert!(Arc::ptr_eq(
        &pending[0].request.context.cancelled,
        &cancelled
    ));
    lanes.reap().unwrap(); // Never joins the native owner blocked above.
    assert_eq!(effects.births.lock().len(), 1);

    let (other, other_reply) = envelope(2, 21);
    lanes.dispatch(other).unwrap();
    tokio::time::timeout(Duration::from_secs(1), other_reply)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*effects.requests.lock(), vec![(1, 11), (2, 21)]);
    let (excess, excess_reply) = envelope(3, 31);
    lanes.dispatch(excess).unwrap();
    assert_eq!(excess_reply.await.unwrap_err().code, "OVERLOADED");
    assert_eq!(lanes.lanes.len(), 2); // Retiring threads still occupy capacity.

    effects.release_drop.store(true, Ordering::Release);
    wait_until(|| lanes.lanes[&1].thread.is_finished());
    lanes.reap().unwrap();
    next_reply.await.unwrap();
    last_reply.await.unwrap();
    wait_until(|| {
        lanes.reap().unwrap();
        lanes.lanes.is_empty()
    });
    assert_eq!(
        *effects.requests.lock(),
        vec![(1, 11), (2, 21), (1, 12), (1, 13)]
    );
    let births = effects.births.lock();
    assert_eq!(births.len(), 3);
    assert_eq!(births[2].0, 1);
    assert_ne!(births[2].1, old_boot);
    assert_eq!(effects.dropped.load(Ordering::Acquire), 3);
}

#[tokio::test]
async fn deferred_expiry_and_cancellation_release_original_quota_without_starting_a_writer() {
    let effects = Arc::new(Effects {
        block_drop_database: 1,
        ..Effects::default()
    });
    let mut lanes = lanes(effects.clone());
    let (first, reply) = envelope(1, 1);
    lanes.dispatch(first).unwrap();
    reply.await.unwrap();
    wait_until(|| effects.dropping.load(Ordering::Acquire) == 1);

    let database = database(1);
    let (mailbox, receiver) = Mailbox::new(
        std::slice::from_ref(&database),
        Arc::new(AtomicBool::new(false)),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut replies = Vec::new();
    let mut cancellations = Vec::new();
    for id in 10..10 + MAX_DATABASE_QUEUED as u128 {
        let mut context = context(&database.name, id);
        context.deadline = deadline;
        let response = mailbox.execute(Call {
            context,
            mode: Mode::Write,
            statements: vec![sql("SELECT 1")],
        });
        let request = receiver.recv().unwrap();
        cancellations.push(request.request.context.cancelled.clone());
        lanes.dispatch(request).unwrap();
        replies.push(response);
    }
    let over_quota = mailbox.execute(Call {
        context: context(&database.name, 99),
        mode: Mode::Write,
        statements: vec![sql("SELECT 1")],
    });
    assert_eq!(over_quota.await.unwrap_err().code, "OVERLOADED");
    // The scheduler also bounds its handoff even if a caller bypasses mailbox.
    let (overflow, overflow_reply) = envelope(1, 100);
    lanes.dispatch(overflow).unwrap();
    assert_eq!(overflow_reply.await.unwrap_err().code, "OVERLOADED");
    cancellations[0].store(true, Ordering::Release);
    lanes.reap().unwrap();
    assert_eq!(lanes.lanes[&1].deferred.0.len(), MAX_DATABASE_QUEUED - 1);
    // Inject one monotonic observation at the original deadline. No context or
    // cancellation token is rewritten, and the native Drop is still blocked.
    lanes.reap_at(deadline).unwrap();
    assert!(lanes.lanes[&1].deferred.0.is_empty());
    for response in replies {
        assert_eq!(response.await.unwrap_err().code, "COMMIT_UNKNOWN");
    }
    let replacement = mailbox.execute(Call {
        context: context(&database.name, 101),
        mode: Mode::Write,
        statements: vec![sql("SELECT 1")],
    });
    let accepted = receiver
        .try_recv()
        .expect("expired reservations were released");
    let cancel = accepted.request.context.cancelled.clone();
    lanes.dispatch(accepted).unwrap();
    cancel.store(true, Ordering::Release);
    lanes.reap().unwrap();
    assert_eq!(replacement.await.unwrap_err().code, "COMMIT_UNKNOWN");
    effects.release_drop.store(true, Ordering::Release);
    wait_until(|| lanes.lanes[&1].thread.is_finished());
    lanes.reap().unwrap();
    assert!(lanes.lanes.is_empty());
    assert_eq!(effects.births.lock().len(), 1);
    assert_eq!(*effects.requests.lock(), vec![(1, 1)]);
}

#[tokio::test]
async fn deferred_work_is_cancelled_before_shutdown_join_and_after_failed_owner_close() {
    for panic_close in [false, true] {
        let effects = Arc::new(Effects {
            block_drop_database: 1,
            panic_drop: panic_close,
            ..Effects::default()
        });
        let mut lanes = lanes(effects.clone());
        let (first, reply) = envelope(1, 1);
        lanes.dispatch(first).unwrap();
        reply.await.unwrap();
        wait_until(|| effects.dropping.load(Ordering::Acquire) == 1);
        let (waiting, reply) = envelope(1, 2);
        let cancelled = waiting.request.context.cancelled.clone();
        lanes.dispatch(waiting).unwrap();
        if panic_close {
            effects.release_drop.store(true, Ordering::Release);
            wait_until(|| lanes.lanes[&1].thread.is_finished());
            assert_eq!(lanes.reap().unwrap_err().code, "SQL_LANE_PANICKED");
        } else {
            let observed = cancelled.clone();
            let release = effects.clone();
            let closer = thread::spawn(move || {
                wait_until(|| observed.load(Ordering::Acquire));
                release.release_drop.store(true, Ordering::Release);
            });
            lanes.finish().unwrap();
            closer.join().unwrap();
        }
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(reply.await.unwrap_err().code, "COMMIT_UNKNOWN");
        assert_eq!(effects.births.lock().len(), 1);
        assert_eq!(*effects.requests.lock(), vec![(1, 1)]);
        assert!(lanes.lanes.is_empty());
    }
}

#[tokio::test]
async fn failed_successor_spawn_releases_handoff_without_retrying_the_old_request() {
    let effects = Arc::new(Effects {
        block_drop_database: 1,
        ..Effects::default()
    });
    let mut lanes = lanes(effects.clone());
    let (first, reply) = envelope(1, 1);
    lanes.dispatch(first).unwrap();
    reply.await.unwrap();
    wait_until(|| effects.dropping.load(Ordering::Acquire) == 1);
    let (waiting, reply) = envelope(1, 2);
    let cancelled = waiting.request.context.cancelled.clone();
    lanes.dispatch(waiting).unwrap();
    lanes.spawn = failed_spawn;
    effects.release_drop.store(true, Ordering::Release);
    wait_until(|| lanes.lanes[&1].thread.is_finished());
    assert_eq!(lanes.reap().unwrap_err().code, "SQL_LANE_SPAWN");
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(reply.await.unwrap_err().code, "COMMIT_UNKNOWN");
    assert_eq!(*effects.requests.lock(), vec![(1, 1)]);
    assert_eq!(effects.births.lock().len(), 1);
    assert_eq!(effects.dropped.load(Ordering::Acquire), 1);
    assert!(lanes.lanes.is_empty());
}

#[tokio::test]
async fn admission_preserves_deadline_cancellation_capacity_and_live_lane_bounds() {
    for case in 0..3 {
        let effects = Arc::new(Effects::default());
        let mut lanes = lanes(effects.clone());
        let (mut request, response) = envelope(1, 1);
        match case {
            0 => lanes.stopped.store(true, Ordering::Release),
            1 => request
                .request
                .context
                .cancelled
                .store(true, Ordering::Release),
            _ => request.request.context.deadline = Instant::now(),
        }
        lanes.dispatch(request).unwrap();
        assert_eq!(response.await.unwrap_err().code, "COMMIT_UNKNOWN");
        assert!(effects.births.lock().is_empty());
    }
    let effects = Arc::new(Effects::default());
    effects.keep_active.store(true, Ordering::Release);
    let mut lanes = Lanes::with_spawn(
        1,
        Arc::new(AtomicBool::new(false)),
        prepare(effects.clone()),
        1,
        native_spawn,
    )
    .unwrap();
    lanes.recover(database(1)).unwrap();
    wait_until(|| effects.ticks.load(Ordering::Acquire) > 0);
    lanes.recover(database(1)).unwrap();
    lanes.recover(database(2)).unwrap();
    assert_eq!(lanes.lanes.len(), 1);
    lanes.reap().unwrap(); // running threads are never joined on dispatch
    let (request, rejected) = envelope(2, 2);
    lanes.dispatch(request).unwrap();
    assert_eq!(rejected.await.unwrap_err().code, "OVERLOADED");
    let (request, accepted) = envelope(1, 3);
    lanes.dispatch(request).unwrap();
    accepted.await.unwrap();
    lanes.stopped.store(true, Ordering::Release);
    lanes.recover(database(3)).unwrap();
    lanes.finish().unwrap();
    assert_eq!(effects.births.lock().len(), 1);
    assert_eq!(effects.dropped.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn shutdown_cancels_active_and_queued_requests_and_joins_all_native_owners() {
    let effects = Arc::new(Effects {
        block_database: 1,
        ..Effects::default()
    });
    let mut lanes = lanes(effects.clone());
    let (active, active_reply) = envelope(1, 1);
    let cancelled = active.request.context.cancelled.clone();
    lanes.dispatch(active).unwrap();
    wait_until(|| effects.started.load(Ordering::Acquire) == 1);
    let (queued, queued_reply) = envelope(1, 2);
    let queued_cancelled = queued.request.context.cancelled.clone();
    lanes.dispatch(queued).unwrap();
    lanes.finish().unwrap();
    assert!(cancelled.load(Ordering::Acquire));
    assert!(queued_cancelled.load(Ordering::Acquire));
    assert_eq!(active_reply.await.unwrap_err().code, "COMMIT_UNKNOWN");
    assert_eq!(queued_reply.await.unwrap_err().code, "COMMIT_UNKNOWN");
    assert_eq!(effects.dropped.load(Ordering::Acquire), 1);
    assert!(effects.requests.lock().is_empty());
    lanes.finish().unwrap();
}

fn failed_spawn(_: Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>> {
    Err(std::io::Error::other("injected thread limit"))
}

fn skipped_spawn(task: Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>> {
    drop(task);
    Ok(thread::spawn(|| {}))
}

#[tokio::test]
async fn spawn_build_and_panic_failures_cancel_work_and_reap_cannot_hide_them() {
    let effects = Arc::new(Effects::default());
    let mut failed = Lanes::with_spawn(
        1,
        Arc::new(AtomicBool::new(false)),
        prepare(effects.clone()),
        1,
        failed_spawn,
    )
    .unwrap();
    let (request, response) = envelope(1, 1);
    let cancelled = request.request.context.cancelled.clone();
    assert_eq!(failed.dispatch(request).unwrap_err().code, "SQL_LANE_SPAWN");
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(response.await.unwrap_err().code, "COMMIT_UNKNOWN");
    assert!(failed.lanes.is_empty());
    for case in 0..3 {
        let effects = Arc::new(Effects {
            fail_build: case == 0,
            panic_build: case == 1,
            ..Effects::default()
        });
        let mut failed = Lanes::with_spawn(
            2,
            Arc::new(AtomicBool::new(false)),
            prepare(effects.clone()),
            1,
            if case == 2 {
                skipped_spawn
            } else {
                native_spawn
            },
        )
        .unwrap();
        let (request, response) = envelope(1, case + 1);
        failed.dispatch(request).unwrap();
        wait_until(|| failed.lanes[&1].thread.is_finished());
        let (late, late_reply) = envelope(1, case + 10);
        let late_cancelled = late.request.context.cancelled.clone();
        failed.dispatch(late).unwrap();
        let expected = ["TEST_BUILD", "SQL_LANE_PANICKED", "SQL_LANE_STOPPED"][case as usize];
        assert_eq!(failed.reap().unwrap_err().code, expected);
        assert!(failed.lanes.is_empty());
        assert_eq!(response.await.unwrap_err().code, "COMMIT_UNKNOWN");
        assert!(late_cancelled.load(Ordering::Acquire));
        assert_eq!(late_reply.await.unwrap_err().code, "COMMIT_UNKNOWN");
        assert!(effects.requests.lock().is_empty());
    }
}

#[test]
fn invalid_capacity_identity_exhaustion_and_finish_failure_are_explicit() {
    for (boot, limit) in [(0, 1), (1, 0), (1, MAX_LANES + 1)] {
        assert_eq!(
            Lanes::with_spawn(
                boot,
                Arc::new(AtomicBool::new(false)),
                prepare(Arc::new(Effects::default())),
                limit,
                native_spawn,
            )
            .err()
            .unwrap()
            .code,
            "SQL_LANE_CONFIG"
        );
    }
    let effects = Arc::new(Effects::default());
    let mut lanes = lanes(effects);
    lanes.sequence = u64::MAX;
    assert_eq!(
        lanes.recover(database(1)).unwrap_err().code,
        "IDENTITY_EXHAUSTED"
    );
    assert!(lanes.lanes.is_empty());
    let effects = Arc::new(Effects {
        fail_build: true,
        ..Effects::default()
    });
    let mut failed = self::lanes(effects);
    failed.recover(database(1)).unwrap();
    assert_eq!(failed.finish().unwrap_err().code, "TEST_BUILD");
    assert!(failed.lanes.is_empty());
}

#[test]
fn global_stop_prevents_executor_use_and_drop_joins_idle_and_failed_threads() {
    let effects = Arc::new(Effects::default());
    let mut executor = TestExecutor {
        database: 1,
        effects: effects.clone(),
    };
    run(&mut executor, &Queue::new(), &AtomicBool::new(true));
    assert_eq!(effects.ticks.load(Ordering::Acquire), 0);
    let mut lanes = lanes(effects.clone());
    effects.keep_active.store(true, Ordering::Release);
    lanes.recover(database(1)).unwrap();
    wait_until(|| effects.births.lock().len() == 1);
    drop(lanes);
    assert_eq!(effects.dropped.load(Ordering::Acquire), 1);
    assert!(effects.requests.lock().is_empty());
}
