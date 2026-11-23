use super::*;
use crate::catalogue_wire::{Action, Call};
use crate::tests::{principal, until};
use crate::wire::Decimal;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn limits() -> Limits {
    Limits {
        workers: 1,
        queued_total: 12,
        queued_per_tenant: 6,
        queued_per_name: 3,
    }
}
fn call(name: Option<&str>) -> Call {
    Call {
        version: 1,
        action: match name {
            Some(name) => Action::ResolveName { name: name.into() },
            None => Action::InspectCreateOperation {
                create_operation: Decimal(1),
            },
        },
    }
}
fn job(tenant: u64, name: Option<&str>) -> (Job, oneshot::Receiver<Result<Value, Failure>>) {
    let mut principal = principal();
    principal.tenant = tenant;
    let (reply, receiver) = oneshot::channel();
    (
        Job {
            _reservation: None,
            principal,
            call: call(name),
            deadline: until(),
            reply,
        },
        receiver,
    )
}

fn diagnostic_intake(
    registry: &Arc<crate::lifecycle::Registry>,
    recovery: bool,
) -> Arc<crate::intake::Intake> {
    Arc::new(
        crate::intake::Intake::new(
            if recovery {
                crate::intake::Class::Recovery
            } else {
                crate::intake::Class::Catalogue
            },
            4,
            4096,
            None,
        )
        .unwrap()
        .with_lifecycle(
            registry.clone(),
            if recovery {
                crate::lifecycle::Lane::Restore
            } else {
                crate::lifecycle::Lane::Catalogue
            },
        )
        .unwrap(),
    )
}

fn diagnostic_lease(intake: &Arc<crate::intake::Intake>) -> Arc<crate::intake::Lease> {
    let lease = intake.acquire(&principal()).unwrap();
    lease.shrink_body(0).unwrap();
    lease
}

fn restore_call() -> Call {
    Call {
        version: 1,
        action: Action::ResumeRestore {
            reference: crate::restore_wire::Reference {
                creation: serde_json::from_value(crate::catalogue_wire::creation(
                    &crate::tests::named_creation("diagnostic-restore", 1),
                ))
                .unwrap(),
                descriptor_hash: "a".repeat(64),
            },
        },
    }
}

#[test]
fn catalogue_and_restore_lifecycle_use_the_actual_worker_return_without_worker_encoding() {
    for recovery in [false, true] {
        let registry = Arc::new(crate::lifecycle::Registry::new());
        let intake = diagnostic_intake(&registry, recovery);
        let scheduler = if recovery {
            Scheduler::new_recovery(limits(), factory())
        } else {
            Scheduler::new(limits(), factory())
        }
        .unwrap();
        scheduler
            .submit_reserved(
                principal(),
                if recovery {
                    restore_call()
                } else {
                    call(Some("diagnostic"))
                },
                until(),
                diagnostic_lease(&intake),
            )
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap();
        drop(scheduler);
        let snapshot = registry.snapshot();
        assert!(snapshot.valid);
        let lane = snapshot.lanes[if recovery { 4 } else { 3 }];
        assert_eq!((lane.acquired.0, lane.released.0, lane.active.0), (1, 1, 0));
        for interval in [0, 1, 2, 3, 5, 7] {
            assert_eq!(lane.intervals[interval].distribution.completed.0, 1);
        }
        assert_eq!(lane.intervals[4].distribution.not_reached.0, 1);
        assert_eq!(lane.intervals[6].distribution.not_reached.0, 1);
    }
}

#[test]
fn catalogue_lifecycle_preserves_rejected_jobs_and_does_not_start_expired_or_closed_waiters() {
    let registry = Arc::new(crate::lifecycle::Registry::new());
    let intake = diagnostic_intake(&registry, false);
    let mut queue = Queue::default();
    let mut worker = ReservedWorker {
        worker: Box::new(Echo),
        reservation: None,
    };
    for kind in [
        "disconnected",
        "expired",
        "admission_expired",
        "admission_closed",
    ] {
        let (mut job, receiver) = job(2, Some("diagnostic"));
        job._reservation = Some(diagnostic_lease(&intake));
        if kind == "admission_expired" {
            job.deadline = Instant::now();
        }
        if kind == "admission_closed" {
            queue.closed = true;
        }
        let mut pending = Some(job);
        let outcome = queue.push(&mut pending, limits(), false);
        if kind.starts_with("admission_") {
            assert_eq!(
                outcome.unwrap_err().code,
                if kind == "admission_closed" {
                    "UNAVAILABLE"
                } else {
                    "DEADLINE"
                }
            );
            assert!(
                pending.is_some(),
                "rejection must leave cleanup with the unlocked caller"
            );
            drop((pending, receiver));
        } else {
            outcome.unwrap();
            assert!(pending.is_none());
            let mut job = queue.pop().unwrap();
            if kind == "disconnected" {
                drop(receiver);
                worker.execute(job);
            } else {
                job.deadline = Instant::now();
                worker.execute(job);
                assert_eq!(
                    receiver.blocking_recv().unwrap().unwrap_err().code,
                    "DEADLINE"
                );
            }
        }
    }
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    let lane = snapshot.lanes[3];
    assert_eq!((lane.released.0, lane.active.0), (4, 0));
    assert_eq!(lane.intervals[1].distribution.completed.0, 2);
    assert_eq!(lane.intervals[1].distribution.censored.0, 2);
    assert_eq!(lane.intervals[2].distribution.censored.0, 2);
    assert_eq!(lane.intervals[2].distribution.not_reached.0, 2);
    assert_eq!(lane.intervals[3].distribution.not_reached.0, 4);
    assert_eq!(lane.intervals[4].distribution.not_reached.0, 4);
}

#[test]
fn catalogue_shutdown_unlocks_the_queue_before_releasing_the_last_request_owner() {
    let registry = Arc::new(crate::lifecycle::Registry::new());
    let intake = diagnostic_intake(&registry, false);
    let lane = Arc::new(Lane::default());
    let (mut job, receiver) = job(2, Some("diagnostic"));
    job._reservation = Some(diagnostic_lease(&intake));
    lane.queue
        .lock()
        .unwrap()
        .push(&mut Some(job), limits(), false)
        .unwrap();
    let guard = crate::lifecycle::tests::hold_aggregation(&registry);
    let closing = lane.clone();
    let thread = std::thread::spawn(move || closing.close());
    let result = receiver.blocking_recv().unwrap();
    let observed = lane
        .queue
        .try_lock()
        .map(|queue| (queue.closed, queue.tenants.is_empty()))
        .ok();
    drop(guard);
    thread.join().unwrap();
    assert_eq!(result.unwrap_err().code, "UNAVAILABLE");
    assert_eq!(observed, Some((true, true)));
    assert_eq!(registry.snapshot().lanes[3].released.0, 1);
    assert_eq!(intake.available_permits(), 4);
}

#[test]
fn catalogue_rejected_admission_drops_the_request_after_unlocking_the_queue() {
    let registry = Arc::new(crate::lifecycle::Registry::new());
    let intake = diagnostic_intake(&registry, false);
    let scheduler = Arc::new(Scheduler::new(limits(), factory()).unwrap());
    scheduler.lane.close();
    let lease = diagnostic_lease(&intake);
    let guard = crate::lifecycle::tests::hold_aggregation(&registry);
    let submitting = scheduler.clone();
    let thread = std::thread::spawn(move || {
        submitting.submit_reserved(principal(), call(Some("diagnostic")), until(), lease)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while intake.available_permits() != 4 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    let refunded = intake.available_permits();
    let unlocked = scheduler.lane.queue.try_lock().is_ok();
    drop(guard);
    assert_eq!(thread.join().unwrap().unwrap_err().code, "UNAVAILABLE");
    assert_eq!(refunded, 4);
    assert!(
        unlocked,
        "aggregation must not retain the original queue mutex"
    );
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    assert_eq!(snapshot.lanes[3].intervals[1].distribution.censored.0, 1);
    assert_eq!(snapshot.lanes[3].intervals[2].distribution.not_reached.0, 1);
}

#[test]
fn catalogue_and_restore_diagnostics_preserve_global_tenant_name_order_and_snapshot() {
    use crate::tests::assert_budget;
    for (recovery, budgets) in [
        (
            false,
            [
                Budget::CatalogueQueueGlobal,
                Budget::CatalogueQueueTenant,
                Budget::CatalogueQueueName,
            ],
        ),
        (
            true,
            [
                Budget::RestoreQueueGlobal,
                Budget::RestoreQueueTenant,
                Budget::RestoreQueueName,
            ],
        ),
    ] {
        let mut queue = Queue::default();
        for _ in 0..3 {
            queue
                .push(&mut Some(job(1, None).0), limits(), recovery)
                .unwrap();
        }
        let name = queue
            .push(
                &mut Some(job(1, Some("not-yet-known")).0),
                limits(),
                recovery,
            )
            .unwrap_err();
        assert_budget(&name, budgets[2], 3, 3, 1);
        while queue.pop().is_some() {}
        for name in ["a", "b"] {
            for _ in 0..3 {
                queue
                    .push(&mut Some(job(1, Some(name)).0), limits(), recovery)
                    .unwrap();
            }
        }
        let tenant = queue
            .push(&mut Some(job(1, Some("a")).0), limits(), recovery)
            .unwrap_err();
        assert_budget(&tenant, budgets[1], 6, 6, 1);
        for tenant in 2..=7 {
            queue
                .push(&mut Some(job(tenant, Some("a")).0), limits(), recovery)
                .unwrap();
        }
        let global = queue
            .push(&mut Some(job(1, Some("a")).0), limits(), recovery)
            .unwrap_err();
        assert_budget(&global, budgets[0], 12, 12, 1);
        while queue.pop().is_some() {}
        assert_budget(&name, budgets[2], 3, 3, 1);
        assert_budget(&tenant, budgets[1], 6, 6, 1);
        assert_budget(&global, budgets[0], 12, 12, 1);
    }
}

#[test]
fn queue_rotates_exact_tenants_and_names_without_leaving_empty_groups() {
    let mut queue = Queue::default();
    assert!(queue.pop().is_none());
    for (tenant, name) in [(1, "A"), (1, "A"), (1, "a"), (2, "A"), (2, " A")] {
        queue
            .push(&mut Some(job(tenant, Some(name)).0), limits(), false)
            .unwrap();
    }
    let actual: Vec<_> = std::iter::from_fn(|| {
        queue.pop().map(|job| {
            (
                job.principal.tenant,
                job.call.action.name().unwrap().to_owned(),
            )
        })
    })
    .collect();
    assert_eq!(
        actual,
        [
            (1, "A".into()),
            (2, "A".into()),
            (1, "a".into()),
            (2, " A".into()),
            (1, "A".into())
        ]
    );
    assert!(queue.tenants.is_empty());
    queue.closed = true;
    assert_eq!(
        queue
            .push(&mut Some(job(1, Some("a")).0), limits(), false)
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
}

#[test]
fn total_tenant_and_unknown_name_inspection_caps_cannot_be_bypassed() {
    let mut queue = Queue::default();
    for _ in 0..3 {
        queue
            .push(&mut Some(job(1, Some("a")).0), limits(), false)
            .unwrap();
    }
    assert_eq!(
        queue
            .push(&mut Some(job(1, Some("a")).0), limits(), false)
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(
        queue
            .push(&mut Some(job(1, None).0), limits(), false)
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    for _ in 0..3 {
        queue
            .push(&mut Some(job(1, Some("b")).0), limits(), false)
            .unwrap();
    }
    assert_eq!(
        queue
            .push(&mut Some(job(1, Some("new")).0), limits(), false)
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    for tenant in 2..=7 {
        queue
            .push(&mut Some(job(tenant, Some("a")).0), limits(), false)
            .unwrap();
    }
    assert_eq!(
        queue
            .push(&mut Some(job(8, Some("a")).0), limits(), false)
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(queue.tenants.len(), 7);

    let mut queue = Queue::default();
    queue
        .push(&mut Some(job(1, None).0), limits(), false)
        .unwrap();
    queue
        .push(&mut Some(job(1, Some("a")).0), limits(), false)
        .unwrap();
    queue
        .push(&mut Some(job(1, Some("b")).0), limits(), false)
        .unwrap();
    queue
        .push(&mut Some(job(1, None).0), limits(), false)
        .unwrap();
    for name in [Some("a"), Some("b"), None] {
        assert_eq!(
            queue
                .push(&mut Some(job(1, name).0), limits(), false)
                .unwrap_err()
                .code,
            "BACKPRESSURE"
        );
    }
    queue
        .push(&mut Some(job(1, Some("new")).0), limits(), false)
        .unwrap();
    assert_eq!(queue.pop().unwrap().call.action.name(), None);
    queue
        .push(&mut Some(job(1, Some("a")).0), limits(), false)
        .unwrap();

    let mut queue = Queue::default();
    for _ in 0..3 {
        queue
            .push(&mut Some(job(1, None).0), limits(), false)
            .unwrap();
    }
    for name in [None, Some("new")] {
        assert!(queue
            .push(&mut Some(job(1, name).0), limits(), false)
            .is_err());
    }
}

#[test]
fn expired_admission_does_not_reserve_a_tenant_name_or_intake_slot() {
    use crate::intake::{Class, Intake};
    let mut queue = Queue::default();
    for name in [Some("new"), None] {
        let (mut expired, receiver) = job(1, name);
        expired.deadline = Instant::now();
        assert_eq!(
            queue
                .push(&mut Some(expired), limits(), false)
                .unwrap_err()
                .code,
            "DEADLINE"
        );
        assert!(receiver.blocking_recv().is_err());
        assert!(queue.tenants.is_empty());
    }
    let scheduler = Scheduler::new(limits(), factory()).unwrap();
    let intake = Arc::new(Intake::new(Class::Catalogue, 4, 4096, None).unwrap());
    assert_eq!(
        scheduler
            .submit_reserved(
                principal(),
                call(Some("new")),
                Instant::now(),
                intake.acquire(&principal()).unwrap(),
            )
            .unwrap_err()
            .code,
        "DEADLINE"
    );
    assert_eq!(intake.available_permits(), 4);
    assert!(scheduler.lane.queue.lock().unwrap().tenants.is_empty());
    assert_eq!(
        scheduler
            .submit(principal(), call(Some("new")), until())
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap()["name"],
        "new"
    );
}

#[test]
fn catalogue_admission_mutex_wait_cannot_extend_the_original_deadline() {
    let scheduler = Arc::new(Scheduler::new(limits(), factory()).unwrap());
    let queue = scheduler.lane.queue.lock().unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let request = scheduler.clone();
    let (entered, started) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        entered.send(()).unwrap();
        request.submit(principal(), call(Some("new")), deadline)
    });
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    drop(queue);
    assert_eq!(thread.join().unwrap().unwrap_err().code, "DEADLINE");
    assert!(scheduler.lane.queue.lock().unwrap().tenants.is_empty());
}

struct Echo;
impl Worker for Echo {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        if call.action.name() == Some("panic") {
            panic!("injected directory worker loss");
        }
        Ok(json!({"name":call.action.name()}))
    }
}
fn factory() -> Factory {
    Arc::new(|_| Ok(Box::new(Echo)))
}
fn error(value: Result<Scheduler, Failure>) -> &'static str {
    value.err().expect("expected failure").code
}

#[test]
fn invalid_limits_partial_startup_and_worker_loss_close_the_whole_bounded_pool() {
    for set in [
        |v: &mut Limits| v.workers = 0,
        |v: &mut Limits| v.workers = 33,
        |v: &mut Limits| v.queued_total = 0,
        |v: &mut Limits| v.queued_total = 65537,
        |v: &mut Limits| v.queued_per_tenant = 0,
        |v: &mut Limits| v.queued_per_tenant = 13,
        |v: &mut Limits| v.queued_per_name = 0,
        |v: &mut Limits| v.queued_per_name = 7,
    ] {
        let mut value = limits();
        set(&mut value);
        assert_eq!(error(Scheduler::new(value, factory())), "CONFIG");
    }
    let mut value = limits();
    value.workers = 2;
    assert_eq!(
        error(Scheduler::new(
            value,
            Arc::new(|index| if index == 0 {
                Ok(Box::new(Echo))
            } else {
                Err(Failure::new("STARTUP"))
            })
        )),
        "STARTUP"
    );
    assert_eq!(
        error(Scheduler::new(
            limits(),
            Arc::new(|_| panic!("factory failure"))
        )),
        "UNAVAILABLE"
    );
    fn fail(_: Task) -> std::io::Result<JoinHandle<()>> {
        Err(std::io::Error::other("spawn failure"))
    }
    assert_eq!(
        error(Scheduler::with_spawner(limits(), factory(), fail)),
        "UNAVAILABLE"
    );
    let mut scheduler = Scheduler::new(limits(), factory()).unwrap();
    assert!(scheduler
        .submit(principal(), call(Some("panic")), until())
        .unwrap()
        .blocking_recv()
        .is_err());
    assert!(scheduler.threads.remove(0).join().is_err());
    assert_eq!(
        scheduler
            .submit(principal(), call(Some("ok")), until())
            .unwrap_err()
            .code,
        "UNAVAILABLE"
    );
}

#[test]
fn catalogue_and_restore_panics_hold_intake_until_worker_cleanup_even_after_disconnect() {
    use crate::intake::{Class, Intake};

    struct PanicWorker {
        held: Option<Call>,
        entered: mpsc::SyncSender<()>,
        panic_now: mpsc::Receiver<()>,
        dropping: mpsc::SyncSender<()>,
        cleanup: mpsc::Receiver<()>,
    }
    impl Worker for PanicWorker {
        fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
            self.held = Some(call);
            self.entered.send(()).unwrap();
            self.panic_now.recv_timeout(Duration::from_secs(5)).unwrap();
            panic!("controlled catalogue/recovery worker failure");
        }
    }
    impl Drop for PanicWorker {
        fn drop(&mut self) {
            let _ = self.dropping.send(());
            let _ = self.cleanup.recv_timeout(Duration::from_secs(5));
        }
    }

    for recovery in [false, true] {
        for disconnected in [false, true] {
            let registry = Arc::new(crate::lifecycle::Registry::new());
            let (entered, started) = mpsc::sync_channel(1);
            let (panic_now, panic_receiver) = mpsc::sync_channel(1);
            let (dropping, drop_started) = mpsc::sync_channel(1);
            let (cleanup, cleanup_receiver) = mpsc::sync_channel(1);
            let source = Arc::new(Mutex::new(Some((panic_receiver, cleanup_receiver))));
            let factory: Factory = Arc::new(move |_| {
                let (panic_now, cleanup) = source.lock().unwrap().take().unwrap();
                Ok(Box::new(PanicWorker {
                    held: None,
                    entered: entered.clone(),
                    panic_now,
                    dropping: dropping.clone(),
                    cleanup,
                }))
            });
            let scheduler = if recovery {
                Scheduler::new_recovery(limits(), factory)
            } else {
                Scheduler::new(limits(), factory)
            }
            .unwrap();
            let intake = Arc::new(
                Intake::new(
                    if recovery {
                        Class::Recovery
                    } else {
                        Class::Catalogue
                    },
                    1,
                    4096,
                    None,
                )
                .unwrap()
                .with_lifecycle(
                    registry.clone(),
                    if recovery {
                        crate::lifecycle::Lane::Restore
                    } else {
                        crate::lifecycle::Lane::Catalogue
                    },
                )
                .unwrap(),
            );
            let call = if recovery {
                let creation = crate::tests::named_creation("held-restore", 1);
                Call {
                    version: 1,
                    action: Action::ResumeRestore {
                        reference: crate::restore_wire::Reference {
                            creation: serde_json::from_value(crate::catalogue_wire::creation(
                                &creation,
                            ))
                            .unwrap(),
                            descriptor_hash: "a".repeat(64),
                        },
                    },
                }
            } else {
                call(Some("held-catalogue"))
            };
            let receiver = scheduler
                .submit_reserved(principal(), call, until(), diagnostic_lease(&intake))
                .unwrap();
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut receiver = Some(receiver);
            if disconnected {
                drop(receiver.take());
            }
            panic_now.send(()).unwrap();
            drop_started.recv_timeout(Duration::from_secs(5)).unwrap();
            let permits_during_cleanup = intake.available_permits();
            let diagnostic_during_cleanup = registry.snapshot();
            cleanup.send(()).unwrap();
            drop(scheduler);
            if let Some(receiver) = receiver {
                assert!(receiver.blocking_recv().is_err());
            }
            assert_eq!(
                permits_during_cleanup, 0,
                "recovery={recovery}, disconnected={disconnected}: intake refunded before cleanup"
            );
            assert_eq!(intake.available_permits(), 1);
            let lane_index = if recovery { 4 } else { 3 };
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

#[test]
fn closed_waiters_and_expired_queue_entries_never_execute_or_retry() {
    let (entered, started) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Arc::new(Mutex::new(Some(wait)));
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    struct Blocking {
        entered: mpsc::SyncSender<()>,
        wait: mpsc::Receiver<()>,
        count: Arc<AtomicUsize>,
    }
    impl Worker for Blocking {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            if self.count.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.send(()).unwrap();
                self.wait.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            Ok(json!(true))
        }
    }
    let scheduler = Scheduler::new(
        limits(),
        Arc::new(move |_| {
            Ok(Box::new(Blocking {
                entered: entered.clone(),
                wait: wait.lock().unwrap().take().unwrap(),
                count: calls.clone(),
            }))
        }),
    )
    .unwrap();
    let first = scheduler
        .submit(principal(), call(Some("a")), until())
        .unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(
        scheduler
            .submit(principal(), call(Some("a")), until())
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    let expired = scheduler
        .submit(principal(), call(Some("a")), deadline)
        .unwrap();
    let last = scheduler
        .submit(principal(), call(Some("a")), until())
        .unwrap();
    assert_eq!(
        scheduler
            .submit(principal(), call(Some("a")), until())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    release.send(()).unwrap();
    first.blocking_recv().unwrap().unwrap();
    assert_eq!(
        expired.blocking_recv().unwrap().unwrap_err().code,
        "DEADLINE"
    );
    last.blocking_recv().unwrap().unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(
        scheduler
            .submit(principal(), call(Some("")), until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    let mut denied = principal();
    denied.provision = false;
    assert_eq!(
        scheduler
            .submit(denied, call(None), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
}

#[test]
fn shutdown_and_mutex_poison_keep_pending_replies_bounded_and_wake_every_waiter() {
    let lane = Arc::new(Lane::default());
    let (job, reply) = job(1, Some("a"));
    lane.queue
        .lock()
        .unwrap()
        .push(&mut Some(job), limits(), false)
        .unwrap();
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
        panic!("poison");
    })
    .join();
    let waiter = lane.clone();
    let (started, ready) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        started.send(()).unwrap();
        waiter.next()
    });
    ready.recv().unwrap();
    std::thread::sleep(Duration::from_millis(10));
    lane.close();
    assert!(thread.join().unwrap().is_none());
    let scheduler = Scheduler::new(limits(), factory()).unwrap();
    let poison = scheduler.lane.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poison.queue.lock().unwrap();
        panic!("poison submit");
    })
    .join();
    assert_eq!(
        scheduler
            .submit(principal(), call(Some("a")), until())
            .unwrap()
            .blocking_recv()
            .unwrap()
            .unwrap()["name"],
        "a"
    );
}
