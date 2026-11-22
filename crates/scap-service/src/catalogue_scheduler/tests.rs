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

#[test]
fn queue_rotates_exact_tenants_and_names_without_leaving_empty_groups() {
    let mut queue = Queue::default();
    assert!(queue.pop().is_none());
    for (tenant, name) in [(1, "A"), (1, "A"), (1, "a"), (2, "A"), (2, " A")] {
        queue.push(job(tenant, Some(name)).0, limits()).unwrap();
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
        queue.push(job(1, Some("a")).0, limits()).unwrap_err().code,
        "UNAVAILABLE"
    );
}

#[test]
fn total_tenant_and_unknown_name_inspection_caps_cannot_be_bypassed() {
    let mut queue = Queue::default();
    for _ in 0..3 {
        queue.push(job(1, Some("a")).0, limits()).unwrap();
    }
    assert_eq!(
        queue.push(job(1, Some("a")).0, limits()).unwrap_err().code,
        "BACKPRESSURE"
    );
    assert_eq!(
        queue.push(job(1, None).0, limits()).unwrap_err().code,
        "BACKPRESSURE"
    );
    for _ in 0..3 {
        queue.push(job(1, Some("b")).0, limits()).unwrap();
    }
    assert_eq!(
        queue
            .push(job(1, Some("new")).0, limits())
            .unwrap_err()
            .code,
        "BACKPRESSURE"
    );
    for tenant in 2..=7 {
        queue.push(job(tenant, Some("a")).0, limits()).unwrap();
    }
    assert_eq!(
        queue.push(job(8, Some("a")).0, limits()).unwrap_err().code,
        "BACKPRESSURE"
    );
    assert_eq!(queue.tenants.len(), 7);

    let mut queue = Queue::default();
    queue.push(job(1, None).0, limits()).unwrap();
    queue.push(job(1, Some("a")).0, limits()).unwrap();
    queue.push(job(1, Some("b")).0, limits()).unwrap();
    queue.push(job(1, None).0, limits()).unwrap();
    for name in [Some("a"), Some("b"), None] {
        assert_eq!(
            queue.push(job(1, name).0, limits()).unwrap_err().code,
            "BACKPRESSURE"
        );
    }
    queue.push(job(1, Some("new")).0, limits()).unwrap();
    assert_eq!(queue.pop().unwrap().call.action.name(), None);
    queue.push(job(1, Some("a")).0, limits()).unwrap();

    let mut queue = Queue::default();
    for _ in 0..3 {
        queue.push(job(1, None).0, limits()).unwrap();
    }
    for name in [None, Some("new")] {
        assert!(queue.push(job(1, name).0, limits()).is_err());
    }
}

#[test]
fn expired_admission_does_not_reserve_a_tenant_name_or_intake_slot() {
    use crate::intake::{Class, Intake};
    let mut queue = Queue::default();
    for name in [Some("new"), None] {
        let (mut expired, receiver) = job(1, name);
        expired.deadline = Instant::now();
        assert_eq!(queue.push(expired, limits()).unwrap_err().code, "DEADLINE");
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
                .submit_reserved(
                    principal(),
                    call,
                    until(),
                    intake.acquire(&principal()).unwrap(),
                )
                .unwrap();
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut receiver = Some(receiver);
            if disconnected {
                drop(receiver.take());
            }
            panic_now.send(()).unwrap();
            drop_started.recv_timeout(Duration::from_secs(5)).unwrap();
            let permits_during_cleanup = intake.available_permits();
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
