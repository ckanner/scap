use super::*;
use crate::tests::{call, principal, until};
use crate::wire::{Decimal, Identity, Parameter, WireStatement};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;

fn profile() -> Profile {
    Profile {
        version: 1,
        max_members: 3,
        max_input_bytes: 65536,
        max_changed_pages: 2048,
        max_result_bytes: 1048576,
    }
}

fn write(id: u64) -> Call {
    let statements = vec![WireStatement {
        sql: format!("SELECT {id}"),
        params: vec![],
    }];
    let request =
        scap_object::request(1, id, 3, &crate::wire::statements(&statements).unwrap()).unwrap();
    call(Action::Execute {
        request: Identity {
            epoch: Decimal(1),
            id: Decimal(id),
            principal: Decimal(3),
            fingerprint: request.fingerprint,
        },
        statements,
    })
}

fn id(call: &Call) -> u64 {
    match &call.action {
        Action::Execute { request, .. } => request.id.0,
        _ => 0,
    }
}

fn job(number: u64) -> (Job, oneshot::Receiver<Result<Value, Failure>>) {
    let call = write(number);
    let key = scap_object::format::head_key(&call.scope.native().unwrap());
    let (reply, receiver) = oneshot::channel();
    (
        Job {
            principal: principal(),
            call,
            key,
            deadline: until(),
            reply: Reply::Value(reply),
            _reservation: None,
            output: None,
            _output_hold: None,
        },
        receiver,
    )
}

fn diagnostic_intake(registry: &Arc<crate::lifecycle::Registry>) -> Arc<crate::intake::Intake> {
    Arc::new(
        crate::intake::Intake::new(crate::intake::Class::Data, 8, 4096, None)
            .unwrap()
            .with_lifecycle(registry.clone(), crate::lifecycle::Lane::Data)
            .unwrap(),
    )
}

fn traced_job(
    number: u64,
    intake: &Arc<crate::intake::Intake>,
) -> (Job, oneshot::Receiver<Result<Value, Failure>>) {
    let (mut job, receiver) = job(number);
    let lease = intake.acquire(&job.principal).unwrap();
    lease.shrink_body(0).unwrap();
    job._reservation = Some(lease);
    job.enqueued();
    (job, receiver)
}

fn registered(jobs: impl IntoIterator<Item = Job>) -> Arc<Shared> {
    let mut usage = Usage::default();
    let mut queue = DatabaseQueue::default();
    let mut key = String::new();
    for job in jobs {
        if key.is_empty() {
            key = job.key.clone();
        }
        usage.add(&job);
        queue.push(job);
    }
    Arc::new(Shared {
        state: Mutex::new(State {
            closed: false,
            actors: BTreeMap::from([(
                key,
                Actor {
                    slot: 0,
                    tenant: (1, 2),
                    phase: Phase::Running,
                    jobs: queue,
                    changed: Arc::new(Condvar::new()),
                    thread: None,
                },
            )]),
            controls: vec![],
            readers: Readers::default(),
            usage,
        }),
        reaping: Condvar::new(),
    })
}

fn take(shared: &Arc<Shared>, profile: Option<Profile>) -> Work {
    let (key, changed) = {
        let state = lock(&shared.state);
        let (key, actor) = state.actors.iter().next().unwrap();
        (key.clone(), actor.changed.clone())
    };
    shared
        .next_actor(&key, &changed, Duration::from_secs(1), profile)
        .unwrap()
}

fn batch(work: Work) -> Batch {
    match work {
        Work::Group(batch) => batch,
        Work::Single(_) => panic!("expected multiple queued writes"),
    }
}

fn queued(shared: &Shared) -> Vec<u64> {
    lock(&shared.state)
        .actors
        .values()
        .next()
        .unwrap()
        .jobs
        .normal
        .iter()
        .map(|job| id(&job.call))
        .collect()
}

#[test]
fn profile_checks_core_bounds_and_queue_reservations_before_any_factory() {
    let mut limits = super::super::tests::limits();
    profile().validate(limits).unwrap();
    limits.queued_per_database = 0;
    assert_eq!(profile().validate(limits).unwrap_err().code, "CONFIG");
    let mut invalid = profile();
    invalid.version = 2;
    assert_eq!(
        Scheduler::with_execution(
            super::super::tests::limits(),
            None,
            Some(invalid),
            Arc::new(|_| panic!("invalid group profile must precede factory"))
        )
        .err()
        .unwrap()
        .code,
        "CONFIG"
    );
}

#[test]
fn collection_counts_conservative_input_without_allocating_native_payloads() {
    let mut call = write(1);
    let Action::Execute { statements, .. } = &mut call.action else {
        unreachable!()
    };
    statements[0].params = vec![
        Parameter::Null {},
        Parameter::Integer { value: "1".into() },
        Parameter::Real {
            bits: "3ff0000000000000".into(),
        },
        Parameter::Text {
            value: "界".into()
        },
        Parameter::Blob {
            base64: "AA==".into(),
        },
    ];
    let extent = 128 + 64 + 8 + "SELECT 1".len() + 1 + 9 + 16 + 8 + 9;
    assert_eq!(input_remaining(&call, extent), Some(0));
    for maximum in [0, 128, 192, 200, extent - 1] {
        assert!(input_remaining(&call, maximum).is_none());
    }
    call.version = 2;
    assert!(input_remaining(&call, 65536).is_none());
    call.version = 1;
    call.action = Action::Create { nonce: Decimal(1) };
    assert!(input_remaining(&call, 65536).is_none());
}

#[test]
fn collection_is_opportunistic_and_stops_at_complete_identity_and_liveness_boundaries() {
    for mutation in 0..12 {
        let (mut first, first_reply) = job(1);
        let (mut second, second_reply) = job(2);
        let mut first_reply = Some(first_reply);
        let mut second_reply = Some(second_reply);
        let mut selected = Some(profile());
        match mutation {
            0 => selected = None,
            1 => drop(first_reply.take()),
            2 => first.deadline = Instant::now(),
            3 => first.call.version = 2,
            4 => first.call.scope.incarnation.0 = 0,
            5 => second.principal.provision = false,
            6 => second.call.scope.incarnation.0 += 1,
            7 => second.call.scope.generation.0 += 1,
            8 => drop(second_reply.take()),
            9 => second.deadline = Instant::now(),
            10 => second.call.action = Action::Query { statements: vec![] },
            11 => selected.as_mut().unwrap().max_input_bytes = 1,
            _ => unreachable!(),
        }
        let shared = registered([first, second]);
        let work = take(&shared, selected);
        assert!(matches!(work, Work::Single(_)), "boundary {mutation}");
        assert_eq!(lock(&shared.state).usage.all.total, 1);
        drop((work, first_reply, second_reply));
    }
    let (first, first_reply) = job(1);
    let shared = registered([first]);
    assert!(matches!(take(&shared, Some(profile())), Work::Single(_)));
    assert_eq!(lock(&shared.state).usage.all.total, 0);
    drop(first_reply);
}

#[test]
fn priority_and_aggregate_input_boundaries_do_not_let_groups_overtake_other_work() {
    let (first, a) = job(1);
    let (second, b) = job(2);
    let (mut priority, c) = job(3);
    priority.call.action = Action::Open {};
    let shared = registered([first, second, priority]);
    lock(&shared.state)
        .actors
        .values_mut()
        .next()
        .unwrap()
        .jobs
        .priority_taken = 3;
    let Work::Single(first) = take(&shared, Some(profile())) else {
        panic!("waiting priority must stop collection")
    };
    assert_eq!(id(&first.call), 1);
    assert_eq!(queued(&shared), vec![2]);
    assert_eq!(lock(&shared.state).usage.all.total, 2);
    drop((first, a, b, c));

    let (first, a) = job(1);
    let (second, b) = job(2);
    let (third, c) = job(3);
    let first_size = 65536 - input_remaining(&first.call, 65536).unwrap();
    let second_size = 65536 - input_remaining(&second.call, 65536).unwrap();
    let shared = registered([first, second, third]);
    let batch = batch(take(
        &shared,
        Some(Profile {
            max_input_bytes: first_size + second_size,
            ..profile()
        }),
    ));
    assert_eq!(batch.jobs.len(), 1);
    assert!(batch.first.is_some());
    assert_eq!(queued(&shared), vec![3]);
    assert_eq!(lock(&shared.state).usage.all.total, 3);
    drop(batch);
    assert_eq!(lock(&shared.state).usage.all.total, 1);
    drop((a, b, c));
}

struct Prefix {
    consumed: usize,
    fail_last: bool,
}
impl Worker for Prefix {
    fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
        panic!("group worker should not replay one member")
    }
    fn execute_group(
        &mut self,
        members: &mut [Member<'_>],
        _: scap_object::GroupLimits,
    ) -> Outcome {
        Outcome::Completed(
            members
                .iter()
                .take(self.consumed)
                .enumerate()
                .map(|(index, member)| {
                    if self.fail_last && index + 1 == self.consumed {
                        Err(Failure::new("ENGINE"))
                    } else {
                        Ok(json!(id(member.call)))
                    }
                })
                .collect(),
        )
    }
}

#[test]
fn consumed_prefix_refunds_only_itself_and_suffix_precedes_new_arrivals_without_readmission() {
    let pairs: Vec<_> = (1..=3).map(job).collect();
    let (jobs, mut replies): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let shared = registered(jobs);
    let mut batch = batch(take(&shared, Some(profile())));
    assert_eq!(lock(&shared.state).usage.all.total, 3);
    let mut limits = super::super::tests::limits();
    limits.queued_per_database = 5;
    limits.reserved_controls = 1;
    let (arrival, arrival_reply) = job(4);
    {
        let mut state = lock(&shared.state);
        state.usage.check(&arrival, limits).unwrap();
        state.usage.add(&arrival);
        state.actors.values_mut().next().unwrap().jobs.push(arrival);
        let (overflow, overflow_reply) = job(5);
        assert_eq!(
            state.usage.check(&overflow, limits).unwrap_err().code,
            "BACKPRESSURE"
        );
        drop((overflow, overflow_reply));
    }
    batch.run(&mut Prefix {
        consumed: 2,
        fail_last: true,
    });
    assert_eq!(
        replies.remove(0).blocking_recv().unwrap().unwrap(),
        json!(1)
    );
    assert_eq!(
        replies.remove(0).blocking_recv().unwrap().unwrap_err().code,
        "ENGINE"
    );
    assert!(matches!(
        replies[0].try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(queued(&shared), vec![3, 4]);
    assert_eq!(lock(&shared.state).usage.all.total, 2);
    drop((batch, replies, arrival_reply));
}

#[test]
fn lifecycle_only_attributes_the_trusted_prefix_and_keeps_the_suffix_original_queue_time() {
    let registry = Arc::new(crate::lifecycle::Registry::new());
    let intake = diagnostic_intake(&registry);
    let (jobs, mut replies): (Vec<_>, Vec<_>) =
        (1..=3).map(|number| traced_job(number, &intake)).unzip();
    let shared = registered(jobs);
    let mut selected = batch(take(&shared, Some(profile())));
    selected.run(&mut Prefix {
        consumed: 2,
        fail_last: true,
    });
    assert_eq!(
        replies.remove(0).blocking_recv().unwrap().unwrap(),
        json!(1)
    );
    assert_eq!(
        replies.remove(0).blocking_recv().unwrap().unwrap_err().code,
        "ENGINE"
    );
    let prefix = registry.snapshot();
    assert!(prefix.valid);
    assert_eq!(
        (prefix.lanes[0].released.0, prefix.lanes[0].active.0),
        (2, 1)
    );
    assert_eq!(prefix.groups.attempts.0, 1);
    assert_eq!(prefix.groups.selected.0, 3);
    assert_eq!(prefix.groups.consumed.0, 2);
    assert_eq!(prefix.groups.selected_sizes[2].0, 1);
    assert_eq!(prefix.groups.consumed_sizes[1].0, 1);
    assert_eq!(prefix.lanes[0].intervals[3].distribution.completed.0, 2);
    assert_eq!(
        prefix.lanes[0].intervals[3].distribution.total_us.0,
        2 * prefix.groups.duration.total_us.0
    );
    assert_eq!(queued(&shared), vec![3]);
    let Work::Single(suffix) = take(&shared, None) else {
        panic!("the suffix must remain unstarted")
    };
    SingleWorker::new(Box::new(Legacy(Arc::new(AtomicUsize::new(0))))).execute(suffix);
    assert_eq!(
        replies.remove(0).blocking_recv().unwrap().unwrap(),
        json!(3)
    );
    let final_state = registry.snapshot();
    assert!(final_state.valid, "requeue must not mark a second enqueue");
    assert_eq!(
        (
            final_state.lanes[0].released.0,
            final_state.lanes[0].active.0
        ),
        (3, 0)
    );
    assert_eq!(
        final_state.lanes[0].intervals[1].distribution.completed.0,
        3
    );
    assert_eq!(
        final_state.lanes[0].intervals[2].distribution.completed.0,
        3
    );
    assert_eq!(
        final_state.lanes[0].intervals[3].distribution.completed.0,
        3
    );
    assert_eq!(final_state.groups.attempts.0, 1);
}

#[test]
fn an_unreserved_member_does_not_create_a_fictitious_intake_trace() {
    for first_traced in [false, true] {
        let registry = Arc::new(crate::lifecycle::Registry::new());
        let intake = diagnostic_intake(&registry);
        let (first, first_reply) = if first_traced {
            traced_job(1, &intake)
        } else {
            job(1)
        };
        let (second, second_reply) = if first_traced {
            job(2)
        } else {
            traced_job(2, &intake)
        };
        let shared = registered([first, second]);
        batch(take(&shared, Some(profile()))).run(&mut Prefix {
            consumed: 2,
            fail_last: false,
        });
        first_reply.blocking_recv().unwrap().unwrap();
        second_reply.blocking_recv().unwrap().unwrap();
        let snapshot = registry.snapshot();
        assert!(snapshot.valid);
        assert_eq!(
            (snapshot.groups.selected.0, snapshot.groups.consumed.0),
            (2, 2)
        );
        assert_eq!(
            (snapshot.lanes[0].acquired.0, snapshot.lanes[0].released.0),
            (1, 1)
        );
        assert_eq!(snapshot.lanes[0].intervals[3].distribution.completed.0, 1);
    }
}

struct Legacy(Arc<AtomicUsize>);
impl Worker for Legacy {
    fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!(id(&call)))
    }
}

#[test]
fn legacy_decline_runs_only_the_original_head_and_preserves_unstarted_jobs() {
    for diagnostics in [false, true] {
        let count = Arc::new(AtomicUsize::new(0));
        for ended in 0..3 {
            let registry = Arc::new(crate::lifecycle::Registry::new());
            let intake = diagnostic_intake(&registry);
            let (first, first_reply) = if diagnostics {
                traced_job(1, &intake)
            } else {
                job(1)
            };
            let (second, second_reply) = if diagnostics {
                traced_job(2, &intake)
            } else {
                job(2)
            };
            let shared = registered([first, second]);
            let mut batch = batch(take(&shared, Some(profile())));
            let mut first_reply = Some(first_reply);
            if ended == 1 {
                drop(first_reply.take());
            }
            if ended == 2 {
                batch.first.as_mut().unwrap().deadline = Instant::now();
            }
            batch.run(&mut Legacy(count.clone()));
            if let Some(reply) = first_reply {
                let result = reply.blocking_recv().unwrap();
                if ended == 0 {
                    assert_eq!(result.unwrap(), json!(1));
                } else {
                    assert_eq!(result.unwrap_err().code, "DEADLINE");
                }
            }
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(queued(&shared), vec![2]);
            assert_eq!(lock(&shared.state).usage.all.total, 1);
            let snapshot = registry.snapshot();
            assert!(snapshot.valid);
            if diagnostics {
                assert_eq!(
                    (snapshot.groups.attempts.0, snapshot.groups.declined.0),
                    (1, 1)
                );
                assert_eq!(snapshot.groups.duration.completed.0, 1);
                assert_eq!(snapshot.groups.consumed.0, 0);
                assert_eq!(
                    (snapshot.lanes[0].released.0, snapshot.lanes[0].active.0),
                    (1, 1)
                );
                assert_eq!(
                    snapshot.lanes[0].intervals[3].distribution.completed.0,
                    u64::from(ended == 0)
                );
                assert_eq!(
                    snapshot.lanes[0].intervals[3].distribution.not_reached.0,
                    u64::from(ended != 0)
                );
            } else {
                assert_eq!(snapshot.groups.attempts.0, 0);
            }
            drop((batch, second_reply));
        }
    }
}

#[test]
fn shutdown_keeps_completed_outcome_and_fails_unstarted_suffix_without_rescheduling() {
    let (first, first_reply) = job(1);
    let (second, second_reply) = job(2);
    let shared = registered([first, second]);
    let mut batch = batch(take(&shared, Some(profile())));
    shared.close();
    batch.run(&mut Prefix {
        consumed: 1,
        fail_last: false,
    });
    assert_eq!(first_reply.blocking_recv().unwrap().unwrap(), json!(1));
    assert_eq!(
        second_reply.blocking_recv().unwrap().unwrap_err().code,
        "UNAVAILABLE"
    );
    assert!(queued(&shared).is_empty());
    assert_eq!(lock(&shared.state).usage.all.total, 0);
}

#[test]
fn invalid_worker_prefix_fails_closed_instead_of_requeuing_possibly_executed_members() {
    struct Broken(usize);
    impl Worker for Broken {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            unreachable!()
        }
        fn execute_group(&mut self, _: &mut [Member<'_>], _: scap_object::GroupLimits) -> Outcome {
            Outcome::Completed((0..self.0).map(|_| Err(Failure::new("UNKNOWN"))).collect())
        }
    }
    for length in [0, 3] {
        let registry = Arc::new(crate::lifecycle::Registry::new());
        let intake = diagnostic_intake(&registry);
        let (first, first_reply) = traced_job(1, &intake);
        let (second, second_reply) = traced_job(2, &intake);
        let shared = registered([first, second]);
        let mut selected = batch(take(&shared, Some(profile())));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || selected.run(&mut Broken(length))
        ))
        .is_err());
        drop(selected);
        assert_eq!(lock(&shared.state).usage.all.total, 0);
        assert!(first_reply.blocking_recv().is_err());
        assert!(second_reply.blocking_recv().is_err());
        assert!(queued(&shared).is_empty());
        let snapshot = registry.snapshot();
        assert!(snapshot.valid);
        assert_eq!(snapshot.groups.incomplete.0, 1);
        assert_eq!(snapshot.groups.duration.censored.0, 1);
        assert_eq!(snapshot.groups.consumed.0, 0);
        assert_eq!(snapshot.lanes[0].intervals[2].distribution.censored.0, 2);
        assert_eq!(snapshot.lanes[0].intervals[3].distribution.not_reached.0, 2);
    }
}

#[test]
fn panic_releases_group_credits_and_leases_only_after_worker_native_cleanup() {
    use crate::intake::{Class, Intake};
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    let registry = Arc::new(crate::lifecycle::Registry::new());
    let intake = Arc::new(
        Intake::new(
            Class::Data,
            2,
            4096,
            Some(crate::intake::Profile {
                version: 1,
                requests_per_tenant: 2,
                body_bytes: 8192,
                body_bytes_per_tenant: 8192,
            }),
        )
        .unwrap()
        .with_lifecycle(registry.clone(), crate::lifecycle::Lane::Data)
        .unwrap(),
    );
    let pool = small_pool(4 * BASE_BYTES, 4 * BASE_BYTES);
    let mut jobs = Vec::new();
    let mut replies = Vec::new();
    for number in 1..=2 {
        let (mut job, old) = job(number);
        drop(old);
        let output = pool.acquire(&job.principal, false).unwrap();
        job._output_hold = Some(output.work_hold());
        job.output = Some(output);
        let lease = intake.acquire(&job.principal).unwrap();
        lease.shrink_body(0).unwrap();
        job._reservation = Some(lease);
        job.enqueued();
        let (sender, receiver) = oneshot::channel();
        job.reply = Reply::Encoded(sender);
        jobs.push(job);
        replies.push(receiver);
    }
    let shared = registered(jobs);
    let (started, wait) = mpsc::sync_channel(1);
    let (release, freed) = mpsc::sync_channel(1);
    struct SlowDrop {
        started: mpsc::SyncSender<()>,
        freed: mpsc::Receiver<()>,
    }
    impl Worker for SlowDrop {
        fn execute(&mut self, _: &Principal, _: Call, _: Instant) -> Result<Value, Failure> {
            unreachable!()
        }
        fn execute_group(&mut self, _: &mut [Member<'_>], _: scap_object::GroupLimits) -> Outcome {
            panic!("native worker failure")
        }
    }
    impl Drop for SlowDrop {
        fn drop(&mut self) {
            self.started.send(()).unwrap();
            self.freed.recv_timeout(Duration::from_secs(5)).unwrap();
        }
    }
    let work = shared.clone();
    let child = std::thread::spawn(move || {
        let mut owned = ActorWorker {
            worker: SingleWorker::new(Box::new(SlowDrop { started, freed })),
            active: Some(batch(take(&work, Some(profile())))),
        };
        owned
            .active
            .as_mut()
            .unwrap()
            .run(owned.worker.worker.as_mut());
    });
    wait.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(lock(&shared.state).usage.all.total, 2);
    assert_eq!(intake.available_permits(), 0);
    assert_eq!(usage(&pool).0, 2 * BASE_BYTES);
    let during_cleanup = registry.snapshot();
    release.send(()).unwrap();
    assert!(child.join().is_err());
    assert_eq!(lock(&shared.state).usage.all.total, 0);
    assert_eq!(intake.available_permits(), 2);
    assert_eq!(usage(&pool), (0, 0, 0));
    assert!(during_cleanup.valid);
    assert_eq!(
        (
            during_cleanup.lanes[0].active.0,
            during_cleanup.lanes[0].released.0
        ),
        (2, 0)
    );
    assert_eq!(during_cleanup.groups.incomplete.0, 1);
    assert_eq!(during_cleanup.groups.duration.censored.0, 1);
    let snapshot = registry.snapshot();
    assert!(snapshot.valid);
    assert_eq!(
        (snapshot.lanes[0].active.0, snapshot.lanes[0].released.0),
        (0, 2)
    );
    assert_eq!(snapshot.lanes[0].intervals[2].distribution.censored.0, 2);
    assert_eq!(snapshot.lanes[0].intervals[3].distribution.not_reached.0, 2);
    assert_eq!(snapshot.groups.consumed.0, 0);
    for reply in replies {
        assert!(reply.blocking_recv().is_err());
    }
}

#[test]
fn real_actor_batches_already_queued_writes_and_keeps_control_capacity_independent() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let grouping = Arc::new(Barrier::new(2));
    let complete = Arc::new(Barrier::new(2));
    let observed = Arc::new(Mutex::new(Vec::new()));
    struct Held {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        grouping: Arc<Barrier>,
        complete: Arc<Barrier>,
        observed: Arc<Mutex<Vec<Vec<u64>>>>,
    }
    impl Worker for Held {
        fn execute(&mut self, _: &Principal, call: Call, _: Instant) -> Result<Value, Failure> {
            if matches!(call.action, Action::Query { .. }) {
                self.entered.wait();
                self.release.wait();
            }
            Ok(json!(id(&call)))
        }
        fn execute_group(
            &mut self,
            members: &mut [Member<'_>],
            _: scap_object::GroupLimits,
        ) -> Outcome {
            self.observed
                .lock()
                .unwrap()
                .push(members.iter().map(|member| id(member.call)).collect());
            self.grouping.wait();
            self.complete.wait();
            Outcome::Completed(
                members
                    .iter()
                    .map(|member| Ok(json!(id(member.call))))
                    .collect(),
            )
        }
    }
    let factory: Factory = {
        let (entered, release, grouping, complete, observed) = (
            entered.clone(),
            release.clone(),
            grouping.clone(),
            complete.clone(),
            observed.clone(),
        );
        Arc::new(move |_| {
            Ok(Box::new(Held {
                entered: entered.clone(),
                release: release.clone(),
                grouping: grouping.clone(),
                complete: complete.clone(),
                observed: observed.clone(),
            }))
        })
    };
    let mut limits = super::super::tests::limits();
    limits.queued_per_database = 4;
    limits.reserved_controls = 1;
    let scheduler = Scheduler::with_execution(limits, None, Some(profile()), factory).unwrap();
    let first = scheduler
        .submit(
            principal(),
            call(Action::Query { statements: vec![] }),
            until(),
        )
        .unwrap();
    entered.wait();
    let replies: Vec<_> = (1..=3)
        .map(|number| {
            scheduler
                .submit(principal(), write(number), until())
                .unwrap()
        })
        .collect();
    assert_eq!(
        scheduler
            .submit(principal(), write(4), until())
            .err()
            .unwrap()
            .code,
        "BACKPRESSURE"
    );
    let control = scheduler
        .submit(
            principal(),
            call(Action::Status {
                expected_worker_instance: None,
            }),
            until(),
        )
        .unwrap();
    assert_eq!(control.blocking_recv().unwrap().unwrap(), json!(0));
    release.wait();
    grouping.wait();
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 3);
    assert_eq!(
        scheduler
            .submit(principal(), write(4), until())
            .err()
            .unwrap()
            .code,
        "BACKPRESSURE"
    );
    assert_eq!(*observed.lock().unwrap(), vec![vec![1, 2, 3]]);
    complete.wait();
    first.blocking_recv().unwrap().unwrap();
    for (index, reply) in replies.into_iter().enumerate() {
        assert_eq!(reply.blocking_recv().unwrap().unwrap(), json!(index + 1));
    }
    assert_eq!(lock(&scheduler.shared.state).usage.all.total, 0);
}
