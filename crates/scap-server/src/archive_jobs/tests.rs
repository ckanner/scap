use super::*;
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

use raft::eraftpb::Entry as RaftEntry;
use scap_cell::{
    Admission, CellApplication, CellState, Command, CommandKind, Grant, OwnerToken, Position,
};
use scap_cell_client::CellPort;
use scap_raft_driver::{Application, ProposalResult, ProposalTicket, ReadBarrier, ReadTicket};
use scap_raft_runtime::{Error as RuntimeError, ReadView, SystemClock};
use scap_raft_store::Identity;

use crate::tests::config;
use crate::worker::tests::TestClock;

fn job(id: u128, now: Instant) -> Job {
    Job {
        database: DatabaseView {
            control_revision: None,
            request_epoch: 1,
            retained_requests: 0,
            unacknowledged_requests: 0,
            retired_revision: 0,
            identity: scap_cell::DatabaseIdentity {
                database_id: id,
                incarnation: 1,
                placement_generation: 1,
            },
            auth_epoch: 1,
            owner: OwnerToken {
                epoch: 0,
                worker_instance_id: 0,
            },
            active: false,
            revision: 0,
            base_revision: 0,
            tail_entries: 0,
            tail_bytes: 0,
            commit_hash: [0; 32],
            suspended: true,
            cold: false,
            archive: None,
        },
        context: RequestContext {
            admission: Admission {
                principal_id: 100,
                credential_id: 101,
                admission_id: 102,
                auth_epoch: 1,
                request_epoch: 1,
            },
            deadline: now + Duration::from_secs(30),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
        publish: id * 10 + 2,
        prune: id * 10 + 3,
    }
}

fn queued(request: Job) -> QueuedJob {
    QueuedJob {
        request,
        gate: Arc::new(Mutex::new(())),
    }
}

fn make_queue(
    capacity: usize,
    databases: usize,
) -> (Queue, Receiver<QueuedJob>, SyncSender<Completion>) {
    let (sender, jobs) = mpsc::sync_channel(capacity);
    let (complete, completions) = mpsc::sync_channel(MAX_PENDING);
    (
        Queue {
            sender: Some(sender),
            completions,
            entries: BTreeMap::new(),
            gates: BTreeMap::new(),
            max_databases: databases,
            control: Arc::new(Control::default()),
        },
        jobs,
        complete,
    )
}

#[test]
fn queue_bounds_pending_catalogue_and_preserves_job_scope_budget_and_backoff() {
    let now = Instant::now();
    let (mut queue, receive, complete) = make_queue(MAX_PENDING, MAX_PENDING + 1);
    for id in 1..=MAX_PENDING as u128 {
        queue.enqueue(job(id, now), now).unwrap();
    }
    queue.enqueue(job(9, now), now).unwrap();
    assert_eq!(queue.entries.len(), MAX_PENDING);
    let original = receive.recv().unwrap().request;
    assert_eq!(original.context.deadline, now + Duration::from_secs(30));
    let mut changed = original.clone();
    changed.database.identity.incarnation += 1;
    changed.database.owner.epoch += 1;
    changed.prune += 100;
    queue.enqueue(changed, now).unwrap();
    assert_eq!(queue.entries[&1].pending, Some(original.prune));
    complete
        .send(Completion {
            database: 999,
            prune: 999,
            completed: true,
        })
        .unwrap();
    complete
        .send(Completion {
            database: 1,
            prune: 999,
            completed: true,
        })
        .unwrap();
    assert!(!queue.poll());
    assert!(queue.entries[&1].pending.is_some());
    complete
        .send(Completion {
            database: 1,
            prune: original.prune,
            completed: false,
        })
        .unwrap();
    assert!(!queue.poll());
    queue.enqueue(job(1, now), now).unwrap();
    assert!(queue.entries[&1].pending.is_none());
    let later = original.context.deadline + RETRY_BACKOFF;
    queue.enqueue(job(1, later), later).unwrap();
    assert!(queue.entries[&1].pending.is_some());
    complete
        .send(Completion {
            database: 2,
            prune: job(2, now).prune,
            completed: true,
        })
        .unwrap();
    assert!(queue.poll());
    assert!(!queue.poll());
    queue.enqueue(job(2, now), now).unwrap();
    assert!(queue.entries[&2].pending.is_none()); // transport still full, no receipt installed

    let (mut catalog, received, complete) = make_queue(2, 1);
    catalog.enqueue(job(1, now), now).unwrap();
    let first = received.recv().unwrap().request;
    complete
        .send(Completion {
            database: 1,
            prune: first.prune,
            completed: true,
        })
        .unwrap();
    assert!(catalog.poll());
    catalog.enqueue(job(2, now), now).unwrap();
    assert_eq!(catalog.entries.len(), 1);
    catalog.enqueue(job(1, now), now).unwrap();
    assert_eq!(
        received
            .recv()
            .unwrap()
            .request
            .database
            .identity
            .database_id,
        1
    );
}

#[test]
fn queue_failures_do_not_admit_pending_jobs_or_rewrite_deadlines() {
    let now = Instant::now();
    let (mut state, received, _) = make_queue(0, 1);
    state.enqueue(job(1, now), now).unwrap(); // full zero-capacity adapter
    assert!(state.entries.is_empty());
    drop(received);
    assert_eq!(
        state.enqueue(job(1, now), now).unwrap_err().code,
        "ARCHIVE_STOPPED"
    );
    state.control.stop();
    assert_eq!(
        state.enqueue(job(1, now), now).unwrap_err().code,
        "ARCHIVE_STOPPED"
    );
    let (mut state, _received, _) = make_queue(1, 1);
    let mut request = job(1, now);
    request.context.cancelled.store(true, Ordering::Release);
    assert_eq!(
        state.enqueue(request.clone(), now).unwrap_err().code,
        "COMMIT_UNKNOWN"
    );
    request.context.cancelled.store(false, Ordering::Release);
    request.context.deadline = now;
    assert_eq!(
        state.enqueue(request, now).unwrap_err().code,
        "COMMIT_UNKNOWN"
    );
    state.sender = None;
    state.enqueue(job(1, now), now).unwrap();
    assert!(state.entries.is_empty());
}

struct CountingRunner {
    calls: Arc<AtomicUsize>,
    fail_at: usize,
}
impl Runner for CountingRunner {
    fn run(&mut self, _: &QueuedJob) -> Result<(), ServiceError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.fail_at {
            Err(failure("INJECTED"))
        } else {
            Ok(())
        }
    }
}

struct ScriptBus {
    jobs: VecDeque<Result<QueuedJob, RecvTimeoutError>>,
    completed: Vec<Completion>,
    control: Arc<Control>,
    stop_on_receive: bool,
    complete_ok: bool,
}
impl Bus for ScriptBus {
    fn receive(&mut self) -> Result<QueuedJob, RecvTimeoutError> {
        let result = self.jobs.pop_front().unwrap();
        if self.stop_on_receive {
            self.control.stop();
        }
        result
    }
    fn complete(&mut self, completion: Completion) -> bool {
        self.completed.push(completion);
        self.complete_ok
    }
}

#[test]
fn background_delivery_handles_timeout_stop_failure_and_completion_disconnect() {
    let now = Instant::now();
    for scenario in 0..4 {
        let control = Arc::new(Control::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut bus = ScriptBus {
            jobs: [
                Err(RecvTimeoutError::Timeout),
                Ok(queued(job(1, now))),
                Ok(queued(job(2, now))),
                Err(RecvTimeoutError::Disconnected),
            ]
            .into(),
            completed: Vec::new(),
            control: control.clone(),
            stop_on_receive: scenario == 2,
            complete_ok: scenario != 3,
        };
        if scenario == 1 {
            control.stop();
        }
        if scenario == 2 {
            bus.jobs.pop_front();
        }
        run_worker(
            Box::new(CountingRunner {
                calls: calls.clone(),
                fail_at: 2,
            }),
            &mut bus,
            &control,
        );
        assert!(control.active.lock().is_none());
        match scenario {
            0 => {
                assert_eq!(calls.load(Ordering::Acquire), 2);
                assert!(bus.completed[0].completed);
                assert!(!bus.completed[1].completed);
            }
            3 => assert_eq!(calls.load(Ordering::Acquire), 1),
            _ => assert_eq!(calls.load(Ordering::Acquire), 0),
        }
    }
}

#[test]
fn native_bus_has_bounded_receive_and_never_blocks_for_completions() {
    let (sender, jobs) = mpsc::sync_channel(1);
    let (complete, completions) = mpsc::sync_channel(1);
    let mut bus = NativeBus {
        jobs,
        completions: complete,
    };
    assert!(matches!(bus.receive(), Err(RecvTimeoutError::Timeout)));
    sender.send(queued(job(1, Instant::now()))).unwrap();
    assert_eq!(
        bus.receive().unwrap().request.database.identity.database_id,
        1
    );
    assert!(bus.complete(Completion {
        database: 1,
        prune: 1,
        completed: true
    }));
    assert!(!bus.complete(Completion {
        database: 1,
        prune: 1,
        completed: true
    }));
    drop(completions);
    assert!(!bus.complete(Completion {
        database: 1,
        prune: 1,
        completed: true
    }));
    drop(sender);
    assert!(matches!(bus.receive(), Err(RecvTimeoutError::Disconnected)));
}

struct CancelRunner(SyncSender<()>);
impl Runner for CancelRunner {
    fn run(&mut self, queued: &QueuedJob) -> Result<(), ServiceError> {
        let job = &queued.request;
        self.0.send(()).unwrap();
        while !job.context.cancelled.load(Ordering::Acquire) {
            assert!(Instant::now() < job.context.deadline);
            thread::sleep(Duration::from_millis(1));
        }
        Err(failure("CANCELLED"))
    }
}
struct PanicRunner;
impl Runner for PanicRunner {
    fn run(&mut self, _: &QueuedJob) -> Result<(), ServiceError> {
        panic!("injected background panic")
    }
}
fn failed_spawn(_: Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>> {
    Err(std::io::Error::other("injected unavailable thread"))
}

#[tokio::test]
async fn supervisor_observes_panic_and_joins_or_cancels_all_threads() {
    let now = Instant::now();
    let (entered, wait) = mpsc::sync_channel(1);
    let (mut queue, mut supervisor) =
        start(Some(Box::new(CancelRunner(entered))), 1, native_spawn).unwrap();
    let task = job(1, now);
    let cancelled = task.context.cancelled.clone();
    queue.enqueue(task, now).unwrap();
    wait.recv_timeout(Duration::from_secs(1)).unwrap();
    supervisor.request_stop();
    tokio::time::timeout(Duration::from_secs(1), supervisor.completed())
        .await
        .unwrap();
    assert!(cancelled.load(Ordering::Acquire));
    supervisor.join().unwrap();

    let (mut queue, mut supervisor) = start(Some(Box::new(PanicRunner)), 1, native_spawn).unwrap();
    queue.enqueue(job(1, now), now).unwrap();
    tokio::time::timeout(Duration::from_secs(1), supervisor.completed())
        .await
        .unwrap();
    assert_eq!(supervisor.join().unwrap_err().code, "ARCHIVE_PANICKED");

    let (_queue, supervisor) = start(
        Some(Box::new(CountingRunner {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_at: 0,
        })),
        1,
        native_spawn,
    )
    .unwrap();
    drop(supervisor); // leak-prevention path owns and joins the idle native thread
    let (_queue, mut disabled) = start(None, 1, native_spawn).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), disabled.completed())
            .await
            .is_err()
    );
    disabled.join().unwrap();
    for capacity in [0, cell_limits().max_databases as usize + 1] {
        assert_eq!(
            start(None, capacity, native_spawn).err().unwrap().code,
            "ARCHIVE_CAPACITY"
        );
    }
    assert_eq!(
        start(Some(Box::new(PanicRunner)), 1, failed_spawn)
            .err()
            .unwrap()
            .code,
        "ARCHIVE_SPAWN"
    );
}

#[derive(Clone)]
struct Port {
    identity: Identity,
    state: Arc<Mutex<CellState>>,
    reads_fail: Arc<AtomicBool>,
    reject_at: Arc<AtomicUsize>,
    proposals: Arc<AtomicUsize>,
    pause: Arc<Mutex<Option<PauseProposal>>>,
}
struct PauseProposal {
    at: usize,
    entered: SyncSender<Instant>,
    released: Receiver<()>,
}
impl Port {
    fn new() -> Self {
        let config = config();
        Self {
            identity: Identity {
                cluster_id: config.cluster_id,
                cell_id: config.cell.cell_id,
                cell_incarnation: config.cell.cell_incarnation,
                node_id: config.node_id,
            },
            state: Arc::new(Mutex::new(
                CellState::bootstrap(
                    config.cell,
                    config.administrator_id,
                    Position { term: 1, index: 1 },
                    cell_limits(),
                )
                .unwrap(),
            )),
            reads_fail: Arc::new(AtomicBool::new(false)),
            reject_at: Arc::new(AtomicUsize::new(0)),
            proposals: Arc::new(AtomicUsize::new(0)),
            pause: Arc::new(Mutex::new(None)),
        }
    }
    fn apply(&self, data: Vec<u8>) -> scap_cell::AppliedOutcome {
        let mut state = self.state.lock();
        let position = Position {
            term: 1,
            index: state.position().index + 1,
        };
        let entry = RaftEntry {
            term: position.term,
            index: position.index,
            data: data.into(),
            ..RaftEntry::default()
        };
        let batch = CellApplication::new(state.identity(), cell_limits())
            .unwrap()
            .apply_with_results(&state.encode(), &[entry], &[position.index])
            .unwrap();
        *state = CellState::decode_bound(&batch.state, state.identity(), position, cell_limits())
            .unwrap();
        scap_cell::decode_applied_outcome(&batch.results[0], position).unwrap()
    }
    fn create(&self) {
        let config = config();
        let request = job(3, Instant::now());
        let command = Command {
            control_revision: None,
            cell: config.cell,
            database: request.database.identity,
            admission: request.context.admission,
            kind: CommandKind::Create {
                operation_id: 1,
                policy: vec![Grant {
                    principal_id: 100,
                    permissions: scap_cell::READ | scap_cell::WRITE | scap_cell::ADMIN,
                }],
            },
        };
        self.apply(scap_cell::encode_command(&command, cell_limits()).unwrap());
    }
}
impl CellPort for Port {
    fn identity(&self) -> Identity {
        self.identity.clone()
    }
    fn read(&mut self, _: Instant, _: &AtomicBool) -> Result<ReadView, RuntimeError> {
        if self.reads_fail.load(Ordering::Acquire) {
            return Err(RuntimeError::Unknown);
        }
        let state = self.state.lock();
        let position = state.position();
        Ok(ReadView {
            identity: self.identity(),
            term: position.term,
            index: position.index,
            application: state.encode(),
            barrier: ReadBarrier {
                ticket: ReadTicket {
                    boot_id: 1,
                    sequence: 1,
                },
                index: position.index,
            },
        })
    }
    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        _: &AtomicBool,
    ) -> Result<ProposalResult, RuntimeError> {
        let call = self.proposals.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some(pause) = self.pause.lock().as_ref() {
            if call == pause.at {
                pause.entered.send(deadline).unwrap();
                pause.released.recv_timeout(Duration::from_secs(2)).unwrap();
            }
        }
        if self.reject_at.load(Ordering::Acquire) == call {
            return Err(RuntimeError::Unknown);
        }
        let applied = self.apply(data);
        Ok(ProposalResult {
            ticket: ProposalTicket {
                boot_id: 1,
                sequence: call as u64,
            },
            term: applied.position.term,
            index: applied.position.index,
            data: scap_cell::encode_applied_outcome(&applied),
        })
    }
}
impl ControlPort for Port {
    fn leadership(&self, _: Instant) -> Result<(bool, u64), ServiceError> {
        Ok((true, 1))
    }
    fn maintain(&self, _: Instant, _: bool) -> Result<(), ServiceError> {
        Ok(())
    }
}
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);
impl Objects for Memory {
    fn put(
        &mut self,
        key: &str,
        bytes: &[u8],
        _: &RequestContext,
    ) -> Result<(), scap_archive::Error> {
        self.0
            .lock()
            .entry(key.into())
            .or_insert_with(|| bytes.to_vec());
        Ok(())
    }
    fn get(
        &mut self,
        key: &str,
        _: u32,
        _: &RequestContext,
    ) -> Result<Vec<u8>, scap_archive::Error> {
        self.0
            .lock()
            .get(key)
            .cloned()
            .ok_or(scap_archive::Error::Object)
    }
}
fn client(port: &Port, clock: Arc<dyn Clock>) -> Client<Port> {
    let cfg = config();
    Client::new(cfg.cluster_id, cfg.cell, cell_limits(), port.clone(), clock).unwrap()
}

#[test]
fn bound_runner_retains_exact_view_and_reports_publication_or_prune_failure() {
    for failure in 0..3 {
        let port = Port::new();
        port.create();
        let now = Instant::now();
        let mut request = job(3, now);
        request.database = port.state.lock().database(3).unwrap();
        if failure == 1 {
            port.reads_fail.store(true, Ordering::Release);
        }
        if failure == 2 {
            port.reject_at.store(2, Ordering::Release);
        }
        let mut runner = BoundRunner {
            controller: Controller::new(client(&port, Arc::new(SystemClock)), Memory::default()),
            clock: Arc::new(SystemClock),
        };
        let scheduled = queued(request);
        let result = runner.run(&scheduled);
        assert!(
            scheduled.gate.try_lock().is_some(),
            "every result releases the gate"
        );
        if failure == 0 {
            result.unwrap();
            assert!(port.state.lock().database(3).unwrap().cold);
        } else {
            assert_eq!(result.unwrap_err().code, "ARCHIVE_UNAVAILABLE");
            assert!(!port.state.lock().database(3).unwrap().cold);
        }
    }
}

#[test]
fn jobs_adapter_enqueues_without_waiting_and_foreground_hydrate_keeps_deadline() {
    let port = Port::new();
    port.create();
    let clock = Arc::new(TestClock::new());
    let mut client = client(&port, clock.clone());
    let (mut jobs, supervisor) =
        spawn(client.clone(), Some(Memory::default()), 1, clock.clone()).unwrap();
    let mut sibling = jobs.clone();
    assert!(Arc::ptr_eq(&jobs.queue, &sibling.queue));
    let request = job(3, clock.now().unwrap().instant);
    assert!(!jobs
        .archive(
            &mut client,
            &request.context,
            &request.database,
            request.publish,
            request.prune
        )
        .unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    while !jobs.poll() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    assert!(!sibling.poll()); // one shared completion, not one archive per lane
    assert!(port.state.lock().database(3).unwrap().cold);
    let cold = port.state.lock().database(3).unwrap();
    let mut unauthorized = request.context.clone();
    unauthorized.admission.auth_epoch += 1;
    assert_eq!(
        jobs.hydrate(&mut client, &unauthorized, &cold, 90)
            .unwrap_err()
            .code,
        "ARCHIVE_UNAVAILABLE"
    );
    assert!(port.state.lock().database(3).unwrap().cold);
    sibling
        .hydrate(&mut client, &request.context, &cold, 90)
        .unwrap();
    assert!(!port.state.lock().database(3).unwrap().cold);
    clock.fail.store(true, Ordering::Release);
    assert_eq!(
        jobs.archive(&mut client, &request.context, &cold, 91, 92)
            .unwrap_err()
            .code,
        "CLOCK"
    );
    clock.fail.store(false, Ordering::Release);
    supervisor.request_stop();
    assert_eq!(
        jobs.archive(&mut client, &request.context, &cold, 91, 92)
            .unwrap_err()
            .code,
        "ARCHIVE_STOPPED"
    );
    supervisor.join().unwrap();
    let (mut disabled, guard) = spawn::<_, Memory>(client.clone(), None, 1, clock.clone()).unwrap();
    assert!(!disabled
        .archive(&mut client, &request.context, &cold, 91, 92)
        .unwrap());
    assert_eq!(
        disabled
            .hydrate(&mut client, &request.context, &cold, 93)
            .unwrap_err()
            .code,
        "ARCHIVE_UNAVAILABLE"
    );
    guard.join().unwrap();
    assert_eq!(
        spawn::<_, Memory>(client, None, 0, clock)
            .err()
            .unwrap()
            .code,
        "ARCHIVE_CAPACITY"
    );
}

#[derive(Clone)]
struct PausedObjects {
    memory: Memory,
    pause: Arc<AtomicBool>,
    entered: SyncSender<Instant>,
    released: Arc<Mutex<Receiver<()>>>,
}

impl scap_archive::Objects for PausedObjects {
    fn put(
        &mut self,
        key: &str,
        bytes: &[u8],
        context: &RequestContext,
    ) -> Result<(), scap_archive::Error> {
        self.memory.put(key, bytes, context)
    }

    fn get(
        &mut self,
        key: &str,
        max_bytes: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, scap_archive::Error> {
        if self.pause.load(Ordering::Acquire) {
            self.entered.send(context.deadline).unwrap();
            self.released
                .lock()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        }
        self.memory.get(key, max_bytes, context)
    }
}

#[test]
fn foreground_object_wait_never_holds_the_shared_archive_queue_lock() {
    let port = Port::new();
    port.create();
    let clock = Arc::new(SystemClock);
    let mut client = client(&port, clock.clone());
    let (entered, entering) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let pause = Arc::new(AtomicBool::new(false));
    let objects = PausedObjects {
        memory: Memory::default(),
        pause: pause.clone(),
        entered,
        released: Arc::new(Mutex::new(released)),
    };
    let (mut jobs, supervisor) = spawn(client.clone(), Some(objects), 1, clock).unwrap();
    let request = job(3, Instant::now());
    jobs.archive(
        &mut client,
        &request.context,
        &request.database,
        request.publish,
        request.prune,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !jobs.poll() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    let cold = port.state.lock().database(3).unwrap();
    assert!(cold.cold);
    pause.store(true, Ordering::Release);
    let mut sibling = jobs.clone();
    let original_deadline = request.context.deadline;
    let hydrating = thread::spawn(move || {
        let _guard = sibling.recovery_guard(cold.identity, &request.context)?;
        sibling.hydrate(&mut client, &request.context, &cold, 99)
    });
    assert_eq!(
        entering.recv_timeout(Duration::from_secs(1)).unwrap(),
        original_deadline
    );
    assert!(jobs.queue.try_lock().is_some());
    assert!(!jobs.poll());
    release.send(()).unwrap();
    hydrating.join().unwrap().unwrap();
    assert!(!port.state.lock().database(3).unwrap().cold);
    supervisor.join().unwrap();
}

#[test]
fn recovery_gates_share_identity_bound_memory_and_leave_other_databases_free() {
    let port = Port::new();
    port.create();
    let clock = Arc::new(TestClock::new());
    let mut client = client(&port, clock.clone());
    let (queue, received, _complete) = make_queue(2, 2);
    let mut jobs = Jobs {
        client: client.clone(),
        foreground: Some(Memory::default()),
        queue: Arc::new(Mutex::new(queue)),
        clock: clock.clone(),
    };
    let mut sibling = jobs.clone();
    let mut request = job(3, clock.now().unwrap().instant);
    request.context.deadline = Instant::now() + Duration::from_millis(30);
    let first = jobs
        .recovery_guard(request.database.identity, &request.context)
        .unwrap();
    assert!(first.is_some());
    let other = sibling
        .recovery_guard(
            job(4, Instant::now()).database.identity,
            &job(4, Instant::now()).context,
        )
        .unwrap();
    assert!(
        other.is_some(),
        "another database never waits for this guard"
    );
    assert!(jobs.queue.try_lock().is_some());
    assert_eq!(
        jobs.recovery_guard(job(5, Instant::now()).database.identity, &request.context)
            .err()
            .unwrap()
            .code,
        "ARCHIVE_CAPACITY"
    );
    assert_eq!(jobs.queue.lock().gates.len(), 2);
    assert!(jobs.queue.lock().entries.is_empty());

    jobs.archive(
        &mut client,
        &request.context,
        &request.database,
        request.publish,
        request.prune,
    )
    .unwrap();
    let scheduled = received.recv().unwrap();
    assert_eq!(scheduled.request.database, request.database);
    assert_eq!(scheduled.request.context.deadline, request.context.deadline);
    let registered = jobs.queue.lock().gates[&3].clone();
    assert!(Arc::ptr_eq(&registered, &scheduled.gate));
    assert!(scheduled.gate.try_lock().is_none());
    let objects = Memory::default();
    let mut runner = BoundRunner {
        controller: Controller::new(client.clone(), objects.clone()),
        clock: clock.clone(),
    };
    assert_eq!(runner.run(&scheduled).unwrap_err().code, "COMMIT_UNKNOWN");
    assert_eq!(port.proposals.load(Ordering::Acquire), 0);
    assert!(
        objects.0.lock().is_empty(),
        "a waiting archive never starts object I/O"
    );
    assert!(
        registered.try_lock().is_none(),
        "a timeout cannot release another owner's guard"
    );

    drop(first);
    assert!(registered.try_lock().is_some());
    let mut reincarnated = request.database.identity;
    reincarnated.incarnation += 1;
    reincarnated.placement_generation += 1;
    let fresh = job(3, clock.now().unwrap().instant);
    let again = sibling
        .recovery_guard(reincarnated, &fresh.context)
        .unwrap();
    assert!(again.is_some());
    assert!(Arc::ptr_eq(&registered, &jobs.queue.lock().gates[&3]));
    assert!(registered.try_lock().is_none());
    drop(again);
    drop(other);

    // Foreground gate reservations consume the same bounded identity map even
    // before any background job exists. An excess job cannot split the gate.
    let (mut limited, empty, _complete) = make_queue(1, 1);
    let existing = limited.gate(3).unwrap();
    limited
        .enqueue(job(4, Instant::now()), Instant::now())
        .unwrap();
    assert!(empty.try_recv().is_err());
    assert!(limited.entries.is_empty());
    assert!(Arc::ptr_eq(&existing, &limited.gate(3).unwrap()));
    assert_eq!(limited.gates.len(), 1);

    jobs.queue.lock().control.stop();
    assert_eq!(
        jobs.recovery_guard(request.database.identity, &fresh.context)
            .err()
            .unwrap()
            .code,
        "ARCHIVE_STOPPED"
    );
    let (mut disabled, supervisor) = spawn::<_, Memory>(client, None, 1, clock.clone()).unwrap();
    clock.fail.store(true, Ordering::Release);
    fresh.context.cancelled.store(true, Ordering::Release);
    assert!(disabled
        .recovery_guard(request.database.identity, &fresh.context)
        .unwrap()
        .is_none());
    assert!(
        disabled.queue.lock().gates.is_empty(),
        "disabled object storage allocates no gate"
    );
    supervisor.join().unwrap();
}

struct GateClock {
    inner: TestClock,
    calls: AtomicUsize,
    expire_at: usize,
    fail_at: usize,
    entered: Option<SyncSender<()>>,
}

impl Clock for GateClock {
    fn now(&self) -> Result<scap_raft_runtime::ClockReading, RuntimeError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.fail_at {
            return Err(RuntimeError::Clock);
        }
        if call == self.expire_at {
            self.inner.elapsed.store(31, Ordering::Release);
        }
        let reading = self.inner.now()?;
        if call == 1 {
            if let Some(entered) = &self.entered {
                entered.send(()).unwrap();
            }
        }
        Ok(reading)
    }
}

#[test]
fn gate_acquisition_checks_original_context_before_and_after_wait_and_releases_errors() {
    // Exercise the real foreground and background adapters, including error
    // propagation after either side of their actual mutex acquisition.
    for foreground in [false, true] {
        for scenario in 0..6 {
            let (entered, entering) = mpsc::sync_channel(1);
            let clock = Arc::new(GateClock {
                inner: TestClock::new(),
                calls: AtomicUsize::new(0),
                expire_at: match scenario {
                    1 => 1,
                    4 => 2,
                    _ => usize::MAX,
                },
                fail_at: match scenario {
                    2 => 1,
                    5 => 2,
                    _ => usize::MAX,
                },
                entered: (scenario == 3).then_some(entered),
            });
            let request = job(3, clock.inner.now().unwrap().instant);
            if scenario == 0 {
                request.context.cancelled.store(true, Ordering::Release);
            }
            let port = Port::new();
            port.create();
            let before = port.state.lock().encode();
            let client = client(&port, clock.clone());
            let objects = Memory::default();
            let (queue, _received, _complete) = make_queue(1, 1);
            let mut jobs = Jobs {
                client: client.clone(),
                foreground: Some(objects.clone()),
                queue: Arc::new(Mutex::new(queue)),
                clock: clock.clone(),
            };
            let gate = jobs.queue.lock().gate(3).unwrap();
            let held = (scenario == 3).then(|| gate.lock());
            let scheduled = QueuedJob {
                request: request.clone(),
                gate: gate.clone(),
            };
            let mut runner = BoundRunner {
                controller: Controller::new(client, objects.clone()),
                clock: clock.clone(),
            };
            let failing = thread::spawn(move || {
                let result = if foreground {
                    jobs.recovery_guard(
                        scheduled.request.database.identity,
                        &scheduled.request.context,
                    )
                    .map(drop)
                } else {
                    runner.run(&scheduled)
                };
                result.err().unwrap().code
            });
            if scenario == 3 {
                // The first live check has read cancellation as false. Cancel
                // before releasing the real mutex: the second check must fail
                // and drop the newly acquired guard without starting any I/O.
                entering.recv_timeout(Duration::from_secs(1)).unwrap();
                request.context.cancelled.store(true, Ordering::Release);
            }
            drop(held);
            assert_eq!(
                failing.join().unwrap(),
                if scenario == 2 || scenario == 5 {
                    "CLOCK"
                } else {
                    "COMMIT_UNKNOWN"
                }
            );
            assert_eq!(
                clock.calls.load(Ordering::Acquire),
                match scenario {
                    0 => 0,
                    4 | 5 => 2,
                    _ => 1,
                }
            );
            assert!(
                gate.try_lock().is_some(),
                "every adapter failure must release its acquired guard"
            );
            assert_eq!(port.state.lock().encode(), before);
            assert_eq!(port.proposals.load(Ordering::Acquire), 0);
            assert!(
                objects.0.lock().is_empty(),
                "no object I/O may start after the context fails"
            );
        }
    }
}

#[test]
fn background_gate_spans_publication_and_prune_while_unrelated_recovery_is_free() {
    let port = Port::new();
    port.create();
    let clock = Arc::new(TestClock::new());
    let mut client = client(&port, clock.clone());
    let (entered, entering) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    *port.pause.lock() = Some(PauseProposal {
        at: 2,
        entered,
        released,
    });
    let (mut jobs, supervisor) =
        spawn(client.clone(), Some(Memory::default()), 2, clock.clone()).unwrap();
    let request = job(3, clock.now().unwrap().instant);
    jobs.archive(
        &mut client,
        &request.context,
        &request.database,
        request.publish,
        request.prune,
    )
    .unwrap();
    assert_eq!(
        entering.recv_timeout(Duration::from_secs(1)).unwrap(),
        request.context.deadline
    );
    let published = port.state.lock().database(3).unwrap();
    assert!(published.archive.is_some());
    assert!(
        !published.cold,
        "pause after publication but before the exact prune applies"
    );
    let gate = jobs.queue.lock().gates[&3].clone();
    assert!(
        gate.try_lock().is_none(),
        "publication must not drop the archive guard before prune"
    );
    assert!(jobs.queue.try_lock().is_some());
    let other = jobs
        .recovery_guard(
            job(4, Instant::now()).database.identity,
            &job(4, Instant::now()).context,
        )
        .unwrap();
    assert!(other.is_some());
    let mut waiting = request.context.clone();
    waiting.cancelled = Arc::new(AtomicBool::new(false));
    waiting.deadline = Instant::now() + Duration::from_millis(30);
    let mut foreground = jobs.clone();
    let identity = request.database.identity;
    let blocked = thread::spawn(move || {
        foreground
            .recovery_guard(identity, &waiting)
            .err()
            .unwrap()
            .code
    });
    assert_eq!(blocked.join().unwrap(), "COMMIT_UNKNOWN");
    assert_eq!(port.proposals.load(Ordering::Acquire), 2);
    assert!(!port.state.lock().database(3).unwrap().cold);
    release.send(()).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while !jobs.poll() {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(1));
    }
    assert!(port.state.lock().database(3).unwrap().cold);
    assert!(gate.try_lock().is_some());
    let after = jobs.recovery_guard(identity, &request.context).unwrap();
    assert!(after.is_some());
    assert!(gate.try_lock().is_none());
    drop(after);
    drop(other);
    supervisor.join().unwrap();
}
