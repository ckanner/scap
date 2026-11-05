use super::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::AtomicU64;

use raft::eraftpb::Entry;
use scap_cell::{CellApplication, CellState, Command, Position};
use scap_raft_driver::{Application, ProposalResult, ProposalTicket, ReadBarrier, ReadTicket};
use scap_raft_runtime::{ClockReading, Error as RuntimeError, ReadView};
use scap_raft_store::Identity;
use scap_sql_worker::NativeFactory;

use crate::tests::{config, sql};

pub(crate) struct Effects {
    pub state: CellState,
    pub leader: bool,
    pub term: u64,
    pub reads: usize,
    pub read_error: Option<usize>,
    pub read_override: Option<(usize, CellState)>,
    pub proposal_error: bool,
    pub proposals: usize,
    pub proposal_error_at: Option<usize>,
    pub before_proposal: Option<(usize, Command)>,
    pub lost_result: bool,
    lost_result_at: Option<usize>,
    pub outcome: Option<Outcome>,
    pub status_error: bool,
    pub maintenance_error: bool,
    pub maintenance: Vec<bool>,
    guard_trace: Rc<RefCell<GuardTrace>>,
}

#[derive(Clone)]
pub(crate) struct Port {
    pub identity: Identity,
    pub effects: Rc<RefCell<Effects>>,
}

impl Port {
    pub(crate) fn new(config: &Config) -> Self {
        let port = Self {
            identity: Identity {
                cluster_id: config.cluster_id,
                cell_id: config.cell.cell_id,
                cell_incarnation: config.cell.cell_incarnation,
                node_id: config.node_id,
            },
            effects: Rc::new(RefCell::new(Effects {
                state: CellState::bootstrap(
                    config.cell,
                    config.administrator_id,
                    Position { term: 1, index: 1 },
                    cell_limits(),
                )
                .unwrap(),
                leader: true,
                term: 1,
                reads: 0,
                read_error: None,
                read_override: None,
                proposal_error: false,
                proposals: 0,
                proposal_error_at: None,
                before_proposal: None,
                lost_result: false,
                lost_result_at: None,
                outcome: None,
                status_error: false,
                maintenance_error: false,
                maintenance: vec![],
                guard_trace: Rc::new(RefCell::new(GuardTrace::default())),
            })),
        };
        port.apply_raw(scap_cell::encode_retention_activation(
            config.cell,
            config.administrator_id,
        ));
        port.apply_raw(scap_cell::encode_control_activation(
            config.cell,
            config.administrator_id,
        ));
        port
    }

    pub(crate) fn apply(&self, command: Command) -> scap_cell::AppliedOutcome {
        let bytes = scap_cell::encode_command(&command, cell_limits()).unwrap();
        self.apply_bytes(bytes)
    }

    fn apply_bytes(&self, data: Vec<u8>) -> scap_cell::AppliedOutcome {
        let result = self.apply_raw(data);
        scap_cell::decode_applied_outcome(
            &result.data,
            Position {
                term: result.term,
                index: result.index,
            },
        )
        .unwrap()
    }

    fn apply_raw(&self, data: Vec<u8>) -> ProposalResult {
        let mut held = self.effects.borrow_mut();
        let position = Position {
            term: held.term,
            index: held.state.position().index + 1,
        };
        let entry = Entry {
            term: position.term,
            index: position.index,
            data: data.into(),
            ..Entry::default()
        };
        let cell = held.state.identity();
        let batch = CellApplication::new(cell, cell_limits())
            .unwrap()
            .apply_with_results(&held.state.encode(), &[entry], &[position.index])
            .unwrap();
        held.state = CellState::decode_bound(&batch.state, cell, position, cell_limits()).unwrap();
        ProposalResult {
            ticket: ProposalTicket {
                boot_id: 1,
                sequence: position.index,
            },
            index: position.index,
            term: position.term,
            data: batch.results.into_iter().next().unwrap(),
        }
    }
}

impl CellPort for Port {
    fn identity(&self) -> Identity {
        self.identity.clone()
    }
    fn read(&mut self, _: Instant, _: &AtomicBool) -> Result<ReadView, RuntimeError> {
        let mut held = self.effects.borrow_mut();
        held.guard_trace.borrow_mut().record("read");
        held.reads += 1;
        if held.read_error == Some(held.reads) {
            return Err(RuntimeError::Unknown);
        }
        let state = held
            .read_override
            .as_ref()
            .filter(|(read, _)| *read == held.reads)
            .map_or(&held.state, |(_, state)| state);
        let position = state.position();
        Ok(ReadView {
            identity: self.identity(),
            term: position.term,
            index: position.index,
            barrier: ReadBarrier {
                ticket: ReadTicket {
                    boot_id: 1,
                    sequence: held.reads as u64,
                },
                index: position.index,
            },
            application: state.encode(),
        })
    }
    fn propose(
        &mut self,
        data: Vec<u8>,
        _: Instant,
        _: &AtomicBool,
    ) -> Result<ProposalResult, RuntimeError> {
        {
            let mut held = self.effects.borrow_mut();
            held.guard_trace.borrow_mut().record("proposal");
            held.proposals += 1;
            if held.proposal_error || held.proposal_error_at == Some(held.proposals) {
                return Err(RuntimeError::Unknown);
            }
        }
        let injection = {
            let mut held = self.effects.borrow_mut();
            if held
                .before_proposal
                .as_ref()
                .is_some_and(|(number, _)| *number == held.proposals)
            {
                held.before_proposal.take()
            } else {
                None
            }
        };
        if let Some((_, command)) = injection {
            assert!(!matches!(self.apply(command).outcome, Outcome::Rejected(_)));
        }
        let mut result = self.apply_raw(data);
        if self.effects.borrow().lost_result
            || self.effects.borrow().lost_result_at == Some(self.effects.borrow().proposals)
        {
            return Err(RuntimeError::Unknown);
        }
        if let Some(outcome) = self.effects.borrow_mut().outcome.take() {
            result.data = scap_cell::encode_applied_outcome(&scap_cell::AppliedOutcome {
                position: Position {
                    term: result.term,
                    index: result.index,
                },
                outcome,
            });
        }
        Ok(result)
    }
}

impl ControlPort for Port {
    fn leadership(&self, _: Instant) -> Result<(bool, u64), ServiceError> {
        let held = self.effects.borrow();
        if held.status_error {
            return Err(failure("UNAVAILABLE"));
        }
        Ok((held.leader, held.term))
    }
    fn maintain(&self, _: Instant, force: bool) -> Result<(), ServiceError> {
        let mut held = self.effects.borrow_mut();
        held.maintenance.push(force);
        if held.maintenance_error {
            return Err(failure("CHECKPOINT_UNAVAILABLE"));
        }
        Ok(())
    }
}

pub(crate) struct TestClock {
    base: Instant,
    pub elapsed: AtomicU64,
    pub fail: AtomicBool,
    calls: AtomicU64,
    fail_at: AtomicU64,
}
impl TestClock {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            elapsed: AtomicU64::new(0),
            fail: AtomicBool::new(false),
            calls: AtomicU64::new(0),
            fail_at: AtomicU64::new(u64::MAX),
        }
    }
}
impl Clock for TestClock {
    fn now(&self) -> Result<ClockReading, RuntimeError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if self.fail.load(Ordering::Acquire) || call == self.fail_at.load(Ordering::Acquire) {
            return Err(RuntimeError::Clock);
        }
        Ok(ClockReading {
            instant: self.base + Duration::from_secs(self.elapsed.load(Ordering::Acquire)),
            unix_seconds: 1_800_000_000,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct Memory(pub Rc<RefCell<BTreeMap<String, Vec<u8>>>>);
impl scap_archive::Objects for Memory {
    fn put(
        &mut self,
        key: &str,
        bytes: &[u8],
        _: &RequestContext,
    ) -> Result<(), scap_archive::Error> {
        self.0
            .borrow_mut()
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
            .borrow()
            .get(key)
            .cloned()
            .ok_or(scap_archive::Error::Object)
    }
}

// Only the deterministic test scheduler runs archive work synchronously. The
// daemon uses archive_jobs; all archive algorithms here remain the production
// Controller's implementation, rather than a parallel mock state machine.
#[derive(Default)]
struct GuardTrace {
    held: bool,
    acquired: usize,
    dropped: usize,
    database: Option<DatabaseIdentity>,
    context: Option<RequestContext>,
    events: Vec<(&'static str, bool)>,
}

impl GuardTrace {
    fn record(&mut self, event: &'static str) {
        self.events.push((event, self.held));
    }
}

struct TestRecoveryGuard(Rc<RefCell<GuardTrace>>);

impl Drop for TestRecoveryGuard {
    fn drop(&mut self) {
        let mut trace = self.0.borrow_mut();
        assert!(trace.held);
        trace.record("released");
        trace.held = false;
        trace.dropped += 1;
    }
}

struct TestCold {
    controller: Option<scap_archive::Controller<Port, Memory>>,
    fail_archive: bool,
    fail_hydrate: bool,
    completed: bool,
    guard_trace: Rc<RefCell<GuardTrace>>,
    before_guard: Option<Box<dyn FnOnce()>>,
    fail_guard: bool,
}

impl ColdStorage<Port> for TestCold {
    type RecoveryGuard = TestRecoveryGuard;

    fn recovery_guard(
        &mut self,
        database: DatabaseIdentity,
        context: &RequestContext,
    ) -> Result<Self::RecoveryGuard, ServiceError> {
        {
            let mut trace = self.guard_trace.borrow_mut();
            assert!(!trace.held);
            trace.database = Some(database);
            trace.context = Some(context.clone());
            trace.record("waiting");
        }
        if self.fail_guard {
            return Err(failure("RECOVERY_UNAVAILABLE"));
        }
        if let Some(action) = self.before_guard.take() {
            action();
        }
        {
            let mut trace = self.guard_trace.borrow_mut();
            trace.held = true;
            trace.acquired += 1;
            trace.record("acquired");
        }
        Ok(TestRecoveryGuard(self.guard_trace.clone()))
    }

    fn poll(&mut self) -> bool {
        std::mem::take(&mut self.completed)
    }
    fn hydrate(
        &mut self,
        _: &mut Client<Port>,
        context: &RequestContext,
        database: &DatabaseView,
        operation: u128,
    ) -> Result<(), ServiceError> {
        self.guard_trace.borrow_mut().record("hydrate");
        if self.fail_hydrate {
            return Err(failure("ARCHIVE_UNAVAILABLE"));
        }
        self.controller
            .as_mut()
            .ok_or_else(|| failure("ARCHIVE_UNAVAILABLE"))?
            .hydrate_bound(context, database.clone(), operation)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))
    }
    fn archive(
        &mut self,
        _: &mut Client<Port>,
        context: &RequestContext,
        database: &DatabaseView,
        publish: u128,
        prune: u128,
    ) -> Result<bool, ServiceError> {
        if self.fail_archive {
            return Err(failure("ARCHIVE_UNAVAILABLE"));
        }
        let Some(controller) = &mut self.controller else {
            return Ok(false);
        };
        let published = controller
            .publish_bound(context, database.clone(), publish)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))?;
        controller
            .prune_bound(context, database.clone(), published, prune)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))?;
        Ok(true)
    }
}

type TestWorker = Worker<Port, NativeFactory, TestCold>;

fn build() -> (TestWorker, Port, Arc<TestClock>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.data_dir = temp.path().to_path_buf();
    cfg.idle_timeout = Duration::from_secs(5);
    std::fs::create_dir(cfg.data_dir.join("writers")).unwrap();
    let port = Port::new(&cfg);
    let clock = Arc::new(TestClock::new());
    let client = Client::new(
        cfg.cluster_id,
        cfg.cell,
        cell_limits(),
        port.clone(),
        clock.clone(),
    )
    .unwrap();
    let cold = TestCold {
        controller: Some(scap_archive::Controller::new(client, Memory::default())),
        fail_archive: false,
        fail_hydrate: false,
        completed: false,
        guard_trace: port.effects.borrow().guard_trace.clone(),
        before_guard: None,
        fail_guard: false,
    };
    let worker = Worker::new(
        cfg,
        port.clone(),
        NativeFactory,
        cold,
        clock.clone(),
        Arc::new(AtomicBool::new(false)),
        10,
    )
    .unwrap();
    (worker, port, clock, temp)
}

fn legacy(worker: &TestWorker) -> CellState {
    CellState::bootstrap_legacy(
        worker.config.cell,
        worker.config.administrator_id,
        Position { term: 1, index: 1 },
        cell_limits(),
    )
    .unwrap()
}

fn request(worker: &TestWorker, id: u128, operation: Operation) -> Request {
    let database = worker.config.databases[0].clone();
    Request {
        database,
        context: RequestContext {
            admission: Admission {
                principal_id: 200,
                credential_id: 201,
                admission_id: id,
                auth_epoch: 1,
                request_epoch: 1,
            },
            deadline: worker.clock.now().unwrap().instant + Duration::from_secs(30),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
        request_id: id,
        operation,
    }
}

fn execute(
    worker: &mut TestWorker,
    id: u128,
    text: &str,
    mode: Mode,
) -> Result<TransactionResult, ServiceError> {
    let request = request(
        worker,
        id,
        Operation::Execute {
            mode,
            statements: vec![sql(text)],
        },
    );
    match worker.request(request)? {
        Reply::Sql(result) => Ok(result),
        _ => panic!("SQL reply"),
    }
}

#[test]
fn legacy_lanes_refuse_all_business_operations_before_owner_or_archive_effects() {
    let (mut worker, port, _, directory) = build();
    port.effects.borrow_mut().state = legacy(&worker);
    let before = port.effects.borrow().state.encode();
    worker.cold.fail_archive = true;
    worker.cold.fail_hydrate = true;
    worker.ready.store(true, Ordering::Release);
    assert_eq!(worker.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    for operation in [
        Operation::Status,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 1")],
        },
        Operation::Execute {
            mode: Mode::Write,
            statements: vec![sql("CREATE TABLE denied(v)")],
        },
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![sql("SELECT 1")],
        },
        Operation::Outcome {
            action: OutcomeAction::ResolveOrCancel,
            statements: vec![sql("SELECT 1")],
        },
    ] {
        let request = request(&worker, 88_100, operation);
        assert_eq!(
            worker.request(request).err().unwrap().code,
            "COMMIT_UNKNOWN"
        );
    }
    assert!(!worker.ready.load(Ordering::Acquire));
    assert!(!worker.history_active);
    assert!(worker.writers.is_empty());
    assert_eq!(port.effects.borrow().proposals, 0);
    assert_eq!(port.effects.borrow().state.encode(), before);
    assert_eq!(
        std::fs::read_dir(directory.path().join("writers"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn catalogue_activates_before_mutation_and_restart_confirms_without_reproposal() {
    let (mut worker, port, _, _directory) = build();
    port.effects.borrow_mut().state = legacy(&worker);
    worker.cold.controller = None;
    worker.scan().unwrap();
    assert!(worker.history_active);
    assert!(worker.ready.load(Ordering::Acquire));
    let held = port.effects.borrow();
    assert_eq!(held.state.physical_history_version(), 5);
    assert_eq!(held.proposals, 4); // Ordered v3, v4, v5 activation, then Create.
    assert_eq!(held.state.position().index, 5);
    assert!(held.state.database(3).unwrap().suspended);
    let position = held.state.position();
    let encoded = held.state.encode();
    drop(held);
    worker.scan().unwrap();
    assert_eq!(port.effects.borrow().proposals, 4);
    assert!(worker.writers.is_empty());

    let (mut restarted, restarted_port, _, _restarted_directory) = build();
    restarted.cold.controller = None;
    restarted_port.effects.borrow_mut().state =
        CellState::decode_bound(&encoded, restarted.config.cell, position, cell_limits()).unwrap();
    assert!(!restarted.history_active && !restarted.ready.load(Ordering::Acquire));
    restarted.scan().unwrap();
    assert!(restarted.history_active && restarted.ready.load(Ordering::Acquire));
    assert_eq!(restarted_port.effects.borrow().proposals, 0);
    assert_eq!(restarted_port.effects.borrow().state.encode(), encoded);
}

#[test]
fn unknown_activation_or_failed_confirmation_never_creates_a_database_or_marks_ready() {
    // A failed proposal may have applied. Both response loss and a failed
    // fresh ReadIndex leave readiness false; the next scan queries first.
    for failure_point in 0..3 {
        let (mut worker, port, _, _directory) = build();
        worker.cold.controller = None;
        port.effects.borrow_mut().state = legacy(&worker);
        {
            let mut held = port.effects.borrow_mut();
            held.proposal_error = failure_point == 0;
            held.lost_result = failure_point == 1;
            held.read_error = (failure_point == 2).then_some(2);
        }
        assert_eq!(worker.scan().unwrap_err().code, "COMMIT_UNKNOWN");
        assert!(!worker.ready.load(Ordering::Acquire));
        assert!(!worker.history_active);
        assert!(worker.writers.is_empty());
        {
            let mut held = port.effects.borrow_mut();
            assert_eq!(held.proposals, 1);
            assert!(held.state.database(3).is_none());
            assert_eq!(
                held.state.physical_history_version(),
                if failure_point == 0 { 2 } else { 3 }
            );
            held.proposal_error = false;
            held.lost_result = false;
            held.read_error = None;
        }
        worker.scan().unwrap();
        assert!(worker.ready.load(Ordering::Acquire));
        assert!(worker.history_active);
        assert_eq!(
            port.effects.borrow().proposals,
            if failure_point == 0 { 5 } else { 4 }
        );
        assert_eq!(port.effects.borrow().state.physical_history_version(), 5);
        assert!(port.effects.borrow().state.database(3).is_some());
    }
}

#[test]
fn history_activation_requires_leadership_bootstrap_authority_and_bounded_identity() {
    let (mut worker, port, _, _directory) = build();
    port.effects.borrow_mut().state = legacy(&worker);
    let before = port.effects.borrow().state.encode();
    port.effects.borrow_mut().leader = false;
    assert_eq!(worker.scan().unwrap_err().code, "NOT_LEADER");
    assert_eq!(port.effects.borrow().proposals, 0);
    assert_eq!(port.effects.borrow().state.encode(), before);
    assert!(!worker.ready.load(Ordering::Acquire));
    port.effects.borrow_mut().leader = true;
    worker.sequence = u64::MAX;
    assert_eq!(worker.scan().unwrap_err().code, "IDENTITY_EXHAUSTED");
    assert_eq!(port.effects.borrow().proposals, 0);
    worker.sequence = 0;
    worker.config.administrator_id += 1;
    assert_eq!(worker.scan().unwrap_err().code, "COMMIT_UNKNOWN");
    assert_eq!(port.effects.borrow().proposals, 1);
    assert_eq!(port.effects.borrow().state.physical_history_version(), 2);
    assert!(port.effects.borrow().state.database(3).is_none());
    assert!(!worker.ready.load(Ordering::Acquire));
}

#[test]
fn a_legacy_view_retires_every_local_writer_and_clears_the_activation_hint() {
    let (mut worker, port, clock, _directory) = build();
    execute(&mut worker, 88_200, "CREATE TABLE durable(v)", Mode::Write).unwrap();
    assert!(worker.history_active && !worker.writers.is_empty());
    let next = port.effects.borrow().reads + 1;
    port.effects.borrow_mut().read_override = Some((next, legacy(&worker)));
    assert_eq!(
        worker
            .state(clock.now().unwrap().instant + Duration::from_secs(10))
            .unwrap_err()
            .code,
        "COMMIT_UNKNOWN"
    );
    assert!(!worker.history_active);
    assert!(!worker.ready.load(Ordering::Acquire));
    assert!(worker.writers.is_empty());
}

#[test]
fn native_queries_writes_outcomes_and_cold_recovery_use_one_authority() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    assert!(worker.ready.load(Ordering::Acquire));
    execute(
        &mut worker,
        1000,
        "CREATE TABLE items(id INTEGER PRIMARY KEY, value BLOB)",
        Mode::Write,
    )
    .unwrap();
    let statement = "INSERT INTO items(value) VALUES(randomblob(16)) RETURNING value";
    let original = execute(&mut worker, 1001, statement, Mode::Write).unwrap();
    let before = port.effects.borrow().state.database(3).unwrap().revision;
    let read = execute(&mut worker, 1002, "SELECT value FROM items", Mode::Read).unwrap();
    assert_eq!(original.statements[0].rows, read.statements[0].rows);
    worker.tick().unwrap();
    assert_eq!(
        port.effects.borrow().state.database(3).unwrap().revision,
        before
    );
    for resolve in [false, true] {
        let call = request(
            &worker,
            1001,
            Operation::Outcome {
                action: if resolve {
                    OutcomeAction::ResolveOrCancel
                } else {
                    OutcomeAction::Lookup
                },
                statements: vec![sql(statement)],
            },
        );
        assert!(
            matches!(worker.request(call).unwrap(), Reply::Outcome(ServiceOutcome::Committed { result, sequence: 2, .. }) if result == original)
        );
    }
    let lookup = request(
        &worker,
        1010,
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(lookup).unwrap(),
        Reply::Outcome(ServiceOutcome::Unknown)
    ));
    let cancel = request(
        &worker,
        1010,
        Operation::Outcome {
            action: OutcomeAction::ResolveOrCancel,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(cancel).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled { .. })
    ));
    clock.elapsed.store(6, Ordering::Release);
    worker.tick().unwrap();
    assert!(worker.writers.is_empty());
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    let restored = execute(&mut worker, 1003, "SELECT value FROM items", Mode::Read).unwrap();
    assert_eq!(restored.statements[0].rows, original.statements[0].rows);
    assert!(!port.effects.borrow().state.database(3).unwrap().cold);
    assert_eq!(
        execute(&mut worker, 1001, statement, Mode::Write).unwrap(),
        original
    );
    assert!(worker.writers.is_empty());
    execute(&mut worker, 1004, "SELECT count(*) FROM items", Mode::Read).unwrap();
}

#[test]
fn leadership_deadline_current_permissions_and_stopped_engines_fail_closed() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    port.effects.borrow_mut().leader = false;
    assert_eq!(
        execute(&mut worker, 1, "SELECT 1", Mode::Read)
            .unwrap_err()
            .code,
        "NOT_LEADER"
    );
    assert!(worker.writers.is_empty());
    assert!(!worker.ready.load(Ordering::Acquire));
    port.effects.borrow_mut().leader = true;
    port.effects.borrow_mut().term += 1;
    worker.tick().unwrap();
    let mut cancelled = request(
        &worker,
        2,
        Operation::Execute {
            mode: Mode::Write,
            statements: vec![sql("SELECT 1")],
        },
    );
    cancelled.context.cancelled.store(true, Ordering::Release);
    assert_eq!(
        worker.request(cancelled).err().unwrap().code,
        "COMMIT_UNKNOWN"
    );
    cancelled = request(
        &worker,
        2,
        Operation::Execute {
            mode: Mode::Write,
            statements: vec![sql("SELECT 1")],
        },
    );
    cancelled.context.deadline = clock.now().unwrap().instant;
    assert_eq!(
        worker.request(cancelled).err().unwrap().code,
        "COMMIT_UNKNOWN"
    );
    assert_eq!(
        execute(&mut worker, 3, "CREATE TABLE forbidden(x)", Mode::Read)
            .unwrap_err()
            .code,
        "QUERY_FAILED"
    );
    assert!(worker.writers.is_empty());
    assert_eq!(
        execute(&mut worker, 4, "invalid sql", Mode::Write)
            .unwrap_err()
            .code,
        "COMMIT_UNKNOWN"
    );
    let mut wrong = request(
        &worker,
        5,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 1")],
        },
    );
    wrong.context.admission.auth_epoch = 2;
    assert_eq!(
        worker.request(wrong).err().unwrap().code,
        "OUTCOME_FORBIDDEN"
    );
    port.effects.borrow_mut().status_error = true;
    assert!(worker.tick().is_err());
    port.effects.borrow_mut().status_error = false;
    port.effects.borrow_mut().maintenance_error = true;
    assert!(worker.tick().is_err());
    port.effects.borrow_mut().maintenance_error = false;
    clock.fail.store(true, Ordering::Release);
    assert_eq!(worker.tick().unwrap_err().code, "CLOCK");
}

#[test]
fn every_owner_and_outcome_wait_preserves_unknown_and_rejects_wrong_bindings() {
    let (mut worker, port, _clock, _temp) = build();
    port.effects.borrow_mut().read_error = Some(1);
    assert_eq!(worker.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    port.effects.borrow_mut().read_error = None;
    port.effects.borrow_mut().proposal_error = true;
    assert_eq!(worker.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    port.effects.borrow_mut().proposal_error = false;
    port.effects.borrow_mut().outcome = Some(Outcome::Rejected(scap_cell::Reject::Capacity));
    assert_eq!(worker.tick().unwrap_err().code, "DATABASE_CREATE_REJECTED");
    worker.tick().unwrap();
    let mut wrong = worker.config.databases[0].clone();
    wrong.identity.incarnation += 1;
    assert_eq!(
        worker
            .database(&wrong, Instant::now() + Duration::from_secs(30))
            .unwrap_err()
            .code,
        "DATABASE_FENCED"
    );
    let invalid = request(
        &worker,
        20,
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![],
        },
    );
    assert_eq!(
        worker.request(invalid).err().unwrap().code,
        "INVALID_REQUEST"
    );
    port.effects.borrow_mut().outcome = Some(Outcome::Rejected(scap_cell::Reject::Capacity));
    let reject = request(
        &worker,
        21,
        Operation::Outcome {
            action: OutcomeAction::ResolveOrCancel,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert_eq!(
        worker.request(reject).err().unwrap().code,
        "RESOLVE_REJECTED"
    );
    port.effects.borrow_mut().proposal_error = true;
    let unknown = request(
        &worker,
        22,
        Operation::Outcome {
            action: OutcomeAction::ResolveOrCancel,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert_eq!(
        worker.request(unknown).err().unwrap().code,
        "COMMIT_UNKNOWN"
    );
    worker.sequence = u64::MAX;
    assert_eq!(worker.id().unwrap_err().code, "IDENTITY_EXHAUSTED");
}

fn administrative(worker: &TestWorker, kind: CommandKind) -> Command {
    Command {
        control_revision: worker
            .port
            .effects
            .borrow()
            .state
            .database(3)
            .unwrap()
            .control_revision,
        cell: worker.config.cell,
        database: worker.config.databases[0].identity,
        admission: Admission {
            principal_id: worker.config.administrator_id,
            credential_id: worker.config.service_credential_id,
            admission_id: 50_000,
            auth_epoch: 1,
            request_epoch: 1,
        },
        kind,
    }
}

#[test]
fn an_old_idle_timer_never_suspends_a_new_owner_or_a_different_head() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    execute(&mut worker, 3999, "SELECT 1", Mode::Read).unwrap();
    let original = port.effects.borrow().state.database(3).unwrap();
    assert!(current_owner(original.owner, original.revision, &original));
    assert!(!current_owner(
        original.owner,
        original.revision + 1,
        &original
    ));
    let mut inactive = original.clone();
    inactive.active = false;
    assert!(!current_owner(inactive.owner, inactive.revision, &inactive));
    let claimed = port.apply(administrative(
        &worker,
        CommandKind::ClaimOwner {
            operation_id: 50_001,
            expected_epoch: original.owner.epoch,
            worker_instance_id: 60_001,
        },
    ));
    assert!(matches!(
        claimed.outcome,
        Outcome::ControlApplied(ControlResult {
            result: AdminResult::OwnerClaimed(_),
            ..
        })
    ));
    clock.elapsed.store(6, Ordering::Release);
    worker.tick().unwrap();
    assert!(worker.writers.is_empty());
    let new = port.effects.borrow().state.database(3).unwrap();
    assert!(!new.suspended);
    assert_eq!(new.owner.worker_instance_id, 60_001);
    // A subsequent recovery gets another fenced owner; it never revives the
    // old directory or treats its former idle timer as an administrative grant.
    worker.tick().unwrap();
    assert_ne!(worker.writers[&3].writer.owner(), original.owner);
    assert!(execute(&mut worker, 4000, "SELECT 1", Mode::Read).is_ok());
}

#[test]
fn metadata_and_original_outcomes_remain_available_without_the_cold_object() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    execute(&mut worker, 4100, "CREATE TABLE items(value)", Mode::Write).unwrap();
    let statement = "INSERT INTO items VALUES(randomblob(16)) RETURNING value";
    let original = execute(&mut worker, 4101, statement, Mode::Write).unwrap();
    for request_id in 4200..4207 {
        execute(&mut worker, request_id, "SELECT 1", Mode::Write).unwrap();
    }
    let call = request(&worker, 4102, Operation::Status);
    assert!(
        matches!(worker.request(call).unwrap(), Reply::Status(s) if s.revision == 9 && s.base_revision == 8 && s.tail_entries == 1 && s.tail_bytes > 0 && s.owner_active && !s.cold && !s.suspended && s.archived_revision == Some(0))
    );
    let mut denied = request(&worker, 4102, Operation::Status);
    denied.context.admission.auth_epoch = 2;
    assert_eq!(
        worker.request(denied).err().unwrap().code,
        "OUTCOME_FORBIDDEN"
    );
    let next = port.effects.borrow().reads + 1;
    port.effects.borrow_mut().read_error = Some(next);
    let unavailable = request(&worker, 4102, Operation::Status);
    assert_eq!(
        worker.request(unavailable).err().unwrap().code,
        "COMMIT_UNKNOWN"
    );
    port.effects.borrow_mut().read_error = None;
    clock.elapsed.store(6, Ordering::Release);
    worker.tick().unwrap();
    worker.cold.controller = None;
    let call = request(&worker, 4103, Operation::Status);
    assert!(
        matches!(worker.request(call).unwrap(), Reply::Status(s) if s.revision == 9 && s.base_revision == 8 && s.tail_entries == 0 && s.tail_bytes == 0 && !s.owner_active && s.cold && s.suspended && s.archived_revision == Some(9))
    );
    let lookup = request(
        &worker,
        4101,
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![sql(statement)],
        },
    );
    assert!(
        matches!(worker.request(lookup).unwrap(), Reply::Outcome(ServiceOutcome::Committed { result, sequence: 2, .. }) if result == original)
    );
    let cancellation = request(
        &worker,
        4199,
        Operation::Outcome {
            action: OutcomeAction::ResolveOrCancel,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(cancellation).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled { .. })
    ));
    let again = request(
        &worker,
        4199,
        Operation::Outcome {
            action: OutcomeAction::ResolveOrCancel,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(again).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled { .. })
    ));
    assert_eq!(
        execute(&mut worker, 4104, "SELECT * FROM items", Mode::Read)
            .unwrap_err()
            .code,
        "ARCHIVE_UNAVAILABLE"
    );
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    assert!(worker.writers.is_empty());
}

#[test]
fn object_outage_keeps_recovery_history_and_retries_only_bounded_maintenance() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    execute(
        &mut worker,
        4200,
        "CREATE TABLE durable(value)",
        Mode::Write,
    )
    .unwrap();
    clock.elapsed.store(6, Ordering::Release);
    worker.cold.fail_archive = true;
    assert_eq!(worker.tick().unwrap_err().code, "ARCHIVE_UNAVAILABLE");
    let suspended = port.effects.borrow().state.database(3).unwrap();
    assert!(suspended.suspended && !suspended.cold);
    assert!(worker.ready.load(Ordering::Acquire));
    assert!(worker.writers.is_empty());
    worker.cold.completed = true;
    assert_eq!(worker.tick().unwrap_err().code, "ARCHIVE_UNAVAILABLE");
    assert_eq!(port.effects.borrow().maintenance.last(), Some(&true));
    worker.cold.fail_archive = false;
    worker.tick().unwrap();
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    assert!(worker.checkpoint_needed);
    worker.tick().unwrap();
    assert!(!worker.checkpoint_needed);
    assert_eq!(port.effects.borrow().maintenance.last(), Some(&true));
    worker.maintenance_round = 29;
    worker.tick().unwrap();
    assert_eq!(port.effects.borrow().maintenance.last(), Some(&true));
    assert!(worker.writers.is_empty());
}

#[test]
fn invalid_boot_scope_cache_cleanup_and_missing_recovery_directory_fail_closed() {
    for boot in [0, 1] {
        let (worker, mut port, clock, _temp) = build();
        let config = worker.config.clone();
        if boot == 1 {
            port.identity.cluster_id += 1;
        }
        let error = Worker::new(
            config,
            port,
            NativeFactory,
            worker.cold,
            clock,
            Arc::new(AtomicBool::new(false)),
            boot,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, if boot == 0 { "BOOT_ID" } else { "CELL_SCOPE" });
    }
    let (mut worker, _port, _clock, _temp) = build();
    worker.cache_failed.store(true, Ordering::Release);
    assert_eq!(worker.tick().unwrap_err().code, "CACHE_CLEANUP_REQUIRED");
    assert_eq!(
        execute(&mut worker, 4300, "SELECT 1", Mode::Read)
            .unwrap_err()
            .code,
        "CACHE_CLEANUP_REQUIRED"
    );
    assert!(!worker.ready.load(Ordering::Acquire));
    worker.cache_failed.store(false, Ordering::Release);
    std::fs::remove_dir(worker.config.data_dir.join("writers")).unwrap();
    assert_eq!(
        execute(&mut worker, 4301, "SELECT 1", Mode::Read)
            .unwrap_err()
            .code,
        "RECOVERY_UNAVAILABLE"
    );
    assert!(worker.writers.is_empty());
    {
        let trace = worker.cold.guard_trace.borrow();
        assert_eq!((trace.acquired, trace.dropped, trace.held), (1, 1, false));
    }
    std::fs::write(
        worker.config.data_dir.join("writers"),
        b"operator-owned-file",
    )
    .unwrap();
    assert_eq!(
        execute(&mut worker, 4302, "SELECT 1", Mode::Read)
            .unwrap_err()
            .code,
        "CACHE_IO"
    );
    assert_eq!(
        std::fs::read(worker.config.data_dir.join("writers")).unwrap(),
        b"operator-owned-file"
    );
    let trace = worker.cold.guard_trace.borrow();
    assert_eq!((trace.acquired, trace.dropped, trace.held), (2, 2, false));
}

#[test]
fn native_clock_failure_at_every_write_boundary_preserves_unknown_or_original_commit() {
    let (mut reference, _port, clock, _temp) = build();
    reference.tick().unwrap();
    let call = request(
        &reference,
        4400,
        Operation::Execute {
            mode: Mode::Write,
            statements: vec![sql("CREATE TABLE acknowledged(value)")],
        },
    );
    let before = clock.calls.load(Ordering::Acquire);
    reference.request(call).unwrap();
    let calls = clock.calls.load(Ordering::Acquire) - before;
    let mut codes = std::collections::BTreeSet::new();
    for offset in 1..=calls {
        let (mut worker, port, clock, _temp) = build();
        worker.tick().unwrap();
        let call = request(
            &worker,
            4400,
            Operation::Execute {
                mode: Mode::Write,
                statements: vec![sql("CREATE TABLE acknowledged(value)")],
            },
        );
        let start = clock.calls.load(Ordering::Acquire);
        clock.fail_at.store(start + offset, Ordering::Release);
        let result = worker.request(call);
        // A clock read that the native callback treats as interruption must
        // not be transformed into an ACK. Stored outcomes remain resolvable.
        assert!(result.is_err(), "clock boundary {offset}/{calls}");
        codes.insert(result.err().unwrap().code);
        assert!(worker.writers.is_empty() || offset == 1);
        clock.fail_at.store(u64::MAX, Ordering::Release);
        let revision = port.effects.borrow().state.database(3).unwrap().revision;
        let call = request(
            &worker,
            4400,
            Operation::Outcome {
                action: OutcomeAction::Lookup,
                statements: vec![sql("CREATE TABLE acknowledged(value)")],
            },
        );
        let outcome = worker.request(call).unwrap();
        assert!(matches!(
            (revision, outcome),
            (0, Reply::Outcome(ServiceOutcome::Unknown))
                | (
                    1,
                    Reply::Outcome(ServiceOutcome::Committed { sequence: 1, .. })
                )
        ));
    }
    assert!(codes.contains("CLOCK"));
    assert!(codes.contains("COMMIT_UNKNOWN"));
    assert!(codes.contains("COMMITTED_RESULT_UNAVAILABLE"));
}

#[test]
fn status_lookup_and_hot_execution_recheck_scope_and_current_authorization() {
    let (mut worker, port, _clock, _temp) = build();
    worker.tick().unwrap();
    execute(&mut worker, 4499, "SELECT 1", Mode::Read).unwrap();
    let mut fenced = request(
        &worker,
        4500,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 1")],
        },
    );
    fenced.database.identity.incarnation += 1;
    assert_eq!(
        worker.request(fenced).err().unwrap().code,
        "DATABASE_FENCED"
    );
    let mut forbidden = request(
        &worker,
        4501,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 1")],
        },
    );
    forbidden.context.admission.auth_epoch = 2;
    assert_eq!(
        worker.request(forbidden).err().unwrap().code,
        "QUERY_FAILED"
    );
    assert!(worker.writers.is_empty());
    let owner = port.effects.borrow().state.database(3).unwrap().owner;
    let mut forbidden = request(
        &worker,
        4502,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 1")],
        },
    );
    forbidden.context.admission.auth_epoch = 2;
    assert_eq!(
        worker.request(forbidden).err().unwrap().code,
        "OUTCOME_FORBIDDEN"
    );
    assert_eq!(
        port.effects.borrow().state.database(3).unwrap().owner,
        owner
    );
    let mut forbidden = request(
        &worker,
        4503,
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![sql("SELECT 1")],
        },
    );
    forbidden.context.admission.principal_id = 999;
    assert_eq!(
        worker.request(forbidden).err().unwrap().code,
        "OUTCOME_FORBIDDEN"
    );
    let next = port.effects.borrow().reads + 1;
    port.effects.borrow_mut().read_error = Some(next);
    let call = request(
        &worker,
        4504,
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert_eq!(worker.request(call).err().unwrap().code, "COMMIT_UNKNOWN");
    port.effects.borrow_mut().read_error = None;
    let invalid = request(
        &worker,
        4505,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![],
        },
    );
    assert_eq!(
        worker.request(invalid).err().unwrap().code,
        "INVALID_REQUEST"
    );
}

#[test]
fn corrupt_retained_result_is_never_returned_as_successful_sql() {
    let (mut worker, port, _clock, _temp) = build();
    worker.tick().unwrap();
    execute(&mut worker, 4599, "SELECT 1", Mode::Read).unwrap();
    let call = request(
        &worker,
        4600,
        Operation::Outcome {
            action: OutcomeAction::Lookup,
            statements: vec![sql("SELECT 1")],
        },
    );
    let view = port.effects.borrow().state.database(3).unwrap();
    let physical_changes = vec![1, 2, 3];
    let command = Command {
        control_revision: None,
        cell: worker.config.cell,
        database: view.identity,
        admission: call.context.admission,
        kind: CommandKind::Commit {
            write: scap_core::PreparedWrite {
                ticket: scap_core::CommitTicket {
                    cell_id: worker.config.cell.cell_id,
                    cell_incarnation: worker.config.cell.cell_incarnation,
                    database_id: view.identity.database_id,
                    incarnation: view.identity.incarnation,
                    placement_generation: view.identity.placement_generation,
                    owner_epoch: view.owner.epoch,
                    worker_instance_id: view.owner.worker_instance_id,
                    auth_epoch: 1,
                    request_id: 4600,
                    predecessor: 0,
                    payload_digest: scap_cell::payload_digest(&physical_changes),
                },
                physical_changes,
            },
            request_fingerprint: scap_sql::request_fingerprint(
                &[sql("SELECT 1")],
                worker_limits().sqlite.sql,
            )
            .unwrap(),
            result: vec![255],
        },
    };
    assert!(matches!(port.apply(command).outcome, Outcome::Accepted(_)));
    assert_eq!(worker.request(call).err().unwrap().code, "RESULT_CORRUPT");
}

#[test]
fn missing_database_after_an_applied_create_and_unconfirmed_suspend_are_not_success() {
    let (mut worker, port, clock, _temp) = build();
    let initial = port.effects.borrow().state.clone();
    port.effects.borrow_mut().read_override = Some((2, initial));
    assert_eq!(worker.tick().unwrap_err().code, "DATABASE_MISSING");
    port.effects.borrow_mut().read_override = None;
    worker.tick().unwrap();
    execute(&mut worker, 4699, "SELECT 1", Mode::Read).unwrap();
    clock.elapsed.store(6, Ordering::Release);
    port.effects.borrow_mut().proposal_error = true;
    assert_eq!(worker.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    assert!(!port.effects.borrow().state.database(3).unwrap().suspended);
    port.effects.borrow_mut().proposal_error = false;
    port.effects.borrow_mut().outcome = Some(Outcome::Rejected(scap_cell::Reject::Conflict));
    assert_eq!(worker.tick().unwrap_err().code, "SUSPEND_REJECTED");
    // The operation could have committed before its response was damaged.
    // The next fresh view retires stale ownership, and only then archives it.
    assert!(port.effects.borrow().state.database(3).unwrap().suspended);
    worker.tick().unwrap();
    assert!(worker.writers.is_empty());
    worker.tick().unwrap();
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
}

#[test]
fn concurrent_archive_prune_fences_recovery_before_sql_without_refreshing_identity() {
    let (mut worker, port, clock, _temp) = build();
    execute(
        &mut worker,
        4700,
        "CREATE TABLE preserved(value)",
        Mode::Write,
    )
    .unwrap();
    let view = port.effects.borrow().state.database(3).unwrap();
    let suspend = administrative(
        &worker,
        CommandKind::SuspendDb {
            operation_id: 50_010,
            token: view.owner,
            expected_revision: view.revision,
        },
    );
    assert!(matches!(
        port.apply(suspend).outcome,
        Outcome::ControlApplied(ControlResult {
            result: AdminResult::Suspended(_),
            ..
        })
    ));
    worker.writers.clear();
    let context = worker
        .admin(1, clock.now().unwrap().instant + Duration::from_secs(30))
        .unwrap();
    let source = port.effects.borrow().state.database(3).unwrap();
    let publication = worker
        .cold
        .controller
        .as_mut()
        .unwrap()
        .publish_bound(&context, source, 50_011)
        .unwrap();
    let published = port.effects.borrow().state.database(3).unwrap();
    assert!(!published.cold);
    let prune = administrative(
        &worker,
        CommandKind::PruneArchive {
            operation_id: 50_012,
            expected_owner: published.owner,
            archive_digest: publication.archive().object_digest,
        },
    );
    let next = port.effects.borrow().proposals + 1;
    port.effects.borrow_mut().before_proposal = Some((next, prune));
    assert_eq!(
        execute(
            &mut worker,
            4701,
            "INSERT INTO preserved VALUES(7)",
            Mode::Write,
        )
        .unwrap_err()
        .code,
        "RECOVERY_UNAVAILABLE"
    );
    let fenced = port.effects.borrow().state.database(3).unwrap();
    assert_eq!(fenced.revision, 1);
    assert!(fenced.cold);
    assert!(worker.writers.is_empty());
    assert_eq!(port.effects.borrow().proposals, next);
    assert!(worker
        .cold
        .guard_trace
        .borrow()
        .events
        .ends_with(&[("proposal", true), ("released", true)]));
    // The original invocation never ran SQL or rebound its Claim. A separate
    // later invocation creates a new recovery and a new business request.
    execute(
        &mut worker,
        4703,
        "INSERT INTO preserved VALUES(7)",
        Mode::Write,
    )
    .unwrap();
    let accepted = port.effects.borrow().state.database(3).unwrap();
    assert_eq!(accepted.revision, 2);
    assert!(accepted.active && !accepted.cold);
    assert_eq!(
        execute(&mut worker, 4702, "SELECT value FROM preserved", Mode::Read)
            .unwrap()
            .statements[0]
            .rows,
        vec![vec![scap_sql::Value::Integer(7)]]
    );
    // A later independent invocation captures its view after taking the guard;
    // a prune completed before that capture is an ordinary cold wake.
    let suspended = administrative(
        &worker,
        CommandKind::SuspendDb {
            operation_id: 50_013,
            token: accepted.owner,
            expected_revision: accepted.revision,
        },
    );
    port.apply(suspended);
    worker.writers.clear();
    let context = worker
        .admin(1, clock.now().unwrap().instant + Duration::from_secs(30))
        .unwrap();
    let source = port.effects.borrow().state.database(3).unwrap();
    let publication = worker
        .cold
        .controller
        .as_mut()
        .unwrap()
        .publish_bound(&context, source.clone(), 50_014)
        .unwrap();
    worker
        .cold
        .controller
        .as_mut()
        .unwrap()
        .prune_bound(&context, source, publication, 50_015)
        .unwrap();
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    assert_eq!(
        execute(&mut worker, 4704, "SELECT value FROM preserved", Mode::Read)
            .unwrap()
            .statements[0]
            .rows,
        vec![vec![scap_sql::Value::Integer(7)]]
    );
    assert!(!port.effects.borrow().state.database(3).unwrap().cold);
}

#[test]
fn exhaustion_and_failed_authority_reads_stop_each_maintenance_transition() {
    // Administrative identifiers are never reused, including at integer
    // exhaustion in the middle of create, wake, recovery or suspend/archive.
    for phase in 0..4 {
        for remaining in 0..12 {
            let (mut worker, port, clock, _temp) = build();
            if phase != 0 {
                worker.tick().unwrap();
            }
            if phase >= 2 {
                execute(&mut worker, 4800, "SELECT 1", Mode::Read).unwrap();
                if phase == 2 {
                    worker.writers.clear();
                } else {
                    clock.elapsed.store(6, Ordering::Release);
                }
            }
            worker.sequence = u64::MAX - remaining;
            let result = if phase == 1 {
                execute(&mut worker, 4801, "SELECT 1", Mode::Read).map(|_| ())
            } else {
                worker.tick()
            };
            if let Err(error) = result {
                assert_eq!(
                    error.code, "IDENTITY_EXHAUSTED",
                    "phase {phase}, remaining {remaining}"
                );
            }
            assert!(port
                .effects
                .borrow()
                .state
                .database(3)
                .is_none_or(|database| database.revision == 0));
        }
    }
    let (mut worker, port, _clock, _temp) = build();
    port.effects.borrow_mut().read_error = Some(2);
    assert_eq!(worker.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    assert!(port.effects.borrow().state.database(3).is_some());
    let (mut worker, port, clock, _temp) = build();
    execute(&mut worker, 4810, "SELECT 1", Mode::Read).unwrap();
    clock.elapsed.store(6, Ordering::Release);
    let after_suspend = port.effects.borrow().reads + 2;
    port.effects.borrow_mut().read_error = Some(after_suspend);
    assert_eq!(worker.tick().unwrap_err().code, "COMMIT_UNKNOWN");
    assert!(port.effects.borrow().state.database(3).unwrap().suspended);
    assert!(worker.writers.is_empty());
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    let guarded_read = port.effects.borrow().reads + 1;
    port.effects.borrow_mut().read_error = Some(guarded_read);
    let database = worker.config.databases[0].clone();
    assert_eq!(
        worker
            .recover(
                &database,
                RecoveryRequest::Maintenance(
                    clock.now().unwrap().instant + Duration::from_secs(30)
                ),
            )
            .unwrap_err()
            .code,
        "COMMIT_UNKNOWN"
    );
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    assert_eq!(port.effects.borrow().reads, guarded_read);
    assert!(!worker.cold.guard_trace.borrow().held);
}

#[test]
fn catalogue_scanning_never_opens_engines_or_hydrates_suspended_databases() {
    let (mut worker, port, clock, directory) = build();
    assert!(worker.dormant());
    // Creation and archival can progress without constructing a SQL owner.
    assert!(worker.scan().unwrap().is_none());
    assert!(worker.writers.is_empty());
    assert_eq!(
        std::fs::read_dir(directory.path().join("writers"))
            .unwrap()
            .count(),
        0
    );
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    worker.cold.fail_hydrate = true;
    assert!(worker.scan().unwrap().is_none());
    assert!(worker.dormant());

    worker.cold.fail_hydrate = false;
    execute(
        &mut worker,
        49_100,
        "CREATE TABLE durable(value)",
        Mode::Write,
    )
    .unwrap();
    let owner = port.effects.borrow().state.database(3).unwrap().owner;
    assert!(!worker.dormant());
    // Only existing unsuspended authority is returned as a recovery candidate;
    // scanning does not claim a replacement owner or mutate a live connection.
    let candidate = worker.scan().unwrap().unwrap();
    assert_eq!(candidate.identity.database_id, 3);
    assert_eq!(
        port.effects.borrow().state.database(3).unwrap().owner,
        owner
    );
    clock.elapsed.store(6, Ordering::Release);
    worker.cold.fail_archive = true;
    assert_eq!(worker.tick().unwrap_err().code, "ARCHIVE_UNAVAILABLE");
    assert!(worker.dormant());
    assert_eq!(worker.scan().unwrap_err().code, "ARCHIVE_UNAVAILABLE");
    worker.cold.fail_archive = false;
    assert!(worker.scan().unwrap().is_none());
    assert!(worker.dormant());
    worker.cache_failed.store(true, Ordering::Release);
    assert!(!worker.dormant());
    assert_eq!(worker.scan().unwrap_err().code, "CACHE_CLEANUP_REQUIRED");
}

#[test]
fn catalogue_scan_preserves_failed_reads_and_every_administrative_id_boundary() {
    for remaining in 0..=4 {
        let (mut worker, port, _clock, _directory) = build();
        worker.cold.controller = None;
        worker.tick().unwrap();
        let before = port.effects.borrow().state.database(3).unwrap();
        assert!(before.suspended && !before.cold);
        worker.sequence = u64::MAX - remaining;
        let result = worker.scan();
        if remaining < 4 {
            assert_eq!(result.unwrap_err().code, "IDENTITY_EXHAUSTED");
        } else {
            assert!(result.unwrap().is_none());
        }
        assert!(worker.writers.is_empty());
        assert_eq!(port.effects.borrow().state.database(3).unwrap(), before);
    }
    let (mut worker, port, _clock, _directory) = build();
    port.effects.borrow_mut().read_error = Some(1);
    assert_eq!(worker.scan().unwrap_err().code, "COMMIT_UNKNOWN");
    assert!(worker.writers.is_empty());
    assert!(port.effects.borrow().state.database(3).is_none());
}

#[test]
fn lane_executor_adapter_preserves_worker_authority_and_native_thread_confinement() {
    use crate::lanes::Executor;
    let (mut worker, port, _clock, _directory) = build();
    assert!(Executor::dormant(&worker));
    Executor::tick(&mut worker);
    let request = request(
        &worker,
        49_200,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 17")],
        },
    );
    assert!(
        matches!(Executor::request(&mut worker, request).unwrap(), Reply::Sql(result) if result.statements[0].rows == vec![vec![scap_sql::Value::Integer(17)]])
    );
    assert!(!Executor::dormant(&worker));
    port.effects.borrow_mut().leader = false;
    Executor::tick(&mut worker);
    assert!(Executor::dormant(&worker));
}

fn terminal_request(
    worker: &TestWorker,
    id: u128,
    epoch: u64,
    text: &str,
    action: OutcomeAction,
) -> Request {
    let mut call = request(
        worker,
        id,
        Operation::Outcome {
            action,
            statements: vec![sql(text)],
        },
    );
    call.context.admission.request_epoch = epoch;
    call
}

fn acknowledge(worker: &mut TestWorker, id: u128, epoch: u64, text: &str) {
    let call = terminal_request(worker, id, epoch, text, OutcomeAction::Lookup);
    let expected = match worker.request(call).unwrap() {
        Reply::Outcome(ServiceOutcome::Committed { sequence, .. }) => {
            ServiceTerminal::Committed { sequence }
        }
        Reply::Outcome(ServiceOutcome::Cancelled { position, .. }) => {
            ServiceTerminal::Cancelled { position }
        }
        _ => panic!("a caller must know the original terminal outcome"),
    };
    let call = terminal_request(
        worker,
        id,
        epoch,
        text,
        OutcomeAction::Acknowledge { expected },
    );
    assert!(matches!(
        worker.request(call).unwrap(),
        Reply::Outcome(ServiceOutcome::Acknowledged)
    ));
}

fn rotate_request(worker: &TestWorker, epoch: u64) -> Request {
    let mut call = request(
        worker,
        99_000,
        Operation::Rotate {
            expected_epoch: epoch,
        },
    );
    call.context.admission.principal_id = worker.config.administrator_id;
    call.context.admission.request_epoch = epoch;
    call
}

#[test]
fn result_retirement_preserves_live_sql_head_and_rejects_old_ids_before_recovery_or_execution() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    let ddl = "CREATE TABLE retained(id INTEGER PRIMARY KEY, value TEXT)";
    let insert = "INSERT INTO retained VALUES(1,hex(randomblob(16))) RETURNING value";
    execute(&mut worker, 91_001, ddl, Mode::Write).unwrap();
    let original = execute(&mut worker, 91_002, insert, Mode::Write).unwrap();
    let cancelled = "INSERT INTO retained VALUES(2,'must never execute')";
    let call = terminal_request(
        &worker,
        91_003,
        1,
        cancelled,
        OutcomeAction::ResolveOrCancel,
    );
    assert!(matches!(
        worker.request(call).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled {
            acknowledged: false,
            ..
        })
    ));
    let before = port.effects.borrow().state.database(3).unwrap();
    assert_eq!(
        (before.retained_requests, before.unacknowledged_requests),
        (3, 3)
    );
    let call = rotate_request(&worker, 1);
    assert_eq!(
        worker.request(call).err().unwrap().code,
        "RETIREMENT_REJECTED"
    );
    // A terminal proof from another result cannot release this request.
    let call = terminal_request(
        &worker,
        91_001,
        1,
        ddl,
        OutcomeAction::Acknowledge {
            expected: ServiceTerminal::Committed { sequence: 2 },
        },
    );
    assert_eq!(worker.request(call).err().unwrap().code, "RESOLVE_REJECTED");
    for (id, text) in [(91_001, ddl), (91_002, insert), (91_003, cancelled)] {
        acknowledge(&mut worker, id, 1, text);
        acknowledge(&mut worker, id, 1, text);
    }
    let call = request(&worker, 99_002, Operation::Rotate { expected_epoch: 1 });
    assert_eq!(
        worker.request(call).err().unwrap().code,
        "RETIREMENT_REJECTED"
    );
    let call = rotate_request(&worker, 1);
    assert!(matches!(worker.request(call).unwrap(), Reply::Rotated(2)));
    let after = port.effects.borrow().state.database(3).unwrap();
    assert_eq!(
        (
            after.request_epoch,
            after.retained_requests,
            after.unacknowledged_requests
        ),
        (2, 0, 0)
    );
    assert_eq!(
        (after.revision, after.commit_hash, after.owner),
        (before.revision, before.commit_hash, before.owner)
    );
    assert_eq!(after.retired_revision, before.revision);
    let current = execute(
        &mut worker,
        91_020,
        "SELECT value FROM retained WHERE id=1",
        Mode::Read,
    )
    .unwrap();
    assert_eq!(current.statements[0].rows, original.statements[0].rows);
    assert_eq!(
        execute(&mut worker, 91_002, insert, Mode::Write)
            .unwrap_err()
            .code,
        "REQUEST_RETIRED"
    );
    assert!(worker.writers.is_empty());
    let owner = port.effects.borrow().state.database(3).unwrap().owner;
    assert_eq!(
        execute(&mut worker, 91_003, cancelled, Mode::Write)
            .unwrap_err()
            .code,
        "REQUEST_RETIRED"
    );
    assert_eq!(
        port.effects.borrow().state.database(3).unwrap().owner,
        owner
    );
    let call = terminal_request(&worker, 91_002, 1, insert, OutcomeAction::Lookup);
    assert!(matches!(
        worker.request(call).unwrap(),
        Reply::Outcome(ServiceOutcome::Retired { current_epoch: 2 })
    ));
    for action in [
        OutcomeAction::ResolveOrCancel,
        OutcomeAction::Acknowledge {
            expected: ServiceTerminal::Committed { sequence: 2 },
        },
    ] {
        let call = terminal_request(&worker, 91_002, 1, insert, action);
        assert_eq!(worker.request(call).err().unwrap().code, "REQUEST_RETIRED");
    }
    let call = rotate_request(&worker, 1);
    assert_eq!(worker.request(call).err().unwrap().code, "REQUEST_RETIRED");
    let fresh = "INSERT INTO retained VALUES(3,'new generation')";
    let mut call = request(
        &worker,
        91_002,
        Operation::Execute {
            mode: Mode::Write,
            statements: vec![sql(fresh)],
        },
    );
    call.context.admission.request_epoch = 2;
    assert!(matches!(worker.request(call).unwrap(), Reply::Sql(_)));
    assert_eq!(port.effects.borrow().state.database(3).unwrap().revision, 3);
    // ACK while physically cold must survive hydration of an older archive.
    clock.elapsed.store(6, Ordering::Release);
    worker.tick().unwrap();
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    acknowledge(&mut worker, 91_002, 2, fresh);
    let call = rotate_request(&worker, 2);
    assert_eq!(
        worker.request(call).err().unwrap().code,
        "RETIREMENT_REJECTED"
    );
    execute(
        &mut worker,
        91_030,
        "SELECT count(*) FROM retained",
        Mode::Read,
    )
    .unwrap();
    let call = terminal_request(&worker, 91_002, 2, fresh, OutcomeAction::Lookup);
    assert!(matches!(
        worker.request(call).unwrap(),
        Reply::Outcome(ServiceOutcome::Committed {
            acknowledged: true,
            ..
        })
    ));
    let call = rotate_request(&worker, 2);
    assert!(matches!(worker.request(call).unwrap(), Reply::Rotated(3)));
}

#[test]
fn retirement_unknown_completion_and_mismatched_reply_never_become_success_or_sql_retry() {
    let (mut worker, port, _, _temp) = build();
    worker.tick().unwrap();
    let text = "CREATE TABLE acknowledgement(v)";
    execute(&mut worker, 92_001, text, Mode::Write).unwrap();
    let identity = worker.config.databases[0].identity;
    let context = request(&worker, 92_001, Operation::Status).context;
    let fingerprint =
        scap_sql::request_fingerprint(&[sql(text)], worker_limits().sqlite.sql).unwrap();
    let commit = match port
        .effects
        .borrow()
        .state
        .lookup(identity, context.admission, 92_001, fingerprint)
        .unwrap()
    {
        Lookup::Committed { commit, .. } => commit,
        _ => panic!("the original write must be committed"),
    };
    for outcome in [
        Outcome::Cancelled,
        Outcome::AlreadyCancelled,
        Outcome::AlreadyCommitted(commit),
    ] {
        port.effects.borrow_mut().outcome = Some(outcome);
        let call = terminal_request(
            &worker,
            92_001,
            1,
            text,
            OutcomeAction::Acknowledge {
                expected: ServiceTerminal::Committed { sequence: 1 },
            },
        );
        assert_eq!(worker.request(call).err().unwrap().code, "RESOLVE_REJECTED");
    }
    port.effects.borrow_mut().outcome = Some(Outcome::RequestAcknowledged);
    let call = terminal_request(&worker, 92_001, 1, text, OutcomeAction::ResolveOrCancel);
    assert_eq!(worker.request(call).err().unwrap().code, "RESOLVE_REJECTED");
    port.effects.borrow_mut().outcome = None;
    acknowledge(&mut worker, 92_001, 1, text);
    port.effects.borrow_mut().proposal_error = true;
    let call = rotate_request(&worker, 1);
    assert_eq!(worker.request(call).err().unwrap().code, "COMMIT_UNKNOWN");
    assert_eq!(
        port.effects
            .borrow()
            .state
            .database(3)
            .unwrap()
            .request_epoch,
        1
    );
    port.effects.borrow_mut().proposal_error = false;
    port.effects.borrow_mut().lost_result = true;
    let call = rotate_request(&worker, 1);
    assert_eq!(worker.request(call).err().unwrap().code, "COMMIT_UNKNOWN");
    assert_eq!(
        port.effects
            .borrow()
            .state
            .database(3)
            .unwrap()
            .request_epoch,
        2
    );
    port.effects.borrow_mut().lost_result = false;
    let call = request(&worker, 92_010, Operation::Status);
    assert!(
        matches!(worker.request(call).unwrap(), Reply::Status(status) if status.request_epoch == 2 && status.retained_requests == 0)
    );
}

#[test]
fn ordinary_reads_ignore_request_epochs_and_write_fingerprints_across_cold_recovery() {
    let (mut worker, port, clock, _temp) = build();
    worker.tick().unwrap();
    execute(
        &mut worker,
        92_100,
        "CREATE TABLE read_identity(v)",
        Mode::Write,
    )
    .unwrap();
    for stage in 0..3 {
        if stage == 1 {
            worker.writers.clear();
        } else if stage == 2 {
            clock.elapsed.store(6, Ordering::Release);
            worker.tick().unwrap();
            assert!(port.effects.borrow().state.database(3).unwrap().cold);
        }
        let mut call = request(
            &worker,
            92_100,
            Operation::Execute {
                mode: Mode::Read,
                statements: vec![sql("SELECT count(*) FROM read_identity")],
            },
        );
        call.context.admission.request_epoch = 999;
        match worker.request(call).unwrap() {
            Reply::Sql(result) => assert_eq!(
                result.statements[0].rows,
                vec![vec![scap_sql::Value::Integer(0)]]
            ),
            _ => panic!("an ordinary read must not use write identity resolution"),
        }
    }
    assert_eq!(port.effects.borrow().state.database(3).unwrap().revision, 1);
    worker.writers.clear();
    let before = port.effects.borrow().state.database(3).unwrap().owner;
    let mut call = request(
        &worker,
        92_100,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT count(*) FROM read_identity")],
        },
    );
    call.context.admission.auth_epoch += 1;
    assert_eq!(
        worker.request(call).err().unwrap().code,
        "OUTCOME_FORBIDDEN"
    );
    assert!(worker.writers.is_empty());
    assert_eq!(
        port.effects.borrow().state.database(3).unwrap().owner,
        before
    );
}

#[test]
fn absent_writer_rejects_future_or_conflicting_write_identity_before_owner_recovery() {
    let (mut worker, port, _, _temp) = build();
    execute(
        &mut worker,
        92_200,
        "CREATE TABLE write_identity(v)",
        Mode::Write,
    )
    .unwrap();
    worker.writers.clear();
    let before = port.effects.borrow().state.database(3).unwrap();
    let proposals = port.effects.borrow().proposals;
    for (id, epoch) in [(92_200, 1), (92_201, 2)] {
        let mut call = request(
            &worker,
            id,
            Operation::Execute {
                mode: Mode::Write,
                statements: vec![sql("INSERT INTO write_identity VALUES(1)")],
            },
        );
        call.context.admission.request_epoch = epoch;
        assert_eq!(
            worker.request(call).err().unwrap().code,
            "OUTCOME_FORBIDDEN"
        );
        assert!(worker.writers.is_empty());
        assert_eq!(port.effects.borrow().state.database(3).unwrap(), before);
        assert_eq!(port.effects.borrow().proposals, proposals);
    }
}

#[test]
fn v3_requires_separate_durable_retention_activation_and_confirmation_before_readiness() {
    for fail in 0..3 {
        let (mut worker, port, _, _temp) = build();
        port.effects.borrow_mut().state = CellState::bootstrap(
            worker.config.cell,
            worker.config.administrator_id,
            Position { term: 1, index: 1 },
            cell_limits(),
        )
        .unwrap();
        worker.cold.controller = None;
        {
            let mut effects = port.effects.borrow_mut();
            effects.proposal_error = fail == 0;
            effects.lost_result = fail == 1;
            effects.read_error = (fail == 2).then_some(2);
        }
        assert_eq!(worker.scan().unwrap_err().code, "COMMIT_UNKNOWN");
        assert!(!worker.ready.load(Ordering::Acquire));
        assert!(port.effects.borrow().state.database(3).is_none());
        {
            let mut effects = port.effects.borrow_mut();
            effects.proposal_error = false;
            effects.lost_result = false;
            effects.read_error = None;
        }
        worker.scan().unwrap();
        assert_eq!(port.effects.borrow().state.physical_history_version(), 5);
        assert!(worker.ready.load(Ordering::Acquire));
    }
}

#[test]
fn v4_control_activation_requires_exact_durable_result_and_fresh_confirmation() {
    for failure_point in 0..3 {
        let (mut worker, port, _, _temp) = build();
        port.effects.borrow_mut().state = CellState::bootstrap(
            worker.config.cell,
            worker.config.administrator_id,
            Position { term: 1, index: 1 },
            cell_limits(),
        )
        .unwrap();
        port.apply_raw(scap_cell::encode_retention_activation(
            worker.config.cell,
            worker.config.administrator_id,
        ));
        assert_eq!(port.effects.borrow().state.physical_history_version(), 4);
        worker.cold.controller = None;
        {
            let mut effects = port.effects.borrow_mut();
            effects.proposal_error = failure_point == 0;
            effects.lost_result = failure_point == 1;
            effects.read_error = (failure_point == 2).then_some(2);
        }
        assert_eq!(worker.scan().unwrap_err().code, "COMMIT_UNKNOWN");
        assert!(!worker.ready.load(Ordering::Acquire));
        assert!(!worker.history_active);
        assert!(port.effects.borrow().state.database(3).is_none());
        assert_eq!(port.effects.borrow().proposals, 1);
        assert_eq!(
            port.effects.borrow().state.physical_history_version(),
            if failure_point == 0 { 4 } else { 5 }
        );
        {
            let mut effects = port.effects.borrow_mut();
            effects.proposal_error = false;
            effects.lost_result = false;
            effects.read_error = None;
        }
        worker.scan().unwrap();
        assert!(worker.ready.load(Ordering::Acquire));
        assert!(worker.history_active);
        let database = port.effects.borrow().state.database(3).unwrap();
        assert_eq!(database.control_revision, Some(1));
        assert!(database.suspended);
        assert_eq!(
            port.effects.borrow().proposals,
            if failure_point == 0 { 3 } else { 2 }
        );
    }
}

#[test]
fn queued_archive_finishes_before_guarded_recovery_captures_its_control_intent() {
    let (mut worker, port, clock, _temp) = build();
    let database = worker.config.databases[0].clone();
    let deadline = clock.now().unwrap().instant + Duration::from_secs(30);
    let source = worker.database(&database, deadline).unwrap();
    assert!(source.suspended && !source.cold);
    let objects = Memory::default();
    worker.cold.controller = Some(scap_archive::Controller::new(
        worker.client.clone(),
        objects.clone(),
    ));
    let mut queued = scap_archive::Controller::new(worker.client.clone(), objects);
    let archive_context = worker.admin(source.auth_epoch, deadline).unwrap();
    let expected_revision = source.control_revision.unwrap() + 5;
    let waiting_clock = clock.clone();
    worker.cold.before_guard = Some(Box::new(move || {
        // The pending job retains the view it captured before the wake. Its
        // publication and prune complete while foreground acquisition waits.
        let published = queued
            .publish_bound(&archive_context, source.clone(), 93_001)
            .unwrap();
        queued
            .prune_bound(&archive_context, source, published, 93_002)
            .unwrap();
        waiting_clock.elapsed.store(2, Ordering::Release);
    }));
    let call = request(
        &worker,
        93_003,
        Operation::Execute {
            mode: Mode::Read,
            statements: vec![sql("SELECT 37")],
        },
    );
    let original = call.context.clone();
    match worker.request(call).unwrap() {
        Reply::Sql(result) => assert_eq!(
            result.statements[0].rows,
            vec![vec![scap_sql::Value::Integer(37)]]
        ),
        _ => panic!("fresh guarded recovery must serve the original request"),
    }
    let view = port.effects.borrow().state.database(3).unwrap();
    assert_eq!(view.control_revision, Some(expected_revision));
    assert_eq!(view.owner.epoch, 1);
    assert!(view.active && !view.suspended && !view.cold);
    let trace = worker.cold.guard_trace.borrow();
    assert_eq!((trace.acquired, trace.dropped, trace.held), (1, 1, false));
    assert_eq!(trace.database, Some(database.identity));
    let guarded = trace.context.as_ref().unwrap();
    assert_eq!(guarded.deadline, original.deadline);
    assert!(Arc::ptr_eq(&guarded.cancelled, &original.cancelled));
    let acquired = trace
        .events
        .iter()
        .position(|event| event.0 == "acquired")
        .unwrap();
    let released = trace
        .events
        .iter()
        .position(|event| event.0 == "released")
        .unwrap();
    assert!(trace.events[..acquired].contains(&("proposal", false)));
    assert_eq!(trace.events[acquired + 1], ("read", true));
    assert!(trace.events[acquired..=released]
        .iter()
        .all(|event| event.1));
    assert_eq!(
        trace.events[acquired..released]
            .iter()
            .filter(|event| event.0 == "proposal")
            .count(),
        3
    );
    assert!(trace.events[acquired..released].contains(&("hydrate", true)));
    // The ordinary query begins after the owner has been fully published and
    // the guard released; no control or SQL command is retried by recovery.
    assert_eq!(trace.events[released + 1..], [("read", false)]);
}

#[test]
fn guarded_wake_rechecks_original_tenant_authority_before_admin_effects() {
    for mode in [Mode::Read, Mode::Write] {
        let (mut worker, port, _clock, _temp) = build();
        worker.tick().unwrap();
        let before = port.effects.borrow().state.database(3).unwrap();
        assert!(before.cold);
        let fence = administrative(
            &worker,
            CommandKind::AuthFence {
                operation_id: 93_100,
                expected_epoch: before.auth_epoch,
                policy: vec![Grant {
                    principal_id: worker.config.administrator_id,
                    permissions: scap_cell::ADMIN | scap_cell::READ | scap_cell::WRITE,
                }],
            },
        );
        let waiting_port = port.clone();
        worker.cold.before_guard = Some(Box::new(move || {
            assert!(matches!(
                waiting_port.apply(fence).outcome,
                Outcome::ControlApplied(ControlResult {
                    result: AdminResult::AuthChanged(2),
                    ..
                })
            ));
        }));
        let proposals = port.effects.borrow().proposals;
        assert_eq!(
            execute(&mut worker, 93_101, "SELECT 1", mode)
                .unwrap_err()
                .code,
            "OUTCOME_FORBIDDEN"
        );
        let after = port.effects.borrow().state.database(3).unwrap();
        assert_eq!(after.auth_epoch, 2);
        assert_eq!(
            after.control_revision,
            before.control_revision.map(|revision| revision + 1)
        );
        assert_eq!(after.owner, before.owner);
        assert!(after.cold && after.suspended && !after.active);
        assert_eq!(port.effects.borrow().proposals, proposals);
        assert!(worker.writers.is_empty());
        let trace = worker.cold.guard_trace.borrow();
        assert_eq!((trace.acquired, trace.dropped, trace.held), (1, 1, false));
        assert!(!trace.events.contains(&("hydrate", true)));
        assert!(!trace.events.contains(&("proposal", true)));
    }
}

#[test]
fn guarded_write_does_not_wake_a_request_epoch_retired_while_waiting() {
    let (mut worker, port, _clock, _temp) = build();
    worker.cold.controller = None;
    worker.tick().unwrap();
    // Rotation requires a nonempty, fully acknowledged window. A cancelled
    // request supplies it without creating or activating an SQL owner.
    let cancelled = terminal_request(
        &worker,
        93_299,
        1,
        "SELECT 8",
        OutcomeAction::ResolveOrCancel,
    );
    assert!(matches!(
        worker.request(cancelled).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled { .. })
    ));
    acknowledge(&mut worker, 93_299, 1, "SELECT 8");
    let before = port.effects.borrow().state.database(3).unwrap();
    let mut rotate = administrative(&worker, CommandKind::RotateRequests { expected_epoch: 1 });
    rotate.control_revision = None;
    let waiting_port = port.clone();
    worker.cold.before_guard = Some(Box::new(move || {
        assert_eq!(
            waiting_port.apply(rotate).outcome,
            Outcome::RequestsRotated { epoch: 2 }
        );
    }));
    let proposals = port.effects.borrow().proposals;
    assert_eq!(
        execute(&mut worker, 93_200, "SELECT 1", Mode::Write)
            .unwrap_err()
            .code,
        "REQUEST_RETIRED"
    );
    let after = port.effects.borrow().state.database(3).unwrap();
    assert_eq!(after.request_epoch, 2);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.cold, before.cold);
    assert!(after.suspended && !after.active);
    assert_eq!(port.effects.borrow().proposals, proposals);
    assert!(worker.writers.is_empty());
    let trace = worker.cold.guard_trace.borrow();
    assert_eq!((trace.acquired, trace.dropped, trace.held), (1, 1, false));
    assert!(!trace.events.contains(&("hydrate", true)));
}

#[test]
fn maintenance_rechecks_sleep_and_current_admin_authority_after_guard_wait() {
    for suspended in [true, false] {
        let (mut worker, port, _clock, _temp) = build();
        execute(&mut worker, 93_300, "SELECT 1", Mode::Read).unwrap();
        worker.writers.clear();
        let before = port.effects.borrow().state.database(3).unwrap();
        let transition = administrative(
            &worker,
            if suspended {
                CommandKind::SuspendDb {
                    operation_id: 93_301,
                    token: before.owner,
                    expected_revision: before.revision,
                }
            } else {
                CommandKind::AuthFence {
                    operation_id: 93_301,
                    expected_epoch: before.auth_epoch,
                    policy: vec![Grant {
                        principal_id: worker.config.administrator_id,
                        permissions: scap_cell::ADMIN | scap_cell::READ | scap_cell::WRITE,
                    }],
                }
            },
        );
        let waiting_port = port.clone();
        worker.cold.before_guard = Some(Box::new(move || {
            assert!(matches!(
                waiting_port.apply(transition).outcome,
                Outcome::ControlApplied(_)
            ));
        }));
        let proposals = port.effects.borrow().proposals;
        worker.tick().unwrap();
        let after = port.effects.borrow().state.database(3).unwrap();
        assert_eq!(after.suspended, suspended);
        assert_eq!(after.active, !suspended);
        assert_eq!(after.owner.epoch, before.owner.epoch + 1);
        assert_eq!(worker.writers.is_empty(), suspended);
        assert_eq!(
            port.effects.borrow().proposals - proposals,
            if suspended { 0 } else { 2 }
        );
        assert_eq!(after.auth_epoch, if suspended { 1 } else { 2 });
        let trace = worker.cold.guard_trace.borrow();
        assert_eq!(trace.acquired, trace.dropped);
        assert!(!trace.held);
    }
}

#[test]
fn recovery_guard_failures_and_original_cancellation_or_deadline_never_submit() {
    for failure_point in 0..4 {
        let (mut worker, port, clock, _temp) = build();
        worker.tick().unwrap();
        let before = port.effects.borrow().state.database(3).unwrap();
        let call = request(
            &worker,
            93_400,
            Operation::Execute {
                mode: Mode::Read,
                statements: vec![sql("SELECT 1")],
            },
        );
        let original = call.context.clone();
        match failure_point {
            0 => worker.cold.fail_guard = true,
            1 => {
                let cancelled = original.cancelled.clone();
                worker.cold.before_guard = Some(Box::new(move || {
                    cancelled.store(true, Ordering::Release);
                }));
            }
            2 => {
                worker.cold.before_guard = Some(Box::new(move || {
                    clock.elapsed.store(31, Ordering::Release);
                }))
            }
            _ => worker.cold.fail_hydrate = true,
        }
        let proposals = port.effects.borrow().proposals;
        let error = worker.request(call).err().unwrap();
        assert_eq!(
            error.code,
            match failure_point {
                0 => "RECOVERY_UNAVAILABLE",
                1 | 2 => "COMMIT_UNKNOWN",
                _ => "ARCHIVE_UNAVAILABLE",
            }
        );
        assert_eq!(port.effects.borrow().proposals, proposals);
        assert_eq!(port.effects.borrow().state.database(3).unwrap(), before);
        assert!(worker.writers.is_empty());
        let trace = worker.cold.guard_trace.borrow();
        let acquired = usize::from(failure_point != 0);
        assert_eq!(
            (trace.acquired, trace.dropped, trace.held),
            (acquired, acquired, false)
        );
        let observed = trace.context.as_ref().unwrap();
        assert_eq!(observed.deadline, original.deadline);
        assert!(Arc::ptr_eq(&observed.cancelled, &original.cancelled));
    }
}

#[test]
fn recovery_rechecks_database_identity_after_guard_and_hydrate_before_owner_effects() {
    for after_hydrate in [false, true] {
        for wrong_incarnation in [false, true] {
            let (mut worker, port, _clock, directory) = build();
            let invalid = if wrong_incarnation {
                let (mut other, other_port, _clock, _directory) = build();
                other.config.databases[0].identity.incarnation += 1;
                other.tick().unwrap();
                let state = other_port.effects.borrow().state.clone();
                state
            } else {
                port.effects.borrow().state.clone()
            };
            worker.tick().unwrap();
            let before = port.effects.borrow().state.database(3).unwrap();
            assert!(before.cold);
            let call = request(
                &worker,
                93_450,
                Operation::Execute {
                    mode: Mode::Read,
                    statements: vec![sql("SELECT 1")],
                },
            );
            let reads = port.effects.borrow().reads;
            let proposals = port.effects.borrow().proposals;
            // Recovery first reads after acquiring the guard. A cold wake then
            // validates the captured view in Controller and confirms Hydrate
            // with a third read before constructing any new owner intent.
            let failed_read = reads + if after_hydrate { 3 } else { 1 };
            port.effects.borrow_mut().read_override = Some((failed_read, invalid));
            let error = worker
                .recover(
                    &call.database,
                    RecoveryRequest::Tenant {
                        context: &call.context,
                        mode: Mode::Read,
                        request_id: call.request_id,
                        fingerprint: scap_sql::request_fingerprint(
                            &[sql("SELECT 1")],
                            worker_limits().sqlite.sql,
                        )
                        .unwrap(),
                    },
                )
                .unwrap_err();
            assert_eq!(
                error.code,
                if wrong_incarnation {
                    "DATABASE_FENCED"
                } else {
                    "DATABASE_MISSING"
                }
            );
            assert_eq!(port.effects.borrow().reads, failed_read);
            assert_eq!(
                port.effects.borrow().proposals,
                proposals + usize::from(after_hydrate)
            );
            let after = port.effects.borrow().state.database(3).unwrap();
            assert_eq!(after.owner, before.owner);
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.cold, !after_hydrate);
            assert_eq!(
                after.control_revision,
                before
                    .control_revision
                    .map(|revision| revision + u64::from(after_hydrate))
            );
            assert!(worker.writers.is_empty());
            assert_eq!(
                std::fs::read_dir(directory.path().join("writers"))
                    .unwrap()
                    .count(),
                0
            );
            let trace = worker.cold.guard_trace.borrow();
            assert_eq!((trace.acquired, trace.dropped, trace.held), (1, 1, false));
            assert!(trace
                .events
                .ends_with(&[("read", true), ("released", true)]));
        }
    }
}

#[test]
fn unknown_claim_or_activation_releases_guard_without_refresh_or_retry() {
    for lost_activation in [false, true] {
        let (mut worker, port, _clock, directory) = build();
        worker.cold.controller = None;
        worker.tick().unwrap();
        let before = port.effects.borrow().state.database(3).unwrap();
        let proposals = port.effects.borrow().proposals;
        let attempts = if lost_activation { 2 } else { 1 };
        port.effects.borrow_mut().lost_result_at = Some(proposals + attempts);
        assert_eq!(
            execute(&mut worker, 93_500, "SELECT 1", Mode::Read)
                .unwrap_err()
                .code,
            "RECOVERY_UNAVAILABLE"
        );
        let after = port.effects.borrow().state.database(3).unwrap();
        assert_eq!(
            after.control_revision,
            before
                .control_revision
                .map(|revision| revision + attempts as u64)
        );
        assert_eq!(after.owner.epoch, before.owner.epoch + 1);
        assert_eq!(after.active, lost_activation);
        assert_eq!(port.effects.borrow().proposals, proposals + attempts);
        assert!(worker.writers.is_empty());
        assert_eq!(
            std::fs::read_dir(directory.path().join("writers"))
                .unwrap()
                .count(),
            0
        );
        let trace = worker.cold.guard_trace.borrow();
        assert_eq!((trace.acquired, trace.dropped, trace.held), (1, 1, false));
        assert!(trace
            .events
            .ends_with(&[("proposal", true), ("released", true)]));
    }
}
