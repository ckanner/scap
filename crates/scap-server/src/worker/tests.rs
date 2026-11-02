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
    pub outcome: Option<Outcome>,
    pub status_error: bool,
    pub maintenance_error: bool,
    pub maintenance: Vec<bool>,
}

#[derive(Clone)]
pub(crate) struct Port {
    pub identity: Identity,
    pub effects: Rc<RefCell<Effects>>,
}

impl Port {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
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
                outcome: None,
                status_error: false,
                maintenance_error: false,
                maintenance: vec![],
            })),
        }
    }

    pub(crate) fn apply(&self, command: Command) -> scap_cell::AppliedOutcome {
        let bytes = scap_cell::encode_command(&command, cell_limits()).unwrap();
        self.apply_bytes(bytes)
    }

    fn apply_bytes(&self, data: Vec<u8>) -> scap_cell::AppliedOutcome {
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
        scap_cell::decode_applied_outcome(&batch.results[0], position).unwrap()
    }
}

impl CellPort for Port {
    fn identity(&self) -> Identity {
        self.identity.clone()
    }
    fn read(&mut self, _: Instant, _: &AtomicBool) -> Result<ReadView, RuntimeError> {
        let mut held = self.effects.borrow_mut();
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
        let mut applied = self.apply_bytes(data);
        if self.effects.borrow().lost_result {
            return Err(RuntimeError::Unknown);
        }
        if let Some(outcome) = self.effects.borrow_mut().outcome.take() {
            applied.outcome = outcome;
        }
        Ok(ProposalResult {
            ticket: ProposalTicket {
                boot_id: 1,
                sequence: applied.position.index,
            },
            index: applied.position.index,
            term: applied.position.term,
            data: scap_cell::encode_applied_outcome(&applied),
        })
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
struct TestCold {
    controller: Option<scap_archive::Controller<Port, Memory>>,
    fail_archive: bool,
    fail_hydrate: bool,
    completed: bool,
}

impl ColdStorage<Port> for TestCold {
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
        if self.fail_hydrate {
            return Err(failure("ARCHIVE_UNAVAILABLE"));
        }
        self.controller
            .as_mut()
            .ok_or_else(|| failure("ARCHIVE_UNAVAILABLE"))?
            .hydrate(context, database.identity, operation)
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
        controller
            .publish(context, database.identity, publish)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))?;
        controller
            .prune(context, database.identity, prune)
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
                resolve,
                statements: vec![sql(statement)],
            },
        );
        assert!(
            matches!(worker.request(call).unwrap(), Reply::Outcome(ServiceOutcome::Committed { result, sequence: 2 }) if result == original)
        );
    }
    let lookup = request(
        &worker,
        1010,
        Operation::Outcome {
            resolve: false,
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
            resolve: true,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(cancel).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled)
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
            resolve: false,
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
            resolve: true,
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
            resolve: true,
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
        cell: worker.config.cell,
        database: worker.config.databases[0].identity,
        admission: Admission {
            principal_id: worker.config.administrator_id,
            credential_id: worker.config.service_credential_id,
            admission_id: 50_000,
            auth_epoch: 1,
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
        Outcome::Administrative(AdminResult::OwnerClaimed(_))
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
    let call = request(&worker, 4102, Operation::Status);
    assert!(
        matches!(worker.request(call).unwrap(), Reply::Status(s) if s.revision == 2 && s.owner_active && !s.cold && !s.suspended && s.archived_revision == Some(0))
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
        matches!(worker.request(call).unwrap(), Reply::Status(s) if s.revision == 2 && !s.owner_active && s.cold && s.suspended && s.archived_revision == Some(2))
    );
    let lookup = request(
        &worker,
        4101,
        Operation::Outcome {
            resolve: false,
            statements: vec![sql(statement)],
        },
    );
    assert!(
        matches!(worker.request(lookup).unwrap(), Reply::Outcome(ServiceOutcome::Committed { result, sequence: 2 }) if result == original)
    );
    let cancellation = request(
        &worker,
        4199,
        Operation::Outcome {
            resolve: true,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(cancellation).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled)
    ));
    let again = request(
        &worker,
        4199,
        Operation::Outcome {
            resolve: true,
            statements: vec![sql("SELECT 1")],
        },
    );
    assert!(matches!(
        worker.request(again).unwrap(),
        Reply::Outcome(ServiceOutcome::Cancelled)
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
                resolve: false,
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
            resolve: false,
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
            resolve: false,
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
            resolve: false,
            statements: vec![sql("SELECT 1")],
        },
    );
    let view = port.effects.borrow().state.database(3).unwrap();
    let physical_changes = vec![1, 2, 3];
    let command = Command {
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
fn concurrent_archive_prune_can_refresh_once_before_any_sql_executes() {
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
        Outcome::Administrative(AdminResult::Suspended(_))
    ));
    worker.writers.clear();
    let context = worker
        .admin(1, clock.now().unwrap().instant + Duration::from_secs(30))
        .unwrap();
    let archive = worker
        .cold
        .controller
        .as_mut()
        .unwrap()
        .publish(&context, view.identity, 50_011)
        .unwrap();
    let published = port.effects.borrow().state.database(3).unwrap();
    assert!(!published.cold);
    let prune = administrative(
        &worker,
        CommandKind::PruneArchive {
            operation_id: 50_012,
            expected_owner: published.owner,
            archive_digest: archive.object_digest,
        },
    );
    let next = port.effects.borrow().proposals + 1;
    port.effects.borrow_mut().before_proposal = Some((next, prune));
    execute(
        &mut worker,
        4701,
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
    // If that one refresh budget is already spent, a definite Cold response
    // fails closed. There is no recursive unbounded retry or SQL replay.
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
    worker
        .cold
        .controller
        .as_mut()
        .unwrap()
        .publish(&context, view.identity, 50_014)
        .unwrap();
    let stale = port.effects.borrow().state.database(3).unwrap();
    worker
        .cold
        .controller
        .as_mut()
        .unwrap()
        .prune(&context, view.identity, 50_015)
        .unwrap();
    let database = worker.config.databases[0].clone();
    assert_eq!(
        worker
            .recover_after_prune(&database, stale, context.deadline, false)
            .unwrap_err()
            .code,
        "RECOVERY_UNAVAILABLE"
    );
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
    assert!(worker.writers.is_empty());
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
    let mut stale = port.effects.borrow().state.database(3).unwrap();
    assert!(stale.cold);
    stale.cold = false;
    let after_rejected_claim = port.effects.borrow().reads + 2;
    port.effects.borrow_mut().read_error = Some(after_rejected_claim);
    let database = worker.config.databases[0].clone();
    assert_eq!(
        worker
            .recover(
                &database,
                stale,
                clock.now().unwrap().instant + Duration::from_secs(30)
            )
            .unwrap_err()
            .code,
        "COMMIT_UNKNOWN"
    );
    assert!(port.effects.borrow().state.database(3).unwrap().cold);
}
