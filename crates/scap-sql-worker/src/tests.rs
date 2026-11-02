use super::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::{Duration, Instant};

use raft::eraftpb::Entry;
use scap_cell::{
    Admission, CellApplication, CellIdentity, CellState, Command, DatabaseIdentity, Grant,
    Position, ADMIN, READ, WRITE,
};
use scap_core::CommitReceipt;
use scap_raft_driver::{Application, ProposalResult, ProposalTicket, ReadBarrier, ReadTicket};
use scap_raft_runtime::{ClockReading, ReadView};
use scap_raft_store::Identity;
use scap_sql::{SqlLimits, TransactionResult, Value};

#[path = "query_tests.rs"]
mod query_tests;

struct TestClock {
    base: Instant,
    mode: AtomicUsize,
}

impl Clock for TestClock {
    fn now(&self) -> Result<ClockReading, scap_raft_runtime::Error> {
        match self.mode.load(Ordering::Acquire) {
            2 => Err(scap_raft_runtime::Error::Clock),
            mode => Ok(ClockReading {
                instant: self.base + Duration::from_secs(if mode == 1 { 60 } else { 0 }),
                unix_seconds: 1,
            }),
        }
    }
}

fn identity() -> EngineIdentity {
    EngineIdentity {
        cell: CellIdentity {
            cell_id: 41,
            cell_incarnation: 9,
        },
        database: DatabaseIdentity {
            database_id: 101,
            incarnation: 3,
            placement_generation: 2,
        },
    }
}

fn replica() -> Identity {
    Identity {
        cluster_id: 55,
        cell_id: 41,
        cell_incarnation: 9,
        node_id: 1,
    }
}

fn admission() -> Admission {
    Admission {
        principal_id: 11,
        credential_id: 12,
        admission_id: 13,
        auth_epoch: 1,
    }
}

fn cell_limits() -> scap_cell::Limits {
    scap_cell::Limits {
        max_state_bytes: 4 * 1024 * 1024,
        max_command_bytes: 128 * 1024,
        max_databases: 4,
        max_policy_grants: 4,
        max_admin_operations: 64,
        max_requests_per_database: 64,
        max_transaction_bytes: 64 * 1024,
        max_result_bytes: 8192,
    }
}

fn limits() -> WorkerLimits {
    WorkerLimits {
        engine: scap_engine::Limits {
            max_database_pages: 16,
            max_changed_pages: 8,
            max_transaction_bytes: 64 * 1024,
        },
        sqlite: WriterLimits {
            sql: SqlLimits {
                max_statements: 4,
                max_sql_bytes: 4096,
                max_parameters: 8,
                max_columns: 8,
                max_rows: 32,
                max_result_bytes: 8192,
                max_value_bytes: 4096,
            },
            max_vm_steps: 100_000,
            max_changed_pages: 8,
        },
    }
}

fn command(kind: CommandKind) -> Command {
    Command {
        cell: identity().cell,
        database: identity().database,
        admission: admission(),
        kind,
    }
}

fn apply_data(state: &mut CellState, data: Vec<u8>) -> ProposalResult {
    let position = Position {
        term: state.position().term,
        index: state.position().index + 1,
    };
    let entry = Entry {
        term: position.term,
        index: position.index,
        data: data.into(),
        ..Entry::default()
    };
    let batch = CellApplication::new(identity().cell, cell_limits())
        .unwrap()
        .apply_with_results(&state.encode(), &[entry], &[position.index])
        .unwrap();
    *state =
        CellState::decode_bound(&batch.state, identity().cell, position, cell_limits()).unwrap();
    ProposalResult {
        ticket: ProposalTicket {
            boot_id: 111,
            sequence: position.index,
        },
        index: position.index,
        term: position.term,
        data: batch.results.into_iter().next().unwrap(),
    }
}

fn apply(state: &mut CellState, kind: CommandKind) {
    apply_data(
        state,
        scap_cell::encode_command(&command(kind), cell_limits()).unwrap(),
    );
}

fn genesis() -> CellState {
    CellState::bootstrap(
        identity().cell,
        admission().principal_id,
        Position { term: 1, index: 1 },
        cell_limits(),
    )
    .unwrap()
}

fn created() -> CellState {
    let mut state = genesis();
    apply(
        &mut state,
        CommandKind::Create {
            operation_id: 1,
            policy: vec![Grant {
                principal_id: 11,
                permissions: READ | WRITE | ADMIN,
            }],
        },
    );
    state
}

struct Model {
    state: CellState,
    reads: usize,
    proposals: usize,
    fail_reads: BTreeSet<usize>,
    fail_proposals: BTreeSet<usize>,
    override_reads: BTreeMap<usize, CellState>,
    mutate_reads: BTreeMap<usize, CommandKind>,
    mutate_proposals: BTreeMap<usize, CommandKind>,
    events: Rc<RefCell<Vec<&'static str>>>,
}

#[derive(Clone)]
struct Port(Rc<RefCell<Model>>);

impl CellPort for Port {
    fn identity(&self) -> Identity {
        replica()
    }

    fn read(
        &mut self,
        _deadline: Instant,
        _cancelled: &AtomicBool,
    ) -> Result<ReadView, scap_raft_runtime::Error> {
        let mut model = self.0.borrow_mut();
        model.reads += 1;
        let number = model.reads;
        model.events.borrow_mut().push("read");
        if model.fail_reads.contains(&number) {
            return Err(scap_raft_runtime::Error::Unknown);
        }
        if let Some(kind) = model.mutate_reads.remove(&number) {
            apply(&mut model.state, kind);
        }
        let state = model
            .override_reads
            .remove(&number)
            .unwrap_or_else(|| model.state.clone());
        Ok(ReadView {
            identity: replica(),
            term: state.position().term,
            index: state.position().index,
            barrier: ReadBarrier {
                ticket: ReadTicket {
                    boot_id: 111,
                    sequence: number as u64,
                },
                index: state.position().index,
            },
            application: state.encode(),
        })
    }

    fn propose(
        &mut self,
        data: Vec<u8>,
        _deadline: Instant,
        _cancelled: &AtomicBool,
    ) -> Result<ProposalResult, scap_raft_runtime::Error> {
        let mut model = self.0.borrow_mut();
        model.proposals += 1;
        let number = model.proposals;
        model.events.borrow_mut().push("propose");
        if model.fail_proposals.contains(&number) {
            return Err(scap_raft_runtime::Error::Unknown);
        }
        if let Some(kind) = model.mutate_proposals.remove(&number) {
            apply(&mut model.state, kind);
        }
        Ok(apply_data(&mut model.state, data))
    }
}

struct Kit {
    port: Port,
    clock: Arc<TestClock>,
    context: RequestContext,
    request: OwnerRequest,
}

impl Kit {
    fn new() -> Self {
        let clock = Arc::new(TestClock {
            base: Instant::now(),
            mode: AtomicUsize::new(0),
        });
        Self {
            port: Port(Rc::new(RefCell::new(Model {
                state: created(),
                reads: 0,
                proposals: 0,
                fail_reads: BTreeSet::new(),
                fail_proposals: BTreeSet::new(),
                override_reads: BTreeMap::new(),
                mutate_reads: BTreeMap::new(),
                mutate_proposals: BTreeMap::new(),
                events: Rc::default(),
            }))),
            context: RequestContext {
                admission: admission(),
                deadline: clock.base + Duration::from_secs(30),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            clock,
            request: OwnerRequest {
                identity: identity(),
                expected_owner_epoch: 0,
                worker_instance_id: 77,
                claim_operation_id: 10,
                activate_operation_id: 11,
            },
        }
    }

    fn client(&self) -> Client<Port> {
        Client::new(
            replica().cluster_id,
            identity().cell,
            cell_limits(),
            self.port.clone(),
            self.clock.clone(),
        )
        .unwrap()
    }

    fn factory(&self) -> Factory {
        Factory {
            effect: Rc::default(),
            clock: self.clock.clone(),
            events: self.port.0.borrow().events.clone(),
        }
    }

    fn recover(
        &self,
        factory: Factory,
        worker_limits: WorkerLimits,
    ) -> Result<Writer<Port, TestEngine>, Error> {
        Writer::recover_with(
            self.client(),
            &self.context,
            self.request,
            Path::new("unused-unit-path"),
            worker_limits,
            self.clock.clone(),
            factory,
        )
    }
}

#[derive(Default)]
struct Effect {
    fail_create: bool,
    expire_create: bool,
    fail_execute: bool,
    expire_execute: bool,
    replay: bool,
    engine_stopped: bool,
    dropped: usize,
    calls: Vec<CommitTicket>,
    query_calls: usize,
    query_mode: u8,
}

struct Factory {
    effect: Rc<RefCell<Effect>>,
    clock: Arc<TestClock>,
    events: Rc<RefCell<Vec<&'static str>>>,
}

impl EngineFactory<Port> for Factory {
    type Engine = TestEngine;

    fn create(
        &mut self,
        _directory: &Path,
        image: Image,
        _limits: WriterLimits,
        _gate: Gate<Port>,
    ) -> Result<TestEngine, scap_sqlite::Error> {
        self.events.borrow_mut().push("create");
        if self.effect.borrow().fail_create {
            return Err(scap_sqlite::Error::InvalidImage);
        }
        if self.effect.borrow().expire_create {
            self.clock.mode.store(1, Ordering::Release);
        }
        Ok(TestEngine {
            head: image.head(),
            effect: self.effect.clone(),
            clock: self.clock.clone(),
        })
    }
}

struct TestEngine {
    head: Head,
    effect: Rc<RefCell<Effect>>,
    clock: Arc<TestClock>,
}

impl Drop for TestEngine {
    fn drop(&mut self) {
        self.effect.borrow_mut().dropped += 1;
    }
}

impl Engine for TestEngine {
    fn head(&self) -> Head {
        self.head
    }
    fn is_stopped(&self) -> bool {
        self.effect.borrow().engine_stopped
    }
    fn execute(
        &mut self,
        ticket: CommitTicket,
        _statements: &[Statement],
    ) -> Result<Completed, scap_sqlite::Error> {
        let mut effect = self.effect.borrow_mut();
        effect.calls.push(ticket.clone());
        if effect.fail_execute {
            return Err(scap_sqlite::Error::OutcomeUnknown);
        }
        if effect.expire_execute {
            self.clock.mode.store(1, Ordering::Release);
        }
        self.head.revision += 1;
        effect.engine_stopped = effect.replay;
        Ok(Completed {
            receipt: CommitReceipt {
                sequence: self.head.revision,
                ticket,
            },
            result: TransactionResult { statements: vec![] },
            replayed: effect.replay,
        })
    }

    fn query(
        &mut self,
        _statements: &[Statement],
        interrupt: ReadInterrupt,
    ) -> Result<TransactionResult, scap_sqlite::Error> {
        let mut effect = self.effect.borrow_mut();
        effect.query_calls += 1;
        match effect.query_mode {
            1 => return Err(scap_sqlite::Error::InvalidSql),
            2 => self.clock.mode.store(1, Ordering::Release),
            3 => self.clock.mode.store(2, Ordering::Release),
            _ => (),
        }
        if interrupt() {
            return Err(scap_sqlite::Error::Interrupted);
        }
        match effect.query_mode {
            4 => effect.engine_stopped = true,
            5 => self.head.revision += 1,
            6 => self.clock.mode.store(1, Ordering::Release),
            _ => (),
        }
        Ok(TransactionResult { statements: vec![] })
    }
}

#[test]
fn recovery_orders_claim_restore_activation_and_fresh_authority_before_serving() {
    let kit = Kit::new();
    let factory = kit.factory();
    let effect = factory.effect.clone();
    let mut writer = kit.recover(factory, limits()).unwrap();
    assert_eq!(
        &*kit.port.0.borrow().events.borrow(),
        &["read", "propose", "read", "create", "propose", "read"]
    );
    assert_eq!(writer.head().revision, 0);
    assert_eq!(
        writer.owner(),
        OwnerToken {
            epoch: 1,
            worker_instance_id: 77
        }
    );
    assert!(!writer.is_stopped());
    let completed = writer.execute(kit.context.clone(), 55, &[]).unwrap();
    assert_eq!(completed.receipt.sequence, 1);
    let mut next = kit.context.clone();
    next.admission.auth_epoch = 2;
    writer.execute(next, 56, &[]).unwrap();
    let calls = &effect.borrow().calls;
    assert_eq!(calls[0].owner_epoch, 1);
    assert_eq!(calls[0].predecessor, 0);
    assert_eq!(calls[1].predecessor, 1);
    assert_eq!(calls[1].auth_epoch, 2);
    assert_eq!(calls[1].request_id, 56);
    assert!(!writer.is_stopped());
}

#[test]
fn invalid_intents_scopes_and_missing_databases_do_not_claim_an_owner() {
    for case in 0..8 {
        let mut kit = Kit::new();
        match case {
            0 => kit.request.worker_instance_id = 0,
            1 => kit.request.claim_operation_id = 0,
            2 => kit.request.activate_operation_id = 0,
            3 => kit.request.activate_operation_id = kit.request.claim_operation_id,
            4 => kit.request.expected_owner_epoch = u64::MAX,
            5 => kit.request.identity.cell.cell_id += 1,
            6 => kit.request.identity.database.database_id += 1,
            _ => kit.request.identity.database.incarnation += 1,
        }
        assert!(kit.recover(kit.factory(), limits()).is_err());
        assert_eq!(kit.port.0.borrow().proposals, 0);
    }
}

#[test]
fn deadlines_cancellation_and_clock_failure_never_authorize_work() {
    for mode in [1, 2] {
        let kit = Kit::new();
        kit.clock.mode.store(mode, Ordering::Release);
        assert!(matches!(
            kit.recover(kit.factory(), limits()),
            Err(Error::Unknown)
        ));
        assert_eq!(kit.port.0.borrow().reads, 0);
    }
    let kit = Kit::new();
    kit.context.cancelled.store(true, Ordering::Release);
    assert!(matches!(
        kit.recover(kit.factory(), limits()),
        Err(Error::Unknown)
    ));
    assert!(live(&kit.context, kit.clock.as_ref()).is_err());
}

#[test]
fn recovery_failures_retire_partial_resources_and_never_open_an_unverified_writer() {
    for read in 1..=3 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        kit.port.0.borrow_mut().fail_reads.insert(read);
        assert!(matches!(
            kit.recover(factory, limits()),
            Err(Error::Client(_))
        ));
        assert_eq!(effect.borrow().dropped, usize::from(read == 3));
    }
    for proposal in 1..=2 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        kit.port.0.borrow_mut().fail_proposals.insert(proposal);
        assert!(matches!(
            kit.recover(factory, limits()),
            Err(Error::Client(_))
        ));
        assert_eq!(effect.borrow().dropped, usize::from(proposal == 2));
    }
    let kit = Kit::new();
    let mut bad = limits();
    bad.engine.max_database_pages = 0;
    assert!(matches!(
        kit.recover(kit.factory(), bad),
        Err(Error::Image(_))
    ));
    assert_eq!(kit.port.0.borrow().proposals, 1);
    for expires in [false, true] {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        effect.borrow_mut().fail_create = !expires;
        effect.borrow_mut().expire_create = expires;
        assert!(kit.recover(factory, limits()).is_err());
        assert_eq!(effect.borrow().dropped, usize::from(expires));
        assert_eq!(kit.port.0.borrow().proposals, 1);
        assert!(
            !kit.port
                .0
                .borrow()
                .state
                .database(identity().database.database_id)
                .unwrap()
                .active
        );
    }
}

#[test]
fn concurrent_owner_and_authorization_changes_block_recovery() {
    for case in 0..5 {
        let kit = Kit::new();
        match case {
            0 => {
                kit.port.0.borrow_mut().override_reads.insert(2, genesis());
            }
            1 => {
                let mut changed = genesis();
                let mut create = command(CommandKind::Create {
                    operation_id: 1,
                    policy: vec![Grant {
                        principal_id: 11,
                        permissions: READ | WRITE | ADMIN,
                    }],
                });
                create.database.incarnation += 1;
                apply_data(
                    &mut changed,
                    scap_cell::encode_command(&create, cell_limits()).unwrap(),
                );
                kit.port.0.borrow_mut().override_reads.insert(2, changed);
            }
            2 => {
                kit.port.0.borrow_mut().mutate_reads.insert(
                    2,
                    CommandKind::ClaimOwner {
                        operation_id: 20,
                        expected_epoch: 1,
                        worker_instance_id: 88,
                    },
                );
            }
            3 => {
                kit.port.0.borrow_mut().mutate_reads.insert(
                    2,
                    CommandKind::ActivateOwner {
                        operation_id: 20,
                        token: OwnerToken {
                            epoch: 1,
                            worker_instance_id: 77,
                        },
                        restored_revision: 0,
                        restored_hash: [0; 32],
                    },
                );
            }
            _ => {
                kit.port.0.borrow_mut().mutate_reads.insert(
                    3,
                    CommandKind::AuthFence {
                        operation_id: 20,
                        expected_epoch: 1,
                        policy: vec![Grant {
                            principal_id: 11,
                            permissions: READ | WRITE | ADMIN,
                        }],
                    },
                );
            }
        }
        assert!(matches!(
            kit.recover(kit.factory(), limits()),
            Err(Error::Rejected(_))
        ));
    }
    let mut kit = Kit::new();
    kit.request.expected_owner_epoch = 9;
    assert!(matches!(
        kit.recover(kit.factory(), limits()),
        Err(Error::Rejected(Reject::Fenced))
    ));
}

#[test]
fn administrative_results_require_the_exact_expected_effect() {
    for outcome in [
        Outcome::Administrative(AdminResult::OwnerActivated),
        Outcome::AlreadyApplied(AdminResult::OwnerActivated),
    ] {
        assert!(administrative(outcome, AdminResult::OwnerActivated).is_ok());
    }
    assert!(matches!(
        administrative(
            Outcome::Administrative(AdminResult::Created),
            AdminResult::OwnerActivated
        ),
        Err(Error::Unknown)
    ));
    assert!(matches!(
        administrative(
            Outcome::AlreadyApplied(AdminResult::Created),
            AdminResult::OwnerActivated
        ),
        Err(Error::Unknown)
    ));
    assert!(matches!(
        administrative(Outcome::Cancelled, AdminResult::OwnerActivated),
        Err(Error::Unknown)
    ));
    assert!(matches!(
        administrative(
            Outcome::Rejected(Reject::Fenced),
            AdminResult::OwnerActivated
        ),
        Err(Error::Rejected(Reject::Fenced))
    ));
}

#[test]
fn another_claim_between_native_creation_and_activation_retires_the_new_engine() {
    let kit = Kit::new();
    let factory = kit.factory();
    let effect = factory.effect.clone();
    kit.port.0.borrow_mut().mutate_proposals.insert(
        2,
        CommandKind::ClaimOwner {
            operation_id: 20,
            expected_epoch: 1,
            worker_instance_id: 88,
        },
    );
    assert!(matches!(
        kit.recover(factory, limits()),
        Err(Error::Rejected(Reject::Fenced))
    ));
    assert_eq!(effect.borrow().dropped, 1);
    let database = kit
        .port
        .0
        .borrow()
        .state
        .database(identity().database.database_id)
        .unwrap();
    assert_eq!(database.owner.worker_instance_id, 88);
    assert!(!database.active);
}

#[test]
fn recovery_rechecks_the_original_deadline_after_rebuild_and_before_publication() {
    struct CheckpointClock {
        base: Instant,
        calls: AtomicUsize,
        expires: usize,
    }
    impl Clock for CheckpointClock {
        fn now(&self) -> Result<ClockReading, scap_raft_runtime::Error> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(ClockReading {
                instant: self.base + Duration::from_secs(if call >= self.expires { 60 } else { 0 }),
                unix_seconds: 1,
            })
        }
    }
    // The client's controlled clock permits each I/O. This independent policy
    // clock advances at the intervening recovery checkpoint, proving that work
    // outside the port cannot silently start a fresh timeout budget.
    for expires in [2, 4] {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        let clock = Arc::new(CheckpointClock {
            base: kit.clock.base,
            calls: AtomicUsize::new(0),
            expires,
        });
        let result = Writer::<Port, TestEngine>::recover_with(
            kit.client(),
            &kit.context,
            kit.request,
            Path::new("unused-unit-path"),
            limits(),
            clock,
            factory,
        );
        assert!(matches!(result, Err(Error::Unknown)));
        assert_eq!(effect.borrow().dropped, usize::from(expires == 4));
        assert_eq!(
            kit.port.0.borrow().proposals,
            if expires == 4 { 2 } else { 1 }
        );
    }
}

#[test]
fn failed_or_historical_execution_stops_the_writer_and_late_completion_keeps_its_receipt() {
    for case in 0..6 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        let mut writer = kit.recover(factory, limits()).unwrap();
        match case {
            0 => effect.borrow_mut().fail_execute = true,
            1 => effect.borrow_mut().replay = true,
            2 => effect.borrow_mut().expire_execute = true,
            3 => effect.borrow_mut().engine_stopped = true,
            4 => kit.context.cancelled.store(true, Ordering::Release),
            _ => (),
        }
        let result = writer.execute(kit.context.clone(), if case == 5 { 0 } else { 55 }, &[]);
        match case {
            0 => assert!(matches!(
                result,
                Err(Error::Native(scap_sqlite::Error::OutcomeUnknown))
            )),
            1 => assert!(result.unwrap().replayed),
            2 => {
                let Err(Error::Native(scap_sqlite::Error::CommittedButUnavailable { receipt })) =
                    result
                else {
                    panic!("lost committed receipt");
                };
                assert_eq!(receipt.ticket.request_id, 55);
                assert_eq!(receipt.sequence, 1);
            }
            3 => assert!(matches!(result, Err(Error::Stopped))),
            4 => assert!(matches!(result, Err(Error::Unknown))),
            _ => assert!(matches!(result, Err(Error::Invalid))),
        }
        assert!(writer.is_stopped());
        assert!(matches!(
            writer.execute(kit.context.clone(), 56, &[]),
            Err(Error::Stopped)
        ));
    }
}

#[test]
fn a_live_invocation_cannot_be_replaced_by_another_request() {
    let kit = Kit::new();
    let mut writer = kit.recover(kit.factory(), limits()).unwrap();
    let held = writer
        .gate
        .begin(
            kit.context.clone(),
            CommitTicket {
                cell_id: identity().cell.cell_id,
                cell_incarnation: identity().cell.cell_incarnation,
                database_id: identity().database.database_id,
                incarnation: identity().database.incarnation,
                placement_generation: identity().database.placement_generation,
                owner_epoch: 1,
                worker_instance_id: 77,
                auth_epoch: 1,
                request_id: 54,
                predecessor: 0,
                payload_digest: [0; 32],
            },
        )
        .unwrap();
    assert!(matches!(
        writer.execute(kit.context.clone(), 55, &[]),
        Err(Error::Client(scap_cell_client::Error::Busy))
    ));
    drop(held);
    assert!(writer.is_stopped());
}

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "scap-worker-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

#[test]
fn native_factory_and_engine_delegates_use_the_actual_sqlite_gate() {
    let kit = Kit::new();
    let directory = Directory::new();
    let mut writer = Writer::recover(
        kit.client(),
        &kit.context,
        kit.request,
        &directory.0,
        limits(),
        kit.clock.clone(),
    )
    .unwrap();
    assert_eq!(writer.head().revision, 0);
    let completed = writer
        .execute(
            kit.context.clone(),
            55,
            &[Statement {
                sql: "SELECT 42".into(),
                parameters: vec![],
            }],
        )
        .unwrap();
    assert_eq!(
        completed.result.statements[0].rows,
        vec![vec![Value::Integer(42)]]
    );
    assert_eq!(writer.head().revision, 1);
    assert!(!writer.is_stopped());
    assert_eq!(
        kit.port
            .0
            .borrow()
            .state
            .database(identity().database.database_id)
            .unwrap()
            .revision,
        1
    );
    drop(writer);
    let kit = Kit::new();
    assert!(matches!(
        Writer::recover(
            kit.client(),
            &kit.context,
            kit.request,
            &directory.0,
            limits(),
            kit.clock.clone()
        ),
        Err(Error::Native(_))
    ));
    assert!(
        !kit.port
            .0
            .borrow()
            .state
            .database(identity().database.database_id)
            .unwrap()
            .active
    );
}
