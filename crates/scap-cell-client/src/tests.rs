use super::*;
use raft::eraftpb::Entry;
use scap_cell::{AdminResult, CellApplication, Grant, ADMIN, READ, WRITE};
use scap_core::CommitReceipt;
use scap_raft_driver::{Application, ProposalTicket, ReadBarrier, ReadTicket};
use scap_raft_runtime::{ClockReading, Error as RuntimeError};
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;
use std::time::Duration;

const FINGERPRINT: [u8; 32] = [9; 32];
const ORIGINAL_RESULT: &[u8] = b"original RETURNING result";

fn cell() -> CellIdentity {
    CellIdentity {
        cell_id: 20,
        cell_incarnation: 30,
    }
}

pub(super) fn identity() -> Identity {
    Identity {
        cluster_id: 10,
        cell_id: cell().cell_id,
        cell_incarnation: cell().cell_incarnation,
        node_id: 1,
    }
}

fn db() -> DatabaseIdentity {
    DatabaseIdentity {
        database_id: 40,
        incarnation: 50,
        placement_generation: 60,
    }
}

fn limits() -> Limits {
    Limits {
        max_state_bytes: 65536,
        max_command_bytes: 8192,
        max_databases: 4,
        max_policy_grants: 8,
        max_admin_operations: 32,
        max_requests_per_database: 16,
        max_transaction_bytes: 4096,
        max_result_bytes: 4096,
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

fn policy() -> Vec<Grant> {
    vec![
        Grant {
            principal_id: 11,
            permissions: READ | WRITE | ADMIN,
        },
        Grant {
            principal_id: 22,
            permissions: READ,
        },
        Grant {
            principal_id: 33,
            permissions: WRITE,
        },
        Grant {
            principal_id: 44,
            permissions: READ | WRITE,
        },
    ]
}

fn ticket() -> CommitTicket {
    CommitTicket {
        cell_id: cell().cell_id,
        cell_incarnation: cell().cell_incarnation,
        database_id: db().database_id,
        incarnation: db().incarnation,
        placement_generation: db().placement_generation,
        owner_epoch: 1,
        worker_instance_id: 77,
        auth_epoch: 1,
        request_id: 88,
        predecessor: 0,
        payload_digest: [0; 32],
    }
}

fn write() -> PreparedWrite {
    let physical_changes = b"opaque exact native pages".to_vec();
    PreparedWrite {
        ticket: CommitTicket {
            payload_digest: scap_cell::payload_digest(&physical_changes),
            ..ticket()
        },
        physical_changes,
    }
}

fn command(kind: CommandKind) -> Command {
    Command {
        cell: cell(),
        database: db(),
        admission: admission(),
        kind,
    }
}

fn bootstrap() -> CellState {
    CellState::bootstrap(cell(), 11, Position { term: 1, index: 1 }, limits()).unwrap()
}

fn apply_bytes(state: &mut CellState, data: Vec<u8>) -> AppliedOutcome {
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
    let batch = CellApplication::new(cell(), limits())
        .unwrap()
        .apply_with_results(&state.encode(), &[entry], &[position.index])
        .unwrap();
    *state = CellState::decode_bound(&batch.state, cell(), position, limits()).unwrap();
    scap_cell::decode_applied_outcome(&batch.results[0], position).unwrap()
}

fn apply(state: &mut CellState, kind: CommandKind) -> AppliedOutcome {
    apply_bytes(
        state,
        scap_cell::encode_command(&command(kind), limits()).unwrap(),
    )
}

fn activate(token: OwnerToken, revision: u64, hash: [u8; 32], operation_id: u128) -> CommandKind {
    CommandKind::ActivateOwner {
        operation_id,
        token,
        restored_revision: revision,
        restored_hash: hash,
    }
}

fn active() -> CellState {
    let mut state = bootstrap();
    for kind in [
        CommandKind::Create {
            operation_id: 1,
            policy: policy(),
        },
        CommandKind::ClaimOwner {
            operation_id: 2,
            expected_epoch: 0,
            worker_instance_id: 77,
        },
        activate(owner(&ticket()), 0, [0; 32], 3),
    ] {
        assert!(matches!(
            apply(&mut state, kind).outcome,
            Outcome::Administrative(_)
        ));
    }
    state
}

fn commit(state: &mut CellState) -> CommitResult {
    let applied = apply(
        state,
        CommandKind::Commit {
            write: write(),
            request_fingerprint: FINGERPRINT,
            result: ORIGINAL_RESULT.to_vec(),
        },
    );
    let Outcome::Accepted(commit) = applied.outcome else {
        panic!("fixture commit was rejected");
    };
    commit
}

fn view(state: &CellState) -> ReadView {
    let position = state.position();
    ReadView {
        identity: identity(),
        term: position.term,
        index: position.index,
        barrier: ReadBarrier {
            ticket: ReadTicket {
                boot_id: 90,
                sequence: 1,
            },
            index: position.index,
        },
        application: state.encode(),
    }
}

fn reply(applied: AppliedOutcome) -> ProposalResult {
    ProposalResult {
        ticket: ProposalTicket {
            boot_id: 90,
            sequence: 1,
        },
        index: applied.position.index,
        term: applied.position.term,
        data: scap_cell::encode_applied_outcome(&applied),
    }
}

fn outcome(outcome: Outcome) -> ProposalResult {
    reply(AppliedOutcome {
        position: Position { term: 1, index: 5 },
        outcome,
    })
}

struct TestClock {
    instant: Mutex<Instant>,
    fail: AtomicBool,
    calls: AtomicUsize,
    expire_on_call: AtomicUsize,
}

impl TestClock {
    fn new() -> Self {
        Self {
            instant: Mutex::new(Instant::now()),
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            expire_on_call: AtomicUsize::new(0),
        }
    }
    fn expire(&self) {
        *self.instant.lock().unwrap() += Duration::from_secs(60);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Result<ClockReading, RuntimeError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.expire_on_call.load(Ordering::Acquire) {
            self.expire();
        }
        if self.fail.load(Ordering::Acquire) {
            return Err(RuntimeError::Clock);
        }
        Ok(ClockReading {
            instant: *self.instant.lock().unwrap(),
            unix_seconds: 100,
        })
    }
}

struct PortState {
    identity: Identity,
    state: CellState,
    reads: VecDeque<Result<ReadView, RuntimeError>>,
    proposals: VecDeque<Result<ProposalResult, RuntimeError>>,
    read_calls: usize,
    sent: Vec<Vec<u8>>,
    deadlines: Vec<Instant>,
    cancel_pointers: Vec<usize>,
    after_read: Option<Box<dyn FnOnce()>>,
    after_proposal: Option<Box<dyn FnOnce()>>,
}

#[derive(Clone)]
struct Port(Rc<RefCell<PortState>>);

impl Port {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(PortState {
            identity: identity(),
            state: active(),
            reads: VecDeque::new(),
            proposals: VecDeque::new(),
            read_calls: 0,
            sent: Vec::new(),
            deadlines: Vec::new(),
            cancel_pointers: Vec::new(),
            after_read: None,
            after_proposal: None,
        })))
    }
}

impl CellPort for Port {
    fn identity(&self) -> Identity {
        self.0.borrow().identity.clone()
    }
    fn read(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ReadView, RuntimeError> {
        let (result, hook) = {
            let mut state = self.0.borrow_mut();
            state.read_calls += 1;
            state.deadlines.push(deadline);
            state
                .cancel_pointers
                .push(cancelled as *const AtomicBool as usize);
            let result = state
                .reads
                .pop_front()
                .unwrap_or_else(|| Ok(view(&state.state)));
            (result, state.after_read.take())
        };
        if let Some(hook) = hook {
            hook();
        }
        result
    }
    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ProposalResult, RuntimeError> {
        let (result, hook) = {
            let mut state = self.0.borrow_mut();
            state.deadlines.push(deadline);
            state
                .cancel_pointers
                .push(cancelled as *const AtomicBool as usize);
            state.sent.push(data.clone());
            let result = state
                .proposals
                .pop_front()
                .unwrap_or_else(|| Ok(reply(apply_bytes(&mut state.state, data))));
            (result, state.after_proposal.take())
        };
        if let Some(hook) = hook {
            hook();
        }
        result
    }
}

fn build() -> (Client<Port>, Port, Arc<TestClock>, RequestContext) {
    let port = Port::new();
    let clock = Arc::new(TestClock::new());
    let context = RequestContext {
        admission: admission(),
        deadline: clock.now().unwrap().instant + Duration::from_secs(20),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let client = Client::new(10, cell(), limits(), port.clone(), clock.clone()).unwrap();
    (client, port, clock, context)
}

fn cancel_command() -> CommandKind {
    CommandKind::ResolveOrCancel {
        request_id: 88,
        request_fingerprint: FINGERPRINT,
    }
}

fn prepared_gate() -> (
    Gate<Port>,
    Invocation<Port>,
    Port,
    Arc<TestClock>,
    RequestContext,
) {
    let (client, port, clock, context) = build();
    let mut gate = Gate::new(client);
    let invocation = gate.begin(context.clone(), ticket()).unwrap();
    assert!(matches!(
        gate.lookup(&ticket(), FINGERPRINT),
        LookupDecision::NotFound
    ));
    (gate, invocation, port, clock, context)
}

#[test]
fn constructor_and_every_call_bind_the_fixed_replica_scope() {
    let (client, port, clock, context) = build();
    let cases: Vec<(u128, CellIdentity, Identity)> = vec![
        (0, cell(), identity()),
        (
            10,
            CellIdentity {
                cell_id: 0,
                ..cell()
            },
            identity(),
        ),
        (
            10,
            CellIdentity {
                cell_incarnation: 0,
                ..cell()
            },
            identity(),
        ),
        (
            10,
            cell(),
            Identity {
                node_id: 0,
                ..identity()
            },
        ),
        (12, cell(), identity()),
        (
            10,
            CellIdentity {
                cell_id: 12,
                ..cell()
            },
            identity(),
        ),
        (
            10,
            CellIdentity {
                cell_incarnation: 12,
                ..cell()
            },
            identity(),
        ),
    ];
    for (cluster, cell, identity) in cases {
        port.0.borrow_mut().identity = identity;
        assert!(matches!(
            Client::new(cluster, cell, limits(), port.clone(), clock.clone()),
            Err(Error::InvalidContext)
        ));
    }
    port.0.borrow_mut().identity = identity();
    let mut clone = client.clone();
    assert_eq!(clone.read(&context).unwrap().identity(), cell());
    port.0.borrow_mut().identity.node_id = 2;
    assert!(matches!(clone.read(&context), Err(Error::Unknown)));
    assert!(matches!(
        clone.submit(&context, db(), cancel_command()),
        Err(Error::Unknown)
    ));
    assert!(port.0.borrow().sent.is_empty());
    assert_eq!(Error::InvalidContext.to_string(), "InvalidContext");
    let error: &dyn std::error::Error = &Error::Unknown;
    assert_eq!(error.to_string(), "Unknown");
}

#[test]
fn safe_reads_reject_wrong_barriers_scope_positions_and_images() {
    let (mut client, port, _, context) = build();
    let mut variants = Vec::new();
    let good = view(&port.0.borrow().state);
    for field in 0..11 {
        let mut bad = good.clone();
        match field {
            0 => bad.identity.cluster_id += 1,
            1 => bad.term = 0,
            2 => bad.index = 0,
            3 => bad.barrier.ticket.boot_id = 0,
            4 => bad.barrier.ticket.sequence = 0,
            5 => bad.barrier.index = 0,
            6 => bad.barrier.index = bad.index + 1,
            7 => bad.application.clear(),
            8 => bad.term += 1,
            9 => bad.index += 1,
            _ => bad.identity.node_id += 1,
        }
        variants.push(Ok(bad));
    }
    variants.push(Err(RuntimeError::ReadNotReady));
    port.0.borrow_mut().reads.extend(variants);
    for _ in 0..12 {
        assert!(matches!(client.read(&context), Err(Error::Unknown)));
    }
    let state = client.read(&context).unwrap();
    assert_eq!(
        state.position(),
        Position {
            term: good.term,
            index: good.index
        }
    );
}

#[test]
fn original_deadline_cancellation_and_clock_errors_cover_read_and_submit() {
    let (mut client, port, clock, context) = build();
    clock.fail.store(true, Ordering::Release);
    assert!(matches!(client.read(&context), Err(Error::Unknown)));
    clock.fail.store(false, Ordering::Release);
    context.cancelled.store(true, Ordering::Release);
    assert!(matches!(client.read(&context), Err(Error::Unknown)));
    context.cancelled.store(false, Ordering::Release);
    let cancelled = context.cancelled.clone();
    port.0.borrow_mut().after_read =
        Some(Box::new(move || cancelled.store(true, Ordering::Release)));
    assert!(matches!(client.read(&context), Err(Error::Unknown)));
    context.cancelled.store(false, Ordering::Release);
    let timer = clock.clone();
    port.0.borrow_mut().after_proposal = Some(Box::new(move || timer.expire()));
    assert!(matches!(
        client.submit(&context, db(), cancel_command()),
        Err(Error::Unknown)
    ));
    assert!(matches!(client.read(&context), Err(Error::Unknown)));
    let held = port.0.borrow();
    assert_eq!(held.read_calls, 1);
    assert_eq!(held.sent.len(), 1);
    assert!(held
        .deadlines
        .iter()
        .all(|deadline| deadline == &context.deadline));
    assert!(held
        .cancel_pointers
        .iter()
        .all(|pointer| *pointer == Arc::as_ptr(&context.cancelled) as usize));
}

#[test]
fn administrative_calls_use_the_actual_context_and_exact_versioned_result() {
    let (mut client, port, _, context) = build();
    let applied = client.submit(&context, db(), cancel_command()).unwrap();
    assert_eq!(applied.outcome, Outcome::Cancelled);
    assert_eq!(
        port.0.borrow().sent[0],
        scap_cell::encode_command(&command(cancel_command()), limits()).unwrap()
    );
    let mut variants = Vec::new();
    let valid = outcome(Outcome::Cancelled);
    for field in 0..7 {
        let mut bad = valid.clone();
        match field {
            0 => bad.ticket.boot_id = 0,
            1 => bad.ticket.sequence = 0,
            2 => bad.data.clear(),
            3 => bad.index += 1,
            4 => bad.term += 1,
            5 => bad.index = 0,
            _ => bad.term = 0,
        }
        variants.push(Ok(bad));
    }
    variants.push(Err(RuntimeError::Unknown));
    port.0.borrow_mut().proposals.extend(variants);
    for _ in 0..8 {
        assert_eq!(
            client.submit(&context, db(), cancel_command()),
            Err(Error::Unknown)
        );
    }
    client.limits.max_command_bytes = 1;
    assert_eq!(
        client.submit(&context, db(), cancel_command()),
        Err(Error::InvalidContext)
    );
}

#[test]
fn deadline_expiring_during_command_encoding_does_not_admit_a_late_proposal() {
    let (mut client, port, clock, context) = build();
    // Model bounded serialization consuming the remainder of the original
    // budget: the next clock observation succeeds and the following expires.
    clock
        .expire_on_call
        .store(clock.calls.load(Ordering::Acquire) + 2, Ordering::Release);
    assert_eq!(
        client.submit(&context, db(), cancel_command()),
        Err(Error::Unknown)
    );
    assert!(port.0.borrow().sent.is_empty());
}

#[test]
fn invocation_is_single_use_bound_and_cleared_on_drop() {
    let (client, port, clock, context) = build();
    let gate = Gate::new(client);
    let mut writer_gate = gate.clone();
    assert!(matches!(
        writer_gate.lookup(&ticket(), FINGERPRINT),
        LookupDecision::Unknown
    ));
    assert!(matches!(
        writer_gate.propose(&write(), FINGERPRINT, b"new"),
        GateDecision::Unknown
    ));
    for field in 0..4 {
        let mut invalid = ticket();
        match field {
            0 => invalid.cell_id += 1,
            1 => invalid.cell_incarnation += 1,
            2 => invalid.auth_epoch += 1,
            _ => invalid.payload_digest = [1; 32],
        }
        assert!(matches!(
            gate.begin(context.clone(), invalid),
            Err(Error::InvalidContext)
        ));
    }
    clock.fail.store(true, Ordering::Release);
    assert!(matches!(
        gate.begin(context.clone(), ticket()),
        Err(Error::Unknown)
    ));
    clock.fail.store(false, Ordering::Release);
    let guard = gate.begin(context.clone(), ticket()).unwrap();
    assert!(matches!(
        gate.begin(context.clone(), ticket()),
        Err(Error::Busy)
    ));
    assert!(matches!(
        writer_gate.lookup(&ticket(), FINGERPRINT),
        LookupDecision::NotFound
    ));
    drop(guard);
    assert!(matches!(
        writer_gate.propose(&write(), FINGERPRINT, b"new"),
        GateDecision::Unknown
    ));
    let mut other = context.clone();
    other.admission.principal_id = 22;
    let _second = gate.begin(other, ticket()).unwrap();
    assert!(matches!(
        writer_gate.lookup(&ticket(), FINGERPRINT),
        LookupDecision::Rejected(Rejection::Unauthorized)
    ));
    assert!(port.0.borrow().sent.is_empty());
}

#[test]
fn preflight_requires_read_write_owner_identity_and_exact_current_revision() {
    for case in 0..11 {
        let (client, port, _, mut context) = build();
        let mut request = ticket();
        let expected = match case {
            0 => {
                context.admission.principal_id = 22;
                Rejection::Unauthorized
            }
            1 => {
                context.admission.principal_id = 33;
                Rejection::Unauthorized
            }
            2 => {
                context.admission.credential_id = 0;
                Rejection::Unauthorized
            }
            3 => {
                context.admission.auth_epoch = 2;
                request.auth_epoch = 2;
                Rejection::Unauthorized
            }
            4 => {
                request.owner_epoch += 1;
                Rejection::Fenced
            }
            5 => {
                request.worker_instance_id += 1;
                Rejection::Fenced
            }
            6 => {
                request.predecessor += 1;
                Rejection::Conflict
            }
            7 => {
                request.incarnation += 1;
                Rejection::Fenced
            }
            8 => {
                request.placement_generation += 1;
                Rejection::Fenced
            }
            9 => {
                request.database_id += 1;
                Rejection::Fenced
            }
            _ => {
                apply(
                    &mut port.0.borrow_mut().state,
                    CommandKind::ClaimOwner {
                        operation_id: 4,
                        expected_epoch: 1,
                        worker_instance_id: 78,
                    },
                );
                Rejection::Fenced
            }
        };
        let mut gate = Gate::new(client);
        let _guard = gate.begin(context, request.clone()).unwrap();
        assert!(
            matches!(gate.lookup(&request, FINGERPRINT), LookupDecision::Rejected(actual) if actual == expected)
        );
        assert!(port.0.borrow().sent.is_empty());
    }
}

#[test]
fn preflight_returns_original_receipt_after_owner_recovery_and_never_reexecutes() {
    let (client, port, _, context) = build();
    let original = commit(&mut port.0.borrow_mut().state);
    let current = {
        let mut held = port.0.borrow_mut();
        apply(
            &mut held.state,
            CommandKind::ClaimOwner {
                operation_id: 4,
                expected_epoch: 1,
                worker_instance_id: 78,
            },
        );
        let current = held.state.database(db().database_id).unwrap();
        apply(
            &mut held.state,
            activate(current.owner, current.revision, current.commit_hash, 5),
        );
        current
    };
    let request = CommitTicket {
        owner_epoch: current.owner.epoch,
        worker_instance_id: current.owner.worker_instance_id,
        predecessor: current.revision,
        ..ticket()
    };
    let mut gate = Gate::new(client);
    let _guard = gate.begin(context, request.clone()).unwrap();
    let LookupDecision::AlreadyCommitted { receipt, result } = gate.lookup(&request, FINGERPRINT)
    else {
        panic!("expected historical completion");
    };
    assert_eq!(receipt, original.receipt);
    assert_ne!(receipt.ticket.owner_epoch, request.owner_epoch);
    assert_eq!(result, ORIGINAL_RESULT);
    assert!(matches!(
        gate.propose(&write(), FINGERPRINT, b"replacement"),
        GateDecision::Unknown
    ));
    assert!(port.0.borrow().sent.is_empty());
}

#[test]
fn lookup_conflicts_cancellations_and_unavailable_reads_stop_before_sql() {
    for case in 0..4 {
        let (client, port, _, mut context) = build();
        let mut request = ticket();
        let fingerprint = if case == 0 { [1; 32] } else { FINGERPRINT };
        match case {
            0 => {
                commit(&mut port.0.borrow_mut().state);
                request.predecessor = 1;
            }
            1 => {
                commit(&mut port.0.borrow_mut().state);
                request.predecessor = 1;
                context.admission.principal_id = 44;
            }
            2 => {
                apply(&mut port.0.borrow_mut().state, cancel_command());
            }
            _ => {
                port.0
                    .borrow_mut()
                    .reads
                    .push_back(Err(RuntimeError::NotLeader));
            }
        }
        let mut gate = Gate::new(client);
        let _guard = gate.begin(context, request.clone()).unwrap();
        let result = gate.lookup(&request, fingerprint);
        match case {
            0 | 2 => assert!(matches!(
                result,
                LookupDecision::Rejected(Rejection::Conflict)
            )),
            1 => assert!(matches!(
                result,
                LookupDecision::Rejected(Rejection::Unauthorized)
            )),
            _ => assert!(matches!(result, LookupDecision::Unknown)),
        }
        assert!(port.0.borrow().sent.is_empty());
    }
}

#[test]
fn callback_order_ticket_and_fingerprint_are_bound_to_one_invocation() {
    for case in 0..5 {
        let (client, port, _, context) = build();
        let mut gate = Gate::new(client);
        let _guard = gate.begin(context, ticket()).unwrap();
        if case == 0 {
            assert!(matches!(
                gate.propose(&write(), FINGERPRINT, b"new"),
                GateDecision::Unknown
            ));
        } else if case == 1 {
            let mut wrong = ticket();
            wrong.request_id += 1;
            assert!(matches!(
                gate.lookup(&wrong, FINGERPRINT),
                LookupDecision::Unknown
            ));
        } else {
            assert!(matches!(
                gate.lookup(&ticket(), FINGERPRINT),
                LookupDecision::NotFound
            ));
            match case {
                2 => assert!(matches!(
                    gate.lookup(&ticket(), FINGERPRINT),
                    LookupDecision::Unknown
                )),
                3 => assert!(matches!(
                    gate.propose(&write(), [3; 32], b"new"),
                    GateDecision::Unknown
                )),
                _ => {
                    let mut wrong = write();
                    wrong.ticket.request_id += 1;
                    assert!(matches!(
                        gate.propose(&wrong, FINGERPRINT, b"new"),
                        GateDecision::Unknown
                    ));
                }
            }
        }
        assert!(matches!(
            gate.propose(&write(), FINGERPRINT, b"new"),
            GateDecision::Unknown
        ));
        assert!(port.0.borrow().sent.is_empty());
    }
}

#[test]
fn accepted_is_exactly_one_tracked_business_acceptance() {
    let (mut gate, _guard, port, _, context) = prepared_gate();
    let GateDecision::Accepted(receipt) = gate.propose(&write(), FINGERPRINT, ORIGINAL_RESULT)
    else {
        panic!("expected native publish authorization");
    };
    assert_eq!(
        receipt,
        CommitReceipt {
            ticket: write().ticket,
            sequence: 1
        }
    );
    assert_eq!(port.0.borrow().sent.len(), 1);
    assert!(port
        .0
        .borrow()
        .deadlines
        .iter()
        .all(|deadline| deadline == &context.deadline));
    assert!(matches!(
        gate.propose(&write(), FINGERPRINT, b"again"),
        GateDecision::Unknown
    ));
}

#[test]
fn wrong_or_unavailable_proposal_results_cannot_authorize_publication() {
    for case in 0..10 {
        let (mut gate, _guard, port, _, context) = prepared_gate();
        let expected = if case == 8 {
            gate.shared.borrow_mut().client.limits.max_command_bytes = 1;
            Rejection::InvalidTransaction
        } else {
            Rejection::Conflict
        };
        let mut commit = CommitResult {
            receipt: CommitReceipt {
                ticket: write().ticket,
                sequence: 1,
            },
            position: Position { term: 1, index: 5 },
        };
        let result = match case {
            0 => {
                commit.position.index += 1;
                Ok(outcome(Outcome::Accepted(commit)))
            }
            1 => {
                commit.receipt.ticket.request_id += 1;
                Ok(outcome(Outcome::Accepted(commit)))
            }
            2 => {
                commit.receipt.sequence += 1;
                Ok(outcome(Outcome::Accepted(commit)))
            }
            3 => Ok(outcome(Outcome::Cancelled)),
            4 => Ok(outcome(Outcome::Administrative(AdminResult::Created))),
            5 => Err(RuntimeError::Full),
            6 => {
                context.cancelled.store(true, Ordering::Release);
                Err(RuntimeError::Unknown)
            }
            7 => {
                let cancelled = context.cancelled.clone();
                port.0.borrow_mut().after_proposal =
                    Some(Box::new(move || cancelled.store(true, Ordering::Release)));
                Ok(outcome(Outcome::Accepted(commit)))
            }
            8 => Err(RuntimeError::Unknown),
            _ => Ok(outcome(Outcome::AlreadyApplied(AdminResult::Created))),
        };
        port.0.borrow_mut().proposals.push_back(result);
        let result = gate.propose(&write(), FINGERPRINT, b"new");
        if case == 8 {
            assert!(matches!(result, GateDecision::Rejected(actual) if actual == expected));
        } else {
            assert!(matches!(result, GateDecision::Unknown), "case {case}");
        }
    }
}

#[test]
fn all_definitive_rejections_are_preserved_as_their_public_error_class() {
    for (reject, expected) in [
        (Reject::Fenced, Rejection::Fenced),
        (Reject::NotFound, Rejection::Fenced),
        (Reject::Unauthorized, Rejection::Unauthorized),
        (Reject::Conflict, Rejection::Conflict),
        (Reject::Cancelled, Rejection::Conflict),
        (Reject::Exists, Rejection::Conflict),
        (Reject::Invalid, Rejection::InvalidTransaction),
        (Reject::TooLarge, Rejection::InvalidTransaction),
        (Reject::Capacity, Rejection::InvalidTransaction),
        (Reject::Exhausted, Rejection::InvalidTransaction),
    ] {
        let (mut gate, _guard, port, _, _) = prepared_gate();
        port.0
            .borrow_mut()
            .proposals
            .push_back(Ok(outcome(Outcome::Rejected(reject))));
        assert!(
            matches!(gate.propose(&write(), FINGERPRINT, b"new"), GateDecision::Rejected(actual) if actual == expected)
        );
    }
}

#[test]
fn duplicate_after_preflight_fetches_original_result_from_a_fresh_authorized_view() {
    let (mut gate, _guard, port, _, context) = prepared_gate();
    let original = commit(&mut port.0.borrow_mut().state);
    let mut different = write();
    different.physical_changes.push(1);
    different.ticket.payload_digest = scap_cell::payload_digest(&different.physical_changes);
    let GateDecision::AlreadyCommitted { receipt, result } =
        gate.propose(&different, FINGERPRINT, b"never replace stored result")
    else {
        panic!("expected the original committed result");
    };
    assert_eq!(receipt, original.receipt);
    assert_ne!(
        receipt.ticket.payload_digest,
        different.ticket.payload_digest
    );
    assert_eq!(result, ORIGINAL_RESULT);
    let held = port.0.borrow();
    assert_eq!(held.read_calls, 2);
    assert_eq!(held.sent.len(), 1);
    assert!(held
        .deadlines
        .iter()
        .all(|deadline| deadline == &context.deadline));
}

#[test]
fn duplicate_history_does_not_reveal_results_without_current_authorization_and_receipt_match() {
    for case in 0..8 {
        let (mut gate, _guard, port, _, _) = if case == 7 {
            let (client, port, clock, mut context) = build();
            context.admission.principal_id = 44;
            let mut gate = Gate::new(client);
            let guard = gate.begin(context.clone(), ticket()).unwrap();
            assert!(matches!(
                gate.lookup(&ticket(), FINGERPRINT),
                LookupDecision::NotFound
            ));
            (gate, guard, port, clock, context)
        } else {
            prepared_gate()
        };
        let mut original = commit(&mut port.0.borrow_mut().state);
        match case {
            0 => port.0.borrow_mut().state = bootstrap(),
            1 => {
                apply(
                    &mut port.0.borrow_mut().state,
                    CommandKind::ClaimOwner {
                        operation_id: 4,
                        expected_epoch: 1,
                        worker_instance_id: 78,
                    },
                );
            }
            2 => {
                apply(
                    &mut port.0.borrow_mut().state,
                    CommandKind::AuthFence {
                        operation_id: 4,
                        expected_epoch: 1,
                        policy: policy(),
                    },
                );
            }
            3 => port.0.borrow_mut().state = active(),
            4 => {
                port.0.borrow_mut().state = active();
                apply(&mut port.0.borrow_mut().state, cancel_command());
            }
            5 => original.receipt.sequence += 1,
            6 => port
                .0
                .borrow_mut()
                .reads
                .push_back(Err(RuntimeError::Closed)),
            _ => {}
        }
        port.0
            .borrow_mut()
            .proposals
            .push_back(Ok(outcome(Outcome::AlreadyCommitted(original))));
        assert!(
            matches!(
                gate.propose(&write(), FINGERPRINT, b"new"),
                GateDecision::Unknown
            ),
            "case {case}"
        );
    }
}
