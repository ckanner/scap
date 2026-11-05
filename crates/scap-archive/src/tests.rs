use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raft::eraftpb::Entry;
use scap_cell::{
    Admission, AppliedOutcome, CellApplication, CellIdentity, CellState, Command, Grant, Limits,
    OwnerToken, Position, ADMIN, READ, WRITE,
};
use scap_core::{CommitTicket, PreparedWrite};
use scap_raft_driver::{Application, ProposalResult, ProposalTicket, ReadBarrier, ReadTicket};
use scap_raft_runtime::{Error as RuntimeError, ReadView, SystemClock};

fn cell() -> CellIdentity {
    CellIdentity {
        cell_id: 20,
        cell_incarnation: 30,
    }
}
fn identity() -> Identity {
    Identity {
        cluster_id: 10,
        cell_id: 20,
        cell_incarnation: 30,
        node_id: 1,
    }
}
fn database() -> DatabaseIdentity {
    DatabaseIdentity {
        database_id: 40,
        incarnation: 50,
        placement_generation: 60,
    }
}
fn admission() -> Admission {
    Admission {
        principal_id: 11,
        credential_id: 12,
        admission_id: 13,
        request_epoch: 1,
        auth_epoch: 1,
    }
}
fn limits() -> Limits {
    Limits {
        max_state_bytes: 65536,
        max_command_bytes: 8192,
        max_databases: 4,
        max_policy_grants: 8,
        max_admin_operations: 64,
        max_requests_per_database: 16,
        max_transaction_bytes: 4096,
        max_result_bytes: 4096,
    }
}
pub(super) fn context() -> RequestContext {
    RequestContext {
        admission: admission(),
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

fn apply(state: &mut CellState, data: Vec<u8>) -> AppliedOutcome {
    apply_with_limits(state, data, limits())
}
fn apply_with_limits(state: &mut CellState, data: Vec<u8>, limits: Limits) -> AppliedOutcome {
    let result = apply_raw(state, data, limits);
    scap_cell::decode_applied_outcome(
        &result.data,
        Position {
            term: result.term,
            index: result.index,
        },
    )
    .unwrap()
}
fn apply_raw(state: &mut CellState, data: Vec<u8>, limits: Limits) -> ProposalResult {
    let cell = state.identity();
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
    let batch = CellApplication::new(cell, limits)
        .unwrap()
        .apply_with_results(&state.encode(), &[entry], &[position.index])
        .unwrap();
    *state = CellState::decode_bound(&batch.state, cell, position, limits).unwrap();
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
fn apply_kind(state: &mut CellState, kind: CommandKind) {
    let administrative = matches!(
        kind,
        CommandKind::Create { .. }
            | CommandKind::ClaimOwner { .. }
            | CommandKind::ActivateOwner { .. }
            | CommandKind::AuthFence { .. }
            | CommandKind::SuspendDb { .. }
            | CommandKind::PublishArchive { .. }
            | CommandKind::PruneArchive { .. }
            | CommandKind::HydrateArchive { .. }
    );
    let control_revision = if state.control_enabled() && administrative {
        Some(
            state
                .database(database().database_id)
                .map_or(0, |view| view.control_revision.unwrap()),
        )
    } else {
        None
    };
    let command = Command {
        cell: cell(),
        database: database(),
        admission: admission(),
        control_revision,
        kind,
    };
    apply(
        state,
        scap_cell::encode_command(&command, limits()).unwrap(),
    );
}
fn active() -> CellState {
    let mut state =
        CellState::bootstrap(cell(), 11, Position { term: 1, index: 1 }, limits()).unwrap();
    for kind in [
        CommandKind::Create {
            operation_id: 1,
            policy: vec![Grant {
                principal_id: 11,
                permissions: READ | WRITE | ADMIN,
            }],
        },
        CommandKind::ClaimOwner {
            operation_id: 2,
            expected_epoch: 0,
            worker_instance_id: 77,
        },
        CommandKind::ActivateOwner {
            operation_id: 3,
            token: OwnerToken {
                epoch: 1,
                worker_instance_id: 77,
            },
            restored_revision: 0,
            restored_hash: [0; 32],
        },
    ] {
        apply_kind(&mut state, kind);
    }
    state
}
fn initial() -> CellState {
    let mut state = active();
    let bytes = vec![9; 1024];
    apply_kind(
        &mut state,
        CommandKind::Commit {
            write: PreparedWrite {
                ticket: CommitTicket {
                    cell_id: 20,
                    cell_incarnation: 30,
                    database_id: 40,
                    incarnation: 50,
                    placement_generation: 60,
                    owner_epoch: 1,
                    worker_instance_id: 77,
                    auth_epoch: 1,
                    request_id: 88,
                    predecessor: 0,
                    payload_digest: scap_cell::payload_digest(&bytes),
                },
                physical_changes: bytes,
            },
            request_fingerprint: [7; 32],
            result: b"original result".to_vec(),
        },
    );
    state
}
struct Cell {
    state: CellState,
    identity: Identity,
    limits: Limits,
    read_fail: bool,
    propose_fail: bool,
    unknown_after_apply: bool,
    outcome: Option<Outcome>,
    proposals: usize,
    before_propose: Option<fn(&mut CellState)>,
}
#[derive(Clone)]
struct Port(Rc<RefCell<Cell>>);
impl CellPort for Port {
    fn identity(&self) -> Identity {
        self.0.borrow().identity.clone()
    }
    fn read(&mut self, _: Instant, _: &AtomicBool) -> Result<ReadView, RuntimeError> {
        let cell = self.0.borrow();
        if cell.read_fail {
            return Err(RuntimeError::Unknown);
        }
        let pos = cell.state.position();
        Ok(ReadView {
            identity: cell.identity.clone(),
            term: pos.term,
            index: pos.index,
            application: cell.state.encode(),
            barrier: ReadBarrier {
                ticket: ReadTicket {
                    boot_id: 1,
                    sequence: 1,
                },
                index: pos.index,
            },
        })
    }
    fn propose(
        &mut self,
        data: Vec<u8>,
        _: Instant,
        _: &AtomicBool,
    ) -> Result<ProposalResult, RuntimeError> {
        let mut cell = self.0.borrow_mut();
        cell.proposals += 1;
        if cell.propose_fail {
            return Err(RuntimeError::Unknown);
        }
        if let Some(change) = cell.before_propose.take() {
            change(&mut cell.state);
        }
        let limits = cell.limits;
        let mut result = apply_raw(&mut cell.state, data, limits);
        if cell.unknown_after_apply {
            return Err(RuntimeError::Unknown);
        }
        if let Some(outcome) = cell.outcome.take() {
            result.data = scap_cell::encode_applied_outcome(&AppliedOutcome {
                position: Position {
                    term: result.term,
                    index: result.index,
                },
                outcome,
            });
        }
        result.ticket.sequence = cell.proposals as u64;
        Ok(result)
    }
}
#[derive(Default)]
struct Memory {
    objects: BTreeMap<String, Vec<u8>>,
    put_fail: bool,
    get_fail: bool,
    corrupt: bool,
    truncate: bool,
    cancel: bool,
}
#[derive(Clone)]
struct Store(Rc<RefCell<Memory>>);
impl Objects for Store {
    fn put(&mut self, key: &str, bytes: &[u8], _: &RequestContext) -> Result<(), Error> {
        let mut memory = self.0.borrow_mut();
        if memory.put_fail {
            return Err(Error::Object);
        }
        memory
            .objects
            .entry(key.into())
            .or_insert_with(|| bytes.to_vec());
        Ok(())
    }
    fn get(&mut self, key: &str, _: u32, context: &RequestContext) -> Result<Vec<u8>, Error> {
        let memory = self.0.borrow();
        if memory.get_fail {
            return Err(Error::Object);
        }
        let mut bytes = memory.objects.get(key).ok_or(Error::Object)?.clone();
        if memory.corrupt {
            bytes[0] ^= 1;
        }
        if memory.truncate {
            bytes.pop();
        }
        if memory.cancel {
            context.cancelled.store(true, Ordering::Release);
        }
        Ok(bytes)
    }
}
fn build() -> (Controller<Port, Store>, Port, Store, RequestContext) {
    build_with(initial(), identity(), limits(), context())
}
fn build_with(
    state: CellState,
    identity: Identity,
    limits: Limits,
    context: RequestContext,
) -> (Controller<Port, Store>, Port, Store, RequestContext) {
    let cell = state.identity();
    let cluster = identity.cluster_id;
    let port = Port(Rc::new(RefCell::new(Cell {
        state,
        identity,
        limits,
        read_fail: false,
        propose_fail: false,
        unknown_after_apply: false,
        outcome: None,
        proposals: 0,
        before_propose: None,
    })));
    let objects = Store(Rc::new(RefCell::new(Memory::default())));
    let client = Client::new(cluster, cell, limits, port.clone(), Arc::new(SystemClock)).unwrap();
    (
        Controller::new(client, objects.clone()),
        port,
        objects,
        context,
    )
}

#[test]
fn full_cold_lifecycle_keeps_results_and_requires_published_object() {
    let (mut controller, port, store, context) = build();
    assert_eq!(
        controller.publish(&context, database(), 4),
        Err(Error::Rejected(Reject::Fenced))
    );
    assert_eq!(
        controller.prune(&context, database(), 4),
        Err(Error::Rejected(Reject::NotFound))
    );
    controller.hydrate(&context, database(), 4).unwrap();
    controller.suspend(&context, database(), 4).unwrap();
    controller.suspend(&context, database(), 5).unwrap();
    let archive = controller.publish(&context, database(), 6).unwrap();
    assert_eq!(store.0.borrow().objects.len(), 1);
    let key = object_key(identity(), database(), archive.object_digest);
    assert!(key.starts_with("scap/v1/0000000000000000000000000000000a/"));
    controller.prune(&context, database(), 7).unwrap();
    assert!(port.0.borrow().state.database(40).unwrap().cold);
    assert!(
        matches!(port.0.borrow().state.lookup(database(), admission(), 88, [7; 32]).unwrap(), scap_cell::Lookup::Committed { result, .. } if result == b"original result")
    );
    controller.hydrate(&context, database(), 8).unwrap();
    assert!(!port.0.borrow().state.database(40).unwrap().cold);
    assert_eq!(
        port.0
            .borrow()
            .state
            .recovery_source(database(), admission())
            .unwrap()
            .tail[0]
            .physical_changes,
        vec![9; 1024]
    );
    assert_eq!(store.0.borrow().objects.len(), 1);
}

fn fixture_bytes(text: &str) -> Vec<u8> {
    let hex: String = text.split_whitespace().collect();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}

fn apply_as(
    state: &mut CellState,
    database: DatabaseIdentity,
    admission: Admission,
    kind: CommandKind,
    limits: Limits,
) -> AppliedOutcome {
    let command = Command {
        cell: state.identity(),
        database,
        admission,
        control_revision: None,
        kind,
    };
    apply_with_limits(
        state,
        scap_cell::encode_command(&command, limits).unwrap(),
        limits,
    )
}

#[test]
fn genuine_v2_hot_and_cold_archives_preserve_results_and_new_fences_during_upgrade() {
    let cell = CellIdentity {
        cell_id: 7,
        cell_incarnation: 8,
    };
    let database = DatabaseIdentity {
        database_id: 9,
        incarnation: 10,
        placement_generation: 11,
    };
    let limits = Limits {
        max_state_bytes: 65536,
        max_command_bytes: 16384,
        max_databases: 4,
        max_policy_grants: 4,
        max_admin_operations: 64,
        max_requests_per_database: 16,
        max_transaction_bytes: 8192,
        max_result_bytes: 1024,
    };
    let identity = Identity {
        cluster_id: 10,
        cell_id: cell.cell_id,
        cell_incarnation: cell.cell_incarnation,
        node_id: 1,
    };
    let bytes = fixture_bytes(include_str!("../../scap-cell/test-fixtures/archive-v2.hex"));
    let image = fixture_bytes(include_str!("../../scap-cell/test-fixtures/image.hex"));
    for (cold, fixture, index) in [
        (
            false,
            include_str!("../../scap-cell/test-fixtures/hot-v2.hex"),
            9,
        ),
        (
            true,
            include_str!("../../scap-cell/test-fixtures/cold-v2.hex"),
            10,
        ),
    ] {
        let mut context = context();
        context.admission = Admission {
            principal_id: 12,
            credential_id: 13,
            admission_id: 14,
            request_epoch: 1,
            auth_epoch: 1,
        };
        let source = fixture_bytes(fixture);
        assert_eq!(source[8], 2);
        assert_eq!(bytes[8], 2);
        let state =
            CellState::decode_bound(&source, cell, Position { term: 1, index }, limits).unwrap();
        assert_eq!(state.physical_history_version(), 2);
        assert_eq!(state.encode(), source);
        let archive = state
            .database(database.database_id)
            .unwrap()
            .archive
            .unwrap();
        let old_result = state
            .lookup(database, context.admission, 101, [1; 32])
            .unwrap();
        let (mut controller, port, store, mut context) =
            build_with(state, identity.clone(), limits, context);
        let key = object_key(identity.clone(), database, archive.object_digest);
        store.0.borrow_mut().objects.insert(key, bytes.clone());
        let activated = controller.client.activate_history(&context).unwrap();
        assert_eq!(activated.physical_history_version(), 3);
        assert_eq!(activated.position().index, index + 1);
        assert_eq!(
            activated.database(database.database_id).unwrap().archive,
            Some(archive)
        );
        if !cold {
            assert_eq!(
                port.0
                    .borrow()
                    .state
                    .database(database.database_id)
                    .unwrap()
                    .base_revision,
                0
            );
            // Canonical migration follows the same per-commit thresholds as
            // new execution. This two-entry history remains a physical tail;
            // its old exact object still proves complete prune coverage.
            controller.prune(&context, database, 10).unwrap();
        }
        assert!(
            port.0
                .borrow()
                .state
                .database(database.database_id)
                .unwrap()
                .cold
        );
        {
            let state = &mut port.0.borrow_mut().state;
            assert_eq!(
                apply_as(
                    state,
                    database,
                    context.admission,
                    CommandKind::AuthFence {
                        operation_id: 11,
                        expected_epoch: 1,
                        policy: vec![Grant {
                            principal_id: 12,
                            permissions: READ | WRITE | ADMIN,
                        }],
                    },
                    limits,
                )
                .outcome,
                Outcome::Administrative(AdminResult::AuthChanged(2))
            );
        }
        assert_eq!(
            controller.hydrate(&context, database, 12),
            Err(Error::Rejected(Reject::Unauthorized))
        );
        context.admission.auth_epoch = 2;
        assert_eq!(
            apply_as(
                &mut port.0.borrow_mut().state,
                database,
                context.admission,
                CommandKind::ResolveOrCancel {
                    request_id: 104,
                    request_fingerprint: [4; 32],
                },
                limits,
            )
            .outcome,
            Outcome::Cancelled
        );
        controller.hydrate(&context, database, 12).unwrap();
        let upgraded = controller.publish(&context, database, 13).unwrap();
        assert_ne!(upgraded.object_digest, archive.object_digest);
        let upgraded_key = object_key(identity.clone(), database, upgraded.object_digest);
        assert_eq!(store.0.borrow().objects[&upgraded_key][8], 3);
        controller.prune(&context, database, 14).unwrap();
        controller.hydrate(&context, database, 15).unwrap();
        let state = &port.0.borrow().state;
        let view = state.database(database.database_id).unwrap();
        assert!(!view.cold && view.suspended);
        assert_eq!(view.auth_epoch, 2);
        assert_eq!(
            state
                .lookup(database, context.admission, 101, [1; 32])
                .unwrap(),
            old_result
        );
        for (request_id, fingerprint) in [(103, [3; 32]), (104, [4; 32])] {
            assert!(matches!(
                state
                    .lookup(database, context.admission, request_id, fingerprint)
                    .unwrap(),
                scap_cell::Lookup::Cancelled { .. }
            ));
        }
        let recovery = state.recovery_source(database, context.admission).unwrap();
        assert!(recovery.base.is_none());
        assert_eq!(recovery.tail.len(), 2);
        let mut restored = scap_core::physical::Image::empty(
            scap_core::physical::EngineIdentity { cell, database },
            scap_core::physical::Limits {
                max_database_pages: 8,
                max_changed_pages: 8,
                max_transaction_bytes: limits.max_transaction_bytes,
            },
        )
        .unwrap();
        for transaction in recovery.tail {
            restored = restored
                .replay(&transaction.commit.receipt, &transaction.physical_changes)
                .unwrap();
        }
        assert_eq!(restored.bytes(), image);
        assert_eq!(store.0.borrow().objects.len(), 2);
    }
}

#[test]
fn folded_base_and_tail_round_trip_through_exact_publication_prune_and_hydration() {
    use scap_core::physical::{EngineIdentity, Image, PageBatch};

    let mut state = active();
    let mut image = Image::empty(
        EngineIdentity {
            cell: cell(),
            database: database(),
        },
        scap_core::physical::Limits {
            max_database_pages: 1,
            max_changed_pages: 1,
            max_transaction_bytes: limits().max_transaction_bytes,
        },
    )
    .unwrap();
    for sequence in 1..=9 {
        let prepared = image
            .prepare(
                CommitTicket {
                    cell_id: cell().cell_id,
                    cell_incarnation: cell().cell_incarnation,
                    database_id: database().database_id,
                    incarnation: database().incarnation,
                    placement_generation: database().placement_generation,
                    owner_epoch: 1,
                    worker_instance_id: 77,
                    auth_epoch: 1,
                    request_id: 100 + sequence,
                    predecessor: sequence as u64 - 1,
                    payload_digest: [0; 32],
                },
                PageBatch {
                    size_after: 0,
                    pages: vec![],
                },
            )
            .unwrap();
        apply_kind(
            &mut state,
            CommandKind::Commit {
                write: prepared.write().clone(),
                request_fingerprint: [7; 32],
                result: vec![sequence as u8],
            },
        );
        let Outcome::Accepted(commit) = &state.last_outcome().unwrap().outcome else {
            panic!("valid physical transition rejected");
        };
        image = prepared.accepted(&commit.receipt).unwrap();
    }
    let expected = state.recovery_source(database(), admission()).unwrap();
    assert_eq!(expected.base.unwrap().revision, 8);
    assert_eq!(expected.tail.len(), 1);
    let base = expected.base.cloned();
    let tail = expected.tail.to_vec();
    let original = state.lookup(database(), admission(), 101, [7; 32]).unwrap();
    let (mut controller, port, store, context) = build_with(state, identity(), limits(), context());
    controller.suspend(&context, database(), 10).unwrap();
    let archive = controller.publish(&context, database(), 11).unwrap();
    let key = object_key(identity(), database(), archive.object_digest);
    assert_eq!(store.0.borrow().objects[&key][8], 3);
    controller.prune(&context, database(), 12).unwrap();
    let cold = port
        .0
        .borrow()
        .state
        .database(database().database_id)
        .unwrap();
    assert_eq!(cold.base_revision, 8);
    assert_eq!((cold.tail_entries, cold.tail_bytes), (0, 0));
    assert!(matches!(
        port.0
            .borrow()
            .state
            .recovery_source(database(), admission()),
        Err(Reject::Cold)
    ));
    controller.hydrate(&context, database(), 13).unwrap();
    let state = &port.0.borrow().state;
    let recovered = state.recovery_source(database(), admission()).unwrap();
    assert_eq!(recovered.base, base.as_ref());
    assert_eq!(recovered.tail, tail);
    assert_eq!(
        state.lookup(database(), admission(), 101, [7; 32]).unwrap(),
        original
    );
    assert_eq!(store.0.borrow().objects.len(), 1);
}

#[test]
fn upload_failure_corruption_deadline_or_quorum_never_publishes_or_prunes() {
    for failure in 0..7 {
        let (mut controller, port, store, context) = build();
        controller.suspend(&context, database(), 4).unwrap();
        match failure {
            0 => store.0.borrow_mut().put_fail = true,
            1 => store.0.borrow_mut().get_fail = true,
            2 => store.0.borrow_mut().corrupt = true,
            3 => store.0.borrow_mut().truncate = true,
            4 => store.0.borrow_mut().cancel = true,
            5 => port.0.borrow_mut().propose_fail = true,
            _ => port.0.borrow_mut().read_fail = true,
        }
        assert!(controller.publish(&context, database(), 5).is_err());
        let view = port.0.borrow().state.database(40).unwrap();
        assert!(!view.cold && view.archive.is_none());
        assert_eq!(
            port.0
                .borrow()
                .state
                .recovery_source(database(), admission())
                .unwrap()
                .tail[0]
                .physical_changes,
            vec![9; 1024]
        );
    }
}

#[test]
fn every_lifecycle_stage_rechecks_current_identity_and_propagates_unknown() {
    for stage in 0..4 {
        for failure in 0..4 {
            let (mut controller, port, store, context) = build();
            controller.suspend(&context, database(), 4).unwrap();
            controller.publish(&context, database(), 5).unwrap();
            controller.prune(&context, database(), 6).unwrap();
            let mut request = context.clone();
            match failure {
                0 => port.0.borrow_mut().read_fail = true,
                1 => request.admission.principal_id = 999,
                2 => port.0.borrow_mut().propose_fail = true,
                _ => port.0.borrow_mut().outcome = Some(Outcome::Rejected(Reject::Capacity)),
            }
            let result = match stage {
                0 => controller.suspend(&request, database(), 7),
                1 => controller.publish(&request, database(), 7).map(|_| ()),
                2 => controller.prune(&request, database(), 7),
                _ => controller.hydrate(&request, database(), 7),
            };
            assert!(result.is_err(), "stage {stage} failure {failure}");
            assert_eq!(store.0.borrow().objects.len(), 1);
        }
    }
    for failure in 0..4 {
        let (mut controller, _, store, context) = build();
        controller.suspend(&context, database(), 4).unwrap();
        controller.publish(&context, database(), 5).unwrap();
        controller.prune(&context, database(), 6).unwrap();
        match failure {
            0 => store.0.borrow_mut().get_fail = true,
            1 => store.0.borrow_mut().corrupt = true,
            2 => store.0.borrow_mut().truncate = true,
            _ => store.0.borrow_mut().cancel = true,
        }
        assert!(controller.hydrate(&context, database(), 7).is_err());
    }
}

#[test]
fn exact_admin_outcome_is_required_and_known_rejections_are_preserved() {
    let expected = AdminResult::Suspended(4);
    assert_eq!(
        accepted(
            Outcome::AlreadyApplied(expected.clone()),
            expected.clone(),
            None
        ),
        Ok(None)
    );
    assert_eq!(
        accepted(
            Outcome::Administrative(AdminResult::Created),
            expected.clone(),
            None
        ),
        Err(Error::Unknown)
    );
    assert_eq!(
        accepted(Outcome::Cancelled, expected.clone(), None),
        Err(Error::Unknown)
    );
    assert_eq!(
        accepted(Outcome::Rejected(Reject::Fenced), expected, None),
        Err(Error::Rejected(Reject::Fenced))
    );
    let (mut controller, port, _, context) = build();
    {
        let state = &mut port.0.borrow_mut().state;
        let mut encoded = state.encode();
        encoded[17 + 136..17 + 144].copy_from_slice(&u64::MAX.to_be_bytes());
        let end = encoded.len() - 32;
        let digest = scap_cell::payload_digest(&encoded[..end]);
        encoded[end..].copy_from_slice(&digest);
        *state = CellState::decode_bound(&encoded, cell(), state.position(), limits()).unwrap();
    }
    assert_eq!(
        controller.suspend(&context, database(), 4),
        Err(Error::Rejected(Reject::Exhausted))
    );
}

#[test]
fn publication_rejection_after_verified_upload_keeps_the_object_unpublished() {
    for outcome in [
        Outcome::Rejected(Reject::Conflict),
        Outcome::AlreadyApplied(AdminResult::Created),
    ] {
        let (mut controller, port, store, context) = build();
        controller.suspend(&context, database(), 4).unwrap();
        port.0.borrow_mut().outcome = Some(outcome);
        assert!(controller.publish(&context, database(), 5).is_err());
        // A lost/mismatched observation cannot authorize pruning. Uploaded bytes
        // remain; callers must use a new authoritative read before continuing.
        assert_eq!(store.0.borrow().objects.len(), 1);
        assert!(!port.0.borrow().state.database(40).unwrap().cold);
    }
}

#[test]
fn legacy_never_owned_database_suspends_without_inventing_worker_identity() {
    let (mut controller, port, _, context) = build();
    let mut state =
        CellState::bootstrap(cell(), 11, Position { term: 1, index: 1 }, limits()).unwrap();
    let operation_id: u128 = 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00;
    apply_kind(
        &mut state,
        CommandKind::Create {
            operation_id,
            policy: vec![Grant {
                principal_id: 11,
                permissions: READ | WRITE | ADMIN,
            }],
        },
    );
    // Construct the genuine v1 layout: the three v2 lifecycle flags and v3
    // empty-base discriminator are absent. There are no physical transactions.
    // All remaining original bytes and the envelope checksum stay exact.
    let mut bytes = state.encode();
    let operation_offset = bytes
        .windows(16)
        .position(|part| part == operation_id.to_be_bytes())
        .unwrap();
    let extension = operation_offset - 8 - 4;
    assert_eq!(&bytes[extension..extension + 4], &[1, 0, 0, 0]);
    bytes.drain(extension..extension + 4);
    bytes[8] = 1;
    let body_len = (bytes.len() - 49) as u64;
    bytes[9..17].copy_from_slice(&body_len.to_be_bytes());
    let end = bytes.len() - 32;
    let digest = scap_cell::payload_digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
    port.0.borrow_mut().state =
        CellState::decode_bound(&bytes, cell(), state.position(), limits()).unwrap();
    controller.suspend(&context, database(), 2).unwrap();
    let view = port.0.borrow().state.database(40).unwrap();
    assert!(view.suspended);
    assert_eq!(
        view.owner,
        OwnerToken {
            epoch: 0,
            worker_instance_id: 0
        }
    );
    controller.publish(&context, database(), 3).unwrap();
    controller.prune(&context, database(), 4).unwrap();
    controller.hydrate(&context, database(), 5).unwrap();
    assert_eq!(
        port.0.borrow().state.database(40).unwrap().owner,
        view.owner
    );
}

fn replace_suspended_owner(state: &mut CellState) {
    let old = state.database(40).unwrap();
    apply_kind(
        state,
        CommandKind::ClaimOwner {
            operation_id: 1000,
            expected_epoch: old.owner.epoch,
            worker_instance_id: 99,
        },
    );
    let claimed = state.database(40).unwrap();
    apply_kind(
        state,
        CommandKind::SuspendDb {
            operation_id: 1001,
            token: claimed.owner,
            expected_revision: claimed.revision,
        },
    );
    let current = state.database(40).unwrap();
    assert_eq!(current.revision, old.revision);
    assert_ne!(current.owner, old.owner);
}

#[test]
fn queued_archive_never_refreshes_old_scope_or_owner_and_ordered_acceptance_rechecks_it() {
    for stage in 0..2 {
        for failure in 0..5 {
            let (mut controller, port, _, mut context) = build();
            controller.suspend(&context, database(), 4).unwrap();
            let expected = port.0.borrow().state.database(40).unwrap();
            let archive = if stage == 1 {
                Some(
                    controller
                        .publish_bound(&context, expected.clone(), 5)
                        .unwrap(),
                )
            } else {
                None
            };
            match failure {
                0 => port.0.borrow_mut().read_fail = true,
                1 => context.admission.auth_epoch += 1,
                2 => replace_suspended_owner(&mut port.0.borrow_mut().state),
                3 => port.0.borrow_mut().before_propose = Some(replace_suspended_owner),
                _ => (),
            }
            let result = if let Some(archive) = archive {
                controller.prune_bound(&context, expected, archive, 6)
            } else {
                controller.publish_bound(&context, expected, 5).map(|_| ())
            };
            if failure == 4 {
                result.unwrap();
                assert_eq!(port.0.borrow().state.database(40).unwrap().cold, stage == 1);
            } else {
                assert!(result.is_err(), "stage {stage}, failure {failure}");
                assert!(!port.0.borrow().state.database(40).unwrap().cold);
            }
        }
    }
}

#[path = "control_tests.rs"]
mod control_tests;
