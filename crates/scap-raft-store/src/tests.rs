use super::*;
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    BeforeWrite,
    AfterWrite,
    Panic,
}

#[derive(Default)]
struct Disk {
    bytes: Option<Vec<u8>>,
    unrecognized: bool,
    fail_load: bool,
    fault: Fault,
    writes: usize,
    requested_bound: usize,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Disk>>);

impl AtomicBackend for Fake {
    type Error = &'static str;

    fn load(&mut self, max_image_bytes: usize) -> Result<LoadState, Self::Error> {
        let mut disk = self.0.borrow_mut();
        disk.requested_bound = max_image_bytes;
        if disk.fail_load {
            return Err("load failed");
        }
        if disk.unrecognized {
            return Ok(LoadState::Unrecognized);
        }
        match &disk.bytes {
            Some(bytes) if bytes.len() > max_image_bytes => Err("owned image exceeds bound"),
            Some(bytes) => Ok(LoadState::Image(bytes.clone())),
            None => Ok(LoadState::Empty),
        }
    }

    fn replace_sync(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        let mut disk = self.0.borrow_mut();
        disk.writes += 1;
        match disk.fault {
            Fault::BeforeWrite => return Err("write failed before replacement"),
            Fault::Panic => panic!("backend panic"),
            _ => {}
        }
        disk.bytes = Some(image.to_vec());
        if matches!(disk.fault, Fault::AfterWrite) {
            return Err("write outcome unknown after replacement");
        }
        Ok(())
    }
}

fn limits() -> Limits {
    Limits {
        max_image_bytes: 65_536,
        max_entry_bytes: 1024,
        max_entries: 32,
        max_application_bytes: 4096,
    }
}

fn identity() -> Identity {
    Identity {
        cluster_id: 11,
        cell_id: 22,
        cell_incarnation: 3,
        node_id: 1,
    }
}

fn configuration() -> ConfState {
    ConfState {
        voters: vec![1, 2, 3],
        ..Default::default()
    }
}

fn joint_configuration() -> ConfState {
    ConfState {
        voters: vec![1, 2],
        voters_outgoing: vec![1, 3],
        learners: vec![4],
        learners_next: vec![3],
        auto_leave: true,
        ..Default::default()
    }
}

fn hard_state(term: u64, vote: u64, commit: u64) -> HardState {
    HardState {
        term,
        vote,
        commit,
        ..Default::default()
    }
}

fn entry(index: u64, term: u64, data: &[u8]) -> Entry {
    Entry {
        index,
        term,
        data: data.to_vec().into(),
        context: b"request-context".to_vec().into(),
        ..Default::default()
    }
}

fn new_store() -> (Store<Fake>, Fake) {
    let backend = Fake::default();
    let store = Store::create_new(backend.clone(), identity(), configuration(), limits()).unwrap();
    (store, backend)
}

fn with_log() -> (Store<Fake>, Fake, Vec<Entry>) {
    let (mut store, backend) = new_store();
    let entries = vec![entry(2, 2, b"a"), entry(3, 2, b"b"), entry(4, 2, b"c")];
    store
        .persist_ready(&entries, Some(&hard_state(2, 1, 2)), None)
        .unwrap();
    (store, backend, entries)
}

fn context() -> GetEntriesContext {
    GetEntriesContext::empty(false)
}

fn put_state(backend: &Fake, state: &State) {
    backend.0.borrow_mut().bytes = Some(encode(state, limits()).unwrap());
}

fn body(image: &[u8]) -> Vec<u8> {
    image[..image.len() - 32].to_vec()
}

fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.extend_from_slice(&checksum(&bytes));
    bytes
}

fn blob_offsets(bytes: &[u8]) -> (Vec<usize>, usize) {
    let mut cursor = Cursor {
        bytes,
        position: 68,
    };
    let mut starts = Vec::new();
    for _ in 0..4 {
        starts.push(cursor.position);
        cursor.blob().unwrap();
    }
    let count_at = cursor.position;
    let count = cursor.u32().unwrap();
    for _ in 0..count {
        starts.push(cursor.position);
        cursor.blob().unwrap();
    }
    (starts, count_at)
}

#[test]
fn genesis_is_durable_bound_and_explicitly_reopened() {
    let (store, backend) = new_store();
    let state = store.view().unwrap();
    assert_eq!(state.identity, identity());
    assert_eq!(state.hard_state, hard_state(1, 0, 1));
    assert_eq!(state.applied, 1);
    assert!(state.application.is_empty());
    assert_eq!(state.snapshot.get_metadata().index, 1);
    assert_eq!(state.snapshot.get_metadata().term, 1);
    assert_eq!(
        state.snapshot.get_metadata().get_conf_state(),
        &configuration()
    );
    assert!(!store.is_stopped());
    assert_eq!(backend.0.borrow().writes, 1);
    assert_eq!(backend.0.borrow().requested_bound, limits().max_image_bytes);
    let reopened = Store::open_existing(backend.clone(), identity(), limits()).unwrap();
    assert_eq!(reopened.view().unwrap(), state);
    assert_eq!(
        backend.0.borrow().writes,
        1,
        "opening must not repair or write"
    );
    assert_eq!(
        format!("{}", Error::Invalid("sample")),
        "Invalid(\"sample\")"
    );
}

#[test]
fn create_and_open_never_guess_or_reinitialize_existing_data() {
    let (_, backend) = new_store();
    assert!(matches!(
        Store::create_new(backend.clone(), identity(), configuration(), limits()),
        Err(Error::Invalid(_))
    ));
    let empty = Fake::default();
    assert!(matches!(
        Store::open_existing(empty.clone(), identity(), limits()),
        Err(Error::Invalid(_))
    ));
    empty.0.borrow_mut().unrecognized = true;
    assert!(matches!(
        Store::create_new(empty.clone(), identity(), configuration(), limits()),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Store::open_existing(empty, identity(), limits()),
        Err(Error::Invalid(_))
    ));
    for field in 0..4 {
        let mut different = identity();
        match field {
            0 => different.cluster_id += 1,
            1 => different.cell_id += 1,
            2 => different.cell_incarnation += 1,
            _ => different.node_id += 1,
        }
        assert!(matches!(
            Store::open_existing(backend.clone(), different, limits()),
            Err(Error::Invalid("replica identity mismatch"))
        ));
    }
}

#[test]
fn constructor_io_failures_are_preserved() {
    let backend = Fake::default();
    backend.0.borrow_mut().fail_load = true;
    assert!(matches!(
        Store::create_new(backend.clone(), identity(), configuration(), limits()),
        Err(Error::Backend(_))
    ));
    assert!(matches!(
        Store::open_existing(backend.clone(), identity(), limits()),
        Err(Error::Backend(_))
    ));
    backend.0.borrow_mut().fail_load = false;
    backend.0.borrow_mut().fault = Fault::BeforeWrite;
    assert!(matches!(
        Store::create_new(backend, identity(), configuration(), limits()),
        Err(Error::Backend(_))
    ));
}

#[test]
fn invalid_limits_and_zero_identities_are_rejected() {
    for field in 0..8 {
        let mut bad = limits();
        match field {
            0 => bad.max_image_bytes = 0,
            1 => bad.max_image_bytes = usize::MAX,
            2 => bad.max_entry_bytes = 0,
            3 => bad.max_entries = 0,
            4 => bad.max_application_bytes = 0,
            5 => bad.max_entry_bytes = bad.max_image_bytes + 1,
            6 => bad.max_entries = bad.max_image_bytes + 1,
            _ => bad.max_application_bytes = bad.max_image_bytes + 1,
        }
        assert!(validate_limits(bad).is_err());
        assert!(Store::create_new(Fake::default(), identity(), configuration(), bad).is_err());
        assert!(Store::open_existing(Fake::default(), identity(), bad).is_err());
    }
    for field in 0..4 {
        let mut bad = identity();
        match field {
            0 => bad.cluster_id = 0,
            1 => bad.cell_id = 0,
            2 => bad.cell_incarnation = 0,
            _ => bad.node_id = 0,
        }
        assert!(Store::create_new(Fake::default(), bad, configuration(), limits()).is_err());
    }
}

#[test]
fn full_joint_configuration_and_invalid_memberships_are_checked() {
    validate_configuration(&joint_configuration()).unwrap();
    let mut valid = configuration();
    valid.learners = vec![4];
    validate_configuration(&valid).unwrap();
    for group in 0..4 {
        for members in [vec![0], vec![7, 7]] {
            let mut bad = joint_configuration();
            match group {
                0 => bad.voters = members,
                1 => bad.voters_outgoing = members,
                2 => bad.learners = members,
                _ => bad.learners_next = members,
            }
            assert!(validate_configuration(&bad).is_err());
        }
    }
    let mut cases = Vec::new();
    let mut empty = configuration();
    empty.voters.clear();
    cases.push(empty);
    for learner in [1, 3, 5] {
        let mut bad = joint_configuration();
        bad.learners = vec![learner];
        if learner == 5 {
            bad.learners_next = vec![5];
        }
        cases.push(bad);
    }
    for next in [5, 1] {
        let mut bad = joint_configuration();
        bad.learners_next = vec![next];
        cases.push(bad);
    }
    let mut auto_leave = configuration();
    auto_leave.auto_leave = true;
    cases.push(auto_leave);
    for bad in cases {
        assert!(validate_configuration(&bad).is_err());
        assert!(Store::create_new(Fake::default(), identity(), bad, limits()).is_err());
    }
}

#[test]
fn storage_queries_observe_only_the_persisted_log_and_checkpoint() {
    let (store, backend, entries) = with_log();
    assert_eq!(
        store.initial_state().unwrap().hard_state,
        hard_state(2, 1, 2)
    );
    assert_eq!(store.first_index().unwrap(), 2);
    assert_eq!(store.last_index().unwrap(), 4);
    assert_eq!(store.term(1).unwrap(), 1);
    assert_eq!(store.term(4).unwrap(), 2);
    assert!(matches!(
        store.term(0),
        Err(raft::Error::Store(StorageError::Compacted))
    ));
    assert!(matches!(
        store.term(5),
        Err(raft::Error::Store(StorageError::Unavailable))
    ));
    assert_eq!(store.entries(2, 5, None, context()).unwrap(), entries);
    assert_eq!(
        store.entries(2, 5, Some(0), context()).unwrap(),
        entries[..1]
    );
    assert_eq!(
        store
            .entries(2, 5, Some(entries[0].compute_size() as u64), context())
            .unwrap(),
        entries[..1]
    );
    assert!(store.entries(5, 5, None, context()).unwrap().is_empty());
    for (low, high) in [(2, 6), (4, 3)] {
        assert!(matches!(
            store.entries(low, high, None, context()),
            Err(raft::Error::Store(StorageError::Unavailable))
        ));
    }
    assert!(matches!(
        store.entries(1, 2, None, context()),
        Err(raft::Error::Store(StorageError::Compacted))
    ));
    assert_eq!(store.snapshot(1, 2).unwrap().get_metadata().index, 1);
    assert!(matches!(
        store.snapshot(2, 2),
        Err(raft::Error::Store(
            StorageError::SnapshotTemporarilyUnavailable
        ))
    ));
    assert!(
        !store.is_stopped(),
        "normal query range errors are not corruption"
    );
    let reopened = Store::open_existing(backend, identity(), limits()).unwrap();
    assert_eq!(reopened.view().unwrap().applied, 1);
    assert!(reopened.view().unwrap().application.is_empty());
    assert_eq!(
        reopened.view().unwrap().entries,
        entries,
        "uncommitted suffix remains unapplied"
    );
}

#[test]
fn votes_and_hard_state_never_regress() {
    let (mut store, _) = new_store();
    store
        .persist_ready(&[], Some(&hard_state(1, 2, 1)), None)
        .unwrap();
    store
        .persist_ready(&[], Some(&hard_state(1, 2, 1)), None)
        .unwrap();
    store
        .persist_ready(&[], Some(&hard_state(2, 0, 1)), None)
        .unwrap();
    assert_eq!(store.view().unwrap().hard_state, hard_state(2, 0, 1));
    for incoming in [
        hard_state(0, 0, 1),
        hard_state(1, 2, 0),
        hard_state(1, 0, 1),
        hard_state(1, 3, 1),
    ] {
        let (mut store, backend) = new_store();
        store
            .persist_ready(&[], Some(&hard_state(1, 2, 1)), None)
            .unwrap();
        let previous = backend.0.borrow().bytes.clone();
        assert!(store.persist_ready(&[], Some(&incoming), None).is_err());
        assert!(store.is_stopped());
        assert_eq!(backend.0.borrow().bytes, previous);
    }
}

#[test]
fn uncommitted_suffix_replacement_is_atomic_and_committed_entries_are_protected() {
    let (mut store, backend, entries) = with_log();
    let replacement = entry(3, 3, b"replacement");
    store
        .persist_ready(
            std::slice::from_ref(&replacement),
            Some(&hard_state(3, 0, 2)),
            None,
        )
        .unwrap();
    assert_eq!(
        store.view().unwrap().entries,
        vec![entries[0].clone(), replacement]
    );
    assert_eq!(
        Store::open_existing(backend, identity(), limits())
            .unwrap()
            .last_index()
            .unwrap(),
        3
    );
    // An identical committed prefix can be included in an otherwise legal write.
    let (mut same, _, entries) = with_log();
    same.persist_ready(&entries, None, None).unwrap();
    for append in [
        vec![entry(2, 2, b"different")],
        vec![entry(1, 2, b"compacted")],
        vec![entry(6, 2, b"gap")],
        vec![entry(3, 2, b"x"), entry(2, 2, b"backward")],
        vec![entry(3, 2, b"x"), entry(5, 2, b"gap")],
    ] {
        let (mut store, backend, _) = with_log();
        let previous = backend.0.borrow().bytes.clone();
        assert!(store.persist_ready(&append, None, None).is_err());
        assert!(store.is_stopped());
        assert_eq!(backend.0.borrow().bytes, previous);
    }
    let (mut store, _, entries) = with_log();
    store
        .apply_committed(4, &[], &[], &configuration())
        .unwrap();
    assert!(
        store.persist_ready(&entries[..2], None, None).is_err(),
        "cannot truncate below commit"
    );
}

#[test]
fn apply_and_commit_have_separate_atomic_boundaries() {
    let (mut store, backend, entries) = with_log();
    store
        .apply_committed(3, &[], &[], &configuration())
        .unwrap();
    assert_eq!(store.view().unwrap().hard_state, hard_state(2, 1, 3));
    assert_eq!(store.view().unwrap().applied, 1);
    store
        .apply_committed(3, &entries[..1], b"first-effect", &configuration())
        .unwrap();
    let reopened = Store::open_existing(backend.clone(), identity(), limits()).unwrap();
    assert_eq!(reopened.view().unwrap().hard_state.commit, 3);
    assert_eq!(reopened.view().unwrap().applied, 2);
    assert_eq!(reopened.view().unwrap().application, b"first-effect");
    store
        .apply_committed(3, &entries[1..2], b"second-effect", &configuration())
        .unwrap();
    store.checkpoint_and_compact().unwrap();
    assert_eq!(store.first_index().unwrap(), 4);
    assert_eq!(store.term(3).unwrap(), 2);
    assert_eq!(store.view().unwrap().entries, entries[2..]);
    assert_eq!(
        store.snapshot(3, 2).unwrap().data,
        b"second-effect".as_slice()
    );
    assert!(store.snapshot(4, 2).is_err());
    let once = backend.0.borrow().bytes.clone();
    store.checkpoint_and_compact().unwrap();
    assert_eq!(
        backend.0.borrow().bytes,
        once,
        "same applied view has identical checkpoint bytes"
    );
}

#[test]
fn invalid_application_batches_cannot_change_state() {
    for case in 0..8 {
        let (mut store, backend, entries) = with_log();
        let previous = backend.0.borrow().bytes.clone();
        let result = match case {
            0 => store.apply_committed(1, &[], &[], &configuration()),
            1 => store.apply_committed(2, &[], b"changed", &configuration()),
            2 => store.apply_committed(2, &[], &[], &joint_configuration()),
            3 => store.apply_committed(3, &entries[1..2], b"skipped", &configuration()),
            4 => store.apply_committed(2, &[entry(2, 2, b"different")], b"wrong", &configuration()),
            5 => store.apply_committed(2, &entries[..2], b"beyond-commit", &configuration()),
            6 => store.apply_committed(5, &entries, b"beyond-log", &configuration()),
            _ => store.apply_committed(
                2,
                &entries[..1],
                b"normal-config-change",
                &joint_configuration(),
            ),
        };
        assert!(result.is_err(), "case {case}");
        assert!(store.is_stopped());
        assert_eq!(backend.0.borrow().bytes, previous);
    }
}

#[test]
fn configuration_entries_persist_every_joint_field_with_applied() {
    for kind in [EntryType::EntryConfChange, EntryType::EntryConfChangeV2] {
        let (mut store, backend) = new_store();
        let mut change = entry(2, 2, b"opaque-config-proposal");
        change.set_entry_type(kind);
        store
            .persist_ready(
                std::slice::from_ref(&change),
                Some(&hard_state(2, 1, 2)),
                None,
            )
            .unwrap();
        store
            .apply_committed(
                2,
                &[change],
                b"state-with-membership",
                &joint_configuration(),
            )
            .unwrap();
        store.checkpoint_and_compact().unwrap();
        let reopened = Store::open_existing(backend, identity(), limits()).unwrap();
        assert_eq!(reopened.view().unwrap().conf_state, joint_configuration());
        assert_eq!(
            reopened
                .snapshot(2, 1)
                .unwrap()
                .get_metadata()
                .get_conf_state(),
            &joint_configuration()
        );
        assert_eq!(
            reopened.view().unwrap().application,
            b"state-with-membership"
        );
        assert_eq!(reopened.view().unwrap().applied, 2);
    }
}

fn received_snapshot(index: u64, term: u64) -> Snapshot {
    let mut snapshot = Snapshot::default();
    snapshot.mut_metadata().index = index;
    snapshot.mut_metadata().term = term;
    snapshot
        .mut_metadata()
        .set_conf_state(joint_configuration());
    snapshot.data = b"complete-snapshot-state".to_vec().into();
    snapshot
}

#[test]
fn snapshot_installation_covers_state_membership_commit_and_log_boundary() {
    let (mut store, backend, _) = with_log();
    let snapshot = received_snapshot(10, 3);
    let tail = entry(11, 4, b"uncommitted-after-snapshot");
    store
        .persist_ready(
            std::slice::from_ref(&tail),
            Some(&hard_state(4, 3, 10)),
            Some(&snapshot),
        )
        .unwrap();
    let reopened = Store::open_existing(backend, identity(), limits()).unwrap();
    assert_eq!(reopened.first_index().unwrap(), 11);
    assert_eq!(reopened.last_index().unwrap(), 11);
    assert_eq!(reopened.term(10).unwrap(), 3);
    assert_eq!(reopened.view().unwrap().snapshot, snapshot);
    assert_eq!(reopened.view().unwrap().hard_state, hard_state(4, 3, 10));
    assert_eq!(reopened.view().unwrap().applied, 10);
    assert_eq!(reopened.view().unwrap().conf_state, joint_configuration());
    assert_eq!(
        reopened.view().unwrap().application,
        b"complete-snapshot-state"
    );
    assert_eq!(reopened.view().unwrap().entries, vec![tail]);
    for index in [1, 2] {
        let (mut store, _, _) = with_log();
        assert!(store
            .persist_ready(
                &[],
                Some(&hard_state(4, 0, 2)),
                Some(&received_snapshot(index, 2))
            )
            .is_err());
    }
    let (mut store, _, _) = with_log();
    assert!(
        store
            .persist_ready(&[], None, Some(&received_snapshot(10, 3)))
            .is_err(),
        "snapshot alone cannot invent a matching HardState"
    );
}

#[test]
fn every_persistence_failure_stops_the_handle_even_if_disk_changed() {
    for fault in [Fault::BeforeWrite, Fault::AfterWrite] {
        let (mut store, backend) = new_store();
        let old = store.view().unwrap().clone();
        backend.0.borrow_mut().fault = fault;
        let result = store.persist_ready(
            &[entry(2, 2, b"maybe-written")],
            Some(&hard_state(2, 1, 1)),
            None,
        );
        assert!(matches!(result, Err(Error::Backend(_))));
        assert_eq!(
            store.state, old,
            "unconfirmed disk writes never publish the read cache"
        );
        assert!(store.is_stopped());
        let writes = backend.0.borrow().writes;
        assert!(matches!(
            store.persist_ready(&[], None, None),
            Err(Error::Stopped)
        ));
        assert!(matches!(
            store.apply_committed(1, &[], &[], &configuration()),
            Err(Error::Stopped)
        ));
        assert!(matches!(
            store.checkpoint_and_compact(),
            Err(Error::Stopped)
        ));
        assert!(store.initial_state().is_err());
        assert!(store.entries(2, 2, None, context()).is_err());
        assert!(store.term(1).is_err());
        assert!(store.first_index().is_err());
        assert!(store.last_index().is_err());
        assert!(store.snapshot(1, 1).is_err());
        assert_eq!(backend.0.borrow().writes, writes);
        let recovered = Store::open_existing(backend, identity(), limits()).unwrap();
        assert_eq!(recovered.view().unwrap().applied, 1);
        assert_eq!(
            recovered.last_index().unwrap(),
            if matches!(fault, Fault::AfterWrite) {
                2
            } else {
                1
            }
        );
    }
    let (mut store, backend) = new_store();
    backend.0.borrow_mut().fault = Fault::Panic;
    assert!(catch_unwind(AssertUnwindSafe(|| store.persist_ready(&[], None, None))).is_err());
    assert!(store.is_stopped());
    assert!(store.view().is_err());
}

#[test]
fn atomic_apply_and_snapshot_errors_leave_only_whole_recoverable_images() {
    for operation in 0..3 {
        for fault in [Fault::BeforeWrite, Fault::AfterWrite] {
            let (mut store, backend, entries) = with_log();
            if operation == 2 {
                store
                    .apply_committed(2, &entries[..1], b"applied", &configuration())
                    .unwrap();
            }
            let old = store.state.clone();
            backend.0.borrow_mut().fault = fault;
            let result = match operation {
                0 => store.apply_committed(3, &entries[..2], b"two-effects", &configuration()),
                1 => store.persist_ready(
                    &[],
                    Some(&hard_state(4, 0, 10)),
                    Some(&received_snapshot(10, 3)),
                ),
                _ => store.checkpoint_and_compact(),
            };
            assert!(matches!(result, Err(Error::Backend(_))));
            assert_eq!(store.state, old);
            let recovered = Store::open_existing(backend, identity(), limits()).unwrap();
            let state = recovered.view().unwrap();
            if matches!(fault, Fault::BeforeWrite) {
                assert_eq!(state, &old);
            } else {
                assert_ne!(state, &old);
                validate_state(state, limits()).unwrap();
            }
        }
    }
}

#[test]
fn recovery_rejects_invalid_state_instead_of_repairing_watermarks() {
    let (store, backend, _) = with_log();
    let baseline = store.view().unwrap().clone();
    for case in 0..16 {
        let mut bad = baseline.clone();
        match case {
            0 => bad.applied = 0,
            1 => bad.applied = 3,
            2 => bad.hard_state.commit = 5,
            3 => bad.snapshot.mut_metadata().index = 0,
            4 => bad.snapshot.mut_metadata().index = u64::MAX,
            5 => bad.snapshot.mut_metadata().term = 0,
            6 => bad.snapshot.mut_metadata().term = 3,
            7 => bad.entries[1].index = 4,
            8 => bad.entries[0].term = 0,
            9 => bad.entries[1].term = 1,
            10 => bad.entries[1].term = 3,
            11 => bad.application = b"changed-at-checkpoint".to_vec(),
            12 => bad.conf_state = joint_configuration(),
            13 => bad.snapshot.mut_metadata().mut_conf_state().voters.clear(),
            14 => bad.identity.cell_incarnation = 0,
            _ => bad.conf_state.voters.clear(),
        }
        put_state(&backend, &bad);
        let bytes = backend.0.borrow().bytes.clone();
        assert!(
            Store::open_existing(backend.clone(), identity(), limits()).is_err(),
            "case {case}"
        );
        assert_eq!(backend.0.borrow().bytes, bytes);
    }
    // Exercise the index-overflow guard without requiring an enormous log.
    let mut overflow = baseline;
    overflow.snapshot.mut_metadata().index = u64::MAX - 1;
    overflow.entries = vec![entry(u64::MAX, 2, b"overflow")];
    assert!(validate_state(&overflow, limits()).is_err());
    let (mut store, _) = new_store();
    let snapshot = received_snapshot(u64::MAX - 1, 2);
    assert!(store
        .persist_ready(
            &[entry(u64::MAX, 2, b"overflow")],
            Some(&hard_state(2, 0, u64::MAX - 1)),
            Some(&snapshot)
        )
        .is_err());
}

#[test]
fn bounds_reject_oversized_inputs_before_native_io() {
    let (mut store, backend) = new_store();
    assert!(store
        .persist_ready(
            &vec![entry(2, 2, b"x"); 33],
            Some(&hard_state(2, 1, 1)),
            None
        )
        .is_err());
    assert_eq!(backend.0.borrow().writes, 1);
    let (mut store, _) = new_store();
    assert!(store
        .persist_ready(
            &[entry(2, 2, &vec![0; 1025])],
            Some(&hard_state(2, 1, 1)),
            None
        )
        .is_err());
    let (mut store, _, entries) = with_log();
    assert!(store
        .apply_committed(2, &entries[..1], &vec![0; 4097], &configuration())
        .is_err());
    let (mut store, _) = new_store();
    let mut oversized = received_snapshot(10, 2);
    oversized.data = vec![0; 65_537].into();
    assert!(store
        .persist_ready(&[], Some(&hard_state(2, 0, 10)), Some(&oversized))
        .is_err());
    let (mut store, _, entries) = with_log();
    let mut enormous_configuration = configuration();
    enormous_configuration.voters = (1..100_000).collect();
    assert!(store
        .apply_committed(2, &entries[..1], &[], &enormous_configuration)
        .is_err());

    let (store, _) = new_store();
    let mut state = store.view().unwrap().clone();
    state.application = vec![0; 4097];
    assert!(validate_state(&state, limits()).is_err());
    state.application.clear();
    state.snapshot.data = vec![0; 4097].into();
    assert!(validate_state(&state, limits()).is_err());
    state.snapshot.data.clear();
    let tiny = Limits {
        max_image_bytes: 100,
        max_entry_bytes: 100,
        max_entries: 100,
        max_application_bytes: 100,
    };
    assert!(encode(&state, tiny).is_err());
    assert!(Store::create_new(Fake::default(), identity(), configuration(), tiny).is_err());
    assert!(check_entries_size(&[entry(2, 2, &[0; 50]), entry(3, 2, &[0; 50])], tiny).is_err());
    state.conf_state.voters = (1..100).collect();
    assert!(validate_state(&state, tiny).is_err());
    state.conf_state = configuration();
    state.snapshot.mut_metadata().mut_conf_state().voters = (1..100).collect();
    assert!(validate_state(&state, tiny).is_err());
}

#[test]
fn decode_rejects_damage_unknown_versions_and_every_truncated_prefix() {
    let (store, backend, _) = with_log();
    let image = backend.0.borrow().bytes.clone().unwrap();
    assert_eq!(decode(&image, limits()).unwrap(), *store.view().unwrap());
    assert!(decode(&[], limits()).is_err());
    assert!(decode(&vec![0; limits().max_image_bytes + 1], limits()).is_err());
    let mut corrupt = image.clone();
    corrupt[0] ^= 1;
    assert!(decode(&corrupt, limits()).is_err());
    let original = body(&image);
    for offset in [0, 8] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        assert!(decode(&finish(changed), limits()).is_err());
    }
    for size in 0..original.len() {
        assert!(
            decode(&finish(original[..size].to_vec()), limits()).is_err(),
            "truncated prefix {size}"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(decode(&finish(trailing), limits()).is_err());
    let (starts, count_at) = blob_offsets(&original);
    for start in [starts[0], starts[1], starts[2], starts[4]] {
        let mut changed = original.clone();
        let old_length = u32::from_be_bytes(changed[start..start + 4].try_into().unwrap()) as usize;
        changed.splice(start..start + 4 + old_length, [0, 0, 0, 1, 0xff]);
        assert!(matches!(
            decode(&finish(changed), limits()),
            Err(Error::Decode(_))
        ));
    }
    for count in [33u32, 31u32] {
        let mut changed = original.clone();
        changed[count_at..count_at + 4].copy_from_slice(&count.to_be_bytes());
        assert!(decode(&finish(changed), limits()).is_err());
    }
    backend.0.borrow_mut().bytes = Some(corrupt);
    assert!(Store::open_existing(backend, identity(), limits()).is_err());
}

#[test]
fn aggregate_image_limits_keep_the_previous_view_across_every_write_kind() {
    let small = Limits {
        max_image_bytes: 512,
        max_entry_bytes: 256,
        max_entries: 16,
        max_application_bytes: 256,
    };
    for operation in 0..3 {
        let backend = Fake::default();
        let mut store =
            Store::create_new(backend.clone(), identity(), configuration(), small).unwrap();
        let payload = vec![0; if operation == 2 { 40 } else { 120 }];
        let entries = [entry(2, 2, &payload), entry(3, 2, &payload)];
        store
            .persist_ready(&entries, Some(&hard_state(2, 1, 1)), None)
            .unwrap();
        if operation == 2 {
            store
                .apply_committed(2, &entries[..1], &[0; 160], &configuration())
                .unwrap();
        }
        let before = store.view().unwrap().clone();
        let durable = backend.0.borrow().bytes.clone();
        let writes = backend.0.borrow().writes;
        let result = match operation {
            0 => store.persist_ready(&[entry(4, 2, &payload)], None, None),
            1 => store.apply_committed(2, &entries[..1], &[0; 120], &configuration()),
            _ => store.checkpoint_and_compact(),
        };
        assert_eq!(
            result,
            Err(Error::Invalid("encoded image exceeds bound")),
            "operation {operation}"
        );
        assert!(store.is_stopped());
        assert_eq!(store.state, before);
        assert_eq!(
            backend.0.borrow().writes,
            writes,
            "aggregate limit fails before I/O"
        );
        assert_eq!(backend.0.borrow().bytes, durable);
        assert_eq!(
            Store::open_existing(backend, identity(), small)
                .unwrap()
                .view()
                .unwrap(),
            &before
        );
    }
}

#[test]
fn apply_recovery_and_accumulated_tail_each_enforce_entry_limits() {
    let (mut store, backend, _) = with_log();
    let old = backend.0.borrow().bytes.clone();
    assert!(store
        .apply_committed(
            2,
            &[entry(2, 2, &vec![0; 1025])],
            b"oversized",
            &configuration()
        )
        .is_err());
    assert!(store.is_stopped());
    assert_eq!(backend.0.borrow().bytes, old);
    let restrictive = Limits {
        max_entry_bytes: 1,
        ..limits()
    };
    assert!(Store::open_existing(backend, identity(), restrictive).is_err());

    let (mut store, backend) = new_store();
    let prefix: Vec<_> = (2..19).map(|index| entry(index, 2, b"prefix")).collect();
    store
        .persist_ready(&prefix, Some(&hard_state(2, 1, 1)), None)
        .unwrap();
    let old = backend.0.borrow().bytes.clone();
    let suffix: Vec<_> = (19..35).map(|index| entry(index, 2, b"suffix")).collect();
    assert_eq!(
        store.persist_ready(&suffix, None, None),
        Err(Error::Invalid("entry count exceeds bound"))
    );
    assert_eq!(backend.0.borrow().bytes, old);
    assert_eq!(
        Store::open_existing(backend, identity(), limits())
            .unwrap()
            .last_index()
            .unwrap(),
        18
    );
}
