use super::*;
use crate::tests::{deadline, fixture, identity, scope, sql, Memory};
use crate::*;
use scap_object_store::{
    DeleteOutcome, Garbage, GcCandidate, GcError, ListEnd, ListEntry, ListError, ListKind,
    ListMode, ListPage, ListRequest, Listings,
};
use std::sync::Mutex;

#[test]
fn storage_candidates_cannot_change_owner_history_or_cross_a_pending_owner() {
    let (objects, database) = fixture();
    let mut base = database.read_head(deadline()).unwrap();
    base.head.format = 8;
    base.head.revision += 2;
    base.head.head_serial += 2;
    base.head.transition.revision = base.head.revision;
    base.head.active = false;
    base.head.owner_plan = Some(OwnerPlan {
        reference: OwnerPlanRef {
            creator: 7,
            operation: 101,
            descriptor_hash: digest(b"owner descriptor"),
        },
        admission: OwnerAdmission {
            kind: OwnerAdmissionKind::Claim,
            revision: base.head.revision - 1,
            head_serial: base.head.head_serial - 1,
        },
        phase: OwnerPhase {
            kind: OwnerPhaseKind::Aborted,
            revision: base.head.revision,
            head_serial: base.head.head_serial,
            nonce: base.head.transition.nonce,
            owner_epoch: base.head.owner_epoch,
            owner_instance: base.head.owner_instance,
        },
    });
    base.head.validate().unwrap();
    let count = objects.operation_count();
    for cut in 0..4 {
        let mut next = technical_next(&base.head).unwrap();
        match cut {
            0 => next.owner_plan = None,
            1 => next.owner_epoch += 1,
            2 => next.owner_instance += 1,
            _ => next.active = true,
        }
        assert!(
            matches!(
                database.publish_technical(&base, &next, deadline()),
                Err(Error::Format(FormatError::Invalid))
            ),
            "storage cut {cut}"
        );
    }
    let marker = base.head.owner_plan.as_mut().unwrap();
    marker.phase.kind = OwnerPhaseKind::Claimed;
    marker.admission.revision = marker.phase.revision;
    marker.admission.head_serial = marker.phase.head_serial;
    base.head.validate().unwrap();
    let next = technical_next(&base.head).unwrap();
    assert!(matches!(
        database.publish_technical(&base, &next, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.retire_deleted(base.clone(), base.head.head_serial, deadline()),
        Err(Error::Fenced)
    ));
    assert_eq!(objects.operation_count(), count);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Inspect(String),
    Delete(String, String),
}

struct GarbageMemory {
    objects: Arc<Memory>,
    events: Mutex<Vec<Event>>,
    lose_delete: AtomicBool,
    inspect_error: Mutex<Option<GcError>>,
    delete_error: Mutex<Option<GcError>>,
    concurrent_delete: AtomicBool,
}

impl GarbageMemory {
    fn new(objects: Arc<Memory>) -> Self {
        Self {
            objects,
            events: Mutex::new(vec![]),
            lose_delete: AtomicBool::new(false),
            inspect_error: Mutex::new(None),
            delete_error: Mutex::new(None),
            concurrent_delete: AtomicBool::new(false),
        }
    }
}

impl Listings for GarbageMemory {
    fn list_page(&self, request: &ListRequest<'_>, _: Instant) -> Result<ListPage, ListError> {
        assert_eq!(request.mode, ListMode::Keys);
        let values: Vec<_> = self
            .objects
            .entries()
            .into_iter()
            .filter(|(key, _)| {
                key.starts_with(request.prefix)
                    && request.after.is_none_or(|after| key.as_str() > after)
            })
            .collect();
        let more = values.len() > MAX_SWEEP_ENTRIES;
        let entries: Vec<_> = values
            .into_iter()
            .take(MAX_SWEEP_ENTRIES)
            .map(|(key, _)| ListEntry {
                key,
                kind: ListKind::Object,
            })
            .collect();
        let end = if more {
            ListEnd::More {
                after: entries.last().unwrap().key.clone(),
            }
        } else {
            ListEnd::Exhausted
        };
        Ok(ListPage {
            entries,
            end,
            response_bytes: 1,
        })
    }
}

impl Garbage for GarbageMemory {
    fn inspect(&self, prefix: &str, hash: &str, until: Instant) -> Result<GcCandidate, GcError> {
        let key = format!("{prefix}{hash}");
        self.events
            .lock()
            .unwrap()
            .push(Event::Inspect(key.clone()));
        if let Some(error) = self.inspect_error.lock().unwrap().take() {
            return Err(error);
        }
        match self.objects.get(&key, MAX_OBJECT_BYTES, until) {
            Ok(value) => Ok(GcCandidate::Present {
                etag: format!("\"{}\"", value.etag),
            }),
            Err(StoreError::Missing) => Ok(GcCandidate::Missing),
            _ => Err(GcError::Unknown),
        }
    }
    fn delete(
        &self,
        prefix: &str,
        hash: &str,
        etag: &str,
        _: Instant,
    ) -> Result<DeleteOutcome, GcError> {
        let key = format!("{prefix}{hash}");
        self.events
            .lock()
            .unwrap()
            .push(Event::Delete(key.clone(), etag.into()));
        if let Some(error) = self.delete_error.lock().unwrap().take() {
            return Err(error);
        }
        if self.concurrent_delete.swap(false, Ordering::AcqRel) {
            self.objects.remove(&key);
        }
        let result = self.objects.delete_exact(&key, etag);
        if self.lose_delete.swap(false, Ordering::AcqRel) {
            Err(GcError::Unknown)
        } else {
            Ok(result)
        }
    }
}

fn promote(database: &Database) -> Head {
    let before = database.status(7, deadline()).unwrap();
    let head = database
        .compact_begin(7, before.head_serial, deadline())
        .unwrap();
    let serial = head.storage.plan.as_ref().unwrap().serial;
    database.compact_copy(7, serial, deadline()).unwrap();
    database.compact_promote(7, serial, deadline()).unwrap()
}

fn install_held_data(objects: &Memory, database: &Database) -> (Head, Vec<String>) {
    let mut hashes = Vec::new();
    let chunk = encode_object(&Envelope {
        format: 2,
        scope: scope(),
        payload: Payload::Chunk {
            first_page: 1,
            bytes: vec![0x31; PAGE_SIZE],
        },
    })
    .unwrap();
    let hash = digest(&chunk);
    objects.set(object_key(&scope(), 1, &hash), chunk);
    hashes.push(hash.clone());
    let node = encode_object(&Envelope {
        format: 2,
        scope: scope(),
        payload: Payload::Node {
            level: 0,
            first_chunk: 0,
            children: vec![hash],
        },
    })
    .unwrap();
    let hash = digest(&node);
    objects.set(object_key(&scope(), 1, &hash), node);
    hashes.push(hash.clone());
    let manifest = encode_object(&Envelope {
        format: 2,
        scope: scope(),
        payload: Payload::Manifest(Manifest {
            page_count: 1,
            root: Some(hash),
        }),
    })
    .unwrap();
    let hash = digest(&manifest);
    objects.set(object_key(&scope(), 1, &hash), manifest);
    hashes.push(hash.clone());
    let mut head = database.status(7, deadline()).unwrap();
    head.format = 9;
    head.head_serial += 1;
    head.restore_origin = Some(None);
    head.snapshot_limits = Some(SnapshotLimits::default());
    head.snapshots = Some(vec![SnapshotEntry {
        reference: SnapshotRef {
            creator: 7,
            operation: 991,
            capture_serial: head.head_serial,
            descriptor_hash: digest(b"unit retained identity"),
        },
        label: "old".into(),
        point: SnapshotPoint {
            data_root: hash,
            page_count: 1,
            sequence: head.sequence,
            source_revision: head.revision,
        },
    }]);
    objects.set(head_key(&scope()), encode_head(&head).unwrap());
    (head, hashes)
}

#[test]
fn head9_copy_carries_held_data_before_retiring_and_collecting_the_old_generation() {
    let (objects, database) = fixture();
    let (before, hashes) = install_held_data(&objects, &database);
    let after = promote(&database);
    assert_eq!(after.format, 9);
    assert_eq!(after.snapshots, before.snapshots);
    assert_eq!(after.snapshot_limits, before.snapshot_limits);
    for hash in &hashes {
        let old = objects
            .get(&object_key(&scope(), 1, hash), MAX_OBJECT_BYTES, deadline())
            .unwrap();
        let new = objects
            .get(&object_key(&scope(), 2, hash), MAX_OBJECT_BYTES, deadline())
            .unwrap();
        assert_eq!(old.bytes, new.bytes);
    }
    let garbage = GarbageMemory::new(objects.clone());
    let prepared = database
        .gc_prepare(
            7,
            after.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    let serial = prepared.head.storage.sweep.as_ref().unwrap().serial;
    let report = database.gc_resume(7, serial, &garbage, deadline()).unwrap();
    assert!(report.exhausted);
    assert_eq!(report.head.snapshots, before.snapshots);
    for hash in hashes {
        assert!(matches!(
            objects.get(
                &object_key(&scope(), 1, &hash),
                MAX_OBJECT_BYTES,
                deadline()
            ),
            Err(StoreError::Missing)
        ));
        assert!(objects
            .get(
                &object_key(&scope(), 2, &hash),
                MAX_OBJECT_BYTES,
                deadline()
            )
            .is_ok());
    }
}

#[test]
fn head9_copy_never_seals_a_missing_retained_dependency() {
    let (objects, database) = fixture();
    let (before, hashes) = install_held_data(&objects, &database);
    let copying = database
        .compact_begin(7, before.head_serial, deadline())
        .unwrap();
    objects.remove(&object_key(&scope(), 1, &hashes[0]));
    assert!(matches!(
        database.compact_copy(7, copying.storage.plan.as_ref().unwrap().serial, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(database.status(7, deadline()).unwrap(), copying);
}

#[test]
fn technical_capabilities_cannot_edit_snapshot_fields_or_downgrade_head9() {
    let (objects, database) = fixture();
    install_held_data(&objects, &database);
    let base = database.read_head(deadline()).unwrap();
    let before = objects.operation_count();
    for field in 0..4 {
        let mut next = technical_next(&base.head).unwrap();
        match field {
            0 => next.snapshots = Some(vec![]),
            1 => next.snapshot_limits.as_mut().unwrap().max_points = 1,
            2 => next.restore_origin = None,
            _ => next.format = 6,
        }
        assert!(matches!(
            database.publish_technical(&base, &next, deadline()),
            Err(Error::Format(FormatError::Invalid))
        ));
    }
    assert_eq!(objects.operation_count(), before);
}

#[test]
fn released_snapshot_identity_metadata_survives_terminal_payload_gc() {
    let (objects, database, point) = crate::snapshot_integration_tests::fixture();
    database
        .snapshot_release(7, &point.reference, deadline())
        .unwrap();
    let deleted = deleted_direct(&database);
    let terminal = database
        .retire_storage(7, deleted.head_serial, deadline())
        .unwrap();
    let control_prefix = crate::snapshot_records::prefix(&scope());
    let metadata: Vec<_> = objects
        .0
        .entries()
        .into_iter()
        .filter(|(key, _)| key.starts_with(&control_prefix))
        .collect();
    assert_eq!(metadata.len(), 2); // Permanent descriptor and accepted proof.
    let garbage = GarbageMemory::new(objects.0.clone());
    let batch = database
        .gc_prepare(
            7,
            terminal.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    let result = database
        .gc_resume(
            7,
            batch.head.storage.sweep.as_ref().unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert!(result.exhausted);
    assert!(objects
        .0
        .entries()
        .iter()
        .all(|(key, _)| !key.starts_with(&prefix(&scope(), 1))));
    for (key, original) in metadata {
        let current = objects.0.get(&key, MAX_OBJECT_BYTES, deadline()).unwrap();
        assert_eq!(current.bytes, original.bytes);
        assert_eq!(current.etag, original.etag);
    }
    assert_eq!(
        database
            .snapshot_inspect(7, &point.reference.identity(), deadline())
            .unwrap()
            .state,
        crate::snapshot::SnapshotState::ReleasedObserved
    );
}

#[test]
fn snapshot_mutations_are_fenced_while_a_real_retired_generation_sweep_is_pending() {
    let (objects, database, point) = crate::snapshot_integration_tests::fixture();
    let promoted = promote(&database);
    let garbage = GarbageMemory::new(objects.0.clone());
    let sweep = database
        .gc_prepare(
            7,
            promoted.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert!(sweep.head.storage.sweep.is_some());
    let fresh = crate::snapshot::PrepareSnapshotInput {
        creator: 7,
        operation: 902,
        expected_revision: sweep.head.revision,
        expected_head_serial: sweep.head.head_serial,
        label: "during-sweep".into(),
    };
    assert!(matches!(
        database.snapshot_prepare(7, &fresh, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.snapshot_release(7, &point.reference, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            sweep.head.revision,
            991,
            SnapshotLimits::default(),
            deadline()
        ),
        Err(Error::Fenced)
    ));
    assert_eq!(database.status(7, deadline()).unwrap(), sweep.head);
}

fn plan_fixture() -> Head {
    let (_, database) = fixture();
    let mut head = database.status(7, deadline()).unwrap();
    head.head_serial = 64;
    head.revision = 10;
    head.transition.revision = 10;
    head.active = false;
    head.storage.allocated_through = 2;
    head.storage.plan = Some(CopyPlan {
        serial: 32,
        source: 1,
        target: 2,
        phase: CopyPhase::Copying,
        basis: CopyBasis::capture(&head),
    });
    head
}

fn sweep_fixture() -> Head {
    let mut head = plan_fixture();
    head.storage.active_generation = 2;
    head.storage.plan = None;
    head.storage.sweep = Some(SweepCheckpoint {
        serial: 32,
        generation: 1,
        next_after: Some("f".repeat(64)),
        exhausted: false,
        entries: vec![SweepEntry {
            key: object_key(&head.scope, 1, &"a".repeat(64)),
            hash: "a".repeat(64),
            etag: "\"one\"".into(),
            disposition: SweepDisposition::Pending,
        }],
    });
    head
}

#[test]
fn persisted_storage_rejects_every_invalid_allocator_plan_and_frozen_field() {
    let head = plan_fixture();
    assert_eq!(
        decode_head(&encode_head(&head).unwrap(), &head.scope).unwrap(),
        head
    );
    type Mutation = Box<dyn Fn(&mut Head)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|h| h.storage.active_generation = 0),
        Box::new(|h| h.storage.active_generation = 3),
        Box::new(|h| h.storage.allocated_through = 65),
        Box::new(|h| h.storage.sweep = sweep_fixture().storage.sweep),
        Box::new(|h| h.lifecycle = Lifecycle::Maintenance),
        Box::new(|h| h.active = true),
        Box::new(|h| h.storage.plan.as_mut().unwrap().serial = 0),
        Box::new(|h| h.storage.plan.as_mut().unwrap().serial = 65),
        Box::new(|h| h.storage.plan.as_mut().unwrap().source = 2),
        Box::new(|h| h.storage.plan.as_mut().unwrap().target = 3),
        Box::new(|h| {
            h.storage.allocated_through = 1;
            h.storage.plan.as_mut().unwrap().target = 1;
        }),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.revision = 0),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.revision = 33),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.data_root = "b".repeat(64)),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.windows[0].root = "b".repeat(64)),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.sequence += 1),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.revision = 11),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.quota.max_bytes = None),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.retention.max_entries += 1),
        Box::new(|h| h.storage.plan.as_mut().unwrap().basis.request_epoch += 1),
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut invalid = head.clone();
        mutate(&mut invalid);
        assert_eq!(
            invalid.storage.validate(&invalid),
            Err(FormatError::Invalid),
            "case {index}"
        );
    }
    // ACL/revision updates preserve the frozen immutable closure.
    let mut newer = head.clone();
    newer.revision += 1;
    newer.transition.revision += 1;
    newer.policy[0].read = false;
    assert!(encode_head(&newer).is_ok());
    assert!(!head.storage.retired(0));
    assert!(!head.storage.retired(1));
    assert!(!head.storage.retired(2));
    assert!(!head.storage.retired(3));
    let mut aborted = head;
    aborted.storage.plan = None;
    assert!(aborted.storage.retired(2));
    aborted.lifecycle = Lifecycle::Deleted;
    assert!(!aborted.storage.retired(1));
}

#[test]
fn persisted_sweep_rejects_unbound_keys_etags_frontiers_and_unbounded_batches() {
    let head = sweep_fixture();
    assert_eq!(
        decode_head(&encode_head(&head).unwrap(), &head.scope).unwrap(),
        head
    );
    type Mutation = Box<dyn Fn(&mut Head)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|h| h.lifecycle = Lifecycle::Deleted),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().generation = 2),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().serial = 0),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().serial = 65),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().exhausted = true),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().next_after = None),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().entries.clear()),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().next_after = Some("../head".into())),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().entries[0].hash = "A".repeat(64)),
        Box::new(|h| h.storage.sweep.as_mut().unwrap().entries[0].key = head_key(&h.scope)),
        Box::new(|h| {
            let sweep = h.storage.sweep.as_mut().unwrap();
            sweep.entries.push(sweep.entries[0].clone());
        }),
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut invalid = head.clone();
        mutate(&mut invalid);
        assert_eq!(
            invalid.storage.validate(&invalid),
            Err(FormatError::Invalid),
            "case {index}"
        );
    }
    for etag in [
        String::new(),
        "x".into(),
        "\"x\"".repeat(400),
        "x\"".into(),
        "\"x".into(),
        "\"x\"x\"".into(),
        "\"x x\"".into(),
        "\"\u{7f}\"".into(),
        "\"é\"".into(),
    ] {
        let mut invalid = head.clone();
        invalid.storage.sweep.as_mut().unwrap().entries[0].etag = etag;
        assert_eq!(
            invalid.storage.validate(&invalid),
            Err(FormatError::Invalid)
        );
    }
    let mut oversized = head.clone();
    let sweep = oversized.storage.sweep.as_mut().unwrap();
    sweep.entries = vec![sweep.entries[0].clone(); MAX_SWEEP_ENTRIES + 1];
    assert_eq!(
        oversized.storage.validate(&oversized),
        Err(FormatError::Limit)
    );
    let mut missing = serde_json::to_value(&head).unwrap();
    missing["storage"].as_object_mut().unwrap().remove("plan");
    assert!(decode_head(&serde_json::to_vec(&missing).unwrap(), &head.scope).is_err());
    let mut missing = serde_json::to_value(&head).unwrap();
    missing["storage"]["sweep"]
        .as_object_mut()
        .unwrap()
        .remove("next_after");
    assert!(decode_head(&serde_json::to_vec(&missing).unwrap(), &head.scope).is_err());
}

#[test]
fn maximum_sweep_and_plan_with_full_acl_fit_the_fixed_head_budget() {
    for mut head in [plan_fixture(), sweep_fixture()] {
        head.scope = Scope {
            deployment: u64::MAX,
            tenant: u64::MAX,
            database: u64::MAX,
            incarnation: u64::MAX,
            generation: u64::MAX,
        };
        head.policy = (0..MAX_PRINCIPALS)
            .map(|i| Permission {
                principal: u64::MAX - i as u64,
                read: false,
                write: false,
                admin: true,
            })
            .collect();
        if let Some(sweep) = &mut head.storage.sweep {
            sweep.entries = (0..MAX_SWEEP_ENTRIES)
                .map(|i| {
                    let hash = format!("{i:064x}");
                    SweepEntry {
                        key: object_key(&head.scope, 1, &hash),
                        hash,
                        etag: format!("\"{}\"", "x".repeat(1022)),
                        disposition: SweepDisposition::ConditionMismatch,
                    }
                })
                .collect();
        }
        let bytes = encode_head(&head).unwrap();
        assert!(bytes.len() < MAX_HEAD_BYTES / 2, "{} bytes", bytes.len());
        assert_eq!(decode_head(&bytes, &head.scope).unwrap(), head);
    }
}

#[test]
fn every_compaction_and_gc_object_io_cut_withholds_success() {
    fn setup(action: usize) -> (Arc<Memory>, Database, GarbageMemory, u64) {
        let (objects, database) = fixture();
        let mut serial = database.status(7, deadline()).unwrap().head_serial;
        if (1..=3).contains(&action) {
            let begin = database.compact_begin(7, serial, deadline()).unwrap();
            serial = begin.storage.plan.as_ref().unwrap().serial;
            if action == 2 {
                database.compact_copy(7, serial, deadline()).unwrap();
            }
        } else if action >= 4 {
            serial = promote(&database).head_serial;
        }
        let garbage = GarbageMemory::new(objects.clone());
        if action == 5 {
            serial = database
                .gc_prepare(7, serial, 1, None, &garbage, &garbage, deadline())
                .unwrap()
                .head
                .storage
                .sweep
                .unwrap()
                .serial;
        }
        (objects, database, garbage, serial)
    }
    fn invoke(
        action: usize,
        database: &Database,
        garbage: &GarbageMemory,
        serial: u64,
    ) -> Result<(), Error> {
        match action {
            0 => database.compact_begin(7, serial, deadline()).map(|_| ()),
            1 => database.compact_copy(7, serial, deadline()).map(|_| ()),
            2 => database.compact_promote(7, serial, deadline()).map(|_| ()),
            3 => database.compact_abort(7, serial, deadline()).map(|_| ()),
            4 => database
                .gc_prepare(7, serial, 1, None, garbage, garbage, deadline())
                .map(|_| ()),
            _ => database
                .gc_resume(7, serial, garbage, deadline())
                .map(|_| ()),
        }
    }
    for action in 0..6 {
        let (objects, database, garbage, serial) = setup(action);
        let start = objects.operation_count();
        invoke(action, &database, &garbage, serial).unwrap();
        let count = objects.operation_count() - start;
        assert!(count >= 2);
        for cut in 1..=count {
            let (objects, database, garbage, serial) = setup(action);
            objects.fail_after(cut);
            assert!(
                invoke(action, &database, &garbage, serial).is_err(),
                "action {action}, cut {cut}/{count}"
            );
        }
    }
}

#[test]
fn maintenance_requires_current_admin_ready_identity_and_unexhausted_serial() {
    let (objects, database) = fixture();
    let head = database.status(7, deadline()).unwrap();
    assert!(matches!(
        database.compact_begin(8, head.head_serial, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.compact_begin(7, head.head_serial - 1, deadline()),
        Err(Error::Conflict)
    ));
    for result in [
        database.compact_copy(7, 0, deadline()),
        database.compact_promote(7, 1, deadline()),
        database.compact_abort(7, 0, deadline()),
    ] {
        assert!(matches!(result, Err(Error::Conflict)));
    }
    let begin = database
        .compact_begin(7, head.head_serial, deadline())
        .unwrap();
    let serial = begin.storage.plan.as_ref().unwrap().serial;
    assert!(matches!(
        database.compact_begin(7, begin.head_serial, deadline()),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        database.compact_copy(7, 0, deadline()),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        database.compact_promote(7, serial, deadline()),
        Err(Error::Conflict)
    ));
    assert!(matches!(database.writer(&begin), Err(Error::Fenced)));
    let snapshot = database.read_head(deadline()).unwrap();
    assert!(matches!(
        database.publish_metadata(&snapshot, 55, MetadataUpdate::Takeover, deadline()),
        Err(Error::Fenced)
    ));
    let garbage = GarbageMemory::new(objects.clone());
    assert!(matches!(
        database.gc_prepare(
            7,
            begin.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline()
        ),
        Err(Error::Conflict)
    ));
    let ended = database.compact_abort(7, serial, deadline()).unwrap();
    let mut limited = ended.clone();
    limited.head_serial = u64::MAX;
    limited.storage.allocated_through = u64::MAX;
    objects.set(head_key(&scope()), encode_head(&limited).unwrap());
    assert!(matches!(
        database.compact_begin(7, u64::MAX, deadline()),
        Err(Error::Limit)
    ));
    limited.storage.allocated_through = 2;
    limited.lifecycle = Lifecycle::Maintenance;
    objects.set(head_key(&scope()), encode_head(&limited).unwrap());
    assert!(matches!(
        database.compact_begin(7, u64::MAX, deadline()),
        Err(Error::Lifecycle)
    ));
}

#[test]
fn sealing_rechecks_exact_plan_and_current_admin_after_copying() {
    for mutation in 0..6 {
        let (objects, database) = fixture();
        let before = database.status(7, deadline()).unwrap();
        let begin = database
            .compact_begin(7, before.head_serial, deadline())
            .unwrap();
        let serial = begin.storage.plan.as_ref().unwrap().serial;
        let mut changed = begin.clone();
        changed.head_serial += 1;
        match mutation {
            0 => {
                changed.storage.active_generation = 2;
                changed.storage.allocated_through = 3;
                let p = changed.storage.plan.as_mut().unwrap();
                p.source = 2;
                p.target = 3;
            }
            1 => {
                changed.storage.allocated_through = 3;
                changed.storage.plan.as_mut().unwrap().target = 3;
            }
            2 => {
                changed.revision += 1;
                changed.transition.revision += 1;
                changed.storage.plan.as_mut().unwrap().basis.revision += 1;
            }
            3 => changed.storage.plan.as_mut().unwrap().phase = CopyPhase::Sealed,
            4 => changed.storage.plan = None,
            _ => {
                changed.policy[0].admin = false;
                changed.policy.push(Permission {
                    principal: 8,
                    read: false,
                    write: false,
                    admin: true,
                });
            }
        }
        // Empty database has manifest + index: one HEAD, two source/target pairs,
        // then the fresh HEAD which must authorize the seal.
        let reads = objects.get_count();
        objects.replace_after(6, head_key(&scope()), encode_head(&changed).unwrap(), false);
        let result = database.compact_copy(7, serial, deadline());
        assert_eq!(objects.get_count() - reads, 6);
        match mutation {
            3 => assert_eq!(result.unwrap(), changed),
            5 => assert!(matches!(result, Err(Error::Denied))),
            _ => assert!(matches!(result, Err(Error::Conflict))),
        }
    }
}

struct FixedListing(Result<ListPage, ListError>);
impl Listings for FixedListing {
    fn list_page(&self, _: &ListRequest<'_>, _: Instant) -> Result<ListPage, ListError> {
        self.0.clone()
    }
}

#[test]
fn gc_rejects_malformed_listing_and_preserves_typed_backend_failures() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let garbage = GarbageMemory::new(objects);
    let key = object_key(&scope(), 1, &"a".repeat(64));
    let page = ListPage {
        entries: vec![ListEntry {
            key: key.clone(),
            kind: ListKind::Object,
        }],
        end: ListEnd::Exhausted,
        response_bytes: 1,
    };
    for mutation in 0..8 {
        let mut changed = page.clone();
        match mutation {
            0 => changed.entries = vec![changed.entries[0].clone(); 33],
            1 => changed.entries[0].key = head_key(&scope()),
            2 => changed.entries[0].key = object_key(&scope(), 1, "invalid"),
            3 => changed.entries[0].kind = ListKind::Prefix,
            4 => changed.entries.push(changed.entries[0].clone()),
            5 => {
                changed.end = ListEnd::More {
                    after: object_key(&scope(), 1, &"b".repeat(64)),
                }
            }
            6 => {
                changed.entries.clear();
                changed.end = ListEnd::More { after: key.clone() };
            }
            _ => {}
        }
        let after = (mutation == 7).then_some("b".repeat(64));
        assert!(
            matches!(
                database.gc_prepare(
                    7,
                    head.head_serial,
                    1,
                    after.as_deref(),
                    &FixedListing(Ok(changed)),
                    &garbage,
                    deadline()
                ),
                Err(Error::Corrupt)
            ),
            "mutation {mutation}"
        );
        assert!(database
            .status(7, deadline())
            .unwrap()
            .storage
            .sweep
            .is_none());
    }
    for error in [
        ListError::Invalid,
        ListError::Limit,
        ListError::Corrupt,
        ListError::Denied,
        ListError::Unknown,
    ] {
        let result = database.gc_prepare(
            7,
            head.head_serial,
            1,
            None,
            &FixedListing(Err(error)),
            &garbage,
            deadline(),
        );
        assert!(match error {
            ListError::Invalid => matches!(result, Err(Error::Format(FormatError::Invalid))),
            ListError::Limit => matches!(result, Err(Error::Limit)),
            ListError::Corrupt => matches!(result, Err(Error::Corrupt)),
            ListError::Denied => matches!(result, Err(Error::Denied)),
            ListError::Unknown => matches!(result, Err(Error::Unknown)),
        });
    }
    for error in [
        GcError::Invalid,
        GcError::Limit,
        GcError::Corrupt,
        GcError::Denied,
        GcError::Unsupported,
        GcError::Unknown,
    ] {
        *garbage.inspect_error.lock().unwrap() = Some(error);
        assert!(
            matches!(database.gc_prepare(7,head.head_serial,1,None,&FixedListing(Ok(page.clone())),&garbage,deadline()),Err(Error::Gc(actual)) if actual==error)
        );
    }
}

#[test]
fn gc_pagination_is_bounded_and_all_missing_candidates_do_not_fabricate_a_batch() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let garbage = GarbageMemory::new(objects.clone());
    for i in 0..35 {
        objects.set(object_key(&scope(), 1, &format!("{i:064x}")), vec![i as u8]);
    }
    let first = database
        .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
        .unwrap();
    assert_eq!(first.scanned, 32);
    assert!(!first.exhausted);
    let frontier = first.next_after.clone().unwrap();
    assert_eq!(first.head.storage.sweep.as_ref().unwrap().entries.len(), 32);
    let first = database
        .gc_resume(
            7,
            first.head.storage.sweep.unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    let second = database
        .gc_prepare(
            7,
            first.head.head_serial,
            1,
            Some(&frontier),
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert!(second.exhausted);
    assert_eq!(second.scanned, 5); // Three remaining fixture orphans plus two live-closure copies.
    let done = database
        .gc_resume(
            7,
            second.head.storage.sweep.unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    for more in [false, true] {
        let key = object_key(&scope(), 1, &"e".repeat(64));
        let listing = FixedListing(Ok(ListPage {
            entries: vec![ListEntry {
                key: key.clone(),
                kind: ListKind::Object,
            }],
            end: if more {
                ListEnd::More { after: key }
            } else {
                ListEnd::Exhausted
            },
            response_bytes: 1,
        }));
        let absent = database
            .gc_prepare(
                7,
                done.head.head_serial,
                1,
                None,
                &listing,
                &garbage,
                deadline(),
            )
            .unwrap();
        assert_eq!(absent.scanned, 1);
        assert_eq!(absent.exhausted, !more);
        assert_eq!(absent.next_after, more.then_some("e".repeat(64)));
        assert_eq!(absent.head, done.head);
    }
}

#[test]
fn checkpoint_observation_and_final_clear_require_current_exact_authority() {
    for mutation in 0..5 {
        let (objects, database) = fixture();
        let head = promote(&database);
        let garbage = GarbageMemory::new(objects.clone());
        let prepared = database
            .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
            .unwrap()
            .head;
        let serial = prepared.storage.sweep.as_ref().unwrap().serial;
        let count = prepared.storage.sweep.as_ref().unwrap().entries.len();
        let mut changed = prepared.clone();
        changed.head_serial += 1;
        for entry in &mut changed.storage.sweep.as_mut().unwrap().entries {
            entry.disposition = SweepDisposition::Applied;
        }
        let cut = if mutation == 0 || mutation == 4 {
            count + 2
        } else {
            count + 3
        };
        match mutation {
            0 => {
                let sweep = changed.storage.sweep.as_mut().unwrap();
                sweep.next_after = Some("f".repeat(64));
                sweep.exhausted = false;
            }
            1 => changed.storage.sweep = None, // One serial behind the actual clear.
            2 => changed.head_serial += 1,     // Reappearance of a checkpoint after clear.
            3 => {
                changed.head_serial += 2;
                changed.storage.sweep = None;
                changed.active = false;
                changed.storage.allocated_through += 1;
                changed.storage.plan = Some(CopyPlan {
                    serial: changed.head_serial,
                    source: 2,
                    target: 3,
                    phase: CopyPhase::Copying,
                    basis: CopyBasis::capture(&changed),
                });
            }
            _ => {
                changed.policy[0].admin = false;
                changed.policy.push(Permission {
                    principal: 8,
                    read: false,
                    write: false,
                    admin: true,
                });
            }
        }
        objects.replace_after(
            cut,
            head_key(&scope()),
            encode_head(&changed).unwrap(),
            false,
        );
        let result = database.gc_resume(7, serial, &garbage, deadline());
        match mutation {
            3 => assert_eq!(result.unwrap().head, changed),
            4 => assert!(matches!(result, Err(Error::Denied))),
            _ => assert!(matches!(result, Err(Error::Conflict))),
        }
    }
}

#[test]
fn concurrent_absence_at_delete_is_observed_and_unknown_never_clears_the_batch() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let garbage = GarbageMemory::new(objects);
    let prepared = database
        .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
        .unwrap()
        .head;
    let serial = prepared.storage.sweep.as_ref().unwrap().serial;
    assert!(matches!(
        database.gc_resume(7, 0, &garbage, deadline()),
        Err(Error::Conflict)
    ));
    *garbage.delete_error.lock().unwrap() = Some(GcError::Denied);
    assert!(matches!(
        database.gc_resume(7, serial, &garbage, deadline()),
        Err(Error::Gc(GcError::Denied))
    ));
    assert_eq!(database.status(7, deadline()).unwrap(), prepared);
    garbage.concurrent_delete.store(true, Ordering::Release);
    assert!(database
        .gc_resume(7, serial, &garbage, deadline())
        .unwrap()
        .head
        .storage
        .sweep
        .is_none());
}

#[test]
fn complete_copy_keeps_raw_receipt_and_current_acl_then_requires_activation() {
    let (objects, database) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temporary.path().join("source"), deadline())
        .unwrap();
    let (receipt, value) = session
        .execute(7, &identity(1), &sql("SELECT 1"), deadline())
        .unwrap();
    let old = database.read_head(deadline()).unwrap();
    let raw = objects
        .get(
            &object_key(&scope(), 1, &receipt.result_hash),
            MAX_OBJECT_BYTES,
            deadline(),
        )
        .unwrap()
        .bytes;
    let begin = database
        .compact_begin(7, old.head.head_serial, deadline())
        .unwrap();
    let plan = begin.storage.plan.as_ref().unwrap().clone();
    assert_eq!(begin.revision, old.head.revision);
    assert_eq!(begin.transition, old.head.transition);
    assert!(!begin.active);
    let mut policy = begin.policy.clone();
    policy.push(Permission {
        principal: 8,
        read: true,
        write: false,
        admin: false,
    });
    let changed = database
        .set_policy(7, begin.revision, 90, policy, deadline())
        .unwrap();
    assert_eq!(
        changed.storage.plan.as_ref().unwrap().basis.revision,
        old.head.revision
    );
    let sealed = database.compact_copy(7, plan.serial, deadline()).unwrap();
    assert_eq!(sealed.policy, changed.policy);
    assert_eq!(
        sealed.storage.plan.as_ref().unwrap().phase,
        CopyPhase::Sealed
    );
    assert_eq!(
        objects
            .get(
                &object_key(&scope(), 2, &receipt.result_hash),
                MAX_OBJECT_BYTES,
                deadline()
            )
            .unwrap()
            .bytes,
        raw
    );
    assert_eq!(
        database.compact_copy(7, plan.serial, deadline()).unwrap(),
        sealed
    );
    let promoted = database
        .compact_promote(7, plan.serial, deadline())
        .unwrap();
    assert_eq!(promoted.policy, changed.policy);
    assert_eq!(promoted.revision, changed.revision);
    assert_eq!(promoted.storage.active_generation, 2);
    assert!(!promoted.active);
    assert!(
        matches!(database.lookup(7, &receipt.request, deadline()).unwrap(), Resolution::Committed { receipt: saved, .. } if saved == receipt)
    );
    assert!(matches!(
        session.execute(7, &identity(2), &sql("SELECT 1"), deadline()),
        Err(Error::Fenced)
    ));
    let (active, mut recovered) = database
        .activate_session(
            7,
            promoted.revision,
            91,
            &temporary.path().join("target"),
            deadline(),
        )
        .unwrap();
    assert!(active.active);
    assert_eq!(
        recovered
            .execute(7, &identity(1), &sql("SELECT 1"), deadline())
            .unwrap(),
        (receipt, value)
    );
    let garbage = GarbageMemory::new(objects.clone());
    let report = database
        .gc_prepare(
            7,
            active.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    let serial = report.head.storage.sweep.as_ref().unwrap().serial;
    assert!(!garbage
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::Delete(..))));
    let done = database.gc_resume(7, serial, &garbage, deadline()).unwrap();
    assert!(done.head.storage.sweep.is_none());
    assert!(objects
        .entries()
        .iter()
        .all(|(key, _)| !key.contains("/storage/1/objects/")));
    assert!(database
        .session(7, &temporary.path().join("cold"), deadline())
        .is_ok());
}

#[test]
fn freeze_guards_all_mutations_but_preserves_authorized_reads_and_policy() {
    let (_, database) = fixture();
    let head = database.status(7, deadline()).unwrap();
    let begin = database
        .compact_begin(7, head.head_serial, deadline())
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    for result in [
        database.takeover(7, begin.revision, 3, deadline()),
        database.activate(7, begin.revision, 3, deadline()),
        database.set_quota(
            7,
            begin.revision,
            3,
            DatabaseQuota { max_bytes: None },
            deadline(),
        ),
        database.close_full(7, begin.revision, 3, deadline()),
        database.set_lifecycle(7, begin.revision, 3, Lifecycle::Maintenance, deadline()),
    ] {
        assert!(matches!(result, Err(Error::Fenced)));
    }
    assert!(matches!(
        database.activate_session(
            7,
            begin.revision,
            3,
            &temporary.path().join("blocked"),
            deadline()
        ),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.cancel(7, &identity(99), deadline()),
        Err(Error::Fenced)
    ));
    assert!(database
        .query(
            7,
            &sql("SELECT 1"),
            &temporary.path().join("read"),
            deadline()
        )
        .is_ok());
    assert!(database
        .set_policy(7, begin.revision, 4, begin.policy.clone(), deadline())
        .is_ok());
}

#[test]
fn abort_never_reuses_target_and_old_target_failure_expires_without_current_poison() {
    let (objects, database) = fixture();
    let head = database.status(7, deadline()).unwrap();
    let begin = database
        .compact_begin(7, head.head_serial, deadline())
        .unwrap();
    let snapshot = database.read_head(deadline()).unwrap();
    let plan = begin.storage.plan.as_ref().unwrap();
    let target = ObjectContext::target(&database, &snapshot, plan, deadline()).unwrap();
    let aborted = database.compact_abort(7, plan.serial, deadline()).unwrap();
    let next = database
        .compact_begin(7, aborted.head_serial, deadline())
        .unwrap();
    assert_eq!(next.storage.active_generation, 1);
    assert_eq!(next.storage.plan.as_ref().unwrap().target, 3);
    assert!(next.storage.retired(2));
    let before = objects.gets_for(&head_key(&scope()));
    assert!(matches!(
        target.load(&head.data_root, deadline()),
        Err(Error::SnapshotExpired)
    ));
    assert_eq!(objects.gets_for(&head_key(&scope())), before + 1);
    assert!(database.healthy_in(1).is_ok());
    assert!(matches!(
        target.load(&head.data_root, deadline()),
        Err(Error::Unknown)
    ));
    assert_eq!(objects.gets_for(&head_key(&scope())), before + 1);
    assert!(matches!(
        database.compact_promote(7, plan.serial, deadline()),
        Err(Error::Conflict)
    ));
}

#[test]
fn local_budget_closes_attempt_without_probe_or_lineage_incident() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    objects.fail(
        false,
        object_key(&scope(), 1, &base.head.data_root),
        StoreError::Budget,
    );
    let before = objects.gets_for(&head_key(&scope()));
    assert!(matches!(
        context.load(&base.head.data_root, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    assert_eq!(objects.gets_for(&head_key(&scope())), before);
    assert!(database.healthy().is_ok());
    assert!(matches!(
        context.load(&base.head.data_root, deadline()),
        Err(Error::Unknown)
    ));
    assert!(database.healthy().is_ok());
}

#[test]
fn unresolved_old_generation_incident_does_not_poison_fresh_current_attempts() {
    let (objects, database) = fixture();
    let original = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
    let head = promote(&database);
    objects.remove(&object_key(&scope(), 1, &original.head.data_root));
    objects.fail(false, head_key(&scope()), StoreError::Unknown);
    assert!(matches!(
        context.load(&original.head.data_root, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
    assert!(database.healthy_in(2).is_ok());
    let changed = database
        .set_policy(7, head.revision, 55, head.policy.clone(), deadline())
        .unwrap();
    assert_eq!(changed.storage.active_generation, 2);
    assert!(matches!(
        context.load(&original.head.data_root, deadline()),
        Err(Error::Unknown)
    ));
    assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
    let independent = Database::new(objects, scope(), 10).unwrap();
    assert!(independent.healthy().is_ok());
}

#[test]
fn hash_valid_target_scope_semantics_cannot_be_expired_after_abort() {
    let (objects, database) = fixture();
    let head = database.status(7, deadline()).unwrap();
    let begin = database
        .compact_begin(7, head.head_serial, deadline())
        .unwrap();
    let snapshot = database.read_head(deadline()).unwrap();
    let plan = begin.storage.plan.as_ref().unwrap();
    let target = ObjectContext::target(&database, &snapshot, plan, deadline()).unwrap();
    let mut foreign = scope();
    foreign.tenant += 1;
    let bytes = encode_object(&Envelope {
        format: 2,
        scope: foreign,
        payload: Payload::Manifest(Manifest {
            page_count: 0,
            root: None,
        }),
    })
    .unwrap();
    let hash = digest(&bytes);
    objects.set(object_key(&scope(), 2, &hash), bytes);
    database.compact_abort(7, plan.serial, deadline()).unwrap();
    let before = objects.gets_for(&head_key(&scope()));
    assert!(matches!(
        target.load(&hash, deadline()),
        Err(Error::Format(FormatError::Corrupt))
    ));
    assert_eq!(objects.gets_for(&head_key(&scope())), before);
    assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
}

#[test]
fn target_incident_blocks_promotion_and_retirement_gc_does_not_clear_semantics() {
    let (objects, database) = fixture();
    let head = database.status(7, deadline()).unwrap();
    let begin = database
        .compact_begin(7, head.head_serial, deadline())
        .unwrap();
    let serial = begin.storage.plan.as_ref().unwrap().serial;
    database.compact_copy(7, serial, deadline()).unwrap();
    let snapshot = database.read_head(deadline()).unwrap();
    let target = ObjectContext::target(
        &database,
        &snapshot,
        snapshot.head.storage.plan.as_ref().unwrap(),
        deadline(),
    )
    .unwrap();
    objects.fail(
        false,
        object_key(&scope(), 2, &head.data_root),
        StoreError::Missing,
    );
    assert!(matches!(
        target.load(&head.data_root, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(
        database.compact_promote(7, serial, deadline()),
        Err(Error::Corrupt)
    ));
    assert!(database.healthy_in(1).is_ok());
    database.compact_abort(7, serial, deadline()).unwrap();
    let later = ObjectContext::target(
        &database,
        &snapshot,
        snapshot.head.storage.plan.as_ref().unwrap(),
        deadline(),
    )
    .unwrap();
    objects.fail(
        false,
        object_key(&scope(), 2, &head.data_root),
        StoreError::Missing,
    );
    assert!(matches!(
        later.load(&head.data_root, deadline()),
        Err(Error::SnapshotExpired)
    ));
    database.quarantined.store(true, Ordering::Release);
    drop(later);
    drop(target);
    assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
}

#[test]
fn unknown_delete_retains_original_condition_and_new_etag_requires_real_conflict() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let garbage = GarbageMemory::new(objects.clone());
    let prepared = database
        .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
        .unwrap();
    let checkpoint = prepared.head.storage.sweep.as_ref().unwrap().clone();
    let first = &checkpoint.entries[0];
    let raw = objects
        .get(&first.key, MAX_OBJECT_BYTES, deadline())
        .unwrap()
        .bytes;
    garbage.lose_delete.store(true, Ordering::Release);
    assert!(matches!(
        database.gc_resume(7, checkpoint.serial, &garbage, deadline()),
        Err(Error::Gc(GcError::Unknown))
    ));
    assert_eq!(
        database
            .status(7, deadline())
            .unwrap()
            .storage
            .sweep
            .as_ref(),
        Some(&checkpoint)
    );
    objects.set(first.key.clone(), raw);
    let independent = Database::new(objects.clone(), scope(), 10).unwrap();
    let done = independent
        .gc_resume(7, checkpoint.serial, &garbage, deadline())
        .unwrap();
    assert!(done.head.storage.sweep.is_none());
    assert!(objects
        .get(&first.key, MAX_OBJECT_BYTES, deadline())
        .is_ok());
    let attempts: Vec<_> = garbage
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            Event::Delete(key, etag) if key == &first.key => Some(etag.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(attempts, vec![first.etag.clone(), first.etag.clone()]);
    let again = independent
        .gc_prepare(
            7,
            done.head.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert_ne!(
        again.head.storage.sweep.as_ref().unwrap().entries[0].etag,
        first.etag
    );
    independent
        .gc_resume(
            7,
            again.head.storage.sweep.as_ref().unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        objects.get(&first.key, MAX_OBJECT_BYTES, deadline()),
        Err(StoreError::Missing)
    ));
}

#[test]
fn typed_absence_finishes_unknown_delete_but_unknown_inspect_keeps_checkpoint() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let garbage = GarbageMemory::new(objects.clone());
    let prepared = database
        .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
        .unwrap();
    let serial = prepared.head.storage.sweep.as_ref().unwrap().serial;
    garbage.lose_delete.store(true, Ordering::Release);
    assert!(matches!(
        database.gc_resume(7, serial, &garbage, deadline()),
        Err(Error::Gc(GcError::Unknown))
    ));
    *garbage.inspect_error.lock().unwrap() = Some(GcError::Unknown);
    assert!(matches!(
        database.gc_resume(7, serial, &garbage, deadline()),
        Err(Error::Gc(GcError::Unknown))
    ));
    assert_eq!(
        database.status(7, deadline()).unwrap().storage.sweep,
        prepared.head.storage.sweep
    );
    assert!(database
        .gc_resume(7, serial, &garbage, deadline())
        .unwrap()
        .head
        .storage
        .sweep
        .is_none());
    assert!(matches!(
        database.gc_resume(7, serial, &garbage, deadline()),
        Err(Error::Conflict)
    ));
}

#[test]
fn late_retired_put_is_found_by_a_new_round_and_never_changes_current_generation() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let garbage = GarbageMemory::new(objects.clone());
    let key = object_key(&scope(), 1, &head.data_root);
    let bytes = objects
        .get(&key, MAX_OBJECT_BYTES, deadline())
        .unwrap()
        .bytes;
    let prepared = database
        .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
        .unwrap();
    let done = database
        .gc_resume(
            7,
            prepared.head.storage.sweep.as_ref().unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    let empty = database
        .gc_prepare(
            7,
            done.head.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert_eq!(empty.scanned, 0);
    assert!(empty.exhausted);
    objects
        .put(&key, &bytes, Condition::Absent, deadline())
        .unwrap();
    let again = database
        .gc_prepare(
            7,
            empty.head.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert_eq!(again.scanned, 1);
    let final_head = database
        .gc_resume(
            7,
            again.head.storage.sweep.as_ref().unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap()
        .head;
    assert_eq!(final_head.data_root, head.data_root);
    assert!(objects
        .get(
            &object_key(&scope(), 2, &head.data_root),
            MAX_OBJECT_BYTES,
            deadline()
        )
        .is_ok());
}

#[test]
fn failure_probe_rejects_serial_body_etag_and_allocation_contradictions() {
    for mutation in 0..7 {
        let (objects, database) = fixture();
        let head = database.status(7, deadline()).unwrap();
        let begin = database
            .compact_begin(7, head.head_serial, deadline())
            .unwrap();
        database
            .compact_abort(7, begin.storage.plan.as_ref().unwrap().serial, deadline())
            .unwrap();
        let original = database.read_head(deadline()).unwrap();
        let context = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
        let mut changed = original.head.clone();
        match mutation {
            0 => changed.head_serial -= 1,
            1 => changed.storage.allocated_through = 1,
            2 => {} // Same serial and identical body, but a different conditional token.
            3 => changed.auth_epoch += 1,
            4 => changed.storage.allocated_through += 1,
            5 => changed.head_serial += 1,
            _ => changed.scope.generation += 1,
        }
        let bytes = encode_head(&changed).unwrap();
        objects.fail(
            false,
            object_key(&scope(), 1, &original.head.data_root),
            StoreError::Missing,
        );
        objects.replace_after(2, head_key(&scope()), bytes, mutation != 2);
        let before = objects.gets_for(&head_key(&scope()));
        assert!(
            matches!(
                context.load(&original.head.data_root, deadline()),
                Err(Error::Store(StoreError::Missing))
            ),
            "mutation {mutation}"
        );
        assert_eq!(objects.gets_for(&head_key(&scope())), before + 1);
        assert!(
            database.quarantined.load(Ordering::Acquire),
            "mutation {mutation}"
        );
    }
}

#[test]
fn lost_prepare_and_disposition_cas_leave_a_durable_resumable_batch() {
    for lost_stage in 0..2 {
        let (objects, database) = fixture();
        let head = promote(&database);
        let garbage = GarbageMemory::new(objects.clone());
        if lost_stage == 0 {
            objects.lose_next_cas();
        }
        let prepared =
            database.gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline());
        if lost_stage == 0 {
            assert!(matches!(prepared, Err(Error::Store(StoreError::Unknown))));
        } else {
            assert!(prepared.is_ok());
        }
        let batch = database
            .status(7, deadline())
            .unwrap()
            .storage
            .sweep
            .unwrap();
        if lost_stage == 1 {
            objects.lose_next_cas();
            assert!(matches!(
                database.gc_resume(7, batch.serial, &garbage, deadline()),
                Err(Error::Store(StoreError::Unknown))
            ));
            assert!(database
                .status(7, deadline())
                .unwrap()
                .storage
                .sweep
                .as_ref()
                .unwrap()
                .entries
                .iter()
                .all(|entry| entry.disposition != SweepDisposition::Pending));
        }
        let independent = Database::new(objects, scope(), 10).unwrap();
        assert!(independent
            .gc_resume(7, batch.serial, &garbage, deadline())
            .unwrap()
            .head
            .storage
            .sweep
            .is_none());
    }
}

#[test]
fn prepared_batch_and_copy_are_mutually_exclusive_and_current_generations_cannot_sweep() {
    let (objects, database) = fixture();
    let garbage = GarbageMemory::new(objects);
    let head = promote(&database);
    for generation in [0, 2, 3, u64::MAX] {
        assert!(matches!(
            database.gc_prepare(
                7,
                head.head_serial,
                generation,
                None,
                &garbage,
                &garbage,
                deadline()
            ),
            Err(Error::Fenced)
        ));
    }
    assert!(matches!(
        database.gc_prepare(
            7,
            head.head_serial,
            1,
            Some("../head"),
            &garbage,
            &garbage,
            deadline()
        ),
        Err(Error::Format(FormatError::Invalid))
    ));
    assert!(matches!(
        database.gc_prepare(
            7,
            head.head_serial - 1,
            1,
            None,
            &garbage,
            &garbage,
            deadline()
        ),
        Err(Error::Conflict)
    ));
    let report = database
        .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
        .unwrap();
    assert!(matches!(
        database.compact_begin(7, report.head.head_serial, deadline()),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        database.set_lifecycle(7, report.head.revision, 71, Lifecycle::Deleted, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.gc_prepare(
            7,
            report.head.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline()
        ),
        Err(Error::Conflict)
    ));
}

#[test]
fn lineage_context_capacity_rejects_admission_without_creating_a_capability() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let mut live: Vec<_> = (0..64)
        .map(|_| ObjectContext::from_snapshot(&database, &base, deadline()).unwrap())
        .collect();
    let before = objects.operation_count();
    let cloned = database.clone();
    assert!(matches!(
        ObjectContext::from_snapshot(&cloned, &base, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    assert!(matches!(
        ObjectContext::capture(&cloned, &base.head),
        Err(Error::Store(StoreError::Budget))
    ));
    assert!(matches!(
        ObjectContext::bootstrap(&cloned),
        Err(Error::Store(StoreError::Budget))
    ));
    assert!(matches!(
        cloned.create(7, 50, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    assert_eq!(objects.operation_count(), before);
    live.pop();
    let fresh = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    assert!(fresh.load(&base.head.data_root, deadline()).is_ok());
    assert!(matches!(
        ObjectContext::from_snapshot(&cloned, &base, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    drop(fresh);
    assert!(ObjectContext::from_snapshot(&cloned, &base, deadline()).is_ok());
    assert!(database.healthy().is_ok());
}

#[test]
fn unresolved_generation_slots_are_bounded_and_only_proven_retirement_releases_one() {
    let (objects, database) = fixture();
    let mut head = database.status(7, deadline()).unwrap();
    let mut first = None;
    for generation in 1..=64 {
        head.storage.active_generation = generation;
        head.storage.allocated_through = generation;
        head.head_serial = generation + 2;
        objects.set(head_key(&scope()), encode_head(&head).unwrap());
        let snapshot = database.read_head(deadline()).unwrap();
        if generation == 1 {
            first = Some(snapshot.clone());
        }
        let context = ObjectContext::from_snapshot(&database, &snapshot, deadline()).unwrap();
        objects.fail(
            false,
            object_key(&scope(), generation, &head.data_root),
            StoreError::Missing,
        );
        objects.fail(false, head_key(&scope()), StoreError::Unknown);
        assert!(matches!(
            context.load(&head.data_root, deadline()),
            Err(Error::Store(StoreError::Missing))
        ));
        assert!(matches!(context.healthy(), Err(Error::Unknown)));
    }
    head.head_serial = 67;
    head.storage.active_generation = 65;
    head.storage.allocated_through = 65;
    objects.set(head_key(&scope()), encode_head(&head).unwrap());
    let current = database.read_head(deadline()).unwrap();
    assert!(matches!(
        ObjectContext::from_snapshot(&database, &current, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    let old = ObjectContext::from_snapshot(&database, &first.unwrap(), deadline()).unwrap();
    objects.remove(&object_key(&scope(), 1, &head.data_root));
    assert!(matches!(
        old.load(&head.data_root, deadline()),
        Err(Error::SnapshotExpired)
    ));
    drop(old);
    let fresh = ObjectContext::from_snapshot(&database, &current, deadline()).unwrap();
    assert!(fresh.healthy().is_ok());
    assert!(matches!(database.healthy_in(2), Err(Error::Corrupt)));
    assert!(!database.quarantined.load(Ordering::Acquire));
}

#[test]
fn active_generation_rollback_is_an_authority_fault_not_retirement() {
    let (objects, database) = fixture();
    let head = promote(&database);
    let base = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    let mut rollback = head.clone();
    rollback.head_serial += 1;
    rollback.storage.active_generation = 1;
    objects.set(head_key(&scope()), encode_head(&rollback).unwrap());
    objects.fail(
        false,
        object_key(&scope(), 2, &head.data_root),
        StoreError::Missing,
    );
    assert!(matches!(
        context.load(&head.data_root, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(database.quarantined.load(Ordering::Acquire));
}

#[test]
fn context_deadline_cannot_be_extended_and_callback_failure_closes_only_the_prefix() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let expired = ObjectContext::from_snapshot(&database, &base, Instant::now()).unwrap();
    let before = objects.operation_count();
    assert!(matches!(
        expired.load(&base.head.data_root, deadline()),
        Err(Error::Unknown)
    ));
    assert_eq!(objects.operation_count(), before);
    assert!(matches!(
        expired.save_raw(&base.head.data_root, b"not admitted", deadline()),
        Err(Error::Unknown)
    ));
    assert_eq!(objects.operation_count(), before);
    let context = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    assert!(matches!(
        context.with_raw(&base.head.data_root, deadline(), |_, _| Err::<(), _>(
            Error::Limit
        )),
        Err(Error::Limit)
    ));
    assert!(matches!(context.healthy(), Err(Error::Unknown)));
    assert!(database.healthy().is_ok());
    assert!(matches!(
        context.load(&base.head.data_root, deadline()),
        Err(Error::Unknown)
    ));
}

#[test]
fn every_technical_transition_refuses_serial_exhaustion_without_resetting_it() {
    for action in 0..6 {
        let (objects, database) = fixture();
        let mut head = database.status(7, deadline()).unwrap();
        if action <= 2 {
            head = database
                .compact_begin(7, head.head_serial, deadline())
                .unwrap();
            if action == 1 {
                head = database
                    .compact_copy(7, head.storage.plan.as_ref().unwrap().serial, deadline())
                    .unwrap();
            }
        } else {
            head = promote(&database);
        }
        let garbage = GarbageMemory::new(objects.clone());
        if action >= 4 {
            head = database
                .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
                .unwrap()
                .head;
            if action == 5 {
                for entry in &mut head.storage.sweep.as_mut().unwrap().entries {
                    entry.disposition = SweepDisposition::Applied;
                }
            }
        }
        head.head_serial = u64::MAX;
        objects.set(head_key(&scope()), encode_head(&head).unwrap());
        let result = match action {
            0 => database
                .compact_copy(7, head.storage.plan.as_ref().unwrap().serial, deadline())
                .map(|_| ()),
            1 => database
                .compact_promote(7, head.storage.plan.as_ref().unwrap().serial, deadline())
                .map(|_| ()),
            2 => database
                .compact_abort(7, head.storage.plan.as_ref().unwrap().serial, deadline())
                .map(|_| ()),
            3 => database
                .gc_prepare(7, head.head_serial, 1, None, &garbage, &garbage, deadline())
                .map(|_| ()),
            _ => database
                .gc_resume(
                    7,
                    head.storage.sweep.as_ref().unwrap().serial,
                    &garbage,
                    deadline(),
                )
                .map(|_| ()),
        };
        assert!(matches!(result, Err(Error::Limit)), "action {action}");
        assert_eq!(database.status(7, deadline()).unwrap(), head);
    }
}

#[test]
fn physical_hash_failure_can_expire_but_a_hash_valid_contract_violation_cannot() {
    let (objects, database) = fixture();
    let old = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &old, deadline()).unwrap();
    promote(&database);
    objects.set(object_key(&scope(), 1, &old.head.data_root), vec![0]);
    assert!(matches!(
        context.load(&old.head.data_root, deadline()),
        Err(Error::SnapshotExpired)
    ));
    assert!(!database.quarantined.load(Ordering::Acquire));
    drop(context);
    let current = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &current, deadline()).unwrap();
    // Internal raw-save ports also detect a caller violating its hash/bytes
    // contract: an already stored hash-valid object cannot be replaced.
    assert!(matches!(
        context.save_raw(
            &current.head.data_root,
            b"different expected frame",
            deadline()
        ),
        Err(Error::Corrupt)
    ));
    assert!(database.quarantined.load(Ordering::Acquire));
}

struct DiagnosticPort {
    objects: Arc<Memory>,
    oversized: AtomicBool,
    empty_head_etag: AtomicBool,
    expire_response: AtomicBool,
}
impl Objects for DiagnosticPort {
    fn get(
        &self,
        key: &str,
        maximum: usize,
        until: Instant,
    ) -> Result<scap_object_store::Stored, StoreError> {
        if key.ends_with("/head") {
            let mut stored = self.objects.get(key, maximum, until)?;
            if self.empty_head_etag.load(Ordering::Acquire) {
                stored.etag.clear();
            }
            return Ok(stored);
        }
        if self.oversized.load(Ordering::Acquire) {
            return Ok(scap_object_store::Stored {
                bytes: vec![0; MAX_OBJECT_BYTES + 1],
                etag: "oversized".into(),
            });
        }
        if self.expire_response.load(Ordering::Acquire) {
            std::thread::sleep(
                until.saturating_duration_since(Instant::now())
                    + std::time::Duration::from_millis(1),
            );
            return Err(StoreError::Missing);
        }
        self.objects.get(key, maximum, until)
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        self.objects.put(key, bytes, condition, until)
    }
}

#[test]
fn diagnostic_response_bounds_tokens_and_original_time_are_enforced() {
    for fault in 0..4 {
        let (objects, _) = fixture();
        let port = Arc::new(DiagnosticPort {
            objects: objects.clone(),
            oversized: AtomicBool::new(false),
            empty_head_etag: AtomicBool::new(false),
            expire_response: AtomicBool::new(false),
        });
        let database = Database::new(port.clone(), scope(), 10).unwrap();
        let base = database.read_head(deadline()).unwrap();
        let until = if fault == 2 {
            Instant::now() + std::time::Duration::from_millis(50)
        } else {
            deadline()
        };
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        if fault == 0 {
            port.oversized.store(true, Ordering::Release);
        }
        if fault == 1 {
            port.empty_head_etag.store(true, Ordering::Release);
        }
        if fault == 2 {
            port.expire_response.store(true, Ordering::Release);
        }
        if fault == 3 {
            objects.set(head_key(&scope()), b"invalid authority JSON".to_vec());
        }
        objects.remove(&object_key(&scope(), 1, &base.head.data_root));
        let before = objects.gets_for(&head_key(&scope()));
        let result = context.load(&base.head.data_root, deadline());
        assert!(if fault == 0 {
            matches!(result, Err(Error::Format(FormatError::Corrupt)))
        } else {
            matches!(result, Err(Error::Store(StoreError::Missing)))
        });
        assert_eq!(
            objects.gets_for(&head_key(&scope())) - before,
            usize::from(fault != 2)
        );
        assert_eq!(
            database.quarantined.load(Ordering::Acquire),
            fault == 1 || fault == 3
        );
        assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
    }
}

#[test]
fn source_and_target_incidents_block_copy_and_invalid_gc_tokens_never_publish() {
    for target_incident in [false, true] {
        let (objects, database) = fixture();
        let head = database.status(7, deadline()).unwrap();
        let begin = database
            .compact_begin(7, head.head_serial, deadline())
            .unwrap();
        let base = database.read_head(deadline()).unwrap();
        let plan = begin.storage.plan.as_ref().unwrap();
        let context = if target_incident {
            ObjectContext::target(&database, &base, plan, deadline()).unwrap()
        } else {
            ObjectContext::from_snapshot(&database, &base, deadline()).unwrap()
        };
        objects.fail(
            false,
            object_key(
                &scope(),
                if target_incident { 2 } else { 1 },
                &head.data_root,
            ),
            StoreError::Missing,
        );
        assert!(matches!(
            context.load(&head.data_root, deadline()),
            Err(Error::Store(StoreError::Missing))
        ));
        assert!(matches!(
            database.compact_copy(7, plan.serial, deadline()),
            Err(Error::Corrupt)
        ));
        assert_eq!(database.status(7, deadline()).unwrap(), begin);
    }
    struct InvalidTag;
    impl Garbage for InvalidTag {
        fn inspect(&self, _: &str, _: &str, _: Instant) -> Result<GcCandidate, GcError> {
            Ok(GcCandidate::Present {
                etag: "unquoted".into(),
            })
        }
        fn delete(&self, _: &str, _: &str, _: &str, _: Instant) -> Result<DeleteOutcome, GcError> {
            panic!("invalid checkpoint cannot authorize deletion")
        }
    }
    let (objects, database) = fixture();
    let head = promote(&database);
    let listing = GarbageMemory::new(objects);
    assert!(matches!(
        database.gc_prepare(
            7,
            head.head_serial,
            1,
            None,
            &listing,
            &InvalidTag,
            deadline()
        ),
        Err(Error::Format(FormatError::Invalid))
    ));
    assert_eq!(database.status(7, deadline()).unwrap(), head);
    database.quarantined.store(true, Ordering::Release);
    assert!(matches!(
        database.compact_begin(7, head.head_serial, deadline()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn copy_advances_multiple_cursor_steps_and_keeps_all_original_receipts() {
    let objects = Arc::new(Memory::default());
    let mut options = crate::tests::test_options();
    options.retention.max_entries = 128;
    let database = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
    database.create(7, 1, deadline()).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let (_, mut session) = database
        .activate_session(7, 1, 2, &temporary.path().join("native"), deadline())
        .unwrap();
    let mut receipts = Vec::new();
    for id in 1..=65 {
        receipts.push(
            session
                .execute(7, &identity(id), &sql("SELECT 1"), deadline())
                .unwrap()
                .0,
        );
    }
    let before = database.status(7, deadline()).unwrap();
    assert_eq!(before.windows[0].count, 65);
    let after = promote(&database);
    assert_eq!(after.windows, before.windows);
    assert_eq!(after.sequence, before.sequence);
    for receipt in receipts {
        assert!(
            matches!(database.lookup(7,&receipt.request,deadline()).unwrap(),Resolution::Committed{receipt:actual,..} if actual==receipt)
        );
        let source = objects
            .get(
                &object_key(&scope(), 1, &receipt.result_hash),
                MAX_OBJECT_BYTES,
                deadline(),
            )
            .unwrap();
        let target = objects
            .get(
                &object_key(&scope(), 2, &receipt.result_hash),
                MAX_OBJECT_BYTES,
                deadline(),
            )
            .unwrap();
        assert_eq!(source.bytes, target.bytes);
    }
}

type ReadHook = Box<dyn FnOnce() + Send>;
struct HookPort {
    objects: Arc<Memory>,
    hook: Mutex<Option<(String, ReadHook)>>,
}
impl Objects for HookPort {
    fn get(
        &self,
        key: &str,
        maximum: usize,
        until: Instant,
    ) -> Result<scap_object_store::Stored, StoreError> {
        let stored = self.objects.get(key, maximum, until);
        let hook = {
            let mut guard = self.hook.lock().unwrap();
            if guard.as_ref().is_some_and(|(expected, _)| expected == key) {
                guard.take()
            } else {
                None
            }
        };
        if let Some((_, run)) = hook {
            run();
        }
        stored
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        self.objects.put(key, bytes, condition, until)
    }
}

#[test]
fn copy_rechecks_source_and_target_lineage_after_the_complete_raw_traversal() {
    for target in [false, true] {
        let (objects, _) = fixture();
        let port = Arc::new(HookPort {
            objects: objects.clone(),
            hook: Mutex::new(None),
        });
        let database = Database::new(port.clone(), scope(), 10).unwrap();
        let head = database.status(7, deadline()).unwrap();
        let begin = database
            .compact_begin(7, head.head_serial, deadline())
            .unwrap();
        let base = database.read_head(deadline()).unwrap();
        let plan = begin.storage.plan.as_ref().unwrap();
        let context = if target {
            ObjectContext::target(&database, &base, plan, deadline()).unwrap()
        } else {
            ObjectContext::from_snapshot(&database, &base, deadline()).unwrap()
        };
        let root = head.data_root.clone();
        let fail_objects = objects.clone();
        *port.hook.lock().unwrap() = Some((
            object_key(&scope(), 2, &head.windows[0].root),
            Box::new(move || {
                fail_objects.fail(
                    false,
                    object_key(&scope(), if target { 2 } else { 1 }, &root),
                    StoreError::Missing,
                );
                assert!(matches!(
                    context.load(&root, deadline()),
                    Err(Error::Store(StoreError::Missing))
                ));
            }),
        ));
        assert!(matches!(
            database.compact_copy(7, plan.serial, deadline()),
            Err(Error::Corrupt)
        ));
        assert_eq!(database.status(7, deadline()).unwrap(), begin);
    }
}

#[test]
fn every_copy_prefix_stop_including_after_completion_withholds_seal() {
    use std::cell::Cell;
    fn attempt(stop_at: usize) -> usize {
        let (_, database) = fixture();
        let head = database.status(7, deadline()).unwrap();
        let begun = database
            .compact_begin(7, head.head_serial, deadline())
            .unwrap();
        let original = database.read_head(deadline()).unwrap();
        let plan = original.head.storage.plan.as_ref().unwrap();
        let source = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
        let target = ObjectContext::target(&database, &original, plan, deadline()).unwrap();
        let calls = Cell::new(0);
        let stop = || {
            calls.set(calls.get() + 1);
            calls.get() == stop_at
        };
        let result = copy_closure(&source, &target, &original, plan, deadline(), &stop);
        if stop_at == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::Unknown)), "stop {stop_at}");
        }
        assert_eq!(database.status(7, deadline()).unwrap(), begun);
        calls.get()
    }
    let checkpoints = attempt(0);
    assert!(checkpoints > 4);
    for at in 1..=checkpoints {
        attempt(at);
    }
}

#[test]
fn concurrent_failures_on_one_prefix_have_only_one_original_diagnostic_probe() {
    use std::sync::Barrier;
    struct Racing {
        objects: Arc<Memory>,
        barrier: Barrier,
    }
    impl Objects for Racing {
        fn get(
            &self,
            key: &str,
            maximum: usize,
            until: Instant,
        ) -> Result<scap_object_store::Stored, StoreError> {
            if key.ends_with("/head") {
                return self.objects.get(key, maximum, until);
            }
            self.barrier.wait();
            Err(StoreError::Missing)
        }
        fn put(
            &self,
            key: &str,
            bytes: &[u8],
            condition: Condition<'_>,
            until: Instant,
        ) -> Result<String, StoreError> {
            self.objects.put(key, bytes, condition, until)
        }
    }
    let (objects, _) = fixture();
    let database = Database::new(
        Arc::new(Racing {
            objects: objects.clone(),
            barrier: Barrier::new(2),
        }),
        scope(),
        10,
    )
    .unwrap();
    let base = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    let before = objects.gets_for(&head_key(&scope()));
    std::thread::scope(|threads| {
        let left = threads.spawn(|| context.load(&base.head.data_root, deadline()));
        let right = threads.spawn(|| context.load(&base.head.data_root, deadline()));
        assert!(matches!(
            left.join().unwrap(),
            Err(Error::Store(StoreError::Missing))
        ));
        assert!(matches!(
            right.join().unwrap(),
            Err(Error::Store(StoreError::Missing))
        ));
    });
    assert_eq!(objects.gets_for(&head_key(&scope())), before + 1);
    assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
}

#[test]
fn old_validated_value_remains_usable_and_current_incident_survives_old_retirement() {
    let (objects, database) = fixture();
    let original = database.read_head(deadline()).unwrap();
    let old = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
    let materialized = old.load(&original.head.data_root, deadline()).unwrap();
    let head = promote(&database);
    let current = database.read_head(deadline()).unwrap();
    let current_context = ObjectContext::from_snapshot(&database, &current, deadline()).unwrap();
    objects.fail(
        false,
        object_key(&scope(), 2, &head.data_root),
        StoreError::Missing,
    );
    assert!(matches!(
        current_context.load(&head.data_root, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    objects.remove(&object_key(&scope(), 1, &head.data_root));
    assert!(matches!(
        old.load(&head.data_root, deadline()),
        Err(Error::SnapshotExpired)
    ));
    drop(old);
    assert!(matches!(database.healthy_in(2), Err(Error::Corrupt)));
    assert!(matches!(
        materialized,
        Payload::Manifest(Manifest { page_count: 0, .. })
    ));
}

fn deleted_direct(database: &Database) -> Head {
    let current = database.status(7, deadline()).unwrap();
    database
        .set_lifecycle(7, current.revision, 900, Lifecycle::Deleted, deadline())
        .unwrap()
}

#[test]
fn terminal_seal_preserves_business_identity_and_collects_final_active_generation() {
    let (objects, database) = fixture();
    let original = database.read_head(deadline()).unwrap();
    let old_context = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
    let materialized = old_context
        .load(&original.head.data_root, deadline())
        .unwrap();
    let candidate = Database::next(&original.head, 800).unwrap();
    let late = PreparedHead::new(&database, &original, &candidate, deadline()).unwrap();
    let deleted = deleted_direct(&database);
    let garbage = GarbageMemory::new(objects.clone());
    assert!(matches!(
        database.status(7, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.lookup(7, &identity(1), deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.gc_prepare(
            7,
            deleted.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline()
        ),
        Err(Error::Lifecycle)
    ));
    let sealed = database
        .retire_storage(7, deleted.head_serial, deadline())
        .unwrap();
    let mut expected = deleted.clone();
    expected.head_serial += 1;
    expected.format = 7;
    expected.active = false;
    expected.storage.terminal = Some(TerminalSeal {
        serial: expected.head_serial,
    });
    assert_eq!(sealed, expected);
    assert!(matches!(late.publish(), Err(Error::Conflict)));
    assert!(matches!(
        database.create(7, 901, deadline()),
        Err(Error::Store(StoreError::Conflict))
    ));
    let prepared = database
        .gc_prepare(
            7,
            sealed.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    let checkpoint = prepared.head.storage.sweep.as_ref().unwrap();
    assert!(checkpoint.serial > sealed.storage.terminal.as_ref().unwrap().serial);
    let done = database
        .gc_resume(7, checkpoint.serial, &garbage, deadline())
        .unwrap();
    assert!(done.head.storage.sweep.is_none());
    assert_eq!(done.head.storage.terminal, sealed.storage.terminal);
    assert!(objects
        .entries()
        .iter()
        .all(|(key, _)| key == &head_key(&scope())));
    let before = objects.operation_count();
    assert_eq!(database.storage_status(7, deadline()).unwrap(), done.head);
    assert_eq!(objects.operation_count(), before + 1);
    assert!(matches!(
        old_context.load(&original.head.data_root, deadline()),
        Err(Error::SnapshotExpired)
    ));
    assert!(!database.quarantined.load(Ordering::Acquire));
    assert!(matches!(
        materialized,
        Payload::Manifest(Manifest { page_count: 0, .. })
    ));
    let terminal = database.read_head(deadline()).unwrap();
    assert!(!old_context.matches(&terminal.head));
    assert!(matches!(
        ObjectContext::from_snapshot(&database, &terminal, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        ObjectContext::capture(&database, &terminal.head),
        Err(Error::Lifecycle)
    ));
    let plan = CopyPlan {
        serial: terminal.head.head_serial,
        source: 1,
        target: 2,
        phase: CopyPhase::Copying,
        basis: CopyBasis::capture(&terminal.head),
    };
    assert!(matches!(
        ObjectContext::target(&database, &terminal, &plan, deadline()),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        PreparedHead::new(
            &database,
            &terminal,
            &Database::next(&terminal.head, 902).unwrap(),
            deadline()
        ),
        Err(Error::Format(FormatError::Invalid))
    ));
    assert!(matches!(
        database.compact_begin(7, terminal.head.head_serial, deadline()),
        Err(Error::Lifecycle)
    ));
}

#[test]
fn terminal_admission_failures_and_unknown_cas_never_rebase_or_reclassify_state() {
    let (objects, database) = fixture();
    assert!(matches!(
        database.storage_status(7, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.retire_storage(7, 2, deadline()),
        Err(Error::Lifecycle)
    ));
    let deleted = deleted_direct(&database);
    assert!(matches!(
        database.storage_status(8, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.retire_storage(8, deleted.head_serial, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.retire_storage(7, deleted.head_serial - 1, deadline()),
        Err(Error::Conflict)
    ));
    for put in [false, true] {
        objects.fail(put, head_key(&scope()), StoreError::Unknown);
        assert!(matches!(
            database.retire_storage(7, deleted.head_serial, deadline()),
            Err(Error::Store(StoreError::Unknown))
        ));
        assert_eq!(database.storage_status(7, deadline()).unwrap(), deleted);
    }
    objects.fail(false, head_key(&scope()), StoreError::Unknown);
    assert!(matches!(
        database.storage_status(7, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    objects.lose_next_cas();
    let before = objects.operation_count();
    assert!(matches!(
        database.retire_storage(7, deleted.head_serial, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    assert_eq!(objects.operation_count(), before + 2);
    let observed = database.storage_status(7, deadline()).unwrap();
    assert_eq!(
        observed.storage.terminal.as_ref().unwrap().serial,
        deleted.head_serial + 1
    );
    for expected in [deleted.head_serial, observed.head_serial] {
        let before = objects.operation_count();
        assert!(matches!(
            database.retire_storage(7, expected, deadline()),
            Err(Error::Conflict)
        ));
        assert_eq!(objects.operation_count(), before + 1);
    }
}

#[test]
fn terminal_metadata_ignores_only_retired_physical_incidents_and_never_semantic_knowledge() {
    let (objects, database) = fixture();
    let original = database.read_head(deadline()).unwrap();
    let old = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
    let semantic = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
    let deleted = deleted_direct(&database);
    let sealed = database
        .retire_storage(7, deleted.head_serial, deadline())
        .unwrap();
    objects.fail(
        false,
        object_key(&scope(), 1, &original.head.data_root),
        StoreError::Missing,
    );
    objects.fail(false, head_key(&scope()), StoreError::Unknown);
    assert!(matches!(
        old.load(&original.head.data_root, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(database.healthy_in(1), Err(Error::Corrupt)));
    let garbage = GarbageMemory::new(objects.clone());
    let prepared = database
        .gc_prepare(
            7,
            sealed.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    let done = database
        .gc_resume(
            7,
            prepared.head.storage.sweep.as_ref().unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    assert!(database
        .healthy_domain(PublicationDomain::TerminalMetadata)
        .is_ok());
    let _ = semantic.observe(Error::Engine(scap_object_sqlite::Error::InvalidImage));
    assert!(database.quarantined.load(Ordering::Acquire));
    let base = database.read_head(deadline()).unwrap();
    let next = technical_next(&base.head).unwrap();
    assert!(matches!(
        database.publish_technical(&base, &next, deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(database.storage_status(7, deadline()).unwrap(), done.head);
}

#[test]
fn terminal_requires_healthy_original_lineage_and_never_reopens_or_changes_business_fields() {
    let (objects, database) = fixture();
    let original = database.read_head(deadline()).unwrap();
    let old = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
    let deleted = deleted_direct(&database);
    objects.fail(
        false,
        object_key(&scope(), 1, &original.head.data_root),
        StoreError::Missing,
    );
    assert!(matches!(
        old.load(&original.head.data_root, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(
        database.retire_storage(7, deleted.head_serial, deadline()),
        Err(Error::Corrupt)
    ));
    let independent = Database::new(objects.clone(), scope(), 10).unwrap();
    independent
        .retire_storage(7, deleted.head_serial, deadline())
        .unwrap();
    let base = independent.read_head(deadline()).unwrap();
    for change in 0..4 {
        let mut next = technical_next(&base.head).unwrap();
        match change {
            0 => {
                next.format = 6;
                next.storage.terminal = None;
            }
            1 => next.storage.allocated_through += 1,
            2 => next.revision += 1,
            _ => next.policy[0].read = false,
        }
        let before = objects.operation_count();
        assert!(matches!(
            independent.publish_technical(&base, &next, deadline()),
            Err(Error::Format(FormatError::Invalid))
        ));
        assert_eq!(objects.operation_count(), before);
    }
    let mut full = deleted;
    full.head_serial = u64::MAX;
    objects.set(head_key(&scope()), encode_head(&full).unwrap());
    assert!(matches!(
        independent.retire_storage(7, u64::MAX, deadline()),
        Err(Error::Limit)
    ));
}

#[test]
fn terminal_diagnostic_rejects_a_seal_that_predates_the_original_live_context() {
    for old_seal in [false, true] {
        let (objects, database) = fixture();
        let mut before = database.status(7, deadline()).unwrap();
        before.head_serial = 100;
        objects.set(head_key(&scope()), encode_head(&before).unwrap());
        let original = database.read_head(deadline()).unwrap();
        let context = ObjectContext::from_snapshot(&database, &original, deadline()).unwrap();
        let mut fresh = before;
        fresh.format = 7;
        fresh.lifecycle = Lifecycle::Deleted;
        fresh.active = false;
        fresh.head_serial = 102;
        fresh.storage.terminal = Some(TerminalSeal {
            serial: if old_seal { 3 } else { 101 },
        });
        objects.set(head_key(&scope()), encode_head(&fresh).unwrap());
        objects.remove(&object_key(&scope(), 1, &fresh.data_root));
        let result = context.load(&fresh.data_root, deadline());
        if old_seal {
            assert!(matches!(result, Err(Error::Store(StoreError::Missing))));
            assert!(database.quarantined.load(Ordering::Acquire));
        } else {
            assert!(matches!(result, Err(Error::SnapshotExpired)));
            assert!(!database.quarantined.load(Ordering::Acquire));
        }
    }
}

#[test]
fn terminal_collection_preserves_a_real_known_sql_receipt_and_committed_unavailable() {
    let (objects, database) = fixture();
    let statements: Vec<_> = sql("CREATE TABLE terminal_result(v BLOB)")
        .into_iter()
        .chain(sql(
            "INSERT INTO terminal_result VALUES(randomblob(8)) RETURNING hex(v)",
        ))
        .collect();
    let identity = request(1, 41, 7, &statements).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("receipt.sqlite");
    let (receipt, result) = database
        .execute(7, &identity, &statements, &file, deadline())
        .unwrap();
    let original = receipt.clone();
    let deleted = deleted_direct(&database);
    let sealed = database
        .retire_storage(7, deleted.head_serial, deadline())
        .unwrap();
    let garbage = GarbageMemory::new(objects.clone());
    let prepared = database
        .gc_prepare(
            7,
            sealed.head_serial,
            1,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    database
        .gc_resume(
            7,
            prepared.head.storage.sweep.as_ref().unwrap().serial,
            &garbage,
            deadline(),
        )
        .unwrap();
    let success = Database::finish(Some(Ok(receipt.clone())), Ok(result)).unwrap();
    assert_eq!(success.0, original);
    match Database::finish(
        Some(Ok(receipt)),
        Err(scap_object_sqlite::Error::InvalidImage),
    ) {
        Err(Error::CommittedButUnavailable(saved)) => assert_eq!(*saved, original),
        other => panic!("known commit lost its receipt: {other:?}"),
    }
    assert!(matches!(
        database.execute(7, &identity, &statements, &file, deadline()),
        Err(Error::Lifecycle)
    ));
    assert_eq!(database.storage_status(7, deadline()).unwrap().sequence, 1);
}

#[test]
fn exhausted_context_admission_propagates_budget_through_real_public_entrypoints() {
    for case in 0..9 {
        let (objects, database) = fixture();
        if matches!(case, 6 | 7) {
            database.takeover(7, 2, 60, deadline()).unwrap();
        }
        if case == 8 {
            for id in 1..=crate::tests::TEST_WINDOW {
                database
                    .cancel(7, &identity(id as u64), deadline())
                    .unwrap();
            }
        }
        let base = database.read_head(deadline()).unwrap();
        let contexts: Vec<_> = (0..64)
            .map(|_| ObjectContext::from_snapshot(&database, &base, deadline()).unwrap())
            .collect();
        let caller = database.clone();
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("unadmitted.sqlite");
        let statements = sql("SELECT 1");
        let request = request(1, 77, 7, &statements).unwrap();
        let before = objects.operation_count();
        let result = match case {
            0 => caller.lookup(7, &request, deadline()).map(|_| ()),
            1 => caller.cancel(7, &request, deadline()).map(|_| ()),
            2 => caller
                .execute(7, &request, &statements, &file, deadline())
                .map(|_| ()),
            3 => caller.session(7, &file, deadline()).map(|_| ()),
            4 => caller.query(7, &statements, &file, deadline()).map(|_| ()),
            5 => caller
                .set_quota(
                    7,
                    base.head.revision,
                    80,
                    base.head.quota.clone(),
                    deadline(),
                )
                .map(|_| ()),
            6 => caller
                .activate(7, base.head.revision, 80, deadline())
                .map(|_| ()),
            7 => caller
                .activate_session(7, base.head.revision, 80, &file, deadline())
                .map(|_| ()),
            _ => caller
                .close_full(7, base.head.revision, 80, deadline())
                .map(|_| ()),
        };
        assert!(
            matches!(result, Err(Error::Store(StoreError::Budget))),
            "case {case}: {result:?}"
        );
        assert_eq!(
            objects.operation_count(),
            before + 1,
            "only the original admission HEAD GET"
        );
        assert!(!file.exists());
        assert!(database.healthy().is_ok());
        // The private generic publication path is also reached by a real
        // lifecycle mutation; it cannot manufacture an unregistered context.
        let before = objects.operation_count();
        assert!(matches!(
            caller.set_lifecycle(
                7,
                base.head.revision,
                81,
                Lifecycle::Maintenance,
                deadline()
            ),
            Err(Error::Store(StoreError::Budget))
        ));
        assert_eq!(objects.operation_count(), before + 1);
        drop(contexts);
        assert!(ObjectContext::from_snapshot(&caller, &base, deadline()).is_ok());
    }
}

#[test]
fn copy_context_admission_bounds_both_namespaces_and_releases_a_partial_acquisition() {
    for held in [63, 64] {
        let (objects, database) = fixture();
        let started = database.compact_begin(7, 2, deadline()).unwrap();
        let serial = started.storage.plan.as_ref().unwrap().serial;
        let base = database.read_head(deadline()).unwrap();
        let contexts: Vec<_> = (0..held)
            .map(|_| ObjectContext::from_snapshot(&database, &base, deadline()).unwrap())
            .collect();
        let before = objects.operation_count();
        assert!(matches!(
            database.compact_copy(7, serial, deadline()),
            Err(Error::Store(StoreError::Budget))
        ));
        assert_eq!(objects.operation_count(), before + 1);
        assert!(database.healthy().is_ok());
        if held == 63 {
            // The source acquired slot 64 before target admission failed. Its
            // dropped prefix must return that slot, without touching any frame.
            let remaining = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
            assert!(matches!(
                ObjectContext::from_snapshot(&database, &base, deadline()),
                Err(Error::Store(StoreError::Budget))
            ));
            drop(remaining);
        }
        drop(contexts);
        let copied = database.compact_copy(7, serial, deadline()).unwrap();
        assert_eq!(
            copied.storage.plan.as_ref().unwrap().phase,
            CopyPhase::Sealed
        );
    }
}

#[test]
fn terminal_candidate_defends_against_busy_live_maintenance_inputs() {
    let (objects, database) = fixture();
    let begun = database.compact_begin(7, 2, deadline()).unwrap();
    let serial = begun.storage.plan.as_ref().unwrap().serial;
    database.compact_copy(7, serial, deadline()).unwrap();
    let base = database.read_head(deadline()).unwrap();
    let before = objects.operation_count();
    assert!(matches!(
        database.retire_deleted(base.clone(), base.head.head_serial, deadline()),
        Err(Error::Conflict)
    ));
    assert_eq!(objects.operation_count(), before);
    let abandoned = database.compact_abort(7, serial, deadline()).unwrap();
    let garbage = GarbageMemory::new(objects.clone());
    database
        .gc_prepare(
            7,
            abandoned.head_serial,
            2,
            None,
            &garbage,
            &garbage,
            deadline(),
        )
        .unwrap();
    let base = database.read_head(deadline()).unwrap();
    let before = objects.operation_count();
    assert!(matches!(
        database.retire_deleted(base.clone(), base.head.head_serial, deadline()),
        Err(Error::Conflict)
    ));
    assert_eq!(objects.operation_count(), before);
}
