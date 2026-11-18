use super::*;
use crate::catalogue::tests::discovery_tests::Listing;
use crate::catalogue::{
    DiscoveryBudget, DiscoveryError, MetadataState, RecoveryBudget, RecoveryCapability,
    RecoveryInventory, RecoveryJob, RecoveryStop, TenantReaders,
};
use crate::format::{Lifecycle, SnapshotLimits};
use crate::owner::{OwnerMode, OwnerNonces, OwnerPreparation, PrepareOwnerInput};

struct Reader;
impl TenantReaders for Reader {
    fn principal(&self, deployment: u64, tenant: u64) -> Option<u64> {
        assert_eq!((deployment, tenant), (1, 2));
        Some(7)
    }
}

#[test]
fn discovery_and_root_recovery_classify_both_restore_phases_without_opening_the_target() {
    for copied in [false, true] {
        let fixture = Fixture::new(true);
        let prepared = fixture.prepare();
        fixture.copying(&prepared);
        if copied {
            fixture.resume(&prepared, 2);
        }
        let expected = if copied {
            MetadataState::RestoreCopied
        } else {
            MetadataState::RestoreCopying
        };
        let scan = RecoveryInventory::new(
            fixture.objects.clone(),
            Listing::new(fixture.memory.clone()),
            RecoveryCapability::trusted_deployment(1, 20).unwrap(),
            test_options(),
        )
        .unwrap();
        let mut cursor = scan.begin();
        let mut target_observations = 0;
        for step in 0..200 {
            let page = scan
                .page(cursor, DiscoveryBudget::default(), deadline())
                .unwrap();
            for record in page.records {
                if record.creation.as_ref() == Some(&prepared.reference.creation) {
                    assert_eq!(record.state, expected);
                    target_observations += 1;
                }
            }
            if page.completion.traversal_exhausted {
                break;
            }
            assert_eq!(page.stopped, Some(DiscoveryError::Limit));
            cursor = page.cursor;
            assert!(step < 199);
        }
        assert!(
            target_observations >= 3,
            "name, descriptor and physical HEAD must agree"
        );
        fixture.memory.clear_calls();
        let mut job = RecoveryJob::new(
            fixture.objects.clone(),
            Listing::new(fixture.memory.clone()),
            RecoveryCapability::trusted_deployment(1, 20).unwrap(),
            Arc::new(Reader),
            test_options(),
            RecoveryBudget::default(),
            deadline(),
        )
        .unwrap();
        let path = fixture.directory.path().join("root-recovery");
        for step in 0..200 {
            let mut next = job.step(&path, deadline()).unwrap();
            assert!(next.stopped.is_none(), "{:?}", next.stopped);
            if let Some(record) = &next.metadata {
                if record.scope.as_ref() == Some(&prepared.reference.creation.scope) {
                    assert_eq!(record.state, expected);
                    assert!(next.recovered.is_none());
                    assert!(!path.exists());
                }
            }
            if let Some(mut recovered) = next.recovered.take() {
                assert_eq!(recovered.head().scope, scope());
                assert_eq!(
                    recovered
                        .query(&sql("SELECT n FROM restored"), deadline())
                        .unwrap()
                        .statements[0]
                        .rows,
                    vec![vec![Value::Integer(1)]]
                );
                drop(recovered);
            }
            if next.completion.recovery_complete {
                assert_eq!(
                    (
                        next.completion.data_verified,
                        next.completion.data_not_required
                    ),
                    (1, 1)
                );
                break;
            }
            assert!(step < 199);
        }
        assert!(!path.exists());
        assert!(fixture.memory.calls().iter().all(|call| !call.put));
    }
}

#[test]
fn missing_completion_blocks_root_recovery_even_when_the_target_was_once_ready() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    for step in 0..5 {
        fixture.resume(&prepared, step);
    }
    fixture.memory.remove(&fixture.completion_key(&prepared));
    let mut job = RecoveryJob::new(
        fixture.objects.clone(),
        Listing::new(fixture.memory.clone()),
        RecoveryCapability::trusted_deployment(1, 20).unwrap(),
        Arc::new(Reader),
        test_options(),
        RecoveryBudget::default(),
        deadline(),
    )
    .unwrap();
    let path = fixture.directory.path().join("incomplete-recovery");
    for step in 0..200 {
        let next = job.step(&path, deadline()).unwrap();
        if next.stopped.is_some() {
            assert_eq!(next.stopped, Some(RecoveryStop::Corrupt));
            assert!(!next.completion.recovery_complete);
            assert!(!path.exists());
            return;
        }
        assert!(!next.completion.recovery_complete);
        assert!(step < 199);
    }
    panic!("missing permanent completion was skipped");
}

#[test]
fn copied_provenance_survives_sql_snapshots_owner_handoff_and_compaction_without_retaining_old_payload(
) {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    for step in 0..5 {
        fixture.resume(&prepared, step);
    }
    let target_scope = prepared.reference.creation.scope.clone();
    let target = Database::with_options(
        fixture.objects.clone(),
        target_scope.clone(),
        11,
        test_options(),
    )
    .unwrap();
    let initial = target.status(7, deadline()).unwrap();
    let origin = initial.restore_origin.clone();
    target
        .activate(7, initial.revision, 800, deadline())
        .unwrap();
    let statements = sql("UPDATE restored SET v=zeroblob(1)");
    target
        .execute(
            7,
            &request(1, 1, 7, &statements).unwrap(),
            &statements,
            &fixture.directory.path().join("updated-target"),
            deadline(),
        )
        .unwrap();
    let updated = target.status(7, deadline()).unwrap();
    assert_eq!(updated.restore_origin, origin);
    assert_ne!(updated.data_root, initial.data_root);
    let limits = SnapshotLimits {
        max_points: 8,
        ..updated.snapshot_limits.clone().unwrap()
    };
    let limited = target
        .set_snapshot_limits(7, updated.revision, 801, limits, deadline())
        .unwrap();
    assert_eq!(limited.restore_origin, origin);
    let retained = target
        .snapshot_prepare(
            7,
            &PrepareSnapshotInput {
                creator: 7,
                operation: 902,
                expected_revision: limited.revision,
                expected_head_serial: limited.head_serial,
                label: "target-only".into(),
            },
            deadline(),
        )
        .unwrap();
    let captured = target
        .snapshot_capture(7, &retained.reference, deadline())
        .unwrap();
    assert_eq!(captured.head.restore_origin, origin);
    let released = target
        .snapshot_release(7, &retained.reference, deadline())
        .unwrap();
    assert_eq!(released.head.restore_origin, origin);
    let OwnerPreparation::Prepared(plan) = target
        .owner_prepare(
            7,
            &PrepareOwnerInput {
                creator: 7,
                operation: 803,
                expected_revision: released.head.revision,
                expected_head_serial: released.head.head_serial,
                mode: OwnerMode::Takeover,
                target_worker: 20,
                nonces: OwnerNonces {
                    claim: 8031,
                    cancel: 8032,
                    activate: 8033,
                    abort: 8034,
                },
            },
            deadline(),
        )
        .unwrap()
    else {
        panic!()
    };
    let successor = Database::with_options(
        fixture.objects.clone(),
        target_scope.clone(),
        20,
        test_options(),
    )
    .unwrap();
    let claimed = successor
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    assert_eq!(claimed.head.restore_origin, origin);
    let (owned, session) = successor
        .owner_resume(
            7,
            &plan.reference,
            &fixture.directory.path().join("owner-target"),
            deadline(),
        )
        .unwrap();
    drop(session);
    assert_eq!(owned.head.restore_origin, origin);
    let copy = successor
        .compact_begin(7, owned.head.head_serial, deadline())
        .unwrap();
    successor
        .compact_copy(7, copy.head_serial, deadline())
        .unwrap();
    let promoted = successor
        .compact_promote(7, copy.head_serial, deadline())
        .unwrap();
    assert_eq!(promoted.restore_origin, origin);
    assert!(promoted.snapshots.as_ref().unwrap().is_empty());
    assert_eq!(promoted.storage.active_generation, 2);
    assert!(
        fixture
            .memory
            .get_value(&object_key(&target_scope, 2, &initial.data_root))
            .is_none(),
        "provenance is not a retained data-tree edge"
    );
    let old_prefix = object_key(&target_scope, 1, "");
    for call in fixture.memory.calls() {
        if call.key.starts_with(&old_prefix) {
            fixture.memory.remove(&call.key);
        }
    }
    assert!(fixture
        .memory
        .get_value(&fixture.completion_key(&prepared))
        .is_some());
    let cold =
        Database::with_options(fixture.objects.clone(), target_scope, 30, test_options()).unwrap();
    assert_eq!(
        cold.query(
            7,
            &sql("SELECT n,length(v) FROM restored"),
            &fixture.directory.path().join("cold-after-retirement"),
            deadline()
        )
        .unwrap()
        .statements[0]
            .rows,
        vec![vec![Value::Integer(1), Value::Integer(1)]]
    );
}

#[test]
fn a_held_point_on_a_deleted_source_can_create_an_independent_ready_target() {
    let fixture = Fixture::new(true);
    let head = fixture.source.status(7, deadline()).unwrap();
    fixture
        .source
        .set_lifecycle(7, head.revision, 804, Lifecycle::Deleted, deadline())
        .unwrap();
    let prepared = fixture.prepare();
    for step in 0..5 {
        fixture.resume(&prepared, step);
    }
    assert_eq!(
        fixture
            .catalogue
            .resolve(CREATOR, &prepared.input.name, deadline())
            .unwrap()
            .head
            .lifecycle,
        Lifecycle::Ready
    );
}
