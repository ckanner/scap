use crate::head_publication::PreparedHead;
use crate::owner::{OwnerMode, OwnerNonces, OwnerPreparation, PrepareOwnerInput};
use crate::snapshot::PrepareSnapshotInput;
use crate::tests::{deadline, scope, test_options, Memory};
use crate::*;
use scap_object_store::{Condition, Objects, StoreError, Stored};
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct Quoted(pub(crate) Arc<Memory>);
impl Objects for Quoted {
    fn get(&self, key: &str, cap: usize, until: Instant) -> Result<Stored, StoreError> {
        let mut value = self.0.get(key, cap, until)?;
        value.etag = format!("\"{}\"", value.etag);
        Ok(value)
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        let condition = match condition {
            Condition::Absent => Condition::Absent,
            Condition::Match(etag) => {
                Condition::Match(etag.strip_prefix('"').unwrap().strip_suffix('"').unwrap())
            }
        };
        self.0
            .put(key, bytes, condition, until)
            .map(|etag| format!("\"{etag}\""))
    }
}

pub(crate) fn fixture() -> (Arc<Quoted>, Database, crate::snapshot::PreparedSnapshot) {
    let objects = Arc::new(Quoted(Arc::new(Memory::default())));
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    database.create(7, 1, deadline()).unwrap();
    database.activate(7, 1, 2, deadline()).unwrap();
    let head = database.status(7, deadline()).unwrap();
    let point = database
        .snapshot_prepare(
            7,
            &PrepareSnapshotInput {
                creator: 7,
                operation: 901,
                expected_revision: head.revision,
                expected_head_serial: head.head_serial,
                label: "keep".into(),
            },
            deadline(),
        )
        .unwrap();
    database
        .snapshot_capture(7, &point.reference, deadline())
        .unwrap();
    (objects, database, point)
}

fn owner_input(head: &Head) -> PrepareOwnerInput {
    PrepareOwnerInput {
        creator: 7,
        operation: 101,
        expected_revision: head.revision,
        expected_head_serial: head.head_serial,
        mode: OwnerMode::Takeover,
        target_worker: 20,
        nonces: OwnerNonces {
            claim: 1011,
            cancel: 1012,
            activate: 1013,
            abort: 1014,
        },
    }
}

#[test]
fn ordinary_writers_cannot_change_retained_entries_limits_or_origin() {
    let (objects, database, _) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let before = objects.0.operation_count();
    for field in 0..3 {
        let mut next = Database::next(&base.head, 33).unwrap();
        match field {
            0 => next.snapshots = Some(vec![]),
            1 => next.snapshot_limits.as_mut().unwrap().max_points = 1,
            _ => next.restore_origin = None,
        }
        assert!(matches!(
            PreparedHead::new(&database, &base, &next, deadline()),
            Err(Error::Format(FormatError::Invalid))
        ));
    }
    assert_eq!(objects.0.operation_count(), before);
}

#[test]
fn copy_basis_binds_entries_limits_and_strict_presence() {
    let (_, database, _) = fixture();
    let head = database.status(7, deadline()).unwrap();
    let original = CopyBasis::capture(&head);
    assert!(original.matches(&head));
    for field in 0..2 {
        let mut changed = head.clone();
        if field == 0 {
            changed.snapshots.as_mut().unwrap()[0].label = "changed".into();
        } else {
            changed.snapshot_limits.as_mut().unwrap().max_points = 1;
        }
        assert!(!original.matches(&changed));
    }
    for field in ["snapshots", "snapshot_limits"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CopyBasis>(value).is_err());
        let mut value = serde_json::to_value(&original).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(!serde_json::from_value::<CopyBasis>(value)
            .unwrap()
            .matches(&head));
    }
    let mut old = head;
    old.format = 6;
    old.snapshots = None;
    old.snapshot_limits = None;
    old.restore_origin = None;
    let value = serde_json::to_value(CopyBasis::capture(&old)).unwrap();
    assert!(value.get("snapshots").is_none() && value.get("snapshot_limits").is_none());
    assert!(serde_json::from_value::<CopyBasis>(value)
        .unwrap()
        .matches(&old));
}

#[test]
fn copy_basis_cannot_claim_points_from_after_its_original_capture() {
    let (_, database, _) = fixture();
    let original = database.status(7, deadline()).unwrap();
    let mut copying = original.clone();
    copying.head_serial += 1;
    copying.active = false;
    copying.storage.allocated_through = 2;
    copying.storage.plan = Some(CopyPlan {
        serial: copying.head_serial,
        source: 1,
        target: 2,
        phase: CopyPhase::Copying,
        basis: CopyBasis::capture(&original),
    });
    copying.validate().unwrap();
    for future in [false, true] {
        let mut invalid = copying.clone();
        if future {
            invalid.snapshots.as_mut().unwrap()[0]
                .reference
                .capture_serial = copying.head_serial;
            invalid.storage.plan.as_mut().unwrap().basis.snapshots = invalid.snapshots.clone();
        } else {
            invalid.storage.plan.as_mut().unwrap().basis.revision = 1;
        }
        assert!(matches!(invalid.validate(), Err(FormatError::Invalid)));
    }
}

#[test]
fn owner_claim_and_resume_preserve_head9_and_all_points() {
    let (objects, database, _) = fixture();
    let original = database.status(7, deadline()).unwrap();
    let OwnerPreparation::Prepared(plan) = database
        .owner_prepare(7, &owner_input(&original), deadline())
        .unwrap()
    else {
        panic!()
    };
    let target = Database::with_options(objects.clone(), scope(), 20, test_options()).unwrap();
    let claimed = target.owner_claim(7, &plan.reference, deadline()).unwrap();
    assert_eq!(claimed.head.format, 9);
    assert_eq!(claimed.head.snapshots, original.snapshots);
    let temporary = tempfile::tempdir().unwrap();
    let (resumed, _) = target
        .owner_resume(
            7,
            &plan.reference,
            &temporary.path().join("target"),
            deadline(),
        )
        .unwrap();
    assert_eq!(resumed.head.format, 9);
    assert_eq!(resumed.head.snapshots, original.snapshots);
    assert_eq!(resumed.head.snapshot_limits, original.snapshot_limits);
    assert_eq!(resumed.head.restore_origin, original.restore_origin);
}

#[test]
fn deleted_held_points_block_seal_and_released_head9_stays_head9() {
    let (_, database, point) = fixture();
    let original = database.status(7, deadline()).unwrap();
    let deleted = database
        .set_lifecycle(7, original.revision, 44, Lifecycle::Deleted, deadline())
        .unwrap();
    assert_eq!(deleted.snapshots, original.snapshots);
    assert!(matches!(
        database.retire_storage(7, deleted.head_serial, deadline()),
        Err(Error::Conflict)
    ));
    let released = database
        .snapshot_release(7, &point.reference, deadline())
        .unwrap();
    let sealed = database
        .retire_storage(7, released.head.head_serial, deadline())
        .unwrap();
    assert_eq!(sealed.format, 9);
    assert!(sealed.snapshots.as_ref().unwrap().is_empty());
    assert_eq!(sealed.snapshot_limits, original.snapshot_limits);
    assert!(sealed.storage.terminal.is_some());
}

#[test]
fn ordinary_and_owner_admission_leave_room_for_point_release_and_terminal_cleanup() {
    let (objects, database, _) = fixture();
    let mut base = database.read_head(deadline()).unwrap();
    // One release + one deletion + one seal remain possible at this bound.
    base.head.head_serial = u64::MAX - 3;
    base.head.validate().unwrap();
    objects
        .0
        .set(head_key(&scope()), encode_head(&base.head).unwrap());
    let base = database.read_head(deadline()).unwrap();
    let next = Database::next(&base.head, 55).unwrap();
    assert!(matches!(
        PreparedHead::new(&database, &base, &next, deadline()),
        Err(Error::Limit)
    ));
    assert!(matches!(
        database.owner_prepare(7, &owner_input(&base.head), deadline()),
        Err(Error::Limit)
    ));
}

#[test]
fn named_owner_takeover_keeps_the_future_deletion_epoch() {
    let (objects, database, _) = fixture();
    let mut head = database.status(7, deadline()).unwrap();
    head.creation = Some(NamedCreation {
        creator: 7,
        operation: 800,
        name_hash: digest(b"name"),
        descriptor_hash: digest(b"creation"),
    });
    head.owner_epoch = u64::MAX - 1;
    objects
        .0
        .set(head_key(&scope()), encode_head(&head).unwrap());
    assert!(matches!(
        database.owner_prepare(7, &owner_input(&head), deadline()),
        Err(Error::Limit)
    ));
}

#[test]
fn owner_recovery_requires_retained_roots_even_when_live_native_image_is_valid() {
    let (objects, database, point) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let statements = crate::tests::sql("CREATE TABLE t(x)");
    let id = request(1, 1, 7, &statements).unwrap();
    let mut session = database
        .session(7, &temporary.path().join("source"), deadline())
        .unwrap();
    session.execute(7, &id, &statements, deadline()).unwrap();
    drop(session);
    let head = database.status(7, deadline()).unwrap();
    assert_ne!(head.data_root, point.point.data_root);
    let OwnerPreparation::Prepared(plan) = database
        .owner_prepare(7, &owner_input(&head), deadline())
        .unwrap()
    else {
        panic!()
    };
    let target = Database::with_options(objects.clone(), scope(), 20, test_options()).unwrap();
    target.owner_claim(7, &plan.reference, deadline()).unwrap();
    objects
        .0
        .remove(&object_key(&scope(), 1, &point.point.data_root));
    assert!(matches!(
        target.owner_resume(
            7,
            &plan.reference,
            &temporary.path().join("target"),
            deadline()
        ),
        Err(Error::Store(StoreError::Missing))
    ));
    let current = database.status(7, deadline()).unwrap();
    assert!(!current.active);
    assert_eq!(
        current.owner_plan.unwrap().phase.kind,
        OwnerPhaseKind::Claimed
    );
}

#[test]
fn legacy_activate_session_cannot_bypass_a_retained_root() {
    let (objects, database, point) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let statements = crate::tests::sql("CREATE TABLE t(x)");
    let id = request(1, 1, 7, &statements).unwrap();
    let mut session = database
        .session(7, &temporary.path().join("source"), deadline())
        .unwrap();
    session.execute(7, &id, &statements, deadline()).unwrap();
    drop(session);
    let current = database.status(7, deadline()).unwrap();
    let inactive = database
        .takeover(7, current.revision, 77, deadline())
        .unwrap();
    assert!(inactive.owner_plan.is_none());
    objects
        .0
        .remove(&object_key(&scope(), 1, &point.point.data_root));
    assert!(matches!(
        database.activate_session(
            7,
            inactive.revision,
            78,
            &temporary.path().join("legacy"),
            deadline()
        ),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(database.status(7, deadline()).unwrap(), inactive);
}
