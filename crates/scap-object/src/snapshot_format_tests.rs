use super::*;
use crate::format::*;
use crate::tests::{deadline, fixture};

fn head() -> Head {
    let (_, database) = fixture();
    let mut value = database.status(7, deadline()).unwrap();
    value.format = 9;
    value.head_serial = 10;
    value.snapshots = Some(vec![]);
    value.snapshot_limits = Some(SnapshotLimits::default());
    value.restore_origin = Some(());
    value
}

fn entry(serial: u64) -> SnapshotEntry {
    SnapshotEntry {
        reference: SnapshotRef {
            creator: 7,
            operation: serial,
            capture_serial: serial,
            descriptor_hash: digest(&serial.to_le_bytes()),
        },
        label: format!("point-{serial}"),
        point: SnapshotPoint {
            data_root: digest(b"retained"),
            page_count: 3,
            sequence: 0,
            source_revision: 2,
        },
    }
}

#[test]
fn strict_head9_presence_is_separate_from_legacy_omission_and_future_origins() {
    let mut value = head();
    value.snapshots = Some(vec![entry(3), entry(4)]);
    let wire = encode_head(&value).unwrap();
    assert_eq!(decode_head(&wire, &value.scope).unwrap(), value);
    let json: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(json["restore_origin"], serde_json::Value::Null);
    for field in ["snapshots", "snapshot_limits", "restore_origin"] {
        let mut absent = json.clone();
        absent.as_object_mut().unwrap().remove(field);
        assert!(decode_head(&serde_json::to_vec(&absent).unwrap(), &value.scope).is_err());
        if field != "restore_origin" {
            let mut null = json.clone();
            null[field] = serde_json::Value::Null;
            assert!(decode_head(&serde_json::to_vec(&null).unwrap(), &value.scope).is_err());
        }
    }
    for origin in [
        serde_json::json!({"descriptor_hash": digest(b"restore"), "phase": {"kind": "copying"}}),
        serde_json::json!({"descriptor_hash": digest(b"restore"), "phase": {"kind": "copied"}}),
        serde_json::json!([]),
        serde_json::json!(false),
    ] {
        let mut future = json.clone();
        future["restore_origin"] = origin;
        assert!(decode_head(&serde_json::to_vec(&future).unwrap(), &value.scope).is_err());
    }
    for field in ["snapshots", "snapshot_limits", "restore_origin"] {
        let mut legacy = json.clone();
        legacy["format"] = serde_json::json!(6);
        for absent in ["snapshots", "snapshot_limits", "restore_origin"] {
            if absent != field {
                legacy.as_object_mut().unwrap().remove(absent);
            }
        }
        assert!(decode_head(&serde_json::to_vec(&legacy).unwrap(), &value.scope).is_err());
    }
    value.format = 6;
    value.snapshots = None;
    value.snapshot_limits = None;
    value.restore_origin = None;
    let legacy = encode_head(&value).unwrap();
    assert_eq!(decode_head(&legacy, &value.scope).unwrap(), value);
    assert!(!String::from_utf8(legacy).unwrap().contains("snapshot"));
}

#[test]
fn historical_points_bind_their_own_geometry_identity_and_source_revision() {
    let mut value = head();
    value.snapshots = Some(vec![entry(3), entry(4)]);
    // Current quota does not constrain a previously captured data tree.
    value.quota.max_bytes = Some(PAGE_SIZE as u64);
    value.validate().unwrap();
    let mutations: Vec<fn(&mut SnapshotEntry)> = vec![
        |point| point.reference.creator = 0,
        |point| point.reference.operation = 0,
        |point| point.reference.capture_serial = 0,
        |point| point.reference.descriptor_hash = "not-a-hash".into(),
        |point| point.label.clear(),
        |point| point.label = "é".repeat(65),
        |point| point.label = "a\u{85}".into(),
        |point| point.point.data_root.clear(),
        |point| point.point.page_count = u32::MAX,
        |point| point.point.source_revision = 0,
        |point| point.point.source_revision = 4,
        |point| point.point.source_revision = 3,
        |point| point.point.sequence = 1,
        |point| point.reference.capture_serial = 11,
        |point| point.reference.capture_serial = 3,
        |point| point.reference.operation = 3,
        |point| point.label = "point-3".into(),
    ];
    for mutate in mutations {
        let mut bad = value.clone();
        mutate(&mut bad.snapshots.as_mut().unwrap()[1]);
        assert!(bad.validate().is_err(), "{bad:?}");
    }
    value.snapshots.as_mut().unwrap()[0].point.page_count = 0;
    value.validate().unwrap();
    assert_eq!(
        gross_bytes(value.snapshots.as_ref().unwrap()).unwrap(),
        3 * PAGE_SIZE as u64
    );
    let mut oversized = vec![entry(3); 65];
    assert!(gross_bytes(&oversized).is_err());
    oversized.pop();
    assert_eq!(gross_bytes(&oversized).unwrap(), 64 * 3 * PAGE_SIZE as u64);
}

#[test]
fn durable_policy_bounds_points_and_gross_bytes_without_reinterpreting_old_roots() {
    assert_eq!(SnapshotLimits::default().max_points, 64);
    assert_eq!(
        SnapshotLimits::default().max_logical_bytes,
        32 * 1024 * 1024 * 1024
    );
    let mut value = head();
    value.snapshots = Some(vec![entry(3)]);
    let mutations: Vec<fn(&mut SnapshotLimits)> = vec![
        |limits| limits.max_points = 65,
        |limits| limits.max_logical_bytes = MAX_SNAPSHOT_LOGICAL_BYTES + 1,
        |limits| limits.max_points = 0,
        |limits| limits.max_logical_bytes = 3 * PAGE_SIZE as u64 - 1,
    ];
    for mutate in mutations {
        let mut bad = value.clone();
        mutate(bad.snapshot_limits.as_mut().unwrap());
        assert!(bad.validate().is_err());
    }
    value.snapshot_limits = Some(SnapshotLimits {
        max_points: 1,
        max_logical_bytes: 3 * PAGE_SIZE as u64,
    });
    value.validate().unwrap();
    value.snapshots = Some(vec![]);
    value.snapshot_limits = Some(SnapshotLimits {
        max_points: 0,
        max_logical_bytes: 0,
    });
    value.validate().unwrap();
    let maximum = SnapshotLimits {
        max_points: 64,
        max_logical_bytes: MAX_SNAPSHOT_LOGICAL_BYTES,
    };
    maximum.validate().unwrap();
    let mut options = crate::Options::default();
    options.snapshot_limits.max_points = 65;
    assert!(matches!(options.validate(), Err(crate::Error::Format(_))));
}

#[test]
fn retained_point_rejects_the_reserved_sqlite_page_count() {
    let mut point = entry(3).point;
    point.page_count = MAX_PAGES;
    point.validate().unwrap();
    point.page_count = u32::MAX;
    assert!(point.validate().is_err());
}

fn pending(head: &mut Head, enabled: bool) {
    head.owner_plan = enabled.then(|| OwnerPlan {
        reference: OwnerPlanRef {
            creator: 7,
            operation: 1,
            descriptor_hash: digest(b"owner"),
        },
        admission: OwnerAdmission {
            kind: OwnerAdmissionKind::Claim,
            revision: 2,
            head_serial: 2,
        },
        phase: OwnerPhase {
            kind: OwnerPhaseKind::Claimed,
            revision: 2,
            head_serial: 2,
            nonce: 1,
            owner_epoch: 1,
            owner_instance: 10,
        },
    });
}

#[test]
fn cleanup_reserves_one_release_per_point_and_the_exact_pending_batch_debt() {
    let mut value = head();
    value.snapshots = Some(vec![entry(3), entry(4)]);
    value.revision = u64::MAX - 1;
    value.head_serial = u64::MAX - 4; // two releases + delete + seal
    assert!(cleanup_room(&value));
    value.head_serial += 1;
    assert!(!cleanup_room(&value));
    value.head_serial -= 1;
    value.revision += 1;
    assert!(!cleanup_room(&value));
    value.revision -= 1;
    pending(&mut value, true);
    assert!(!cleanup_room(&value));
    value.revision -= 1;
    value.head_serial -= 1;
    assert!(cleanup_room(&value));
    value.owner_plan.as_mut().unwrap().phase.kind = OwnerPhaseKind::Aborted;
    value.revision += 1;
    value.head_serial += 1;
    assert!(cleanup_room(&value));
    value.owner_plan = None;
    value.lifecycle = Lifecycle::Deleted;
    value.snapshots = Some(vec![]);
    value.storage.terminal = Some(TerminalSeal { serial: 4 });
    value.revision = u64::MAX;
    value.head_serial = u64::MAX;
    assert!(cleanup_room(&value));
    value.storage.sweep = Some(SweepCheckpoint {
        serial: 5,
        generation: 1,
        next_after: None,
        exhausted: true,
        entries: vec![SweepEntry {
            key: "unused-by-capacity".into(),
            hash: digest(b"object"),
            etag: "\"etag\"".into(),
            disposition: SweepDisposition::Pending,
        }],
    });
    assert!(!cleanup_room(&value));
    value.head_serial -= 2;
    assert!(cleanup_room(&value));
    value.head_serial += 1;
    value.storage.sweep.as_mut().unwrap().entries[0].disposition = SweepDisposition::Applied;
    assert!(cleanup_room(&value));
    value.head_serial += 1;
    assert!(!cleanup_room(&value));
    value.storage.sweep = None;
    value.snapshots = None;
    assert!(cleanup_room(&value));
    value.snapshots = Some(vec![entry(3); 65]);
    assert!(!cleanup_room(&value));
    value.format = 6;
    assert!(cleanup_room(&value));
}

#[test]
fn points_cannot_survive_a_terminal_seal_or_preexist_provisioning() {
    let mut value = head();
    value.snapshots = Some(vec![entry(3)]);
    value.storage.terminal = Some(TerminalSeal { serial: 8 });
    assert!(validate_head(&value).is_err());
    value.storage.terminal = None;
    value.lifecycle = Lifecycle::Provisioning;
    assert!(validate_head(&value).is_err());
    value.lifecycle = Lifecycle::Deleted;
    validate_head(&value).unwrap();
    value.snapshots = Some(vec![]);
    value.storage.terminal = Some(TerminalSeal { serial: 8 });
    validate_head(&value).unwrap();
}

#[test]
fn named_delete_and_copy_abort_capacity_cannot_be_spent_by_ordinary_publication() {
    let mut value = head();
    value.creation = Some(NamedCreation {
        creator: 7,
        operation: 99,
        name_hash: digest(b"name"),
        descriptor_hash: digest(b"creation"),
    });
    value.owner_epoch = u64::MAX;
    assert!(!cleanup_room(&value));
    value.owner_epoch -= 1;
    assert!(cleanup_room(&value));
    value.lifecycle = Lifecycle::Deleted;
    value.owner_epoch += 1;
    assert!(cleanup_room(&value));
    value.lifecycle = Lifecycle::Ready;
    value.owner_epoch -= 1;
    value.storage.plan = Some(CopyPlan {
        serial: 10,
        source: 1,
        target: 2,
        phase: CopyPhase::Copying,
        basis: CopyBasis::capture(&value),
    });
    value.head_serial = u64::MAX - 3; // abort + delete + seal
    assert!(cleanup_room(&value));
    value.head_serial += 1;
    assert!(!cleanup_room(&value));
    value.storage.plan = None;
    assert!(cleanup_room(&value));
    value.head_serial += 1;
    assert!(validate_head(&value).is_err());
}

#[test]
fn fully_populated_retained_table_stays_within_the_real_head_codec_budget() {
    let mut value = head();
    value.head_serial = 1000;
    value.policy = (1..=MAX_PRINCIPALS as u64)
        .map(|principal| Permission {
            principal,
            read: true,
            write: true,
            admin: true,
        })
        .collect();
    value.snapshots = Some(
        (3..67)
            .map(|serial| {
                let mut point = entry(serial);
                point.label = format!("{serial:02}{}", "\\".repeat(126));
                point.point.page_count = MAX_PAGES;
                point
            })
            .collect(),
    );
    value.snapshot_limits = Some(SnapshotLimits {
        max_points: MAX_SNAPSHOT_POINTS,
        max_logical_bytes: MAX_SNAPSHOT_LOGICAL_BYTES,
    });
    let encoded = encode_head(&value).unwrap();
    assert!(encoded.len() < MAX_HEAD_BYTES);
    assert_eq!(decode_head(&encoded, &value.scope).unwrap(), value);
}
