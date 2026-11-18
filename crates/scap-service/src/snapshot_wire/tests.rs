use super::*;
use crate::tests::{scope, until, Memory};
use crate::wire::{Action, Call};
use scap_object::Database;
use std::sync::Arc;

fn original() -> PrepareSnapshotInput {
    PrepareSnapshotInput {
        creator: 3,
        operation: 77,
        expected_revision: 1,
        expected_head_serial: 1,
        label: "before migration".into(),
    }
}

fn descriptor() -> PreparedSnapshot {
    PreparedSnapshot {
        scope: scope().native().unwrap(),
        input: original(),
        reference: SnapshotRef {
            creator: 3,
            operation: 77,
            capture_serial: 2,
            descriptor_hash: "a".repeat(64),
        },
        point: SnapshotPoint {
            data_root: "b".repeat(64),
            page_count: 0,
            sequence: 0,
            source_revision: 1,
        },
    }
}

#[test]
fn strict_snapshot_inputs_preserve_u64_and_reject_ambiguous_metadata() {
    let native = original();
    let encoded = input(&native);
    assert_eq!(
        serde_json::from_value::<Prepare>(encoded.clone())
            .unwrap()
            .native()
            .unwrap(),
        native
    );
    for key in [
        "creator",
        "operation",
        "expected_revision",
        "expected_head_serial",
    ] {
        for bad in [
            json!(1),
            json!(null),
            json!("01"),
            json!("18446744073709551616"),
        ] {
            let mut value = encoded.clone();
            value[key] = bad;
            assert!(serde_json::from_value::<Prepare>(value).is_err());
        }
        let mut value = encoded.clone();
        value[key] = json!("0");
        assert_eq!(
            serde_json::from_value::<Prepare>(value)
                .unwrap()
                .native()
                .unwrap_err()
                .code,
            "INVALID"
        );
    }
    for bad in ["", "\n", &"x".repeat(129)] {
        let mut value = encoded.clone();
        value["label"] = json!(bad);
        assert_eq!(
            serde_json::from_value::<Prepare>(value)
                .unwrap()
                .native()
                .unwrap_err()
                .code,
            "INVALID"
        );
    }
    let mut large = native;
    large.operation = u64::MAX;
    assert_eq!(input(&large)["operation"], "18446744073709551615");
    assert_eq!(
        serde_json::from_value::<Prepare>(input(&large))
            .unwrap()
            .native()
            .unwrap(),
        large
    );
    for raw in [
        r#"{"creator":"3","creator":"4","operation":"7"}"#,
        r#"{"creator":"3","operation":"7","extra":true}"#,
    ] {
        assert!(serde_json::from_str::<Identity>(raw).is_err());
    }
    let identity: Identity =
        serde_json::from_value(json!({"creator":"3","operation":"77"})).unwrap();
    assert_eq!(
        identity.native().unwrap(),
        SnapshotIdentity {
            creator: 3,
            operation: 77
        }
    );
    assert_eq!(
        Identity {
            creator: Decimal(0),
            operation: Decimal(77)
        }
        .native()
        .unwrap_err()
        .code,
        "INVALID"
    );
    let reference = descriptor().reference;
    assert_eq!(
        serde_json::from_value::<Reference>(super::reference(&reference))
            .unwrap()
            .native()
            .unwrap(),
        reference
    );
    let invalid = Reference {
        creator: Decimal(3),
        operation: Decimal(77),
        capture_serial: Decimal(2),
        descriptor_hash: "A".repeat(64),
    };
    assert_eq!(invalid.native().unwrap_err().code, "INVALID");
    let limits = SnapshotLimits::default();
    assert_eq!(
        serde_json::from_value::<Limits>(super::limits(&limits))
            .unwrap()
            .native()
            .unwrap(),
        limits
    );
    assert_eq!(
        Limits {
            max_points: 65,
            max_logical_bytes: Decimal(0)
        }
        .native()
        .unwrap_err()
        .code,
        "INVALID"
    );
}

#[test]
fn snapshot_wire_states_keep_original_descriptor_and_optional_acceptance() {
    let db = Database::new(Arc::new(Memory::default()), scope().native().unwrap(), 100).unwrap();
    let head = db.create(3, 1, until()).unwrap();
    assert_eq!(listing(&head)["snapshots"], json!([]));
    assert_eq!(listing(&head)["limits"], Value::Null);
    let saved = descriptor();
    let accepted = SnapshotEntry {
        reference: saved.reference.clone(),
        label: saved.input.label.clone(),
        point: saved.point.clone(),
    };
    for (state, name) in [
        (SnapshotState::Prepared, "prepared"),
        (SnapshotState::Retained, "retained"),
        (SnapshotState::ReleasedObserved, "released_observed"),
        (SnapshotState::Fenced, "fenced"),
    ] {
        let (SnapshotState::Prepared
        | SnapshotState::Retained
        | SnapshotState::ReleasedObserved
        | SnapshotState::Fenced) = state;
        let value = SnapshotObservation {
            head: head.clone(),
            prepared: saved.clone(),
            state,
            accepted: if state == SnapshotState::Retained {
                Some(accepted.clone())
            } else {
                None
            },
        };
        let encoded = observation(&value);
        assert_eq!(encoded["state"], name);
        assert_eq!(encoded["prepared"]["reference"]["capture_serial"], "2");
        assert_eq!(encoded["prepared"]["point"]["page_count"], 0);
        assert_eq!(
            encoded["accepted"].is_null(),
            state != SnapshotState::Retained
        );
    }
    let mut retained = head;
    retained.snapshots = Some(vec![accepted.clone()]);
    retained.snapshot_limits = Some(SnapshotLimits::default());
    let encoded = listing(&retained);
    assert_eq!(encoded["snapshots"], json!([entry(&accepted)]));
    assert_eq!(encoded["limits"]["max_points"], 64);
}

#[test]
fn all_snapshot_actions_use_control_admission_and_native_validation() {
    let cases = [
        ("snapshot_prepare", json!({"input":input(&original())})),
        (
            "snapshot_inspect",
            json!({"identity":{"creator":"3","operation":"77"}}),
        ),
        (
            "snapshot_capture",
            json!({"reference":reference(&descriptor().reference)}),
        ),
        (
            "snapshot_release",
            json!({"reference":reference(&descriptor().reference)}),
        ),
        ("snapshot_list", json!({})),
        (
            "snapshot_limits",
            json!({"expected_revision":"1","nonce":"9","limits":limits(&SnapshotLimits::default())}),
        ),
    ];
    for (operation, fields) in cases {
        let mut value = json!({"version":1,"scope":wire::scope(&scope().native().unwrap()),"operation":operation});
        value
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let call: Call = serde_json::from_value(value).unwrap();
        call.action.validate().unwrap();
        assert_eq!(call.action.admission(), "control");
    }
    let invalid = Action::SnapshotLimits {
        expected_revision: Decimal(0),
        nonce: Decimal(9),
        limits: Limits {
            max_points: 0,
            max_logical_bytes: Decimal(0),
        },
    };
    assert_eq!(invalid.validate().unwrap_err().code, "INVALID");
}
