use super::*;
use crate::tests::{scope, until, Memory};
use crate::wire::{Action, Call};
use scap_object::format::{
    Head, Lifecycle, OwnerAdmission, OwnerAdmissionKind, OwnerPhase, OwnerPhaseKind,
};
use scap_object::Database;
use std::sync::Arc;

fn prepare_input() -> PrepareOwnerInput {
    PrepareOwnerInput {
        creator: 3,
        operation: 77,
        expected_revision: 1,
        expected_head_serial: 1,
        mode: OwnerMode::Takeover,
        target_worker: 100,
        nonces: OwnerNonces {
            claim: 11,
            cancel: 12,
            activate: 13,
            abort: 14,
        },
    }
}

fn prepared_owner() -> PreparedOwner {
    PreparedOwner {
        scope: scope().native().unwrap(),
        input: prepare_input(),
        reference: OwnerPlanRef {
            creator: 3,
            operation: 77,
            descriptor_hash: "a".repeat(64),
        },
    }
}

fn marker(kind: OwnerPhaseKind) -> OwnerPlan {
    let pending = matches!(kind, OwnerPhaseKind::Claimed | OwnerPhaseKind::Cancelling);
    OwnerPlan {
        reference: prepared_owner().reference,
        admission: OwnerAdmission {
            kind: if kind == OwnerPhaseKind::Cancelling {
                OwnerAdmissionKind::Cancel
            } else {
                OwnerAdmissionKind::Claim
            },
            revision: 2,
            head_serial: 2,
        },
        phase: OwnerPhase {
            kind,
            revision: if pending { 2 } else { 3 },
            head_serial: if pending { 2 } else { 3 },
            nonce: match kind {
                OwnerPhaseKind::Claimed => 11,
                OwnerPhaseKind::Cancelling => 12,
                OwnerPhaseKind::Active => 13,
                OwnerPhaseKind::Aborted => 14,
            },
            owner_epoch: 2,
            owner_instance: 100,
        },
    }
}

fn head() -> Head {
    Database::new(Arc::new(Memory::default()), scope().native().unwrap(), 100)
        .unwrap()
        .create(3, 1, until())
        .unwrap()
}

fn request(operation: &str, fields: Value) -> Value {
    let mut value = json!({"version":1,"scope":wire::scope(&scope().native().unwrap()),
        "operation":operation});
    value
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    value
}

#[test]
fn fixed_inputs_are_decimal_strict_and_reuse_native_validation() {
    let original = prepare_input();
    let encoded = input(&original);
    let decoded: Prepare = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded.native().unwrap(), original);
    let mut large = original.clone();
    large.operation = u64::MAX;
    large.expected_revision = u64::MAX;
    large.expected_head_serial = u64::MAX;
    large.target_worker = u64::MAX;
    large.mode = OwnerMode::Activate;
    assert_eq!(input(&large)["operation"], "18446744073709551615");
    assert_eq!(input(&large)["mode"], "activate");
    assert_eq!(
        serde_json::from_value::<Prepare>(input(&large))
            .unwrap()
            .native()
            .unwrap(),
        large
    );

    for key in [
        "creator",
        "operation",
        "expected_revision",
        "expected_head_serial",
        "target_worker",
    ] {
        for bad in [
            json!(0),
            json!("00"),
            json!(null),
            json!("18446744073709551616"),
        ] {
            let mut value = encoded.clone();
            value[key] = bad;
            assert!(serde_json::from_value::<Prepare>(value).is_err(), "{key}");
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
    for name in ["claim", "cancel", "activate", "abort"] {
        let mut value = encoded.clone();
        value["nonces"][name] = json!("0");
        assert_eq!(
            serde_json::from_value::<Prepare>(value)
                .unwrap()
                .native()
                .unwrap_err()
                .code,
            "INVALID"
        );
    }
    let mut duplicate = encoded.clone();
    duplicate["nonces"]["cancel"] = json!("11");
    assert_eq!(
        serde_json::from_value::<Prepare>(duplicate)
            .unwrap()
            .native()
            .unwrap_err()
            .code,
        "INVALID"
    );
    let mut reversed = encoded.clone();
    reversed["expected_revision"] = json!("2");
    assert_eq!(
        serde_json::from_value::<Prepare>(reversed)
            .unwrap()
            .native()
            .unwrap_err()
            .code,
        "INVALID"
    );
    let raw = serde_json::to_string(&encoded).unwrap();
    for value in [
        raw.replacen(
            "\"creator\":\"3\"",
            "\"creator\":\"3\",\"creator\":\"3\"",
            1,
        ),
        raw.replacen("\"claim\":\"11\"", "\"claim\":\"11\",\"claim\":\"11\"", 1),
        raw.replacen('{', "{\"extra\":1,", 1),
        raw.replacen("\"takeover\"", "\"retry\"", 1),
    ] {
        assert!(serde_json::from_str::<Prepare>(&value).is_err());
    }
}

#[test]
fn inspection_identity_and_hash_reference_remain_distinct() {
    let identity: Identity = serde_json::from_str(r#"{"creator":"3","operation":"77"}"#).unwrap();
    assert_eq!(
        identity.native().unwrap(),
        OwnerIdentity {
            creator: 3,
            operation: 77
        }
    );
    let original = prepared_owner().reference;
    assert_eq!(
        serde_json::from_value::<Reference>(reference(&original))
            .unwrap()
            .native()
            .unwrap(),
        original
    );
    for value in [
        json!({"creator":"0","operation":"77"}),
        json!({"creator":"3","operation":"0"}),
    ] {
        assert_eq!(
            serde_json::from_value::<Identity>(value)
                .unwrap()
                .native()
                .unwrap_err()
                .code,
            "INVALID"
        );
    }
    for value in [
        json!({"creator":"0","operation":"77","descriptor_hash":"a".repeat(64)}),
        json!({"creator":"3","operation":"77","descriptor_hash":"A".repeat(64)}),
        json!({"creator":"3","operation":"77","descriptor_hash":"a".repeat(63)}),
    ] {
        assert_eq!(
            serde_json::from_value::<Reference>(value)
                .unwrap()
                .native()
                .unwrap_err()
                .code,
            "INVALID"
        );
    }
    assert!(serde_json::from_value::<Reference>(json!({"creator":"3","operation":"77"})).is_err());
    assert!(serde_json::from_value::<Identity>(reference(&original)).is_err());
    for value in [
        r#"{"creator":"3","operation":"77","creator":"3"}"#,
        r#"{"creator":"3","operation":"77","extra":true}"#,
    ] {
        assert!(serde_json::from_str::<Identity>(value).is_err());
    }
    let raw = serde_json::to_string(&reference(&original)).unwrap();
    let duplicate = raw.replacen(
        "\"creator\":\"3\"",
        "\"creator\":\"3\",\"creator\":\"3\"",
        1,
    );
    assert!(serde_json::from_str::<Reference>(&duplicate).is_err());
}

#[test]
fn owner_requests_require_the_right_worker_guard_and_admission_class() {
    let original = prepared_owner();
    let cases = [
        (
            "owner_prepare",
            json!({"input":input(&original.input)}),
            "control",
            None,
        ),
        (
            "owner_inspect",
            json!({"identity":{"creator":"3","operation":"77"}}),
            "control",
            None,
        ),
        (
            "owner_claim",
            json!({"plan":reference(&original.reference),"expected_worker_instance":"100"}),
            "control",
            Some(100),
        ),
        (
            "owner_resume",
            json!({"plan":reference(&original.reference),"expected_worker_instance":"100"}),
            "recovery",
            Some(100),
        ),
        (
            "owner_abort",
            json!({"plan":reference(&original.reference)}),
            "control",
            None,
        ),
    ];
    for (name, fields, admission, worker) in cases {
        let value = request(name, fields);
        let parsed = wire::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed.action.admission(), admission);
        assert_eq!(parsed.action.expected_worker(), worker);
        assert!(parsed.action.priority());
        let mut malformed = value.clone();
        match name {
            "owner_prepare" => malformed["input"]["nonces"]["abort"] = json!("0"),
            "owner_inspect" => malformed["identity"]["creator"] = json!("0"),
            _ => malformed["plan"]["descriptor_hash"] = json!("bad"),
        }
        assert_eq!(
            wire::parse(&serde_json::to_vec(&malformed).unwrap())
                .unwrap_err()
                .code,
            "INVALID"
        );
        if worker.is_some() {
            for guard in [json!(null), json!("0"), json!(100), json!("0100")] {
                let mut bad = value.clone();
                bad["expected_worker_instance"] = guard;
                assert_eq!(
                    wire::parse(&serde_json::to_vec(&bad).unwrap())
                        .unwrap_err()
                        .code,
                    "INVALID"
                );
            }
            let mut absent = value.clone();
            absent
                .as_object_mut()
                .unwrap()
                .remove("expected_worker_instance");
            assert_eq!(
                wire::parse(&serde_json::to_vec(&absent).unwrap())
                    .unwrap_err()
                    .code,
                "INVALID"
            );
        } else {
            let mut added = value.clone();
            added["expected_worker_instance"] = json!("100");
            assert_eq!(
                wire::parse(&serde_json::to_vec(&added).unwrap())
                    .unwrap_err()
                    .code,
                "INVALID"
            );
        }
        // The outer Call visitor must preserve nested raw bytes so repeated
        // members are rejected by the typed owner decoder.
        let bytes = serde_json::to_string(&value).unwrap();
        let duplicate = bytes.replacen(
            "\"creator\":\"3\"",
            "\"creator\":\"3\",\"creator\":\"3\"",
            1,
        );
        assert!(serde_json::from_str::<Call>(&duplicate).is_err());
    }
    let parsed = wire::parse(
        &serde_json::to_vec(&request(
            "owner_prepare",
            json!({"input": input(&original.input)}),
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(parsed.action, Action::OwnerPrepare { .. }));
}

#[test]
fn observations_keep_fixed_history_separate_from_current_authority() {
    let original = prepared_owner();
    assert_eq!(
        preparation(&OwnerPreparation::Prepared(original.clone())),
        json!({"state":"prepared","prepared":prepared(&original)})
    );
    assert_eq!(
        preparation(&OwnerPreparation::Pending(original.reference.clone())),
        json!({"state":"pending","reference":reference(&original.reference)})
    );
    let mut current = head();
    assert_eq!(wire::status(&current)["owner_plan"], Value::Null);
    for (state, name, phase) in [
        (OwnerState::Prepared, "prepared", None),
        (OwnerState::Fenced, "fenced", None),
        (
            OwnerState::Claimed,
            "claimed",
            Some(OwnerPhaseKind::Claimed),
        ),
        (
            OwnerState::Cancelling,
            "cancelling",
            Some(OwnerPhaseKind::Cancelling),
        ),
        (OwnerState::Active, "active", Some(OwnerPhaseKind::Active)),
        (
            OwnerState::Aborted,
            "aborted",
            Some(OwnerPhaseKind::Aborted),
        ),
    ] {
        let (OwnerState::Prepared
        | OwnerState::Claimed
        | OwnerState::Cancelling
        | OwnerState::Active
        | OwnerState::Aborted
        | OwnerState::Fenced) = state;
        let accepted = phase.map(marker);
        let value = observation(&OwnerObservation {
            head: current.clone(),
            prepared: original.clone(),
            state,
            accepted: accepted.clone(),
        });
        assert_eq!(value["state"], name);
        assert_eq!(
            value["accepted"],
            accepted.as_ref().map(plan).unwrap_or(Value::Null)
        );
        assert_eq!(value["status"], wire::status(&current));
        assert_eq!(value["prepared"], prepared(&original));
    }
    let historical = marker(OwnerPhaseKind::Active);
    current.format = 8;
    current.owner_plan = Some(historical.clone());
    current.revision = 4;
    current.head_serial = 4;
    current.transition.revision = 4;
    current.transition.nonce = 21;
    current.owner_epoch = 3;
    current.lifecycle = Lifecycle::Deleted;
    current.active = false;
    let observed = observation(&OwnerObservation {
        head: current,
        prepared: original,
        state: OwnerState::Active,
        accepted: Some(historical),
    });
    assert_eq!(observed["status"]["revision"], "4");
    assert_eq!(observed["status"]["owner_epoch"], "3");
    assert_eq!(observed["status"]["active"], false);
    assert_eq!(observed["accepted"]["phase"]["revision"], "3");
    assert_eq!(observed["accepted"]["phase"]["owner_epoch"], "2");
    assert_eq!(observed["accepted"]["phase"]["nonce"], "13");
    assert_eq!(observed["status"]["owner_plan"], observed["accepted"]);
    let raw = serde_json::to_string(&observed).unwrap();
    for secret in ["etag", "data_root", "policy", "session", "acknowledged"] {
        assert!(!raw.contains(secret));
    }
}
