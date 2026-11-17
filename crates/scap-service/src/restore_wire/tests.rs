use super::*;
use crate::catalogue_wire::{parse, Action};
use crate::tests::{principal, scope};

fn descriptor() -> core::PreparedRestore {
    core::PreparedRestore {
        reference: core::RestoreRef {
            creation: crate::tests::named_creation("restore É", u64::MAX),
            descriptor_hash: "b".repeat(64),
        },
        input: core::PrepareRestore {
            name: "restore É".into(),
            operation: u64::MAX,
            expected_name_revision: None,
            options: core::CreateOptions::default(),
            source_scope: scope().native().unwrap(),
            snapshot: scap_object::format::SnapshotRef {
                creator: 3,
                operation: 7,
                capture_serial: 2,
                descriptor_hash: "a".repeat(64),
            },
        },
        initial_quota: scap_object::format::DatabaseQuota {
            max_bytes: Some(8192),
        },
        retention: scap_object::format::Retention {
            max_entries: 8,
            max_result_bytes: 8192,
        },
        point: scap_object::format::SnapshotPoint {
            data_root: "c".repeat(64),
            page_count: 2,
            sequence: u64::MAX,
            source_revision: 1,
        },
    }
}

fn requests() -> Vec<Value> {
    let prepared = descriptor();
    let mut prepare = input(&prepared.input);
    prepare["version"] = json!(1);
    prepare["operation"] = json!("prepare_restore");
    vec![
        prepare,
        json!({"version":1,"operation":"resume_restore","reference":reference(&prepared.reference)}),
        json!({"version":1,"operation":"inspect_restore","creator":"3","restore_operation":"18446744073709551615"}),
        json!({"version":1,"operation":"abort_restore","reference":reference(&prepared.reference),
            "control_operation":"2","expected_name_revision":"1","nonce":"3"}),
    ]
}

#[test]
fn restore_wire_projects_only_lossless_original_inputs_and_public_progress() {
    let mut value = descriptor();
    for quota in [
        core::QuotaChoice::Default,
        core::QuotaChoice::Unlimited,
        core::QuotaChoice::Limited { max_bytes: 8192 },
    ] {
        value.input.options.quota = quota;
        let encoded = prepared(&value);
        assert_eq!(
            encoded["input"]["restore_operation"],
            "18446744073709551615"
        );
        assert_eq!(encoded["point"]["sequence"], "18446744073709551615");
        let mut call = encoded["input"].clone();
        call["version"] = json!(1);
        call["operation"] = json!("prepare_restore");
        let parsed = parse(call.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.action.admission(), "catalogue");
        parsed.action.authorize(&principal()).unwrap();
        match parsed.action.native().unwrap() {
            catalogue::NativeAction::PrepareRestore(input) => assert_eq!(input, value.input),
            _ => panic!("wrong native restore input"),
        }
    }
    value.input.expected_name_revision = Some(9);
    value.reference.creation.expected_name_revision = Some(9);
    let decoded: Reference = serde_json::from_value(reference(&value.reference)).unwrap();
    assert_eq!(decoded.native().unwrap(), value.reference);
    for phase in [
        core::RestorePhase::NotReserved,
        core::RestorePhase::Reserved,
        core::RestorePhase::Copying,
        core::RestorePhase::Copied,
        core::RestorePhase::Bound,
        core::RestorePhase::Ready,
        core::RestorePhase::Aborting,
        core::RestorePhase::Aborted,
        core::RestorePhase::Deleting,
        core::RestorePhase::Deleted,
        core::RestorePhase::NameConflict,
        core::RestorePhase::IdentityConflict,
    ] {
        for revision in [None, Some(u64::MAX)] {
            let result = progress(&core::RestoreProgress {
                prepared: value.clone(),
                phase,
                binding_revision: revision,
                head_revision: revision,
            });
            assert_eq!(result["prepared"], prepared(&value));
            assert_eq!(
                result["binding_revision"],
                json!(revision.map(|n| n.to_string()))
            );
        }
    }
    for request in requests() {
        let call = parse(request.to_string().as_bytes()).unwrap();
        call.action.authorize(&principal()).unwrap();
        assert_eq!(
            call.action.admission(),
            if request["operation"] == "resume_restore" {
                "recovery"
            } else {
                "catalogue"
            }
        );
        assert_eq!(
            call.action.name(),
            if request["operation"] == "inspect_restore" {
                None
            } else {
                Some("restore É")
            }
        );
    }
}

#[test]
fn restore_intents_reject_missing_conditions_extra_proofs_and_noncanonical_identities() {
    for request in requests() {
        for field in request.as_object().unwrap().keys() {
            let mut bad = request.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(
                parse(bad.to_string().as_bytes()).is_err(),
                "missing {field}"
            );
        }
        for field in ["completion", "proof", "etag", "data_root", "principal"] {
            let mut bad = request.clone();
            bad[field] = json!(true);
            assert_eq!(
                parse(bad.to_string().as_bytes()).unwrap_err().code,
                "INVALID"
            );
        }
    }
    let mut request = requests()[0].clone();
    request["restore_operation"] = json!("0");
    assert_eq!(
        parse(request.to_string().as_bytes()).unwrap_err().code,
        "INVALID"
    );
    for field in ["creator", "restore_operation"] {
        let mut request = requests()[2].clone();
        request[field] = json!("0");
        assert_eq!(
            parse(request.to_string().as_bytes()).unwrap_err().code,
            "INVALID"
        );
    }
    for field in ["control_operation", "expected_name_revision", "nonce"] {
        let mut request = requests()[3].clone();
        request[field] = json!("0");
        assert_eq!(
            parse(request.to_string().as_bytes()).unwrap_err().code,
            "INVALID"
        );
    }
    let mut bad = descriptor().reference;
    bad.descriptor_hash = "A".repeat(64);
    assert_eq!(
        serde_json::from_value::<Reference>(reference(&bad))
            .unwrap()
            .native()
            .unwrap_err()
            .code,
        "INVALID"
    );
    bad.creation.operation = 0;
    assert_eq!(
        serde_json::from_value::<Reference>(reference(&bad))
            .unwrap()
            .native()
            .unwrap_err()
            .code,
        "INVALID"
    );
    let raw = requests()[1].to_string().replace(
        "\"descriptor_hash\":",
        "\"descriptor_hash\":\"ignored\",\"descriptor_hash\":",
    );
    assert!(parse(raw.as_bytes()).is_err());
}

#[test]
fn restore_authorization_prevents_cross_tenant_and_different_creator_adoption() {
    for request in requests() {
        let call = parse(request.to_string().as_bytes()).unwrap();
        let mut denied = principal();
        denied.provision = false;
        assert_eq!(call.action.authorize(&denied).unwrap_err().code, "DENIED");
        let mut denied = principal();
        denied.principal = 99;
        if !matches!(call.action, Action::PrepareRestore { .. }) {
            assert_eq!(call.action.authorize(&denied).unwrap_err().code, "DENIED");
        }
        let mut denied = principal();
        denied.tenant = 99;
        if !matches!(call.action, Action::InspectRestore { .. }) {
            assert_eq!(call.action.authorize(&denied).unwrap_err().code, "DENIED");
        }
    }
}

#[test]
fn restore_actions_reject_invalid_nested_native_values_before_dispatch() {
    for (index, path, value) in [
        (
            0,
            vec!["options", "quota"],
            json!({"mode":"limited","max_bytes":"4097"}),
        ),
        (0, vec!["source_scope", "generation"], json!("0")),
        (0, vec!["snapshot", "capture_serial"], json!("0")),
        (
            3,
            vec!["reference", "descriptor_hash"],
            json!("A".repeat(64)),
        ),
    ] {
        let mut request = requests()[index].clone();
        let mut target = &mut request;
        for key in path {
            target = &mut target[key];
        }
        *target = value;
        assert_eq!(
            parse(request.to_string().as_bytes()).unwrap_err().code,
            "INVALID"
        );
    }

    // Trusted Rust callers can construct a typed action without parse(). Its
    // authorization boundary must still reject malformed source/target scopes.
    for index in [0, 1, 3] {
        let mut action = parse(requests()[index].to_string().as_bytes())
            .unwrap()
            .action;
        let scope = match &mut action {
            Action::PrepareRestore { source_scope, .. } => source_scope,
            Action::ResumeRestore { reference } | Action::AbortRestore { reference, .. } => {
                &mut reference.creation.scope
            }
            _ => panic!("fixture must carry a restore scope"),
        };
        scope.deployment.0 = 0;
        assert_eq!(action.authorize(&principal()).unwrap_err().code, "INVALID");
    }
}
