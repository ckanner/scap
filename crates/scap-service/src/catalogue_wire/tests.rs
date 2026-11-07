use super::*;
use crate::tests::{principal, until, Memory};
use scap_object::{Database, Options};
use std::sync::Arc;

fn reference() -> Value {
    json!({"creator":"3","operation":"18446744073709551615","name":"  名称É  ",
        "scope":{"deployment":"1","tenant":"2","database":"4","incarnation":"5","generation":"6"},
        "expected_name_revision":null})
}

fn valid() -> Vec<Value> {
    vec![
        json!({"version":1,"operation":"prepare_create","name":"  名称É  ","create_operation":"18446744073709551615","expected_name_revision":null,"options":{"quota":{"mode":"default"}}}),
        json!({"version":1,"operation":"resume_create","creation":reference()}),
        json!({"version":1,"operation":"abort_create","creation":reference(),"control_operation":"2","expected_name_revision":"1","nonce":"3"}),
        json!({"version":1,"operation":"inspect_create_operation","create_operation":"1"}),
        json!({"version":1,"operation":"resolve_name","name":"  名称É  "}),
        json!({"version":1,"operation":"delete_name","creation":reference(),"control_operation":"2","expected_name_revision":"1","expected_head_revision":"3","nonce":"4"}),
    ]
}

fn decoded(value: &Value) -> Call {
    parse(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn all_directory_intents_are_strict_lossless_and_preserve_exact_names() {
    for value in valid() {
        let call = decoded(&value);
        assert_eq!(call.version, 1);
        call.action.authorize(&principal()).unwrap();
        assert!(call.action.name().is_none() || call.action.name() == Some("  名称É  "));
        for field in [
            "principal",
            "provision",
            "tenant",
            "scope",
            "etag",
            "proof",
            "source",
            "unexpected",
        ] {
            let mut extra = value.clone();
            extra[field] = json!(true);
            assert_eq!(
                parse(extra.to_string().as_bytes()).unwrap_err().code,
                "INVALID"
            );
        }
    }
    let reference: Creation = serde_json::from_value(reference()).unwrap();
    let native = reference.native().unwrap();
    assert_eq!(native.operation, u64::MAX);
    assert_eq!(native.name, "  名称É  ");
    assert_eq!(creation(&native), reference_json(&reference));
    let mut expected = reference_json(&reference);
    expected["expected_name_revision"] = json!("18446744073709551615");
    assert_eq!(
        serde_json::from_value::<Creation>(expected)
            .unwrap()
            .native()
            .unwrap()
            .expected_name_revision,
        Some(u64::MAX)
    );
    for quota in [
        json!({"mode":"unlimited"}),
        json!({"mode":"limited","max_bytes":"8192"}),
    ] {
        let mut call = valid()[0].clone();
        call["options"]["quota"] = quota;
        decoded(&call);
    }
}

fn reference_json(value: &Creation) -> Value {
    creation(&value.native().unwrap())
}

#[test]
fn malformed_nullable_integer_names_options_and_nested_duplicates_fail_closed() {
    for bytes in [
        b"[]".as_slice(),
        b"{}",
        b"null",
        b"{\"version\":1,\"version\":1,\"operation\":\"resolve_name\",\"name\":\"x\"}",
        b"{\"version\":1,\"operation\":\"resolve_name\",\"name\":\"x\",\"name\":\"y\"}",
    ] {
        assert_eq!(parse(bytes).unwrap_err().code, "INVALID");
    }
    let mut wrong_version = valid()[4].clone();
    wrong_version["version"] = json!(2);
    assert_eq!(
        parse(wrong_version.to_string().as_bytes())
            .unwrap_err()
            .code,
        "VERSION"
    );
    for text in ["", "01", "-1", "+1", "18446744073709551616"] {
        let mut value = valid()[3].clone();
        value["create_operation"] = json!(text);
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    for replacement in [json!(1), json!(null), json!(true)] {
        let mut value = valid()[3].clone();
        value["create_operation"] = replacement;
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    for name in [
        "".to_owned(),
        "x".repeat(129),
        "é".repeat(65),
        "a\0b".to_owned(),
        "a\u{85}b".to_owned(),
    ] {
        for index in [0, 4] {
            let mut value = valid()[index].clone();
            value["name"] = json!(name);
            assert!(parse(value.to_string().as_bytes()).is_err());
        }
        let mut value = valid()[1].clone();
        value["creation"]["name"] = json!(name);
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    let mut value = valid()[0].clone();
    value["name"] = json!("é".repeat(64));
    decoded(&value);
    for quota in [
        json!({"mode":"limited","max_bytes":"0"}),
        json!({"mode":"limited","max_bytes":"1"}),
        json!({"mode":"unlimited","max_bytes":null}),
        json!({"mode":"default","max_bytes":"8192"}),
        json!({}),
    ] {
        let mut value = valid()[0].clone();
        value["options"]["quota"] = quota;
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    for index in [0, 1] {
        let mut value = valid()[index].clone();
        let target = if index == 0 {
            &mut value
        } else {
            &mut value["creation"]
        };
        target
            .as_object_mut()
            .unwrap()
            .remove("expected_name_revision");
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    for (index, field) in [
        (0, "create_operation"),
        (0, "expected_name_revision"),
        (2, "control_operation"),
        (2, "expected_name_revision"),
        (2, "nonce"),
        (3, "create_operation"),
        (5, "control_operation"),
        (5, "expected_name_revision"),
        (5, "expected_head_revision"),
        (5, "nonce"),
    ] {
        let mut value = valid()[index].clone();
        value[field] = json!("0");
        assert!(
            parse(value.to_string().as_bytes()).is_err(),
            "{index}/{field}"
        );
    }
    for field in ["creator", "operation", "expected_name_revision"] {
        let mut value = valid()[1].clone();
        value["creation"][field] = json!("0");
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    let mut value = valid()[1].clone();
    value["creation"]["scope"]["database"] = json!("0");
    assert!(parse(value.to_string().as_bytes()).is_err());
    let raw = valid()[1]
        .to_string()
        .replace("\"creator\":\"3\"", "\"creator\":\"3\",\"creator\":\"4\"");
    assert!(parse(raw.as_bytes()).is_err());
    let raw = valid()[0].to_string().replace(
        "\"mode\":\"default\"",
        "\"mode\":\"default\",\"mode\":\"unlimited\"",
    );
    assert!(parse(raw.as_bytes()).is_err());
}

#[test]
fn each_normalized_input_and_direct_authorizer_rejects_its_invalid_creation() {
    for index in [2, 5] {
        let mut value = valid()[index].clone();
        value["creation"]["name"] = json!("");
        assert_eq!(
            parse(value.to_string().as_bytes()).unwrap_err().code,
            "INVALID"
        );
    }
    for index in [1, 5] {
        let mut action = decoded(&valid()[index]).action;
        match &mut action {
            Action::ResumeCreate { creation } | Action::DeleteName { creation, .. } => {
                creation.scope.database.0 = 0
            }
            _ => unreachable!(),
        }
        assert_eq!(action.authorize(&principal()).unwrap_err().code, "INVALID");
    }
    for bytes in [
        b"{\"version\":1,1:1}".as_slice(),
        b"{\"version\":\"1\"}",
        b"{\"version\":1,\"operation\":}",
    ] {
        assert_eq!(parse(bytes).unwrap_err().code, "INVALID");
    }
    let mut value = valid()[0].clone();
    value["expected_name_revision"] = json!("19");
    let NativeAction::Prepare(input) = decoded(&value).action.native().unwrap() else {
        panic!("wrong normalized input")
    };
    assert_eq!(input.expected_name_revision, Some(19));
}

#[test]
fn provision_creator_and_tenant_checks_do_not_confuse_admin_with_discovery() {
    let mut principal = principal();
    principal.provision = false;
    for index in [0, 1, 2, 3] {
        assert_eq!(
            decoded(&valid()[index])
                .action
                .authorize(&principal)
                .unwrap_err()
                .code,
            "DENIED"
        );
    }
    for index in [4, 5] {
        decoded(&valid()[index])
            .action
            .authorize(&principal)
            .unwrap();
    }
    principal.provision = true;
    principal.principal = 9;
    for index in [1, 2] {
        assert_eq!(
            decoded(&valid()[index])
                .action
                .authorize(&principal)
                .unwrap_err()
                .code,
            "DENIED"
        );
    }
    decoded(&valid()[5]).action.authorize(&principal).unwrap();
    principal.principal = 3;
    principal.tenant = 99;
    for index in [1, 2, 5] {
        assert_eq!(
            decoded(&valid()[index])
                .action
                .authorize(&principal)
                .unwrap_err()
                .code,
            "DENIED"
        );
    }
}

#[test]
fn every_progress_phase_is_lossless_and_has_no_internal_head_proof() {
    let reference: Creation = serde_json::from_value(reference()).unwrap();
    let native = reference.native().unwrap();
    let initial_quota = DatabaseQuota { max_bytes: None };
    let retained = Retention {
        max_entries: 4096,
        max_result_bytes: u64::MAX,
    };
    let prepared = prepared(core::PreparedCreate {
        creation: native.clone(),
        initial_quota: initial_quota.clone(),
        retention: retained.clone(),
    });
    assert_eq!(
        prepared["retention"]["max_result_bytes"],
        u64::MAX.to_string()
    );
    assert!(prepared["initial_quota"]["max_bytes"].is_null());
    use scap_object::catalogue::CreationPhase::*;
    for (phase, expected) in [
        (NotReserved, "not_reserved"),
        (Reserved, "reserved"),
        (Provisioning, "provisioning"),
        (Bound, "bound"),
        (Ready, "ready"),
        (Aborting, "aborting"),
        (Aborted, "aborted"),
        (Deleting, "deleting"),
        (Deleted, "deleted"),
        (NameConflict, "name_conflict"),
        (IdentityConflict, "identity_conflict"),
    ] {
        let value = progress(core::CreationProgress {
            creation: native.clone(),
            phase,
            binding_revision: None,
            head_revision: Some(u64::MAX),
            initial_quota: initial_quota.clone(),
            retention: retained.clone(),
        });
        assert_eq!(value["phase"], expected);
        assert!(value["binding_revision"].is_null());
        assert_eq!(value["head_revision"], u64::MAX.to_string());
    }
    for (phase, expected) in [
        (core::AbortPhase::NotReserved, "not_reserved"),
        (core::AbortPhase::CannotAbortBound, "cannot_abort_bound"),
        (core::AbortPhase::Aborting, "aborting"),
        (core::AbortPhase::Aborted, "aborted"),
    ] {
        let value = aborted(core::AbortProgress {
            creation: native.clone(),
            operation: u64::MAX,
            nonce: u64::MAX,
            phase,
            binding_revision: Some(4),
            head_revision: None,
        });
        assert_eq!(value["phase"], expected);
        assert_eq!(value["operation"], u64::MAX.to_string());
        assert!(value["head_revision"].is_null());
    }
    for (phase, expected) in [
        (core::DeletionPhase::NotDeleted, "not_deleted"),
        (core::DeletionPhase::Deleting, "deleting"),
        (core::DeletionPhase::Deleted, "deleted"),
    ] {
        let value = deleted(core::DeletionProgress {
            creation: native.clone(),
            operation: u64::MAX,
            nonce: 5,
            phase,
            binding_revision: None,
            head_revision: Some(6),
        });
        assert_eq!(value["phase"], expected);
        assert!(value["binding_revision"].is_null());
    }
    let database = Database::with_options(
        Arc::new(Memory::default()),
        native.scope.clone(),
        100,
        Options::default(),
    )
    .unwrap();
    let head = database.create(3, 7, until()).unwrap();
    let value = named(core::Named {
        creation: native,
        binding_revision: u64::MAX,
        head,
    });
    assert_eq!(value["binding_revision"], u64::MAX.to_string());
    for secret in ["creation", "deletion", "etag", "source", "proof", "policy"] {
        assert!(value["head"].get(secret).is_none());
    }
}
