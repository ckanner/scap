use super::*;
use crate::catalogue_wire::{parse, Action};
use crate::tests::{principal, until, Memory};
use scap_object::{format::Permission, Database};
use serde_json::json;

fn call(value: Value) -> Call {
    parse(value.to_string().as_bytes()).unwrap()
}
fn prepare(name: &str, operation: u64) -> Call {
    call(
        json!({"version":1,"operation":"prepare_create","name":name,"create_operation":operation.to_string(),"expected_name_revision":null,"options":{"quota":{"mode":"default"}}}),
    )
}
fn invoke(worker: &Worker, operation: &str, creation: &Value) -> Value {
    worker
        .execute(
            &principal(),
            call(json!({"version":1,"operation":operation,"creation":creation})),
            until(),
        )
        .unwrap()
}

#[test]
fn adapter_uses_real_descriptor_binding_and_head_transitions_without_resetting_identity() {
    let objects = Arc::new(Memory::default());
    let worker = Worker::new(objects.clone(), 100, Options::default());
    let prepared = worker
        .execute(&principal(), prepare("name", 1), until())
        .unwrap();
    let creation = prepared["creation"].clone();
    assert_eq!(prepared["initial_quota"]["max_bytes"], "10737418240");
    assert_eq!(
        worker
            .execute(&principal(), prepare("name", 1), until())
            .unwrap(),
        prepared
    );
    let inspect =
        call(json!({"version":1,"operation":"inspect_create_operation","create_operation":"1"}));
    assert_eq!(
        worker
            .execute(&principal(), inspect.clone(), until())
            .unwrap()["phase"],
        "not_reserved"
    );
    let aborted=worker.execute(&principal(),call(json!({"version":1,"operation":"abort_create","creation":creation,"control_operation":"2","expected_name_revision":"1","nonce":"3"})),until()).unwrap();
    assert_eq!(aborted["phase"], "not_reserved");
    let ready = invoke(&worker, "resume_create", &creation);
    assert_eq!(ready["phase"], "ready");
    assert_eq!(
        worker.execute(&principal(), inspect, until()).unwrap()["phase"],
        "ready"
    );
    let resolved = worker
        .execute(
            &principal(),
            call(json!({"version":1,"operation":"resolve_name","name":"name"})),
            until(),
        )
        .unwrap();
    assert_eq!(resolved["creation"], creation);
    assert_eq!(resolved["head"]["lifecycle"], "ready");
    assert!(resolved["head"].get("creation").is_none());
    let aborted=worker.execute(&principal(),call(json!({"version":1,"operation":"abort_create","creation":creation,"control_operation":"4","expected_name_revision":ready["binding_revision"],"nonce":"5"})),until()).unwrap();
    assert_eq!(aborted["phase"], "cannot_abort_bound");

    // An ADMIN-only current principal supplies the already-known Creation.
    // This path must neither require provision nor replace the creator.
    let reference: wire::Creation = serde_json::from_value(creation.clone()).unwrap();
    let database = Database::new(objects.clone(), reference.native().unwrap().scope, 100).unwrap();
    let revision = resolved["head"]["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let head = database
        .set_policy(
            3,
            revision,
            10,
            vec![
                Permission {
                    principal: 3,
                    read: true,
                    write: true,
                    admin: true,
                },
                Permission {
                    principal: 9,
                    read: false,
                    write: false,
                    admin: true,
                },
            ],
            until(),
        )
        .unwrap();
    let mut admin = principal();
    admin.principal = 9;
    admin.provision = false;
    assert_eq!(
        worker
            .execute(
                &admin,
                call(json!({"version":1,"operation":"resolve_name","name":"name"})),
                until()
            )
            .unwrap_err()
            .code,
        "DENIED"
    );
    let deletion = call(
        json!({"version":1,"operation":"delete_name","creation":creation,"control_operation":"6","expected_name_revision":ready["binding_revision"],"expected_head_revision":head.revision.to_string(),"nonce":"7"}),
    );
    let deleted = worker.execute(&admin, deletion.clone(), until()).unwrap();
    assert_eq!(deleted["phase"], "deleted");
    assert_eq!(deleted["creation"], creation);
    assert_eq!(worker.execute(&admin, deletion, until()).unwrap(), deleted);
    assert_eq!(
        worker
            .execute(
                &principal(),
                call(json!({"version":1,"operation":"resolve_name","name":"name"})),
                until()
            )
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
}

#[test]
fn no_authority_io_precedes_validation_and_current_authenticated_provision_checks() {
    let objects = Arc::new(Memory::default());
    let worker = Worker::new(objects.clone(), 100, Options::default());
    let mut invalid = prepare("ok", 1);
    if let Action::PrepareCreate {
        create_operation, ..
    } = &mut invalid.action
    {
        create_operation.0 = 0;
    }
    assert_eq!(
        worker
            .execute(&principal(), invalid, until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    let mut denied = principal();
    denied.provision = false;
    assert_eq!(
        worker
            .execute(&denied, prepare("ok", 1), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
    assert!(objects.calls.lock().unwrap().is_empty());
    let bad = Worker::new(objects.clone(), 0, Options::default());
    assert_eq!(
        bad.execute(&principal(), prepare("ok", 1), until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    *objects.fail_put.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        worker
            .execute(&principal(), prepare("ok", 1), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    assert_eq!(
        worker
            .execute(
                &principal(),
                call(json!({"version":1,"operation":"resolve_name","name":"missing"})),
                until()
            )
            .unwrap_err()
            .code,
        "NOT_FOUND"
    );
}

#[test]
fn catalogue_errors_preserve_unknown_missing_identity_and_authorization_distinctions() {
    for (error, expected) in [
        (core::CatalogueError::Invalid, "INVALID"),
        (core::CatalogueError::Denied, "DENIED"),
        (core::CatalogueError::NotFound, "NOT_FOUND"),
        (core::CatalogueError::Conflict, "CONFLICT"),
        (core::CatalogueError::IdentityConflict, "IDENTITY_CONFLICT"),
        (core::CatalogueError::Corrupt, "CORRUPT"),
        (core::CatalogueError::SnapshotExpired, "SNAPSHOT_EXPIRED"),
        (core::CatalogueError::Limit, "LIMIT"),
        (core::CatalogueError::Unknown, "UNKNOWN"),
    ] {
        assert_eq!(Failure::from(error).code, expected);
    }
}

#[test]
fn every_runtime_dispatch_preserves_an_object_failure_without_retry() {
    let objects = Arc::new(Memory::default());
    let worker = Worker::new(objects.clone(), 100, Options::default());
    let prepared = worker
        .execute(&principal(), prepare("dispatch", 40), until())
        .unwrap();
    let creation = prepared["creation"].clone();
    for input in [
        json!({"version":1,"operation":"resume_create","creation":creation}),
        json!({"version":1,"operation":"abort_create","creation":creation,"control_operation":"41","expected_name_revision":"1","nonce":"42"}),
        json!({"version":1,"operation":"inspect_create_operation","create_operation":"40"}),
        json!({"version":1,"operation":"delete_name","creation":creation,"control_operation":"43","expected_name_revision":"1","expected_head_revision":"1","nonce":"44"}),
    ] {
        objects.calls.lock().unwrap().clear();
        *objects.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
        assert_eq!(
            worker
                .execute(&principal(), call(input), until())
                .unwrap_err()
                .code,
            "UNKNOWN"
        );
        assert_eq!(
            objects.calls.lock().unwrap().len(),
            1,
            "dispatch must not retry its failed read"
        );
    }
}
