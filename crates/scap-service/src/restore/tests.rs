use super::*;
use crate::catalogue_scheduler::Worker as _;
use crate::catalogue_wire::parse;
use crate::tests::{principal, scope, until, Memory};
use serde_json::json;

pub(crate) fn profile() -> Value {
    json!({"admission":{"workers":1,"queued_total":4,"queued_per_tenant":3,
        "queued_per_name":2,"intake":2,"max_body_bytes":4096,"timeout_ms":1000},
        "recovery_timeout_ms":30000,"max_staging_bytes":67108864,"max_staging_bytes_per_tenant":33554432,
        "budget":{"source_gets":1000,"source_bytes":10485760,"target_puts":1000,
            "target_put_bytes":10485760,"target_gets":1000,"target_get_bytes":10485760,
            "max_image_bytes":10485760}})
}

fn call(value: Value) -> Call {
    parse(value.to_string().as_bytes()).unwrap()
}

fn fixture() -> (
    Arc<Memory>,
    crate::catalogue::Worker,
    Worker,
    tempfile::TempDir,
    Value,
) {
    let objects = Arc::new(Memory::default());
    let database =
        scap_object::Database::new(objects.clone(), scope().native().unwrap(), 100).unwrap();
    let head = database.create(3, 1, until()).unwrap();
    database.activate(3, head.revision, 2, until()).unwrap();
    let source_image = tempfile::tempdir().unwrap();
    let statements = vec![scap_sql::Statement {
        sql: "CREATE TABLE saved AS SELECT 42 AS value".into(),
        parameters: vec![],
    }];
    let request = scap_object::request(1, 1, 3, &statements).unwrap();
    database
        .execute(
            3,
            &request,
            &statements,
            &source_image.path().join("native"),
            until(),
        )
        .unwrap();
    let head = database.status(3, until()).unwrap();
    let saved = database
        .snapshot_prepare(
            3,
            &scap_object::snapshot::PrepareSnapshotInput {
                creator: 3,
                operation: 7,
                expected_revision: head.revision,
                expected_head_serial: head.head_serial,
                label: "source".into(),
            },
            until(),
        )
        .unwrap();
    database
        .snapshot_capture(3, &saved.reference, until())
        .unwrap();
    let control = crate::catalogue::Worker::new(objects.clone(), 100, Options::default());
    let prepared = control
        .execute(
            &principal(),
            call(json!({"version":1,"operation":"prepare_restore",
        "name":"target","restore_operation":"8","expected_name_revision":null,
        "options":{"quota":{"mode":"default"}}, "source_scope":crate::wire::scope(&saved.scope),
        "snapshot":crate::snapshot_wire::reference(&saved.reference)})),
            until(),
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let worker = Worker::new(
        objects.clone(),
        100,
        Options::default(),
        directory.path(),
        Arc::new(Semaphore::new(1)),
        Arc::new(Pool::new(64 * 1024 * 1024, 32 * 1024 * 1024).unwrap()),
        core::RestoreBudget::default(),
    )
    .unwrap();
    (objects, control, worker, directory, prepared)
}

fn resume(reference: &Value) -> Call {
    call(json!({"version":1,"operation":"resume_restore","reference":reference}))
}

#[test]
fn staging_limits_are_shared_by_tenant_and_held_until_the_last_actual_job_releases() {
    assert_eq!(Pool::new(1, 0).err().unwrap().code, "CONFIG");
    assert_eq!(Pool::new(1, 2).err().unwrap().code, "CONFIG");
    let pool = Arc::new(Pool::new(SIDECAR_ALLOWANCE * 3, SIDECAR_ALLOWANCE * 2).unwrap());
    let one = pool.acquire(&principal(), 0).unwrap();
    let two = pool.acquire(&principal(), 0).unwrap();
    assert_eq!(
        pool.acquire(&principal(), 0).err().unwrap().code,
        "RECOVERY_BUSY"
    );
    let mut other = principal();
    other.tenant = 5;
    let three = pool.acquire(&other, 0).unwrap();
    other.tenant = 6;
    assert_eq!(pool.acquire(&other, 0).err().unwrap().code, "RECOVERY_BUSY");
    assert_eq!(
        pool.acquire(&principal(), u64::MAX).err().unwrap().code,
        "LIMIT"
    );
    drop(one);
    assert_eq!(
        pool.usage.lock().unwrap().tenants[&(1, 2)],
        SIDECAR_ALLOWANCE
    );
    drop((two, three));
    assert_eq!(pool.usage.lock().unwrap().total, 0);
    assert!(pool.usage.lock().unwrap().tenants.is_empty());
    let lease = pool.acquire(&principal(), 0).unwrap();
    let poisoned = pool.clone();
    assert!(std::thread::spawn(move || {
        let _lock = poisoned.usage.lock().unwrap();
        panic!("injected accounting failure");
    })
    .join()
    .is_err());
    assert_eq!(
        pool.acquire(&principal(), 0).err().unwrap().code,
        "UNAVAILABLE"
    );
    drop(lease);
    assert_eq!(pool.usage.lock().err().unwrap().into_inner().total, 0);
}

#[test]
fn restore_profile_is_explicit_and_rejects_unbounded_or_invalid_admission_before_io() {
    let valid: Profile = serde_json::from_value(profile()).unwrap();
    valid.validate().unwrap();
    for (path, value) in [
        (vec!["recovery_timeout_ms"], json!(999)),
        (vec!["recovery_timeout_ms"], json!(604800001_u64)),
        (vec!["max_staging_bytes_per_tenant"], json!(0)),
        (vec!["admission", "workers"], json!(0)),
        (vec!["admission", "max_body_bytes"], json!(0)),
        (vec!["budget", "source_gets"], json!(1_048_577)),
        (vec!["budget", "target_puts"], json!(1_048_577)),
        (vec!["budget", "target_gets"], json!(1_048_577)),
        (vec!["budget", "max_image_bytes"], json!(u64::MAX)),
    ] {
        let mut bad = profile();
        let mut target = &mut bad;
        for key in path {
            target = &mut target[key];
        }
        *target = value;
        assert!(serde_json::from_value::<Profile>(bad)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut bad = profile();
    bad["rss_limit"] = json!(1);
    assert!(serde_json::from_value::<Profile>(bad).is_err());
    let directory = tempfile::tempdir().unwrap();
    let objects = Arc::new(Memory::default());
    let build = |options, path: &Path, budget| {
        Worker::new(
            objects.clone(),
            100,
            options,
            path,
            Arc::new(Semaphore::new(1)),
            Arc::new(Pool::new(1, 1).unwrap()),
            budget,
        )
    };
    let options = Options {
        result_memory_bytes: 0,
        ..Options::default()
    };
    assert_eq!(
        build(options, directory.path(), core::RestoreBudget::default())
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    let budget = core::RestoreBudget {
        source_gets: u64::MAX,
        ..core::RestoreBudget::default()
    };
    assert_eq!(
        build(Options::default(), directory.path(), budget)
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    assert_eq!(
        build(
            Options::default(),
            &directory.path().join("missing"),
            core::RestoreBudget::default()
        )
        .err()
        .unwrap()
        .code,
        "CACHE_IO"
    );
}

#[test]
fn real_restore_workers_keep_copy_and_control_admission_separate_and_clean_private_images() {
    let (_objects, control, mut worker, directory, prepared) = fixture();
    let reference = &prepared["reference"];
    let inspect = call(
        json!({"version":1,"operation":"inspect_restore","creator":"3","restore_operation":"8"}),
    );
    assert_eq!(
        control
            .execute(&principal(), inspect.clone(), until())
            .unwrap()["phase"],
        "not_reserved"
    );
    assert_eq!(
        control
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(
        worker
            .execute(&principal(), inspect.clone(), until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    let mut denied = principal();
    denied.provision = false;
    assert_eq!(
        worker
            .execute(&denied, resume(reference), until())
            .unwrap_err()
            .code,
        "DENIED"
    );
    let mut wrong = reference.clone();
    wrong["descriptor_hash"] = json!("a".repeat(64));
    assert_eq!(
        worker
            .execute(&principal(), resume(&wrong), until())
            .unwrap_err()
            .code,
        "IDENTITY_CONFLICT"
    );
    for phase in ["reserved", "copying", "copied", "bound", "ready"] {
        let progress = worker
            .execute(&principal(), resume(reference), until())
            .unwrap();
        assert_eq!(progress["phase"], phase);
        assert_eq!(progress["prepared"], prepared);
        assert_eq!(worker.staging.usage.lock().unwrap().total, 0);
        assert_eq!(worker.recovery.available_permits(), 1);
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());
    }
    assert_eq!(
        control.execute(&principal(), inspect, until()).unwrap()["phase"],
        "ready"
    );
    let resolved = control
        .execute(
            &principal(),
            call(json!({"version":1,"operation":"resolve_name","name":"target"})),
            until(),
        )
        .unwrap();
    assert_eq!(resolved["head"]["sequence"], "0");
    assert_eq!(resolved["head"]["active"], false);
}

#[test]
fn busy_copy_remains_inspectable_and_cancellable_without_adopting_a_partial_image() {
    let (_objects, control, mut worker, directory, prepared) = fixture();
    let reference = &prepared["reference"];
    for phase in ["reserved", "copying"] {
        assert_eq!(
            worker
                .execute(&principal(), resume(reference), until())
                .unwrap()["phase"],
            phase
        );
    }
    let recovery = worker.recovery.clone();
    let permit = recovery.try_acquire().unwrap();
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    drop(permit);
    worker.staging = Arc::new(Pool::new(1, 1).unwrap());
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "RECOVERY_BUSY"
    );
    let aborted = control
        .execute(
            &principal(),
            call(
                json!({"version":1,"operation":"abort_restore","reference":reference,
        "control_operation":"10","expected_name_revision":"1","nonce":"11"}),
            ),
            until(),
        )
        .unwrap();
    assert!(matches!(
        aborted["phase"].as_str().unwrap(),
        "aborting" | "aborted"
    ));
    let observed = worker
        .execute(&principal(), resume(reference), until())
        .unwrap();
    assert!(matches!(
        observed["phase"].as_str().unwrap(),
        "aborting" | "aborted"
    ));
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn copy_budget_and_filesystem_failures_release_actual_resources_without_publishing_ready() {
    let (objects, control, mut worker, directory, prepared) = fixture();
    let reference = &prepared["reference"];
    for _ in 0..2 {
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap();
    }
    worker.budget.max_image_bytes = 0;
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "LIMIT"
    );
    worker.budget = core::RestoreBudget {
        target_gets: 0,
        ..core::RestoreBudget::default()
    };
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "LIMIT"
    );
    assert_eq!(worker.staging.usage.lock().unwrap().total, 0);
    assert_eq!(worker.recovery.available_permits(), 1);
    worker.budget = core::RestoreBudget::default();
    *objects.fail_get.lock().unwrap() = Some(scap_object_store::StoreError::Unknown);
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "UNKNOWN"
    );
    std::fs::remove_dir(directory.path()).unwrap();
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "CACHE_IO"
    );
    assert_eq!(worker.staging.usage.lock().unwrap().total, 0);
    assert_eq!(worker.recovery.available_permits(), 1);
    assert_eq!(
        control
            .execute(
                &principal(),
                call(json!({"version":1,"operation":"inspect_restore",
        "creator":"3","restore_operation":"8"})),
                until()
            )
            .unwrap()["phase"],
        "copying"
    );
    let mut invalid: Call =
        serde_json::from_value(json!({"version":1,"operation":"resume_restore",
        "reference":reference}))
        .unwrap();
    if let crate::catalogue_wire::Action::ResumeRestore { reference } = &mut invalid.action {
        reference.descriptor_hash = "invalid".into();
    }
    assert_eq!(
        worker
            .execute(&principal(), invalid, until())
            .unwrap_err()
            .code,
        "INVALID"
    );
    worker.worker = 0;
    assert_eq!(
        worker
            .execute(&principal(), resume(reference), until())
            .unwrap_err()
            .code,
        "INVALID"
    );
}
