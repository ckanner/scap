use super::*;
use crate::discovery_cursor::View;
use crate::tests::{principal, until, Memory};
use scap_object::{format::Permission, Database};

pub(crate) fn codec() -> Arc<CursorCodec> {
    Arc::new(CursorCodec::new([31; 32], [47; 32], 100).unwrap())
}
pub(crate) fn discovery(memory: Arc<Memory>) -> Arc<Discovery> {
    Arc::new(Discovery::new(memory.clone(), memory, 100, codec()).unwrap())
}
pub(crate) fn call(operation: &str, cursor: Value) -> Call {
    wire::parse(
        json!({"version":1,"operation":operation,"cursor":cursor})
            .to_string()
            .as_bytes(),
    )
    .unwrap()
}
pub(crate) fn page(discovery: &Discovery, p: &Principal, operation: &str, cursor: Value) -> Value {
    serde_json::from_slice::<Value>(
        &discovery
            .reader
            .execute(p, call(operation, cursor), until())
            .unwrap(),
    )
    .unwrap()["value"]
        .clone()
}
pub(crate) fn seed(memory: Arc<Memory>, tenant: u64, count: u64) -> Vec<core::Creation> {
    let catalogue = core::Catalogue::new(memory, 1, tenant, 100, Options::default()).unwrap();
    let caller = core::Caller {
        principal: 3,
        provision: true,
    };
    (1..=count)
        .map(|id| {
            let input = core::PrepareCreate {
                name: format!("inventory-{tenant}-{id}"),
                operation: id,
                expected_name_revision: None,
                options: core::CreateOptions::default(),
            };
            let prepared = catalogue.prepare(caller, &input, until()).unwrap();
            catalogue
                .resume_create(caller, &prepared.creation, until())
                .unwrap();
            prepared.creation
        })
        .collect()
}

#[test]
fn separate_admission_bounds_global_and_tenant_work_until_the_last_owner_drops() {
    let gate = Admission::default();
    let p = principal();
    let a = gate.acquire(&p).unwrap();
    let a2 = a.clone();
    assert_eq!(gate.acquire(&p).err().unwrap().code, "BACKPRESSURE");
    let b = gate
        .acquire(&Principal {
            tenant: 4,
            ..p.clone()
        })
        .unwrap();
    assert_eq!(
        gate.acquire(&Principal {
            tenant: 5,
            ..p.clone()
        })
        .err()
        .unwrap()
        .code,
        "BACKPRESSURE"
    );
    drop(a);
    assert!(gate.acquire(&p).is_err());
    drop(a2);
    let c = gate.acquire(&p).unwrap();
    drop((b, c));
    let claim = gate.acquire(&p).unwrap();
    let active = gate.active.clone();
    assert!(std::thread::spawn(move || {
        let _lock = active.lock().unwrap();
        panic!("poisoned admission fixture")
    })
    .join()
    .is_err());
    assert_eq!(gate.acquire(&p).err().unwrap().code, "UNAVAILABLE");
    drop(claim);
    assert!(gate.active.lock().unwrap_err().into_inner().is_empty());
}

#[test]
fn opaque_name_continuation_rechecks_read_and_never_exposes_internal_frontiers() {
    let memory = Arc::new(Memory::default());
    let created = seed(memory.clone(), 2, 129);
    let d = discovery(memory.clone());
    let p = principal();
    memory.calls.lock().unwrap().clear();
    let first = page(&d, &p, "list_names", Value::Null);
    assert!(!first["names"].as_array().unwrap().is_empty());
    assert!(first["names"].as_array().unwrap().len() < created.len());
    assert_eq!(first["traversal_exhausted"], false);
    assert_eq!(first["stopped"], "LIMIT");
    assert!(first.get("usage").is_none());
    let mut names: BTreeSet<_> = first["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["creation"]["name"].as_str().unwrap().to_owned())
        .collect();
    let remaining = created
        .iter()
        .find(|n| !names.contains(n.name.as_str()))
        .unwrap();
    let db = Database::new(memory.clone(), remaining.scope.clone(), 100).unwrap();
    let head = db.status(3, until()).unwrap();
    db.set_policy(
        3,
        head.revision,
        91,
        vec![Permission {
            principal: 3,
            read: false,
            write: false,
            admin: true,
        }],
        until(),
    )
    .unwrap();
    let mut cursor = first["cursor"].clone();
    for index in 0..20 {
        let next = page(&d, &p, "list_names", cursor);
        for item in next["names"].as_array().unwrap() {
            let name = item["creation"]["name"].as_str().unwrap();
            assert_ne!(name, remaining.name);
            assert!(names.insert(name.to_owned()));
        }
        if next["traversal_exhausted"] == true {
            assert_eq!(next["cursor"], Value::Null);
            break;
        }
        assert!(index < 19);
        cursor = next["cursor"].clone();
    }
    assert_eq!(names.len(), created.len() - 1);
    assert!(!first.to_string().contains("scap-object/v1/"));
    for changed in [
        Principal {
            tenant: 3,
            ..p.clone()
        },
        Principal {
            principal: 4,
            ..p.clone()
        },
    ] {
        assert_eq!(
            d.reader
                .execute(
                    &changed,
                    call("list_names", first["cursor"].clone()),
                    until()
                )
                .unwrap_err()
                .code,
            "CURSOR_INVALID"
        );
    }
}

#[test]
fn deployment_inventory_requires_explicit_capability_and_is_metadata_only_across_all_tenants() {
    let memory = Arc::new(Memory::default());
    seed(memory.clone(), 2, 1);
    seed(memory.clone(), 8, 1);
    let d = discovery(memory.clone());
    let mut p = principal();
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        d.reader
            .execute(
                &p,
                call("deployment_inventory", json!("unauthenticated-cursor")),
                until()
            )
            .unwrap_err()
            .code,
        "DENIED"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
    p.deployment_inventory = true;
    let mut cursor = Value::Null;
    let mut records = Vec::new();
    let mut passes = 0;
    loop {
        let value = page(&d, &p, "deployment_inventory", cursor);
        passes += 1;
        assert_eq!(value["completion"]["data_recovery"], "not_run");
        assert_eq!(value["completion"]["recovery_complete"], false);
        records.extend(value["records"].as_array().unwrap().clone());
        if value["completion"]["traversal_exhausted"] == true {
            assert_eq!(value["completion"]["preexisting_slots_covered"], true);
            break;
        }
        assert!(passes < 20);
        cursor = value["cursor"].clone();
        let revoked = Principal {
            deployment_inventory: false,
            ..p.clone()
        };
        assert_eq!(
            d.reader
                .execute(
                    &revoked,
                    call("deployment_inventory", cursor.clone()),
                    until()
                )
                .unwrap_err()
                .code,
            "DENIED"
        );
    }
    assert!(records.iter().any(|r| r["scope"]["tenant"] == "8"));
    assert!(!memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|s| s.starts_with("PUT ")));
    let empty = page(
        &discovery(Arc::new(Memory::default())),
        &p,
        "deployment_inventory",
        Value::Null,
    );
    assert_eq!(empty["completion"]["metadata_classified"], "0");
}

#[test]
fn malformed_authenticated_checkpoints_and_deadline_or_backend_errors_never_become_empty_success() {
    let memory = Arc::new(Memory::default());
    let codec = codec();
    let d = Discovery::new(memory.clone(), memory.clone(), 100, codec.clone()).unwrap();
    assert!(Discovery::new(memory.clone(), memory.clone(), 0, codec.clone()).is_err());
    let p = Principal {
        deployment_inventory: true,
        ..principal()
    };
    for (operation, view) in [
        ("list_names", View::Names),
        ("deployment_inventory", View::Inventory),
    ] {
        let invalid = codec.seal(&p, view, b"not-a-checkpoint").unwrap();
        assert_eq!(
            d.reader
                .execute(&p, call(operation, json!(invalid)), until())
                .unwrap_err()
                .code,
            "INVALID"
        );
        assert_eq!(
            d.reader
                .execute(&p, call(operation, Value::Null), Instant::now())
                .unwrap_err()
                .code,
            "DEADLINE"
        );
        *memory.fail_list.lock().unwrap() = Some(scap_object_store::ListError::Denied);
        let value = page(&d, &p, operation, Value::Null);
        assert_eq!(value["stopped"], "DENIED");
        assert!(value["cursor"].is_string());
    }
    assert_eq!(
        d.reader
            .execute(
                &Principal {
                    deployment: 0,
                    ..p.clone()
                },
                call("list_names", Value::Null),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(
        d.reader
            .execute(
                &Principal {
                    principal: 0,
                    ..p.clone()
                },
                call("list_names", Value::Null),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(
        d.reader
            .execute(
                &Principal { deployment: 0, ..p },
                call("deployment_inventory", Value::Null),
                until()
            )
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(
        bounded(json!("x".repeat(MAX_RESPONSE_BYTES)), until())
            .unwrap_err()
            .code,
        "LIMIT"
    );
    assert_eq!(
        bounded(json!(null), Instant::now()).unwrap_err().code,
        "DEADLINE"
    );
}

#[test]
fn worker_submission_is_confined_single_use_bounded_and_reaped_or_joined() {
    use scap_object_store::{ListError, ListPage, ListRequest, Listings};
    use std::sync::{mpsc, Barrier};
    struct Paused {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        memory: Memory,
    }
    impl Listings for Paused {
        fn list_page(
            &self,
            request: &ListRequest<'_>,
            deadline: Instant,
        ) -> Result<ListPage, ListError> {
            assert!(tokio::runtime::Handle::try_current().is_err());
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            self.memory.list_page(request, deadline)
        }
    }
    let (entered, enter) = mpsc::sync_channel(2);
    let (release, receive) = mpsc::sync_channel(2);
    let d = Discovery::new(
        Arc::new(Memory::default()),
        Arc::new(Paused {
            entered,
            release: Mutex::new(receive),
            memory: Memory::default(),
        }),
        100,
        codec(),
    )
    .unwrap();
    let p = principal();
    let lease = d.admission.acquire(&p).unwrap();
    let first = d
        .submit(
            p.clone(),
            call("list_names", Value::Null),
            lease.clone(),
            until(),
        )
        .unwrap();
    assert_eq!(
        d.submit(
            p.clone(),
            call("list_names", Value::Null),
            lease.clone(),
            until()
        )
        .err()
        .unwrap()
        .code,
        "INVALID"
    );
    drop(lease);
    drop(first);
    enter.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(d.admission.acquire(&p).is_err());
    let other = Principal {
        tenant: 9,
        ..p.clone()
    };
    let lease = d.admission.acquire(&other).unwrap();
    let second = d
        .submit(
            other.clone(),
            call("list_names", Value::Null),
            lease,
            until(),
        )
        .unwrap();
    enter.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(d
        .admission
        .acquire(&Principal {
            tenant: 10,
            ..p.clone()
        })
        .is_err());
    release.send(()).unwrap();
    release.send(()).unwrap();
    second.blocking_recv().unwrap().unwrap();
    drop(d);

    let d = discovery(Arc::new(Memory::default()));
    let foreign = Admission::default().acquire(&p).unwrap();
    assert_eq!(
        d.submit(p.clone(), call("list_names", Value::Null), foreign, until())
            .err()
            .unwrap()
            .code,
        "INVALID"
    );
    let lease = d.admission.acquire(&p).unwrap();
    assert_eq!(
        d.submit(
            other.clone(),
            call("list_names", Value::Null),
            lease.clone(),
            until()
        )
        .err()
        .unwrap()
        .code,
        "INVALID"
    );
    fn failed(_: Task) -> std::io::Result<JoinHandle<()>> {
        Err(std::io::Error::other("injected spawn refusal"))
    }
    assert_eq!(
        d.submit_with(
            p.clone(),
            call("list_names", Value::Null),
            lease,
            until(),
            failed
        )
        .err()
        .unwrap()
        .code,
        "UNAVAILABLE"
    );
    let finished = std::thread::spawn(|| panic!("finished worker panic"));
    let stop = Instant::now() + Duration::from_secs(1);
    while !finished.is_finished() {
        assert!(Instant::now() < stop);
        std::thread::yield_now();
    }
    d.workers.lock().unwrap().push(finished);
    let lease = d.admission.acquire(&p).unwrap();
    d.submit(p.clone(), call("list_names", Value::Null), lease, until())
        .unwrap()
        .blocking_recv()
        .unwrap()
        .unwrap();
    drop(d);

    let d = discovery(Arc::new(Memory::default()));
    let barrier = Arc::new(Barrier::new(3));
    for _ in 0..2 {
        let barrier = barrier.clone();
        d.workers.lock().unwrap().push(std::thread::spawn(move || {
            barrier.wait();
        }));
    }
    let lease = d.admission.acquire(&p).unwrap();
    assert_eq!(
        d.submit(p.clone(), call("list_names", Value::Null), lease, until())
            .err()
            .unwrap()
            .code,
        "BACKPRESSURE"
    );
    barrier.wait();
    drop(d);

    let d = discovery(Arc::new(Memory::default()));
    let changed = d.clone();
    assert!(std::thread::spawn(move || {
        let _lock = changed.workers.lock().unwrap();
        panic!("poisoned worker registry");
    })
    .join()
    .is_err());
    let lease = d.admission.acquire(&p).unwrap();
    assert_eq!(
        d.submit(p, call("list_names", Value::Null), lease, until())
            .err()
            .unwrap()
            .code,
        "UNAVAILABLE"
    );
    drop(d);
}

#[test]
fn nonce_capacity_exhaustion_rejects_both_kinds_of_incomplete_page() {
    let memory = Arc::new(Memory::default());
    let d = discovery(memory.clone());
    d.reader.codec.exhaust_for_test();
    let p = Principal {
        deployment_inventory: true,
        ..principal()
    };
    for operation in ["list_names", "deployment_inventory"] {
        *memory.fail_list.lock().unwrap() = Some(scap_object_store::ListError::Unknown);
        assert_eq!(
            d.reader
                .execute(&p, call(operation, Value::Null), until())
                .unwrap_err()
                .code,
            "UNAVAILABLE"
        );
    }
}
