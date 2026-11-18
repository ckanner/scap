//! Addressing and attempt-lifetime regressions through the immutable object port.
//! Physical generation one is frozen; no network, pins or deletion capability.

use super::tests::{deadline, identity, scope, sql, test_options, Memory};
use super::*;
use scap_object_store::Stored;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Operation {
    Get,
    Create,
    Replace(String),
}

#[derive(Clone, Debug)]
struct Call {
    key: String,
    operation: Operation,
    deadline: Instant,
}

struct Pause {
    key: String,
    reached: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

#[derive(Default)]
struct Trace {
    memory: Memory,
    calls: Mutex<Vec<Call>>,
    pause: Mutex<Option<Pause>>,
    forbid_head_reads: AtomicBool,
}

impl Objects for Trace {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        assert!(
            !self.forbid_head_reads.load(Ordering::Acquire) || key != head_key(&scope()),
            "publication must not re-read HEAD after admission"
        );
        self.calls.lock().unwrap().push(Call {
            key: key.into(),
            operation: Operation::Get,
            deadline,
        });
        self.memory.get(key, maximum, deadline)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        let operation = match condition {
            Condition::Absent => Operation::Create,
            Condition::Match(etag) => Operation::Replace(etag.into()),
        };
        self.calls.lock().unwrap().push(Call {
            key: key.into(),
            operation,
            deadline,
        });
        let pause = {
            let mut pause = self.pause.lock().unwrap();
            if pause.as_ref().is_some_and(|pause| pause.key == key) {
                pause.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            pause.reached.send(()).map_err(|_| StoreError::Unknown)?;
            pause
                .resume
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| StoreError::Unknown)?;
        }
        self.memory.put(key, bytes, condition, deadline)
    }
}

fn traced() -> (Arc<Trace>, Database) {
    let objects = Arc::new(Trace::default());
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    database.create(7, 1, deadline()).unwrap();
    database.activate(7, 1, 2, deadline()).unwrap();
    objects.calls.lock().unwrap().clear();
    (objects, database)
}

fn result() -> Vec<u8> {
    scap_sql::encode_result(
        &TransactionResult {
            statements: vec![scap_sql::StatementResult {
                columns: vec!["1".into()],
                rows: vec![vec![scap_sql::Value::Integer(1)]],
                affected_rows: 0,
                last_insert_rowid: 0,
            }],
        },
        sql_limits(),
    )
    .unwrap()
}

#[test]
fn captured_namespace_backend_and_quarantine_outlive_the_source_handle() {
    let (objects, mut database) = traced();
    let observer = database.clone();
    let mut head = database.read_head(deadline()).unwrap().head;
    let context = ObjectContext::capture(&database, &head).unwrap();
    objects.calls.lock().unwrap().clear();

    // Mutate the private source only in the fixture. ObjectContext owns copies
    // and Arcs; neither later source reuse nor dropping it can retarget a call.
    head.scope.generation += 1;
    head.storage.active_generation += 1;
    head.storage.allocated_through += 1;
    database.scope.generation += 2;
    database.objects = Arc::new(Memory::default());
    drop(database);
    let until = deadline();
    let payload = Payload::Manifest(Manifest {
        page_count: 0,
        root: None,
    });
    let root = context.save(payload.clone(), until).unwrap();
    assert_eq!(context.load(&root, until).unwrap(), payload);
    assert_eq!(
        root,
        "18d14e4e54fc17b2e7d8d40a70bbb2d0f198015dd0915619e527a0974f19555e"
    );
    let key = format!("scap-object/v1/1/2/3/inc/4/gen/5/storage/1/objects/{root}");
    let calls = objects.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].operation, Operation::Create);
    assert!(calls[1..]
        .iter()
        .all(|call| call.operation == Operation::Get));
    assert!(calls
        .iter()
        .all(|call| call.key == key && call.deadline == until));

    // Independent literal framing freezes the existing object bytes, not just
    // agreement between a producer and its matching decoder.
    let metadata = br#"{"format":2,"scope":{"deployment":1,"tenant":2,"database":3,"incarnation":4,"generation":5},"payload":{"kind":"manifest","value":{"page_count":0,"root":null}}}"#;
    let mut expected = b"SCAPOBJ2".to_vec();
    expected.extend_from_slice(&159_u32.to_le_bytes());
    expected.extend_from_slice(&0_u64.to_le_bytes());
    expected.extend_from_slice(metadata);
    assert_eq!(
        objects
            .memory
            .get(&key, MAX_OBJECT_BYTES, until)
            .unwrap()
            .bytes,
        expected
    );
    objects.memory.set(key, b"damaged immutable bytes".to_vec());
    assert!(matches!(context.load(&root, until), Err(Error::Format(_))));
    assert!(matches!(observer.healthy(), Err(Error::Corrupt)));
}

#[test]
fn paused_bootstrap_does_not_follow_a_replacement_scope_or_publish_over_it() {
    let objects = Arc::new(Trace::default());
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    let key = object_key(
        &scope(),
        1,
        "18d14e4e54fc17b2e7d8d40a70bbb2d0f198015dd0915619e527a0974f19555e",
    );
    let (reached, wait_reached) = mpsc::channel();
    let (resume, wait_resume) = mpsc::channel();
    *objects.pause.lock().unwrap() = Some(Pause {
        key,
        reached,
        resume: wait_resume,
    });
    let until = deadline();
    let old = std::thread::spawn(move || database.create(7, 1, until));
    wait_reached.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut replacement_scope = scope();
    replacement_scope.incarnation += 1;
    replacement_scope.generation += 1;
    let replacement = Database::with_options(
        objects.clone(),
        replacement_scope.clone(),
        11,
        test_options(),
    )
    .unwrap();
    let winner = replacement
        .create(7, 2, until + Duration::from_secs(1))
        .unwrap();
    resume.send(()).unwrap();
    assert!(matches!(
        old.join().unwrap(),
        Err(Error::Store(StoreError::Conflict))
    ));
    assert_eq!(replacement.read_head(deadline()).unwrap().head, winner);
    assert_eq!(winner.scope, replacement_scope);
    assert_eq!(winner.format, 6);
    assert_eq!(winner.head_serial, 1);
    assert_eq!(winner.storage.active_generation, 1);
    assert_eq!(winner.revision, 1);
    let old_calls: Vec<_> = objects
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.deadline == until)
        .cloned()
        .collect();
    assert_eq!(old_calls.len(), 5);
    assert!(old_calls[..4].iter().all(|call| {
        call.key
            .starts_with("scap-object/v1/1/2/3/inc/4/gen/5/storage/1/objects/")
    }));
    assert_eq!(old_calls[4].key, "scap-object/v1/1/2/3/head");
    assert_eq!(old_calls[4].operation, Operation::Create);
}

#[test]
fn publish_gate_consumes_the_admitted_context_request_etag_and_deadline() {
    let (objects, database) = traced();
    let until = Instant::now() + Duration::from_secs(5);
    let request = identity(1);
    let Admission::Fresh(context) = database
        .admit(7, &request, &sql("SELECT 1"), until)
        .unwrap()
    else {
        panic!("fresh request must have a frozen attempt");
    };
    let original_etag = context.base.etag.clone();
    assert_eq!(context.request, request);
    assert_eq!(context.deadline, until);
    objects.calls.lock().unwrap().clear();
    // The original backend forbids a fresh HEAD read after admission. The
    // final Manifest GET still uses this admitted context and original deadline;
    // it must not refresh the HEAD or rebase the publication's original ETag.
    objects.forbid_head_reads.store(true, Ordering::Release);
    let state = Rc::new(RefCell::new(Publication {
        context: Some(context),
        outcome: None,
    }));
    let mut gate = PublishGate {
        database,
        state: state.clone(),
    };
    let bytes = result();
    assert_eq!(
        gate.publish(
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            &bytes
        ),
        GateDecision::Accepted
    );
    assert!(state.borrow().context.is_none());
    let receipt = state.borrow_mut().outcome.take().unwrap().unwrap();
    assert_eq!(receipt.request, request);
    let calls = objects.calls.lock().unwrap().clone();
    assert!(calls.iter().all(|call| call.deadline == until));
    assert_eq!(calls.last().unwrap().key, head_key(&scope()));
    assert_eq!(
        calls.last().unwrap().operation,
        Operation::Replace(original_etag)
    );
    assert!(calls[..calls.len() - 1].iter().all(|call| {
        call.key
            .starts_with("scap-object/v1/1/2/3/inc/4/gen/5/storage/1/objects/")
    }));
    objects.forbid_head_reads.store(false, Ordering::Release);
    let reader = Database::with_options(objects, scope(), 10, test_options()).unwrap();
    assert_eq!(
        reader.lookup(7, &request, deadline()).unwrap(),
        Resolution::Committed { receipt, bytes }
    );
}

#[test]
fn a_stale_admitted_attempt_keeps_its_original_cas_and_never_replays() {
    let (objects, database) = traced();
    let until = Instant::now() + Duration::from_secs(5);
    let request = identity(1);
    let Admission::Fresh(context) = database
        .admit(7, &request, &sql("SELECT 1"), until)
        .unwrap()
    else {
        panic!("fresh request must have a frozen attempt");
    };
    let original_etag = context.base.etag.clone();
    let changed = database
        .set_lifecycle(
            7,
            context.base.head.revision,
            99,
            Lifecycle::Maintenance,
            deadline(),
        )
        .unwrap();
    objects.calls.lock().unwrap().clear();
    let state = Rc::new(RefCell::new(Publication {
        context: Some(context),
        outcome: None,
    }));
    let mut gate = PublishGate {
        database: database.clone(),
        state: state.clone(),
    };
    assert_eq!(
        gate.publish(
            &PageBatch {
                size_after: 0,
                pages: vec![]
            },
            &result()
        ),
        GateDecision::Unknown
    );
    assert!(state.borrow().context.is_none());
    assert!(matches!(
        state.borrow_mut().outcome.take().unwrap(),
        Err(Error::Conflict)
    ));
    let calls = objects.calls.lock().unwrap().clone();
    let heads: Vec<_> = calls
        .iter()
        .filter(|call| call.key == head_key(&scope()))
        .collect();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].operation, Operation::Replace(original_etag));
    assert!(calls.iter().all(|call| call.deadline == until));
    assert_eq!(database.read_head(deadline()).unwrap().head, changed);
    assert_eq!(
        database.lookup(7, &request, deadline()).unwrap(),
        Resolution::Unknown
    );
}

#[test]
fn warm_query_keeps_one_head_read_and_no_immutable_or_pin_operations() {
    let (objects, database) = traced();
    let directory = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &directory.path().join("image"), deadline())
        .unwrap();
    objects.calls.lock().unwrap().clear();
    let until = Instant::now() + Duration::from_secs(5);
    let result = session.query(7, &sql("SELECT 1"), until).unwrap();
    assert_eq!(
        result.statements[0].rows,
        vec![vec![scap_sql::Value::Integer(1)]]
    );
    let calls = objects.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].key, head_key(&scope()));
    assert_eq!(calls[0].operation, Operation::Get);
    assert_eq!(calls[0].deadline, until);
}
