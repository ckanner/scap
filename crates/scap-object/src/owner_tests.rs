use super::*;
use crate::tests::{deadline, scope, sql, test_options, Memory};
use std::sync::Mutex;

struct Quoted {
    inner: Arc<Memory>,
    unknown_after: Mutex<Option<String>>,
}

impl Objects for Quoted {
    fn get(&self, key: &str, cap: usize, until: Instant) -> Result<Stored, StoreError> {
        let mut stored = self.inner.get(key, cap, until)?;
        stored.etag = format!("\"{}\"", stored.etag);
        Ok(stored)
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
            Condition::Match(etag) => Condition::Match(
                etag.strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap(),
            ),
        };
        let etag = self.inner.put(key, bytes, condition, until)?;
        let mut cut = self.unknown_after.lock().unwrap();
        if cut.as_deref() == Some(key) {
            *cut = None;
            return Err(StoreError::Unknown);
        }
        Ok(format!("\"{etag}\""))
    }
}

fn fixture() -> (Arc<Quoted>, Database) {
    let objects = Arc::new(Quoted {
        inner: Arc::new(Memory::default()),
        unknown_after: Mutex::new(None),
    });
    let database = Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
    database.create(7, 1, deadline()).unwrap();
    (objects, database)
}

fn input(head: &Head, operation: u64, target: u64, mode: OwnerMode) -> PrepareOwnerInput {
    PrepareOwnerInput {
        creator: 7,
        operation,
        expected_revision: head.revision,
        expected_head_serial: head.head_serial,
        mode,
        target_worker: target,
        nonces: OwnerNonces {
            claim: 1001,
            cancel: 1002,
            activate: 1003,
            abort: 1004,
        },
    }
}

fn prepare(database: &Database, operation: u64, target: u64, mode: OwnerMode) -> PreparedOwner {
    let head = database.status(7, deadline()).unwrap();
    let OwnerPreparation::Prepared(prepared) = database
        .owner_prepare(7, &input(&head, operation, target, mode), deadline())
        .unwrap()
    else {
        panic!()
    };
    prepared
}

fn target(objects: &Arc<Quoted>, worker: u64) -> Database {
    Database::with_options(objects.clone(), scope(), worker, test_options()).unwrap()
}

#[test]
fn takeover_claim_resume_preserves_history_and_returns_only_this_calls_native_session() {
    let (objects, source) = fixture();
    let plan = prepare(&source, 101, 20, OwnerMode::Takeover);
    let database = target(&objects, 20);
    let claimed = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    assert_eq!(claimed.state, OwnerState::Claimed);
    assert_eq!(claimed.head.owner_epoch, 2);
    assert!(!claimed.head.active);
    let directory = tempfile::tempdir().unwrap();
    let (active, session) = database
        .owner_resume(
            7,
            &plan.reference,
            &directory.path().join("active"),
            deadline(),
        )
        .unwrap();
    assert_eq!(active.state, OwnerState::Active);
    let mut session = session.unwrap();
    let statements = sql("CREATE TABLE t AS SELECT 42 AS v");
    let request = crate::request(1, 23, 7, &statements).unwrap();
    let (receipt, _) = session
        .execute(7, &request, &statements, deadline())
        .unwrap();
    // More than eight future HEAD reads prove the per-call owner meter did not
    // leak into the returned Session or its native publication gate.
    for _ in 0..12 {
        session
            .query(7, &sql("SELECT v FROM t"), deadline())
            .unwrap();
    }
    assert!(
        matches!(database.lookup(7, &request, deadline()).unwrap(), crate::Resolution::Committed { receipt: stored, .. } if stored == receipt)
    );
    let (_, again) = database
        .owner_resume(
            7,
            &plan.reference,
            &directory.path().join("not-created"),
            deadline(),
        )
        .unwrap();
    assert!(again.is_none());
    assert!(!directory.path().join("not-created").exists());
    for call in [
        database.takeover(7, receipt.transition.revision, 200, deadline()),
        database.activate(7, receipt.transition.revision, 201, deadline()),
    ] {
        assert!(matches!(call, Err(Error::Fenced)));
    }
}

#[test]
fn prepare_lost_reply_recovers_fixed_input_without_the_hash_or_a_new_base() {
    let (objects, database) = fixture();
    let head = database.status(7, deadline()).unwrap();
    let fixed = input(&head, 101, 20, OwnerMode::Takeover);
    *objects.unknown_after.lock().unwrap() =
        Some(owner_format::key(&scope(), &fixed.identity(), false));
    assert!(matches!(
        database.owner_prepare(7, &fixed, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    let later = database
        .set_policy(7, head.revision, 4, head.policy.clone(), deadline())
        .unwrap();
    let OwnerPreparation::Prepared(recovered) =
        database.owner_prepare(7, &fixed, deadline()).unwrap()
    else {
        panic!()
    };
    assert_eq!(recovered.input, fixed);
    assert_eq!(
        database
            .owner_inspect(7, &fixed.identity(), deadline())
            .unwrap()
            .state,
        OwnerState::Fenced
    );
    let mut rebased = fixed.clone();
    rebased.expected_revision = later.revision;
    rebased.expected_head_serial = later.head_serial;
    assert!(matches!(
        database.owner_prepare(7, &rebased, deadline()),
        Err(Error::Conflict)
    ));
    assert_eq!(
        target(&objects, 20)
            .owner_claim(7, &recovered.reference, deadline())
            .unwrap()
            .state,
        OwnerState::Fenced
    );
}

#[test]
fn unknown_claim_is_resumed_once_after_handle_reconstruction_and_abort_is_one_head_step() {
    let (objects, database) = fixture();
    let plan = prepare(&database, 101, 20, OwnerMode::Takeover);
    objects.inner.lose_next_cas();
    assert!(matches!(
        target(&objects, 20).owner_claim(7, &plan.reference, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    let restarted = target(&objects, 20);
    assert_eq!(
        restarted
            .owner_inspect(7, &plan.input.identity(), deadline())
            .unwrap()
            .state,
        OwnerState::Claimed
    );
    let aborted = restarted
        .owner_abort(7, &plan.reference, deadline())
        .unwrap();
    assert_eq!(aborted.state, OwnerState::Aborted);
    assert_eq!(aborted.head.owner_epoch, 2);
    let second = prepare(&database, 102, 30, OwnerMode::Takeover);
    let cancelling = database
        .owner_abort(7, &second.reference, deadline())
        .unwrap();
    assert_eq!(cancelling.state, OwnerState::Cancelling);
    let serial = cancelling.head.head_serial;
    let done = database
        .owner_abort(7, &second.reference, deadline())
        .unwrap();
    assert_eq!(done.state, OwnerState::Aborted);
    assert_eq!(done.head.head_serial, serial + 1);
    assert_eq!(
        database
            .owner_inspect(7, &plan.input.identity(), deadline())
            .unwrap()
            .accepted,
        aborted.accepted
    );
}

#[test]
fn every_owner_io_prefix_fails_closed_without_an_unaccepted_head_or_partial_session() {
    fn run(kind: u8, failure: Option<usize>) -> usize {
        let (objects, database) = fixture();
        let worker = target(&objects, 20);
        let directory = tempfile::tempdir().unwrap();
        let previous = if matches!(kind, 3 | 4 | 9) {
            let previous = prepare(&database, 101, 20, OwnerMode::Takeover);
            database
                .owner_abort(7, &previous.reference, deadline())
                .unwrap();
            database
                .owner_abort(7, &previous.reference, deadline())
                .unwrap();
            Some(previous)
        } else {
            None
        };
        let head = database.status(7, deadline()).unwrap();
        let fixed = input(&head, 102, 20, OwnerMode::Takeover);
        let plan = if kind == 0 {
            None
        } else {
            let OwnerPreparation::Prepared(plan) =
                database.owner_prepare(7, &fixed, deadline()).unwrap()
            else {
                panic!()
            };
            Some(plan)
        };
        if matches!(kind, 5 | 8 | 9 | 10 | 11 | 12) {
            worker
                .owner_claim(7, &plan.as_ref().unwrap().reference, deadline())
                .unwrap();
        }
        if matches!(kind, 6 | 13) {
            database
                .owner_abort(7, &plan.as_ref().unwrap().reference, deadline())
                .unwrap();
        }
        if kind == 13 {
            database
                .owner_abort(7, &plan.as_ref().unwrap().reference, deadline())
                .unwrap();
        }
        if kind == 11 {
            worker
                .owner_resume(
                    7,
                    &plan.as_ref().unwrap().reference,
                    &directory.path().join("initial"),
                    deadline(),
                )
                .unwrap();
        }
        let original = objects
            .inner
            .entries()
            .into_iter()
            .find(|(key, _)| *key == head_key(&scope()))
            .unwrap()
            .1
            .bytes;
        let before = objects.inner.operation_count();
        if let Some(offset) = failure {
            objects.inner.fail_after(offset);
        }
        let result = match kind {
            0 | 1 => database.owner_prepare(7, &fixed, deadline()).map(|_| ()),
            2 | 3 | 12 => worker
                .owner_claim(7, &plan.as_ref().unwrap().reference, deadline())
                .map(|_| ()),
            4 | 5 | 6 | 13 => database
                .owner_abort(7, &plan.as_ref().unwrap().reference, deadline())
                .map(|_| ()),
            7 | 8 => database
                .owner_inspect(7, &fixed.identity(), deadline())
                .map(|_| ()),
            9 => database
                .owner_inspect(7, &previous.as_ref().unwrap().input.identity(), deadline())
                .map(|_| ()),
            10 | 11 => worker
                .owner_resume(
                    7,
                    &plan.as_ref().unwrap().reference,
                    &directory.path().join("attempt"),
                    deadline(),
                )
                .map(|_| ()),
            _ => unreachable!(),
        };
        let count = objects.inner.operation_count() - before;
        if let Some(offset) = failure {
            assert!(
                matches!(result, Err(Error::Store(StoreError::Unknown))),
                "kind {kind}, prefix {offset}: {result:?}"
            );
            let current = objects
                .inner
                .entries()
                .into_iter()
                .find(|(key, _)| *key == head_key(&scope()))
                .unwrap()
                .1
                .bytes;
            assert_eq!(current, original, "kind {kind}, prefix {offset}");
            assert!(!database.quarantined.load(Ordering::Acquire));
            assert!(!worker.quarantined.load(Ordering::Acquire));
        } else {
            assert!(result.is_ok(), "kind {kind}: {result:?}");
        }
        count
    }
    for kind in 0..14 {
        let count = run(kind, None);
        assert!(count > 0);
        for prefix in 1..=count {
            run(kind, Some(prefix));
        }
    }
}

#[test]
fn pending_metadata_preserves_roots_but_cannot_consume_the_final_abort_slot() {
    let (objects, database) = fixture();
    let mut head = database.status(7, deadline()).unwrap();
    head.revision = u64::MAX - 2;
    head.transition.revision = head.revision;
    head.head_serial = head.revision;
    objects
        .inner
        .set(head_key(&scope()), encode_head(&head).unwrap());
    let plan = prepare(&database, 101, 10, OwnerMode::Activate);
    let claimed = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    assert!(matches!(
        database.set_policy(
            7,
            claimed.head.revision,
            44,
            head.policy.clone(),
            deadline()
        ),
        Err(Error::Limit)
    ));
    assert!(matches!(
        database.set_quota(7, claimed.head.revision, 45, head.quota.clone(), deadline()),
        Err(Error::Limit)
    ));
    let done = database
        .owner_abort(7, &plan.reference, deadline())
        .unwrap();
    assert_eq!(done.head.revision, u64::MAX);
    assert_eq!(done.state, OwnerState::Aborted);
}

#[test]
fn terminal_owner_history_remains_metadata_only_after_head8_storage_seal() {
    let (objects, database) = fixture();
    let first = prepare(&database, 101, 10, OwnerMode::Activate);
    database
        .owner_claim(7, &first.reference, deadline())
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (active, _) = database
        .owner_resume(
            7,
            &first.reference,
            &directory.path().join("first"),
            deadline(),
        )
        .unwrap();
    let second = prepare(&database, 102, 20, OwnerMode::Takeover);
    database
        .owner_abort(7, &second.reference, deadline())
        .unwrap();
    let aborted = database
        .owner_abort(7, &second.reference, deadline())
        .unwrap();
    let deleted = database
        .set_lifecycle(
            7,
            aborted.head.revision,
            888,
            Lifecycle::Deleted,
            deadline(),
        )
        .unwrap();
    let sealed = database
        .retire_storage(7, deleted.head_serial, deadline())
        .unwrap();
    assert_eq!(sealed.format, 8);
    for (key, _) in objects.inner.entries() {
        if key.contains("/storage/") {
            objects.inner.remove(&key);
        }
    }
    let historic = database
        .owner_inspect(7, &first.input.identity(), deadline())
        .unwrap();
    assert_eq!(historic.state, OwnerState::Active);
    assert_eq!(historic.accepted, active.accepted);
    assert_eq!(historic.head, sealed);
    assert!(matches!(
        database.status(7, deadline()),
        Err(Error::Lifecycle)
    ));
}

struct NoCollector;
impl scap_object_store::Listings for NoCollector {
    fn list_page(
        &self,
        _: &scap_object_store::ListRequest<'_>,
        _: Instant,
    ) -> Result<scap_object_store::ListPage, scap_object_store::ListError> {
        panic!("pending owner must not list")
    }
}
impl scap_object_store::Garbage for NoCollector {
    fn inspect(
        &self,
        _: &str,
        _: &str,
        _: Instant,
    ) -> Result<scap_object_store::GcCandidate, scap_object_store::GcError> {
        panic!("pending owner must not inspect payload")
    }
    fn delete(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Instant,
    ) -> Result<scap_object_store::DeleteOutcome, scap_object_store::GcError> {
        panic!("pending owner must not delete")
    }
}

#[test]
fn pending_fences_every_mutator_but_keeps_fixed_history_and_readonly_recovery() {
    let (_, database) = fixture();
    let identity = crate::request(1, 33, 7, &sql("SELECT 1")).unwrap();
    let cancelled = database.cancel(7, &identity, deadline()).unwrap();
    let plan = prepare(&database, 101, 10, OwnerMode::Activate);
    let pending = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    let old_roots = (pending.head.data_root.clone(), pending.head.windows.clone());
    let mut policy = pending.head.policy.clone();
    policy.push(Permission {
        principal: 11,
        read: false,
        write: false,
        admin: true,
    });
    let policy = database
        .set_policy(7, pending.head.revision, 50, policy, deadline())
        .unwrap();
    let quota = database
        .set_quota(7, policy.revision, 51, policy.quota.clone(), deadline())
        .unwrap();
    assert_eq!((quota.data_root.clone(), quota.windows.clone()), old_roots);
    assert_eq!(quota.owner_plan, pending.head.owner_plan);
    assert_eq!(
        database.cancel(7, &identity, deadline()).unwrap(),
        cancelled
    );
    assert_eq!(
        database.lookup(7, &identity, deadline()).unwrap(),
        cancelled
    );
    let directory = tempfile::tempdir().unwrap();
    let mut readonly = database
        .session(7, &directory.path().join("readonly"), deadline())
        .unwrap();
    readonly.query(7, &sql("SELECT 1"), deadline()).unwrap();
    let unknown = crate::request(1, 34, 7, &sql("SELECT 1")).unwrap();
    let results = [
        database
            .takeover(7, quota.revision, 60, deadline())
            .map(|_| ()),
        database
            .activate(7, quota.revision, 60, deadline())
            .map(|_| ()),
        database
            .activate_session(
                7,
                quota.revision,
                60,
                &directory.path().join("legacy"),
                deadline(),
            )
            .map(|_| ()),
        database
            .set_lifecycle(7, quota.revision, 60, Lifecycle::Deleted, deadline())
            .map(|_| ()),
        database
            .close_full(7, quota.revision, 60, deadline())
            .map(|_| ()),
        database.cancel(7, &unknown, deadline()).map(|_| ()),
        database
            .execute(
                7,
                &identity,
                &sql("SELECT 1"),
                &directory.path().join("write"),
                deadline(),
            )
            .map(|_| ()),
        readonly
            .execute(7, &unknown, &sql("SELECT 1"), deadline())
            .map(|_| ()),
        database
            .compact_begin(7, quota.head_serial, deadline())
            .map(|_| ()),
        database.compact_copy(7, 1, deadline()).map(|_| ()),
        database.compact_promote(7, 1, deadline()).map(|_| ()),
        database.compact_abort(7, 1, deadline()).map(|_| ()),
        database
            .gc_prepare(
                7,
                quota.head_serial,
                1,
                None,
                &NoCollector,
                &NoCollector,
                deadline(),
            )
            .map(|_| ()),
        database
            .gc_resume(7, 1, &NoCollector, deadline())
            .map(|_| ()),
        database.writer(&quota),
    ];
    for result in results {
        assert!(matches!(result, Err(Error::Fenced)));
    }
    assert!(
        matches!(database.owner_prepare(7, &input(&quota, 102, 10, OwnerMode::Activate), deadline()).unwrap(), OwnerPreparation::Pending(reference) if reference == plan.reference)
    );
    let done = database
        .owner_abort(11, &plan.reference, deadline())
        .unwrap();
    assert_eq!(done.state, OwnerState::Aborted);
}

#[test]
fn missing_original_descriptor_is_never_recreated_when_marker_or_proof_references_it() {
    for cut in 0..3 {
        let (objects, database) = fixture();
        let plan = prepare(&database, 101, 10, OwnerMode::Activate);
        database
            .owner_claim(7, &plan.reference, deadline())
            .unwrap();
        if cut >= 1 {
            database
                .owner_abort(7, &plan.reference, deadline())
                .unwrap();
        }
        if cut == 2 {
            let second = prepare(&database, 102, 20, OwnerMode::Takeover);
            database
                .owner_abort(7, &second.reference, deadline())
                .unwrap();
            database
                .owner_abort(7, &second.reference, deadline())
                .unwrap();
        }
        let key = owner_format::key(&scope(), &plan.input.identity(), false);
        objects.inner.remove(&key);
        let head = database.status(7, deadline()).unwrap();
        assert!(matches!(
            database.owner_prepare(7, &input(&head, 101, 10, OwnerMode::Activate), deadline()),
            Err(Error::Corrupt)
        ));
        assert!(!objects
            .inner
            .entries()
            .iter()
            .any(|(stored, _)| stored == &key));
        assert_eq!(database.read_head(deadline()).unwrap().head, head);
    }
}

#[test]
fn historical_proof_must_precede_the_new_marker_not_only_the_latest_head_counters() {
    for racing in [false, true] {
        let (objects, database) = fixture();
        let first = prepare(&database, 101, 10, OwnerMode::Activate);
        database
            .owner_abort(7, &first.reference, deadline())
            .unwrap();
        let old = database
            .owner_abort(7, &first.reference, deadline())
            .unwrap();
        let next = prepare(&database, 102, 20, OwnerMode::Takeover);
        database
            .owner_abort(7, &next.reference, deadline())
            .unwrap();
        let current = database
            .owner_abort(7, &next.reference, deadline())
            .unwrap();
        let mut marker = old.accepted.unwrap();
        marker.phase.revision = current.head.owner_plan.as_ref().unwrap().admission.revision;
        marker.phase.head_serial = current
            .head
            .owner_plan
            .as_ref()
            .unwrap()
            .admission
            .head_serial;
        let proof = OwnerProof {
            version: 1,
            scope: scope(),
            marker,
        };
        let key = owner_format::key(&scope(), &first.input.identity(), true);
        objects.inner.set(key, proof.bytes().unwrap());
        if racing {
            let later = Database::next(&current.head, 800).unwrap();
            objects
                .inner
                .replace_after(4, head_key(&scope()), encode_head(&later).unwrap(), false);
        }
        let result = database.owner_inspect(7, &first.input.identity(), deadline());
        if racing {
            assert!(matches!(result, Err(Error::Conflict)));
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
        }
    }
}

#[test]
fn named_delete_preserves_history_tuple_and_pending_owner_cannot_publish_its_barrier() {
    use crate::catalogue::{
        Caller, Catalogue, CreateOptions, DeleteNamed, PrepareCreate, RetireNamedStorage,
    };
    let objects = Arc::new(Quoted {
        inner: Arc::new(Memory::default()),
        unknown_after: Mutex::new(None),
    });
    let catalogue = Catalogue::new(objects.clone(), 1, 2, 10, test_options()).unwrap();
    let caller = Caller {
        principal: 7,
        provision: true,
    };
    let create = catalogue
        .prepare(
            caller,
            &PrepareCreate {
                name: "owner-test".into(),
                operation: 45,
                expected_name_revision: None,
                options: CreateOptions::default(),
            },
            deadline(),
        )
        .unwrap();
    catalogue
        .resume_create(caller, &create.creation, deadline())
        .unwrap();
    let database = Database::with_options(
        objects.clone(),
        create.creation.scope.clone(),
        10,
        test_options(),
    )
    .unwrap();
    let plan = prepare(&database, 101, 10, OwnerMode::Activate);
    let claimed = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    let deletion = |head: &Head, operation| DeleteNamed {
        creation: create.creation.clone(),
        operation,
        expected_name_revision: 2,
        expected_head_revision: head.revision,
        nonce: 800,
    };
    assert!(matches!(
        catalogue.delete(caller, &deletion(&claimed.head, 46), deadline()),
        Err(crate::catalogue::CatalogueError::Conflict)
    ));
    let aborted = database
        .owner_abort(7, &plan.reference, deadline())
        .unwrap();
    let historical = aborted.accepted.clone();
    let input = deletion(&aborted.head, 47);
    catalogue.delete(caller, &input, deadline()).unwrap();
    let deleted = catalogue
        .storage_status(caller, &create.creation, deadline())
        .unwrap();
    assert_eq!(deleted.owner_epoch, aborted.head.owner_epoch + 1);
    assert_eq!(deleted.owner_plan, historical);
    let sealed = catalogue
        .retire_storage(
            caller,
            &RetireNamedStorage {
                creation: create.creation,
                expected_head_serial: deleted.head_serial,
            },
            deadline(),
        )
        .unwrap();
    assert_eq!(sealed.format, 8);
    assert_eq!(
        database
            .owner_inspect(7, &plan.input.identity(), deadline())
            .unwrap()
            .accepted,
        historical
    );
    catalogue.delete(caller, &input, deadline()).unwrap();
}

#[test]
fn existing_prepare_authorizes_after_a_delayed_descriptor_read_before_conflict_or_content() {
    for mismatch in [false, true] {
        let (objects, database) = fixture();
        let plan = prepare(&database, 101, 10, OwnerMode::Activate);
        let old = database.status(7, deadline()).unwrap();
        let mut revoked = Database::next(&old, 99).unwrap();
        revoked.auth_epoch += 1;
        revoked.policy = vec![Permission {
            principal: 11,
            read: false,
            write: false,
            admin: true,
        }];
        // The descriptor response completes after the old principal lost ADMIN.
        objects
            .inner
            .replace_after(1, head_key(&scope()), encode_head(&revoked).unwrap(), false);
        let mut fixed = plan.input;
        if mismatch {
            fixed.target_worker = 20;
        }
        assert!(matches!(
            database.owner_prepare(7, &fixed, deadline()),
            Err(Error::Denied)
        ));
        assert_eq!(database.read_head(deadline()).unwrap().head, revoked);
    }
}

fn meter(objects: Arc<dyn Objects>, gets: u64, bytes: u64) -> OwnerMeter {
    OwnerMeter {
        objects,
        head: head_key(&scope()),
        prefix: owner_format::prefix(&scope()),
        remaining: AtomicUsize::new(8),
        deadline: deadline(),
        payload_gets: gets,
        payload_bytes: bytes,
        used: Mutex::new(PayloadUsage::default()),
        now: Instant::now,
    }
}

#[test]
fn metadata_and_payload_budgets_are_independent_and_failed_reservations_are_not_refunded() {
    let (objects, database) = fixture();
    let key = object_key(&scope(), 1, &"c".repeat(64));
    objects.inner.set(key.clone(), vec![1; 4]);
    let counted = meter(objects.clone(), 2, 10);
    for _ in 0..8 {
        counted
            .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
            .unwrap();
    }
    assert!(matches!(
        counted.get(&head_key(&scope()), MAX_HEAD_BYTES, deadline()),
        Err(StoreError::Budget)
    ));
    assert!(matches!(
        counted.put(&head_key(&scope()), b"no", Condition::Absent, deadline()),
        Err(StoreError::Budget)
    ));
    counted.get(&key, 8, deadline()).unwrap();
    {
        let used = counted.used.lock().unwrap();
        assert_eq!((used.gets, used.bytes), (1, 4));
    }
    counted.get(&key, 8, deadline()).unwrap();
    assert_eq!(counted.used.lock().unwrap().bytes, 8);
    assert!(matches!(
        counted.get(&key, 8, deadline()),
        Err(StoreError::Budget)
    ));
    let counted = meter(objects.clone(), 3, 7);
    assert!(matches!(
        counted.get(&key, 3, deadline()),
        Err(StoreError::Limit)
    ));
    assert_eq!(counted.used.lock().unwrap().bytes, 3);
    counted.get(&key, 8, deadline()).unwrap();
    assert_eq!(counted.used.lock().unwrap().bytes, 7);
    assert!(matches!(
        counted.get(&key, 8, deadline()),
        Err(StoreError::Budget)
    ));
    let counted = meter(objects.clone(), 1, 3);
    assert!(matches!(
        counted.get(&key, 8, deadline()),
        Err(StoreError::Budget)
    ));
    assert_eq!(counted.used.lock().unwrap().bytes, 3);
    assert!(database.healthy().is_ok());
    let counted = meter(objects.clone(), 0, 0);
    let before = objects.inner.operation_count();
    assert!(matches!(
        counted.get(&key, 8, deadline()),
        Err(StoreError::Budget)
    ));
    assert_eq!(objects.inner.operation_count(), before);
    counted
        .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
        .unwrap();
    let control = owner_format::key(
        &scope(),
        &OwnerIdentity {
            creator: 7,
            operation: 900,
        },
        false,
    );
    counted
        .put(&control, b"control", Condition::Absent, deadline())
        .unwrap();
    counted.get(&control, 32, deadline()).unwrap();
}

struct OverCap;
impl Objects for OverCap {
    fn get(&self, _: &str, cap: usize, _: Instant) -> Result<Stored, StoreError> {
        Ok(Stored {
            bytes: vec![0; cap + 1],
            etag: "\"etag\"".into(),
        })
    }
    fn put(&self, _: &str, _: &[u8], _: Condition<'_>, _: Instant) -> Result<String, StoreError> {
        unreachable!()
    }
}

#[test]
fn meter_rejects_transport_overdelivery_and_never_extends_original_time() {
    let counted = meter(Arc::new(OverCap), 1, 8);
    assert!(matches!(
        counted.get("payload", 8, deadline()),
        Err(StoreError::Corrupt)
    ));
    assert_eq!(counted.used.lock().unwrap().bytes, 8);
    let (objects, _) = fixture();
    let mut counted = meter(objects.clone(), 1, 8);
    counted.deadline = Instant::now();
    assert!(matches!(
        counted.get("payload", 8, deadline()),
        Err(StoreError::Unknown)
    ));
    assert!(matches!(
        counted.put("payload", b"x", Condition::Absent, deadline()),
        Err(StoreError::Unknown)
    ));
    thread_local! { static TICKS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
    fn clock() -> Instant {
        TICKS.with(|value| {
            let before = value.get();
            value.set(before + 1);
            Instant::now() + std::time::Duration::from_secs(if before == 0 { 0 } else { 120 })
        })
    }
    objects.inner.set("payload".into(), vec![1; 4]);
    let mut counted = meter(objects, 1, 8);
    counted.now = clock;
    assert!(matches!(
        counted.get("payload", 8, deadline()),
        Err(StoreError::Unknown)
    ));
    assert_eq!(counted.used.lock().unwrap().bytes, 4);
}

#[test]
fn owner_recovery_limits_fail_without_active_or_quarantine_and_a_fresh_call_gets_its_own_budget() {
    for kind in 0..4 {
        let (objects, source) = fixture();
        let plan = prepare(&source, 101, 10, OwnerMode::Activate);
        let claimed = source.owner_claim(7, &plan.reference, deadline()).unwrap();
        let root = object_key(&scope(), 1, &claimed.head.data_root);
        let mut options = test_options();
        match kind {
            0 => options.owner_recovery_gets = 0,
            1 => options.owner_recovery_bytes = 0,
            2 => options.owner_recovery_bytes = 1,
            _ => options.owner_recovery_gets = 1,
        }
        let database = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let heads_before = objects.inner.gets_for(&head_key(&scope()));
        let payload_before = objects.inner.gets_for(&root);
        assert!(matches!(
            database.owner_resume(
                7,
                &plan.reference,
                &directory.path().join("budget"),
                deadline()
            ),
            Err(Error::Store(StoreError::Budget))
        ));
        assert_eq!(
            objects.inner.gets_for(&head_key(&scope())),
            heads_before + 1,
            "no diagnostic HEAD after local budget"
        );
        assert_eq!(
            objects.inner.gets_for(&root),
            payload_before + usize::from(kind >= 2)
        );
        assert!(database.healthy().is_ok());
        assert_eq!(source.status(7, deadline()).unwrap(), claimed.head);
        let (active, session) = source
            .owner_resume(
                7,
                &plan.reference,
                &directory.path().join("fresh"),
                deadline(),
            )
            .unwrap();
        assert_eq!(active.state, OwnerState::Active);
        assert!(session.is_some());
    }
    let (objects, database) = fixture();
    let plan = prepare(&database, 101, 10, OwnerMode::Activate);
    let claimed = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    let root = object_key(&scope(), 1, &claimed.head.data_root);
    objects.inner.fail(false, root, StoreError::Limit);
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.owner_resume(
            7,
            &plan.reference,
            &directory.path().join("format-limit"),
            deadline()
        ),
        Err(Error::Store(StoreError::Limit))
    ));
    assert!(
        matches!(database.healthy(), Err(Error::Corrupt)),
        "original format cap is still a physical incident"
    );
    assert_eq!(database.read_head(deadline()).unwrap().head, claimed.head);
    let mut options = test_options();
    options.owner_recovery_gets = crate::options::MAX_OWNER_RECOVERY_GETS + 1;
    assert!(matches!(options.validate(), Err(Error::Limit)));
    options = test_options();
    options.owner_recovery_bytes = crate::options::MAX_OWNER_RECOVERY_BYTES + 1;
    assert!(matches!(options.validate(), Err(Error::Limit)));
}

#[test]
fn a_failed_locally_capped_get_does_not_poison_the_next_resume_with_the_same_options() {
    let (objects, source) = fixture();
    let plan = prepare(&source, 101, 10, OwnerMode::Activate);
    let claimed = source.owner_claim(7, &plan.reference, deadline()).unwrap();
    let root = object_key(&scope(), 1, &claimed.head.data_root);
    let mut options = test_options();
    options.owner_recovery_bytes = 1024 * 1024;
    options.owner_recovery_gets = 2;
    let database = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
    objects.inner.fail(false, root, StoreError::Limit);
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.owner_resume(
            7,
            &plan.reference,
            &directory.path().join("failed"),
            deadline()
        ),
        Err(Error::Store(StoreError::Budget))
    ));
    assert!(database.healthy().is_ok());
    let (active, session) = database
        .owner_resume(
            7,
            &plan.reference,
            &directory.path().join("fresh"),
            deadline(),
        )
        .unwrap();
    assert_eq!(active.state, OwnerState::Active);
    assert!(session.is_some());
}
