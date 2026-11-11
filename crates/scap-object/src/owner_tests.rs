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

/// Complete a real competing operation after an exact GET has obtained its
/// response, but before that response reaches the first caller. The captured
/// result is never rewritten: an earlier Missing remains a legitimate read.
type AfterGetAction = (usize, Box<dyn FnOnce() + Send>);

struct AfterGet {
    inner: Arc<Quoted>,
    key: String,
    reads: AtomicUsize,
    actions: Mutex<Vec<AfterGetAction>>,
}

impl Objects for AfterGet {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        let result = self.inner.get(key, maximum, until);
        if key == self.key {
            let read = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
            let action = {
                let mut actions = self.actions.lock().unwrap();
                actions
                    .iter()
                    .position(|(nth, _)| *nth == read)
                    .map(|index| actions.remove(index).1)
            };
            if let Some(action) = action {
                action();
            }
        }
        result
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        self.inner.put(key, bytes, condition, until)
    }
}

#[test]
fn prepare_missing_before_a_competing_claim_recovers_the_actual_first_winner() {
    for superseded in [false, true] {
        let (objects, source) = fixture();
        let initial = source.status(7, deadline()).unwrap();
        let fixed = input(&initial, 101, 20, OwnerMode::Takeover);
        let competing_input = fixed.clone();
        let competing = target(&objects, 20);
        let winner = Arc::new(Mutex::new(None));
        let observed = winner.clone();
        let delayed = Arc::new(AfterGet {
            inner: objects.clone(),
            key: owner_format::key(&scope(), &fixed.identity(), false),
            reads: AtomicUsize::new(0),
            actions: Mutex::new(vec![(
                1,
                Box::new(move || {
                    let OwnerPreparation::Prepared(plan) = competing
                        .owner_prepare(7, &competing_input, deadline())
                        .unwrap()
                    else {
                        panic!()
                    };
                    competing
                        .owner_claim(7, &plan.reference, deadline())
                        .unwrap();
                    if superseded {
                        competing
                            .owner_abort(7, &plan.reference, deadline())
                            .unwrap();
                        let next = prepare(&competing, 102, 30, OwnerMode::Takeover);
                        competing
                            .owner_abort(7, &next.reference, deadline())
                            .unwrap();
                    }
                    *observed.lock().unwrap() =
                        Some((plan, competing.read_head(deadline()).unwrap()));
                }),
            )]),
        });
        let database = Database::with_options(delayed, scope(), 20, test_options()).unwrap();
        let result = database.owner_prepare(7, &fixed, deadline());
        let (plan, accepted) = winner.lock().unwrap().take().unwrap();
        assert!(
            matches!(&result, Ok(OwnerPreparation::Prepared(found)) if *found == plan),
            "a descriptor absent before another caller creates and claims it is not corrupt: {result:?}"
        );
        assert!(database.healthy().is_ok());
        let after = database.read_head(deadline()).unwrap();
        assert_eq!(after.head, accepted.head);
        assert_eq!(after.etag, accepted.etag);
    }
}

#[test]
fn prepare_refresh_rechecks_permission_before_mismatch_and_preserves_unknown() {
    for revoke in [false, true] {
        let (objects, source) = fixture();
        let initial = source.status(7, deadline()).unwrap();
        let fixed = input(&initial, 101, 20, OwnerMode::Takeover);
        let competing_input = fixed.clone();
        let competing = target(&objects, 20);
        let key = owner_format::key(&scope(), &fixed.identity(), false);
        let failing_objects = objects.clone();
        let failing_key = key.clone();
        let mut actions: Vec<AfterGetAction> = vec![(
            1,
            Box::new(move || {
                let OwnerPreparation::Prepared(plan) = competing
                    .owner_prepare(7, &competing_input, deadline())
                    .unwrap()
                else {
                    panic!()
                };
                competing
                    .owner_claim(7, &plan.reference, deadline())
                    .unwrap();
                if !revoke {
                    failing_objects
                        .inner
                        .fail(false, failing_key, StoreError::Unknown);
                }
            }),
        )];
        let mut supplied = fixed;
        if revoke {
            supplied.target_worker += 1;
            actions.push((
                2,
                Box::new(move || {
                    let head = source.status(7, deadline()).unwrap();
                    source
                        .set_policy(
                            7,
                            head.revision,
                            88,
                            vec![Permission {
                                principal: 11,
                                read: true,
                                write: true,
                                admin: true,
                            }],
                            deadline(),
                        )
                        .unwrap();
                }),
            ));
        }
        let database = Database::with_options(
            Arc::new(AfterGet {
                inner: objects.clone(),
                key,
                reads: AtomicUsize::new(0),
                actions: Mutex::new(actions),
            }),
            scope(),
            20,
            test_options(),
        )
        .unwrap();
        let result = database.owner_prepare(7, &supplied, deadline());
        if revoke {
            assert!(matches!(result, Err(Error::Denied)), "{result:?}");
        } else {
            assert!(
                matches!(result, Err(Error::Store(StoreError::Unknown))),
                "{result:?}"
            );
        }
        assert!(database.healthy().is_ok());
    }
}

#[test]
fn prepare_proof_created_after_absence_requires_a_stable_head_before_quarantine() {
    let (objects, source) = fixture();
    let initial = source.status(7, deadline()).unwrap();
    let fixed = input(&initial, 101, 20, OwnerMode::Takeover);
    let competing_input = fixed.clone();
    let competing = target(&objects, 20);
    let accepted = Arc::new(Mutex::new(None));
    let observed = accepted.clone();
    let database = Database::with_options(
        Arc::new(AfterGet {
            inner: objects.clone(),
            key: head_key(&scope()),
            reads: AtomicUsize::new(0),
            actions: Mutex::new(vec![(
                2,
                Box::new(move || {
                    let OwnerPreparation::Prepared(plan) = competing
                        .owner_prepare(7, &competing_input, deadline())
                        .unwrap()
                    else {
                        panic!()
                    };
                    competing
                        .owner_claim(7, &plan.reference, deadline())
                        .unwrap();
                    competing
                        .owner_abort(7, &plan.reference, deadline())
                        .unwrap();
                    let next = prepare(&competing, 102, 30, OwnerMode::Takeover);
                    competing
                        .owner_abort(7, &next.reference, deadline())
                        .unwrap();
                    *observed.lock().unwrap() = Some(competing.read_head(deadline()).unwrap());
                }),
            )]),
        }),
        scope(),
        20,
        test_options(),
    )
    .unwrap();
    assert!(matches!(
        database.owner_prepare(7, &fixed, deadline()),
        Err(Error::Conflict)
    ));
    assert!(database.healthy().is_ok());
    let expected = accepted.lock().unwrap().take().unwrap();
    let after = database.read_head(deadline()).unwrap();
    assert_eq!(after.head, expected.head);
    assert_eq!(after.etag, expected.etag);
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
fn the_current_identity_cannot_reference_a_different_first_persisted_descriptor() {
    for operation in 0..4 {
        for changes in [false, true] {
            let (objects, source) = fixture();
            let plan = prepare(&source, 101, 20, OwnerMode::Takeover);
            let database = target(&objects, 20);
            let mut current = database
                .owner_claim(7, &plan.reference, deadline())
                .unwrap()
                .head;
            current
                .owner_plan
                .as_mut()
                .unwrap()
                .reference
                .descriptor_hash = "f".repeat(64);
            objects
                .inner
                .set(head_key(&scope()), encode_head(&current).unwrap());
            if changes {
                let later = Database::next(&current, 88).unwrap();
                objects.inner.replace_after(
                    3,
                    head_key(&scope()),
                    encode_head(&later).unwrap(),
                    operation % 2 == 0,
                );
            }
            let directory = tempfile::tempdir().unwrap();
            let result = match operation {
                0 => database
                    .owner_inspect(7, &plan.input.identity(), deadline())
                    .map(|_| ()),
                1 => database
                    .owner_claim(7, &plan.reference, deadline())
                    .map(|_| ()),
                2 => database
                    .owner_resume(
                        7,
                        &plan.reference,
                        &directory.path().join("unopened"),
                        deadline(),
                    )
                    .map(|_| ()),
                _ => database
                    .owner_abort(7, &plan.reference, deadline())
                    .map(|_| ()),
            };
            if changes {
                assert!(
                    matches!(result, Err(Error::Conflict)),
                    "operation {operation}: {result:?}"
                );
                assert!(database.healthy().is_ok());
            } else {
                assert!(
                    matches!(result, Err(Error::Corrupt)),
                    "operation {operation}: {result:?}"
                );
                assert!(matches!(database.healthy(), Err(Error::Corrupt)));
            }
            assert!(!directory.path().join("unopened").exists());
        }
    }
}

#[test]
fn owner_admission_checks_original_counters_mode_worker_and_current_admin() {
    for cut in 0..11 {
        let (objects, database) = fixture();
        let mut head = database.status(7, deadline()).unwrap();
        if cut == 6 {
            head = database.activate(7, head.revision, 55, deadline()).unwrap();
        }
        match cut {
            7 => {
                head.revision = u64::MAX - 1;
                head.transition.revision = head.revision;
                head.head_serial = head.revision;
            }
            8 => head.head_serial = u64::MAX - 1,
            9 => head.owner_epoch = u64::MAX,
            10 => head.lifecycle = Lifecycle::Maintenance,
            _ => {}
        }
        objects
            .inner
            .set(head_key(&scope()), encode_head(&head).unwrap());
        let mut fixed = input(&head, 101, 20, OwnerMode::Takeover);
        match cut {
            0 => fixed.creator = 0,
            1 => fixed.creator = 11,
            2 => {
                fixed.expected_revision += 1;
                fixed.expected_head_serial += 1;
            }
            3 => fixed.expected_head_serial += 1,
            4 => fixed.mode = OwnerMode::Activate,
            5 | 6 => {
                fixed.mode = OwnerMode::Activate;
                fixed.target_worker = 10;
            }
            _ => {}
        }
        let result = database.owner_prepare(if cut == 5 { 11 } else { 7 }, &fixed, deadline());
        match cut {
            0 => assert!(matches!(result, Err(Error::Format(_)))),
            1 | 5 => assert!(matches!(result, Err(Error::Denied))),
            2 | 3 => assert!(matches!(result, Err(Error::Conflict))),
            4 | 6 => assert!(matches!(result, Err(Error::Fenced))),
            7..=9 => assert!(matches!(result, Err(Error::Limit))),
            _ => assert!(matches!(result, Err(Error::Lifecycle))),
        }
        assert_eq!(database.read_head(deadline()).unwrap().head, head);
    }
    let (objects, database) = fixture();
    let plan = prepare(&database, 101, 20, OwnerMode::Takeover);
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.owner_claim(7, &plan.reference, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.owner_resume(7, &plan.reference, directory.path(), deadline()),
        Err(Error::Fenced)
    ));
    let worker = target(&objects, 20);
    let mut wrong = plan.reference.clone();
    wrong.descriptor_hash = "f".repeat(64);
    assert!(matches!(
        worker.owner_claim(7, &wrong, deadline()),
        Err(Error::Conflict)
    ));
    wrong.descriptor_hash = "bad".into();
    assert!(matches!(
        worker.owner_claim(7, &wrong, deadline()),
        Err(Error::Format(_))
    ));
    wrong = plan.reference;
    wrong.operation += 1;
    assert!(matches!(
        worker.owner_claim(7, &wrong, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(matches!(
        worker.owner_inspect(7, &wrong.identity(), deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    wrong.operation = 0;
    assert!(matches!(
        worker.owner_inspect(7, &wrong.identity(), deadline()),
        Err(Error::Format(_))
    ));
}

#[test]
fn prepare_races_keep_the_first_record_and_compare_the_exact_readback() {
    for cut in 0..3 {
        let (objects, database) = fixture();
        let base = database.read_head(deadline()).unwrap();
        let fixed = input(&base.head, 101, 20, OwnerMode::Takeover);
        let mut other = fixed.clone();
        if cut == 1 {
            other.target_worker += 1;
        }
        let descriptor = OwnerDescriptor::new(&base, &other).unwrap();
        let bytes = if cut == 2 {
            serde_json::to_vec_pretty(&descriptor).unwrap()
        } else {
            descriptor.bytes().unwrap()
        };
        let key = owner_format::key(&scope(), &fixed.identity(), false);
        // Both absence reads complete before the competing immutable PUT wins
        // at the proof read. Our original Absent PUT gets 412 and its exact
        // readback must retain that first winner's bytes.
        objects
            .inner
            .replace_after(5, key.clone(), bytes.clone(), false);
        let result = database.owner_prepare(7, &fixed, deadline());
        match cut {
            0 => assert!(matches!(result, Ok(OwnerPreparation::Prepared(_)))),
            1 => assert!(matches!(result, Err(Error::Conflict))),
            _ => assert!(matches!(result, Err(Error::Corrupt))),
        }
        let stored = objects
            .inner
            .entries()
            .into_iter()
            .find(|(k, _)| *k == key)
            .unwrap()
            .1;
        assert_eq!(stored.bytes, bytes);
        assert_eq!(database.read_head(deadline()).unwrap().head, base.head);
    }
}

enum ReadChange {
    Missing,
    Etag(String),
    Bytes(Vec<u8>),
}

struct AlterRead {
    inner: Arc<Quoted>,
    key: String,
    nth: usize,
    reads: AtomicUsize,
    change: ReadChange,
}

impl Objects for AlterRead {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        let result = self.inner.get(key, maximum, until);
        if key != self.key
            || (self.nth != 0 && self.reads.fetch_add(1, Ordering::Relaxed) + 1 != self.nth)
        {
            return result;
        }
        match &self.change {
            ReadChange::Missing => Err(StoreError::Missing),
            ReadChange::Etag(etag) => result.map(|mut value| {
                value.etag = etag.clone();
                value
            }),
            ReadChange::Bytes(bytes) => result.map(|mut value| {
                value.bytes = bytes.clone();
                value
            }),
        }
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        self.inner.put(key, bytes, condition, until)
    }
}

fn altered(objects: &Arc<Quoted>, key: String, nth: usize, change: ReadChange) -> Database {
    Database::with_options(
        Arc::new(AlterRead {
            inner: objects.clone(),
            key,
            nth,
            reads: AtomicUsize::new(0),
            change,
        }),
        scope(),
        20,
        test_options(),
    )
    .unwrap()
}

fn raw_descriptor(descriptor: &mut OwnerDescriptor) -> Vec<u8> {
    descriptor.input_digest = digest(
        &serde_json::to_vec(&(
            descriptor.version,
            &descriptor.scope,
            &descriptor.input,
            &descriptor.base,
        ))
        .unwrap(),
    );
    descriptor.bytes().unwrap()
}

#[test]
fn descriptor_damage_is_not_replaced_or_misreported_as_a_client_input_conflict() {
    for cut in 0..6 {
        let (objects, source) = fixture();
        let plan = prepare(&source, 101, 20, OwnerMode::Takeover);
        let key = owner_format::key(&scope(), &plan.input.identity(), false);
        let mut descriptor = source
            .owner_descriptor(&plan.input.identity(), deadline())
            .unwrap()
            .unwrap();
        let change = match cut {
            0 => ReadChange::Bytes(b"{}".to_vec()),
            1 => ReadChange::Etag(String::new()),
            2 => {
                descriptor.scope.tenant += 1;
                ReadChange::Bytes(raw_descriptor(&mut descriptor))
            }
            3 => {
                descriptor.input.operation += 1;
                ReadChange::Bytes(raw_descriptor(&mut descriptor))
            }
            4 => {
                let mut head = target(&objects, 20)
                    .owner_claim(7, &plan.reference, deadline())
                    .unwrap()
                    .head;
                head.owner_plan.as_mut().unwrap().reference.descriptor_hash = "f".repeat(64);
                objects
                    .inner
                    .set(head_key(&scope()), encode_head(&head).unwrap());
                ReadChange::Bytes(descriptor.bytes().unwrap())
            }
            _ => {
                let accepted = target(&objects, 20)
                    .owner_claim(7, &plan.reference, deadline())
                    .unwrap();
                assert_eq!(
                    source.owner_prepare(7, &plan.input, deadline()).unwrap(),
                    OwnerPreparation::Prepared(plan.clone())
                );
                let mut head = accepted.head;
                head.owner_plan.as_mut().unwrap().phase.nonce += 42;
                head.transition.nonce = head.owner_plan.as_ref().unwrap().phase.nonce;
                objects
                    .inner
                    .set(head_key(&scope()), encode_head(&head).unwrap());
                ReadChange::Bytes(descriptor.bytes().unwrap())
            }
        };
        let database = altered(&objects, key, 1, change);
        assert!(
            matches!(
                database.owner_prepare(7, &plan.input, deadline()),
                Err(Error::Corrupt)
            ),
            "descriptor cut {cut}"
        );
        assert!(matches!(database.healthy(), Err(Error::Corrupt)));
    }
    let (objects, source) = fixture();
    let head = source.status(7, deadline()).unwrap();
    let fixed = input(&head, 101, 20, OwnerMode::Takeover);
    let database = altered(
        &objects,
        owner_format::key(&scope(), &fixed.identity(), false),
        3,
        ReadChange::Missing,
    );
    assert!(matches!(
        database.owner_prepare(7, &fixed, deadline()),
        Err(Error::Corrupt)
    ));
    let (objects, source) = fixture();
    let head = source.status(7, deadline()).unwrap();
    let database = altered(
        &objects,
        head_key(&scope()),
        0,
        ReadChange::Etag("not-an-etag".into()),
    );
    assert!(matches!(
        database.owner_prepare(7, &input(&head, 101, 20, OwnerMode::Takeover), deadline()),
        Err(Error::Format(_))
    ));
}

#[test]
fn replacing_a_terminal_marker_requires_its_original_descriptor_and_exact_permanent_proof() {
    for cut in 0..3 {
        let (objects, source) = fixture();
        let old = prepare(&source, 101, 20, OwnerMode::Takeover);
        source.owner_abort(7, &old.reference, deadline()).unwrap();
        let terminal = source.owner_abort(7, &old.reference, deadline()).unwrap();
        let new = prepare(&source, 102, 20, OwnerMode::Takeover);
        let proof = owner_format::key(&scope(), &old.input.identity(), true);
        let database = if cut == 0 {
            objects
                .inner
                .remove(&owner_format::key(&scope(), &old.input.identity(), false));
            target(&objects, 20)
        } else {
            altered(
                &objects,
                proof,
                1,
                if cut == 1 {
                    ReadChange::Etag(String::new())
                } else {
                    ReadChange::Bytes(b"{}".to_vec())
                },
            )
        };
        assert!(
            matches!(
                database.owner_claim(7, &new.reference, deadline()),
                Err(Error::Corrupt)
            ),
            "proof cut {cut}"
        );
        assert_eq!(database.read_head(deadline()).unwrap().head, terminal.head);
    }
}

#[test]
fn historical_proof_checks_its_body_scope_condition_and_actual_descriptor() {
    for cut in 0..4 {
        let (objects, source) = fixture();
        let old = prepare(&source, 101, 20, OwnerMode::Takeover);
        source.owner_abort(7, &old.reference, deadline()).unwrap();
        source.owner_abort(7, &old.reference, deadline()).unwrap();
        let new = prepare(&source, 102, 20, OwnerMode::Takeover);
        target(&objects, 20)
            .owner_claim(7, &new.reference, deadline())
            .unwrap();
        let key = owner_format::key(&scope(), &old.input.identity(), true);
        let mut proof =
            OwnerProof::decode(&objects.get(&key, MAX_PROOF, deadline()).unwrap().bytes).unwrap();
        let change = match cut {
            0 => ReadChange::Bytes(b"{}".to_vec()),
            1 => ReadChange::Etag(String::new()),
            2 => {
                proof.scope.generation += 1;
                ReadChange::Bytes(proof.bytes().unwrap())
            }
            _ => {
                proof.marker.phase.nonce += 7;
                ReadChange::Bytes(proof.bytes().unwrap())
            }
        };
        let database = altered(&objects, key, 1, change);
        assert!(
            matches!(
                database.owner_inspect(7, &old.input.identity(), deadline()),
                Err(Error::Corrupt)
            ),
            "history cut {cut}"
        );
        assert!(matches!(database.healthy(), Err(Error::Corrupt)));
    }
}

#[test]
fn owner_guard_primitives_reject_storage_work_and_unvalidated_publication_candidates() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    for cut in 0..3 {
        let mut head = base.head.clone();
        match cut {
            0 => {
                head.storage.plan = Some(CopyPlan {
                    serial: head.head_serial,
                    source: 1,
                    target: 2,
                    phase: CopyPhase::Copying,
                    basis: CopyBasis::capture(&head),
                })
            }
            1 => {
                head.storage.sweep = Some(SweepCheckpoint {
                    serial: head.head_serial,
                    generation: 2,
                    next_after: None,
                    exhausted: true,
                    entries: vec![],
                })
            }
            _ => {
                head.storage.terminal = Some(TerminalSeal {
                    serial: head.head_serial,
                })
            }
        }
        assert!(matches!(
            Database::owner_admission(&head),
            Err(Error::Fenced)
        ));
    }
    let descriptor =
        OwnerDescriptor::new(&base, &input(&base.head, 101, 10, OwnerMode::Activate)).unwrap();
    let mut active = base.clone();
    active.head.active = true;
    assert!(matches!(
        database.owner_start(active, &descriptor, OwnerAdmissionKind::Claim, deadline()),
        Err(Error::Fenced)
    ));
    let mut maintenance = base.clone();
    maintenance.head.lifecycle = Lifecycle::Maintenance;
    assert!(matches!(
        database.owner_start(
            maintenance,
            &descriptor,
            OwnerAdmissionKind::Claim,
            deadline()
        ),
        Err(Error::Lifecycle)
    ));
    let plan = prepare(&database, 101, 10, OwnerMode::Activate);
    let claimed = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    assert!(matches!(
        Database::owner_admission(&claimed.head),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.owner_preserve(&claimed.head, deadline()),
        Err(Error::Format(_))
    ));
    let base = database.read_head(deadline()).unwrap();
    let count = objects.inner.operation_count();
    let good = terminal(
        &base.head,
        OwnerPhaseKind::Active,
        descriptor.input.nonces.activate,
    )
    .unwrap();
    let mut wrong_nonce = good.clone();
    wrong_nonce.owner_plan.as_mut().unwrap().phase.nonce += 20;
    assert!(matches!(
        database.owner_publish(base.clone(), wrong_nonce, &descriptor, deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(objects.inner.operation_count(), count);
    // A different handle does not inherit the semantic latch. Its private
    // publication boundary still rejects malformed encoded candidates.
    let fresh = target(&objects, 10);
    let mut invalid = good.clone();
    invalid.transition.nonce = 0;
    assert!(matches!(
        fresh.owner_publish(base.clone(), invalid, &descriptor, deadline()),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.owner_publish(base, good, &descriptor, deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, claimed.head);
    // Encoding/publication validates the fixed nonce; constructing the local
    // successor alone does not make it an accepted or encodable authority.
    assert!(terminal(&claimed.head, OwnerPhaseKind::Active, 0)
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn owner_resume_respects_real_lineage_context_exhaustion_before_payload_or_activation() {
    let (objects, source) = fixture();
    let plan = prepare(&source, 101, 20, OwnerMode::Takeover);
    let database = target(&objects, 20);
    let claimed = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap();
    let snapshot = database.read_head(deadline()).unwrap();
    let contexts: Vec<_> = (0..64)
        .map(|_| ObjectContext::from_snapshot(&database, &snapshot, deadline()).unwrap())
        .collect();
    let reads = objects.inner.get_count();
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        database.owner_resume(
            7,
            &plan.reference,
            &directory.path().join("blocked"),
            deadline()
        ),
        Err(Error::Store(StoreError::Budget))
    ));
    assert_eq!(objects.inner.get_count(), reads + 2);
    assert!(!directory.path().join("blocked").exists());
    assert!(database.healthy().is_ok());
    assert_eq!(database.read_head(deadline()).unwrap().head, claimed.head);
    drop(contexts);
    let (active, session) = database
        .owner_resume(
            7,
            &plan.reference,
            &directory.path().join("independent"),
            deadline(),
        )
        .unwrap();
    assert_eq!(active.state, OwnerState::Active);
    assert!(session.is_some());
}

#[test]
fn a_matching_reference_still_requires_the_original_descriptor_phase_fields() {
    for operation in 0..3 {
        let (objects, source) = fixture();
        let plan = prepare(&source, 101, 20, OwnerMode::Takeover);
        let database = target(&objects, 20);
        let mut head = database
            .owner_claim(7, &plan.reference, deadline())
            .unwrap()
            .head;
        // Internally consistent HEAD fields cannot grant an epoch absent from
        // the actual immutable descriptor's original claim transition.
        head.owner_epoch += 1;
        head.owner_plan.as_mut().unwrap().phase.owner_epoch = head.owner_epoch;
        objects
            .inner
            .set(head_key(&scope()), encode_head(&head).unwrap());
        let directory = tempfile::tempdir().unwrap();
        let result = match operation {
            0 => database
                .owner_inspect(7, &plan.input.identity(), deadline())
                .map(|_| ()),
            1 => database
                .owner_abort(7, &plan.reference, deadline())
                .map(|_| ()),
            _ => database
                .owner_resume(7, &plan.reference, directory.path(), deadline())
                .map(|_| ()),
        };
        assert!(
            matches!(result, Err(Error::Corrupt)),
            "phase operation {operation}"
        );
        assert!(matches!(database.healthy(), Err(Error::Corrupt)));
    }
    let (objects, source) = fixture();
    let old = prepare(&source, 101, 20, OwnerMode::Takeover);
    source.owner_abort(7, &old.reference, deadline()).unwrap();
    let mut head = source
        .owner_abort(7, &old.reference, deadline())
        .unwrap()
        .head;
    head.owner_plan.as_mut().unwrap().reference.descriptor_hash = "f".repeat(64);
    objects
        .inner
        .set(head_key(&scope()), encode_head(&head).unwrap());
    let next = prepare(&source, 102, 20, OwnerMode::Takeover);
    let database = target(&objects, 20);
    assert!(matches!(
        database.owner_claim(7, &next.reference, deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, head);
}

#[test]
fn a_current_phase_nonce_contradiction_is_corrupt_at_the_first_exact_head_read() {
    let (objects, source) = fixture();
    let plan = prepare(&source, 101, 20, OwnerMode::Takeover);
    let database = target(&objects, 20);
    let mut head = database
        .owner_claim(7, &plan.reference, deadline())
        .unwrap()
        .head;
    assert_eq!(
        head.revision,
        head.owner_plan.as_ref().unwrap().phase.revision
    );
    head.transition.nonce += 20;
    // Raw operator corruption bypasses encode_head; the production reader is
    // responsible for rejecting this self-contradictory authority document.
    objects
        .inner
        .set(head_key(&scope()), serde_json::to_vec(&head).unwrap());
    let reads = objects.inner.get_count();
    let result = database.owner_inspect(7, &plan.input.identity(), deadline());
    // decode_head classifies invalid durable fields as FormatError::Corrupt;
    // read_head preserves it, the service maps it to CORRUPT, and observe latches.
    assert!(
        matches!(result, Err(Error::Format(FormatError::Corrupt))),
        "{result:?}"
    );
    assert_eq!(objects.inner.get_count(), reads + 1);
    assert!(matches!(database.healthy(), Err(Error::Corrupt)));
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
    assert!(matches!(
        terminal(&done.head, OwnerPhaseKind::Active, 99),
        Err(Error::Limit)
    ));
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
    assert_eq!(counted.used.lock().unwrap().bytes, 8);
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
