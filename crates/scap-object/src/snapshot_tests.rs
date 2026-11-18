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

fn input(head: &Head, operation: u64) -> PrepareSnapshotInput {
    PrepareSnapshotInput {
        creator: 7,
        operation,
        expected_revision: head.revision,
        expected_head_serial: head.head_serial,
        label: "saved".to_string(),
    }
}

fn prepare(database: &Database, operation: u64) -> PreparedSnapshot {
    let head = database.snapshot_list(7, deadline()).unwrap();
    database
        .snapshot_prepare(7, &input(&head, operation), deadline())
        .unwrap()
}

fn capture(database: &Database, operation: u64) -> PreparedSnapshot {
    let prepared = prepare(database, operation);
    database
        .snapshot_capture(7, &prepared.reference, deadline())
        .unwrap();
    prepared
}

fn restarted(objects: &Arc<Quoted>) -> Database {
    Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap()
}

type Action = (usize, Box<dyn FnOnce() + Send>);
struct AfterGet {
    inner: Arc<Quoted>,
    key: String,
    reads: AtomicUsize,
    actions: Mutex<Vec<Action>>,
}

impl Objects for AfterGet {
    fn get(&self, key: &str, cap: usize, until: Instant) -> Result<Stored, StoreError> {
        let result = self.inner.get(key, cap, until);
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

fn delayed(objects: &Arc<Quoted>, key: String, actions: Vec<Action>) -> Database {
    Database::with_options(
        Arc::new(AfterGet {
            inner: objects.clone(),
            key,
            reads: AtomicUsize::new(0),
            actions: Mutex::new(actions),
        }),
        scope(),
        10,
        test_options(),
    )
    .unwrap()
}

#[test]
fn prepare_capture_release_keep_business_identity_and_permanent_metadata() {
    let (objects, database) = fixture();
    let before = database.snapshot_list(7, deadline()).unwrap();
    let saved = prepare(&database, 101);
    assert_eq!(database.snapshot_list(7, deadline()).unwrap(), before);
    assert_eq!(
        database
            .snapshot_inspect(7, &saved.reference.identity(), deadline())
            .unwrap()
            .state,
        SnapshotState::Prepared
    );
    let captured = database
        .snapshot_capture(7, &saved.reference, deadline())
        .unwrap();
    assert_eq!(captured.state, SnapshotState::Retained);
    assert_eq!(captured.head.format, 9);
    assert_eq!(captured.head.head_serial, before.head_serial + 1);
    assert_eq!(
        (
            captured.head.revision,
            captured.head.sequence,
            &captured.head.windows
        ),
        (before.revision, before.sequence, &before.windows)
    );
    assert_eq!(captured.head.transition, before.transition);
    assert_eq!(saved.point.page_count, 0);
    assert_eq!(
        database
            .snapshot_capture(7, &saved.reference, deadline())
            .unwrap(),
        captured
    );
    assert_eq!(
        database
            .snapshot_prepare(7, &saved.input, deadline())
            .unwrap(),
        saved
    );
    let released = database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    assert_eq!(released.state, SnapshotState::ReleasedObserved);
    assert_eq!(released.accepted, captured.accepted);
    assert!(released.head.snapshots.as_ref().unwrap().is_empty());
    assert_eq!(
        database
            .snapshot_release(7, &saved.reference, deadline())
            .unwrap(),
        released
    );
    assert_eq!(
        database
            .snapshot_capture(7, &saved.reference, deadline())
            .unwrap(),
        released
    );
    let next = capture(&database, 102);
    assert_ne!(saved.reference, next.reference);
    for proof in [false, true] {
        assert!(objects
            .get(
                &snapshot_records::key(&scope(), &saved.input.identity(), proof),
                MAX_DESCRIPTOR,
                deadline()
            )
            .is_ok());
    }
    let mut mismatch = saved.input.clone();
    mismatch.label = "different".to_string();
    assert!(matches!(
        database.snapshot_prepare(7, &mismatch, deadline()),
        Err(Error::Conflict)
    ));
    database.healthy().unwrap();
}

#[test]
fn new_call_recovers_unknown_prepare_capture_proof_and_release_without_rebinding() {
    for stage in 0..4 {
        let (objects, database) = fixture();
        let fixed = input(&database.snapshot_list(7, deadline()).unwrap(), 101);
        let identity = fixed.identity();
        let descriptor_key = snapshot_records::key(&scope(), &identity, false);
        let proof_key = snapshot_records::key(&scope(), &identity, true);
        let saved = if stage == 0 {
            *objects.unknown_after.lock().unwrap() = Some(descriptor_key);
            assert!(matches!(
                database.snapshot_prepare(7, &fixed, deadline()),
                Err(Error::Store(StoreError::Unknown))
            ));
            restarted(&objects)
                .snapshot_prepare(7, &fixed, deadline())
                .unwrap()
        } else {
            prepare(&database, 101)
        };
        if stage == 1 {
            *objects.unknown_after.lock().unwrap() = Some(head_key(&scope()));
        }
        let captured = database.snapshot_capture(7, &saved.reference, deadline());
        if stage == 1 {
            assert!(matches!(captured, Err(Error::Store(StoreError::Unknown))));
        } else {
            captured.unwrap();
        }
        assert_eq!(
            restarted(&objects)
                .snapshot_inspect(7, &identity, deadline())
                .unwrap()
                .state,
            SnapshotState::Retained
        );
        if stage == 2 {
            *objects.unknown_after.lock().unwrap() = Some(proof_key);
        }
        if stage == 3 {
            *objects.unknown_after.lock().unwrap() = Some(head_key(&scope()));
        }
        let release = database.snapshot_release(7, &saved.reference, deadline());
        if stage >= 2 {
            assert!(matches!(release, Err(Error::Store(StoreError::Unknown))));
        } else {
            release.unwrap();
        }
        let fresh = restarted(&objects);
        let observed = fresh.snapshot_inspect(7, &identity, deadline()).unwrap();
        assert_eq!(
            observed.state,
            if stage == 2 {
                SnapshotState::Retained
            } else {
                SnapshotState::ReleasedObserved
            }
        );
        let end = fresh
            .snapshot_release(7, &saved.reference, deadline())
            .unwrap();
        assert_eq!(end.state, SnapshotState::ReleasedObserved);
        assert_eq!(end.head.sequence, 0);
    }
}

#[test]
fn first_winner_limits_survive_a_different_instance_default_and_old_operation_stays_fenced() {
    let (objects, database) = fixture();
    let mut options = test_options();
    options.snapshot_limits.max_points = 2;
    options.snapshot_limits.max_logical_bytes = 0;
    let original = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
    let saved = prepare(&original, 101);
    let mut changed = test_options();
    changed.snapshot_limits.max_points = 0;
    let fresh = Database::with_options(objects.clone(), scope(), 10, changed).unwrap();
    assert_eq!(
        fresh.snapshot_prepare(7, &saved.input, deadline()).unwrap(),
        saved
    );
    let captured = fresh
        .snapshot_capture(7, &saved.reference, deadline())
        .unwrap();
    assert_eq!(
        captured.head.snapshot_limits.as_ref().unwrap().max_points,
        2
    );
    let mut second = input(&captured.head, 102);
    second.label = "second".to_string();
    let second = fresh.snapshot_prepare(7, &second, deadline()).unwrap();
    fresh
        .snapshot_capture(7, &second.reference, deadline())
        .unwrap();
    assert!(matches!(
        fresh.snapshot_prepare(
            7,
            &input(&fresh.snapshot_list(7, deadline()).unwrap(), 103),
            deadline()
        ),
        Err(Error::Limit)
    ));
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    assert_eq!(
        fresh
            .snapshot_capture(7, &saved.reference, deadline())
            .unwrap()
            .state,
        SnapshotState::ReleasedObserved
    );
}

#[test]
fn genuine_missing_before_competing_capture_or_release_recovers_first_winner() {
    for release in [false, true] {
        let (objects, database) = fixture();
        let fixed = input(&database.snapshot_list(7, deadline()).unwrap(), 101);
        let competing = restarted(&objects);
        let same = fixed.clone();
        let winner = Arc::new(Mutex::new(None));
        let output = winner.clone();
        let slow = delayed(
            &objects,
            snapshot_records::key(&scope(), &fixed.identity(), false),
            vec![(
                1,
                Box::new(move || {
                    let saved = competing.snapshot_prepare(7, &same, deadline()).unwrap();
                    competing
                        .snapshot_capture(7, &saved.reference, deadline())
                        .unwrap();
                    if release {
                        competing
                            .snapshot_release(7, &saved.reference, deadline())
                            .unwrap();
                    }
                    *output.lock().unwrap() = Some(saved);
                }),
            )],
        );
        assert_eq!(
            slow.snapshot_prepare(7, &fixed, deadline()).unwrap(),
            winner.lock().unwrap().clone().unwrap()
        );
        slow.healthy().unwrap();
        assert_eq!(
            objects
                .inner
                .entries()
                .iter()
                .filter(|(key, _)| key.contains("/snapshot/v1/descriptor/"))
                .count(),
            1
        );
    }
}

#[test]
fn refresh_change_and_late_proof_change_are_conflicts_without_quarantine() {
    for proof_race in [false, true] {
        let (objects, database) = fixture();
        let fixed = input(&database.snapshot_list(7, deadline()).unwrap(), 101);
        let competing = restarted(&objects);
        let same = fixed.clone();
        let selected = if proof_race {
            head_key(&scope())
        } else {
            snapshot_records::key(&scope(), &fixed.identity(), false)
        };
        let slow = delayed(
            &objects,
            selected,
            vec![(
                2,
                Box::new(move || {
                    let saved = competing.snapshot_prepare(7, &same, deadline()).unwrap();
                    competing
                        .snapshot_capture(7, &saved.reference, deadline())
                        .unwrap();
                    if proof_race {
                        competing
                            .snapshot_release(7, &saved.reference, deadline())
                            .unwrap();
                    }
                }),
            )],
        );
        assert!(
            matches!(
                slow.snapshot_prepare(7, &fixed, deadline()),
                Err(Error::Conflict)
            ),
            "proof race {proof_race}"
        );
        slow.healthy().unwrap();
    }
}

#[test]
fn refreshed_permission_precedes_first_winner_input_mismatch() {
    let (objects, database) = fixture();
    let fixed = input(&database.snapshot_list(7, deadline()).unwrap(), 101);
    let competing = restarted(&objects);
    let revoker = restarted(&objects);
    let mut other = fixed.clone();
    other.label = "another-label".to_string();
    let slow = delayed(
        &objects,
        snapshot_records::key(&scope(), &fixed.identity(), false),
        vec![
            (
                1,
                Box::new(move || {
                    competing.snapshot_prepare(7, &other, deadline()).unwrap();
                }),
            ),
            (
                2,
                Box::new(move || {
                    let head = revoker.snapshot_list(7, deadline()).unwrap();
                    let mut policy = head.policy.clone();
                    policy[0].read = false;
                    revoker
                        .set_policy(7, head.revision, 20, policy, deadline())
                        .unwrap();
                }),
            ),
        ],
    );
    assert!(matches!(
        slow.snapshot_prepare(7, &fixed, deadline()),
        Err(Error::Denied)
    ));
    slow.healthy().unwrap();
}

#[test]
fn existing_descriptor_errors_wait_for_a_stable_current_permission_check() {
    for denied in [false, true] {
        let (objects, database) = fixture();
        let saved = capture(&database, 101);
        // Existing corrupt bytes are not interpreted until the current HEAD
        // read has been authorized and stabilized; this is not a fake GET.
        objects.inner.set(
            snapshot_records::key(&scope(), &saved.input.identity(), false),
            b"invalid-descriptor".to_vec(),
        );
        let competing = restarted(&objects);
        let slow = delayed(
            &objects,
            head_key(&scope()),
            vec![(
                1,
                Box::new(move || {
                    let head = competing.snapshot_list(7, deadline()).unwrap();
                    let mut policy = head.policy.clone();
                    if denied {
                        policy[0].read = false;
                    } else {
                        policy[0].write = false;
                    }
                    competing
                        .set_policy(7, head.revision, 30, policy, deadline())
                        .unwrap();
                }),
            )],
        );
        let result = slow.snapshot_prepare(7, &saved.input, deadline());
        if denied {
            assert!(matches!(result, Err(Error::Denied)));
        } else {
            assert!(matches!(result, Err(Error::Conflict)));
        }
        slow.healthy().unwrap();
    }
}

#[test]
fn release_readback_errors_are_interpreted_only_after_the_final_head_barrier() {
    for change in 0..3 {
        let (objects, database) = fixture();
        let saved = capture(&database, 101);
        let proof_key = snapshot_records::key(&scope(), &saved.input.identity(), true);
        let backing = objects.clone();
        let competing = restarted(&objects);
        let slow = delayed(
            &objects,
            head_key(&scope()),
            vec![(
                2,
                Box::new(move || {
                    // The view's proof read was really Missing. Corrupt the immutable
                    // slot before release's Absent PUT and its exact readback.
                    backing.inner.set(proof_key, b"corrupt-proof".to_vec());
                    if change != 0 {
                        let head = competing.snapshot_list(7, deadline()).unwrap();
                        let mut policy = head.policy.clone();
                        if change == 2 {
                            policy[0].admin = false;
                            policy.push(Permission {
                                principal: 8,
                                read: true,
                                write: true,
                                admin: true,
                            });
                        } else {
                            policy[0].write = false;
                        }
                        competing
                            .set_policy(7, head.revision, 31, policy, deadline())
                            .unwrap();
                    }
                }),
            )],
        );
        let result = slow.snapshot_release(7, &saved.reference, deadline());
        match change {
            0 => {
                assert!(matches!(result, Err(Error::Corrupt)));
                assert!(slow.healthy().is_err());
            }
            1 => {
                assert!(matches!(result, Err(Error::Conflict)));
                slow.healthy().unwrap();
            }
            _ => {
                assert!(matches!(result, Err(Error::Denied)));
                slow.healthy().unwrap();
            }
        }
        assert_eq!(
            database
                .read_head(deadline())
                .unwrap()
                .head
                .snapshots
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn stable_referenced_missing_is_corrupt_but_cross_read_change_is_not() {
    for change in [false, true] {
        let (objects, database) = fixture();
        let saved = capture(&database, 101);
        let key = snapshot_records::key(&scope(), &saved.input.identity(), false);
        objects.inner.remove(&key);
        let revoker = restarted(&objects);
        let actions: Vec<Action> = if change {
            vec![(
                1,
                Box::new(move || {
                    let head = revoker.snapshot_list(7, deadline()).unwrap();
                    let mut policy = head.policy.clone();
                    policy[0].write = false;
                    revoker
                        .set_policy(7, head.revision, 20, policy, deadline())
                        .unwrap();
                }),
            )]
        } else {
            vec![]
        };
        let observer = delayed(&objects, key, actions);
        let result = observer.snapshot_inspect(7, &saved.input.identity(), deadline());
        if change {
            assert!(matches!(result, Err(Error::Conflict)));
            observer.healthy().unwrap();
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
            assert!(observer.healthy().is_err());
        }
    }
}

#[test]
fn prepare_never_recreates_a_descriptor_referenced_by_live_entry_or_permanent_proof() {
    for released in [false, true] {
        let (objects, database) = fixture();
        let saved = capture(&database, 101);
        if released {
            database
                .snapshot_release(7, &saved.reference, deadline())
                .unwrap();
        }
        let key = snapshot_records::key(&scope(), &saved.input.identity(), false);
        objects.inner.remove(&key);
        // The original caller input is deliberately retained. The dependency
        // error takes precedence over proposing a later base for that identity.
        assert!(matches!(
            database.snapshot_prepare(7, &saved.input, deadline()),
            Err(Error::Corrupt)
        ));
        assert!(objects.get(&key, MAX_DESCRIPTOR, deadline()).is_err());
    }
}

#[test]
fn admin_without_read_can_inspect_list_and_release_but_cannot_prepare_or_capture() {
    let (_, database) = fixture();
    let saved = capture(&database, 101);
    let head = database.snapshot_list(7, deadline()).unwrap();
    let mut policy = head.policy.clone();
    policy[0].read = false;
    database
        .set_policy(7, head.revision, 22, policy, deadline())
        .unwrap();
    assert!(matches!(
        database.snapshot_prepare(7, &saved.input, deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.snapshot_capture(7, &saved.reference, deadline()),
        Err(Error::Denied)
    ));
    assert_eq!(
        database
            .snapshot_inspect(7, &saved.input.identity(), deadline())
            .unwrap()
            .state,
        SnapshotState::Retained
    );
    database.snapshot_list(7, deadline()).unwrap();
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    assert!(matches!(
        database.snapshot_list(99, deadline()),
        Err(Error::Denied)
    ));
}

#[test]
fn capture_checks_the_actual_manifest_and_keeps_a_fixed_historical_point_after_sql() {
    let (_, database) = fixture();
    database.activate(7, 1, 2, deadline()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let statements = sql("CREATE TABLE values_table(value BLOB)");
    let request = crate::request(1, 1, 7, &statements).unwrap();
    database
        .execute(
            7,
            &request,
            &statements,
            &directory.path().join("first"),
            deadline(),
        )
        .unwrap();
    let saved = capture(&database, 101);
    assert!(saved.point.page_count > 0);
    let statements = sql("INSERT INTO values_table VALUES(randomblob(9000))");
    let request = crate::request(1, 2, 7, &statements).unwrap();
    database
        .execute(
            7,
            &request,
            &statements,
            &directory.path().join("second"),
            deadline(),
        )
        .unwrap();
    let observed = database
        .snapshot_inspect(7, &saved.input.identity(), deadline())
        .unwrap();
    assert_eq!(observed.prepared, saved);
    assert_ne!(observed.head.data_root, saved.point.data_root);
    assert!(observed.head.sequence > saved.point.sequence);
    assert_eq!(observed.accepted.unwrap().point, saved.point);
}

#[test]
fn a_forged_manifest_count_in_an_otherwise_valid_descriptor_is_not_published() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let fixed = input(&base.head, 101);
    let bad = SnapshotDescriptor::new(&base, &fixed, 1, SnapshotLimits::default()).unwrap();
    objects.inner.set(
        snapshot_records::key(&scope(), &fixed.identity(), false),
        bad.bytes().unwrap(),
    );
    assert!(matches!(
        database.snapshot_capture(7, &bad.reference(), deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, base.head);
    assert!(database.healthy().is_err());
}

#[test]
fn limits_are_durable_business_updates_with_lifecycle_and_original_revision_guards() {
    let (_, database) = fixture();
    let before = database.snapshot_list(7, deadline()).unwrap();
    let disabled = SnapshotLimits {
        max_points: 0,
        max_logical_bytes: 0,
    };
    let limited = database
        .set_snapshot_limits(7, before.revision, 22, disabled.clone(), deadline())
        .unwrap();
    assert_eq!(limited.format, 9);
    assert_eq!(limited.revision, before.revision + 1);
    assert_eq!(limited.head_serial, before.head_serial + 1);
    assert_eq!(limited.transition.nonce, 22);
    assert!(matches!(
        database.snapshot_prepare(7, &input(&limited, 101), deadline()),
        Err(Error::Limit)
    ));
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            before.revision,
            23,
            SnapshotLimits::default(),
            deadline()
        ),
        Err(Error::Conflict)
    ));
    let limited = database
        .set_snapshot_limits(
            7,
            limited.revision,
            24,
            SnapshotLimits::default(),
            deadline(),
        )
        .unwrap();
    let saved = capture(&database, 101);
    assert!(matches!(
        database.set_snapshot_limits(7, limited.revision, 25, disabled, deadline()),
        Err(Error::Limit)
    ));
    let current = database.snapshot_list(7, deadline()).unwrap();
    database
        .set_lifecycle(7, current.revision, 26, Lifecycle::Maintenance, deadline())
        .unwrap();
    let current = database.snapshot_list(7, deadline()).unwrap();
    database
        .set_snapshot_limits(
            7,
            current.revision,
            27,
            SnapshotLimits::default(),
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        database.snapshot_capture(7, &saved.reference, deadline()),
        Err(Error::Lifecycle)
    ));
}

#[test]
fn deleted_keeps_metadata_and_allows_release_but_no_new_capture_or_limits() {
    let (_, database) = fixture();
    let saved = capture(&database, 101);
    let current = database.snapshot_list(7, deadline()).unwrap();
    database
        .set_lifecycle(7, current.revision, 22, Lifecycle::Deleted, deadline())
        .unwrap();
    let deleted = database.snapshot_list(7, deadline()).unwrap();
    assert!(matches!(
        database.status(7, deadline()),
        Err(Error::Lifecycle)
    ));
    assert_eq!(
        database
            .snapshot_inspect(7, &saved.input.identity(), deadline())
            .unwrap()
            .state,
        SnapshotState::Retained
    );
    assert!(matches!(
        database.snapshot_prepare(7, &input(&deleted, 102), deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.snapshot_capture(7, &saved.reference, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            deleted.revision,
            23,
            SnapshotLimits::default(),
            deadline()
        ),
        Err(Error::Lifecycle)
    ));
    assert!(database
        .retire_storage(7, deleted.head_serial, deadline())
        .is_err());
    let released = database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    assert_eq!(released.head.lifecycle, Lifecycle::Deleted);
    assert_eq!(released.head.revision, deleted.revision);
}

#[test]
fn every_control_io_failure_keeps_head_authority_without_hidden_retry() {
    fn run(kind: usize, failure: Option<usize>) -> usize {
        let (objects, database) = fixture();
        let saved = if kind == 0 || kind >= 4 {
            None
        } else {
            Some(prepare(&database, 101))
        };
        if kind == 2 {
            database
                .snapshot_capture(7, &saved.as_ref().unwrap().reference, deadline())
                .unwrap();
        }
        let before = database.read_head(deadline()).unwrap().head;
        let fixed = input(&before, 101);
        let count = objects.inner.operation_count();
        if let Some(failure) = failure {
            objects.inner.fail_after(failure);
        }
        let result = match kind {
            0 => database.snapshot_prepare(7, &fixed, deadline()).map(|_| ()),
            1 => database
                .snapshot_capture(7, &saved.as_ref().unwrap().reference, deadline())
                .map(|_| ()),
            2 => database
                .snapshot_release(7, &saved.as_ref().unwrap().reference, deadline())
                .map(|_| ()),
            3 => database
                .snapshot_inspect(7, &saved.as_ref().unwrap().input.identity(), deadline())
                .map(|_| ()),
            4 => database.snapshot_list(7, deadline()).map(|_| ()),
            _ => database
                .set_snapshot_limits(
                    7,
                    before.revision,
                    22,
                    SnapshotLimits::default(),
                    deadline(),
                )
                .map(|_| ()),
        };
        let used = objects.inner.operation_count() - count;
        if failure.is_some() {
            assert!(
                matches!(result, Err(Error::Store(StoreError::Unknown))),
                "kind {kind} cut {failure:?}: {result:?}"
            );
            assert_eq!(database.read_head(deadline()).unwrap().head, before);
            database.healthy().unwrap();
        } else {
            result.unwrap();
        }
        used
    }
    for kind in 0..6 {
        let operations = run(kind, None);
        assert!(operations <= 12);
        for prefix in 1..=operations {
            run(kind, Some(prefix));
        }
    }
}

#[test]
fn meter_bounds_all_io_and_uses_the_original_absolute_deadline() {
    let (objects, _) = fixture();
    let meter = SnapshotMeter {
        objects,
        remaining: AtomicUsize::new(1),
        deadline: deadline(),
        now: Instant::now,
    };
    meter
        .get(&head_key(&scope()), MAX_HEAD_BYTES, deadline())
        .unwrap();
    assert!(matches!(
        meter.put("unused", b"", Condition::Absent, deadline()),
        Err(StoreError::Budget)
    ));
    let (objects, _) = fixture();
    let meter = SnapshotMeter {
        objects,
        remaining: AtomicUsize::new(2),
        deadline: Instant::now(),
        now: Instant::now,
    };
    assert!(matches!(
        meter.get(&head_key(&scope()), MAX_HEAD_BYTES, deadline()),
        Err(StoreError::Unknown)
    ));
    assert!(matches!(
        meter.put("unused", b"", Condition::Absent, deadline()),
        Err(StoreError::Unknown)
    ));
}

#[test]
fn unknown_identity_and_unwitnessed_history_never_invent_acceptance() {
    let (objects, database) = fixture();
    let absent = SnapshotIdentity {
        creator: 7,
        operation: 999,
    };
    assert!(matches!(
        database.snapshot_inspect(7, &absent, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    objects.inner.fail(
        false,
        snapshot_records::key(&scope(), &absent, true),
        StoreError::Unknown,
    );
    assert!(matches!(
        database.snapshot_inspect(7, &absent, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    database.healthy().unwrap();
    let saved = prepare(&database, 101);
    let base = database.snapshot_list(7, deadline()).unwrap();
    database
        .set_policy(7, base.revision, 30, base.policy.clone(), deadline())
        .unwrap();
    for observed in [
        database
            .snapshot_inspect(7, &saved.input.identity(), deadline())
            .unwrap(),
        database
            .snapshot_capture(7, &saved.reference, deadline())
            .unwrap(),
        database
            .snapshot_release(7, &saved.reference, deadline())
            .unwrap(),
    ] {
        assert_eq!(observed.state, SnapshotState::Fenced);
        assert!(observed.accepted.is_none());
    }
    let saved = capture(&database, 102);
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    objects.inner.remove(&snapshot_records::key(
        &scope(),
        &saved.input.identity(),
        true,
    ));
    let observed = database
        .snapshot_inspect(7, &saved.input.identity(), deadline())
        .unwrap();
    assert_eq!(observed.state, SnapshotState::Fenced);
    assert!(observed.accepted.is_none());
}

#[test]
fn caller_input_and_references_cannot_claim_other_identities_or_rebind_expected_counters() {
    let (_, database) = fixture();
    let base = database.snapshot_list(7, deadline()).unwrap();
    let mut bad = input(&base, 101);
    bad.creator = 8;
    assert!(matches!(
        database.snapshot_prepare(7, &bad, deadline()),
        Err(Error::Denied)
    ));
    bad = input(&base, 101);
    bad.expected_revision = 2;
    bad.expected_head_serial = 2;
    assert!(matches!(
        database.snapshot_prepare(7, &bad, deadline()),
        Err(Error::Conflict)
    ));
    bad = input(&base, 101);
    bad.expected_head_serial += 1;
    assert!(matches!(
        database.snapshot_prepare(7, &bad, deadline()),
        Err(Error::Conflict)
    ));
    bad.label.clear();
    assert!(matches!(
        database.snapshot_prepare(7, &bad, deadline()),
        Err(Error::Format(_))
    ));
    let saved = capture(&database, 101);
    let mut other = saved.reference.clone();
    other.descriptor_hash = "f".repeat(64);
    assert!(matches!(
        database.snapshot_capture(7, &other, deadline()),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        database.snapshot_release(7, &other, deadline()),
        Err(Error::Conflict)
    ));
    other.operation = 0;
    assert!(matches!(
        database.snapshot_capture(7, &other, deadline()),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.snapshot_release(7, &other, deadline()),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.snapshot_inspect(7, &other.identity(), deadline()),
        Err(Error::Format(_))
    ));
    database.healthy().unwrap();
}

#[test]
fn immutable_control_decoders_enforce_exact_scope_identity_and_etag() {
    for case in 0..5 {
        let (_, database) = fixture();
        let base = database.read_head(deadline()).unwrap();
        let fixed = input(&base.head, 101);
        let mut altered = base.clone();
        let mut other = fixed.clone();
        if case == 1 {
            altered.head.scope.tenant += 1;
        }
        if case == 2 {
            other.operation += 1;
        }
        let descriptor =
            SnapshotDescriptor::new(&altered, &other, 0, SnapshotLimits::default()).unwrap();
        let bytes = if case == 3 {
            b"bad".to_vec()
        } else {
            descriptor.bytes().unwrap()
        };
        let stored = Stored {
            bytes,
            etag: if case == 0 {
                String::new()
            } else {
                "\"e\"".to_string()
            },
        };
        let result = database.snapshot_decode(&fixed.identity(), Ok(stored));
        if case == 4 {
            assert!(result.unwrap().is_some());
            database.healthy().unwrap();
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
            assert!(database.healthy().is_err());
        }
    }
    for case in 0..5 {
        let (_, database) = fixture();
        let base = database.read_head(deadline()).unwrap();
        let fixed = input(&base.head, 101);
        let descriptor =
            SnapshotDescriptor::new(&base, &fixed, 0, SnapshotLimits::default()).unwrap();
        let mut proof = SnapshotProof {
            version: 1,
            scope: scope(),
            entry: descriptor.entry(),
        };
        if case == 1 {
            proof.scope.tenant += 1;
        }
        if case == 2 {
            proof.entry.label = "wrong".to_string();
        }
        let bytes = if case == 3 {
            b"bad".to_vec()
        } else {
            proof.bytes().unwrap()
        };
        let stored = Stored {
            bytes,
            etag: if case == 0 {
                String::new()
            } else {
                "\"e\"".to_string()
            },
        };
        let result = database.snapshot_proof(&descriptor, Ok(stored));
        if case == 4 {
            assert!(result.unwrap().is_some());
            database.healthy().unwrap();
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
            assert!(database.healthy().is_err());
        }
    }
}

#[test]
fn inconsistent_live_identity_or_impossible_released_proof_fails_closed() {
    for proof_position in [false, true] {
        let (objects, database) = fixture();
        let saved = capture(&database, 101);
        if proof_position {
            *objects.unknown_after.lock().unwrap() = Some(snapshot_records::key(
                &scope(),
                &saved.input.identity(),
                true,
            ));
            assert!(matches!(
                database.snapshot_release(7, &saved.reference, deadline()),
                Err(Error::Store(StoreError::Unknown))
            ));
        }
        let mut head = database.read_head(deadline()).unwrap().head;
        if proof_position {
            head.snapshots.as_mut().unwrap().clear();
        } else {
            head.snapshots.as_mut().unwrap()[0]
                .reference
                .descriptor_hash = "f".repeat(64);
        }
        objects
            .inner
            .set(head_key(&scope()), encode_head(&head).unwrap());
        if !proof_position {
            assert!(matches!(
                database.snapshot_prepare(7, &saved.input, deadline()),
                Err(Error::Corrupt)
            ));
        }
        assert!(matches!(
            database.snapshot_inspect(7, &saved.input.identity(), deadline()),
            Err(Error::Corrupt)
        ));
        assert!(database.healthy().is_err());
    }
}

#[test]
fn competing_absent_put_first_winner_is_conflict_without_any_head_rebinding() {
    let (objects, database) = fixture();
    let base = database.snapshot_list(7, deadline()).unwrap();
    let fixed = input(&base, 101);
    let mut other = fixed.clone();
    other.label = "competitor".to_string();
    let competing = restarted(&objects);
    let slow = delayed(
        &objects,
        head_key(&scope()),
        vec![(
            2,
            Box::new(move || {
                competing.snapshot_prepare(7, &other, deadline()).unwrap();
            }),
        )],
    );
    assert!(matches!(
        slow.snapshot_prepare(7, &fixed, deadline()),
        Err(Error::Conflict)
    ));
    assert_eq!(database.snapshot_list(7, deadline()).unwrap(), base);
    let actual = database
        .snapshot_inspect(7, &fixed.identity(), deadline())
        .unwrap();
    assert_eq!(actual.prepared.input.label, "competitor");
    slow.healthy().unwrap();
}

#[test]
fn immutable_readback_checks_exact_bytes_and_missing_is_not_a_new_prepare() {
    for missing in [false, true] {
        let (objects, database) = fixture();
        let base = database.read_head(deadline()).unwrap();
        let fixed = input(&base.head, 101);
        let descriptor =
            SnapshotDescriptor::new(&base, &fixed, 0, SnapshotLimits::default()).unwrap();
        let key = snapshot_records::key(&scope(), &fixed.identity(), false);
        // Replace immediately before the real post-PUT GET. Whitespace is
        // semantically decodable but is not the exact bytes just written.
        let mut bytes = descriptor.bytes().unwrap();
        bytes.push(b' ');
        objects.inner.replace_after(7, key.clone(), bytes, false);
        if missing {
            // Install the Missing failure only after the payload manifest GET;
            // the earlier genuine-absence reads retain their normal outcomes.
            let underlying = objects.clone();
            let selected = key.clone();
            let slow = delayed(
                &objects,
                object_key(&scope(), 1, &base.head.data_root),
                vec![(
                    1,
                    Box::new(move || {
                        underlying.inner.fail(false, selected, StoreError::Missing);
                    }),
                )],
            );
            assert!(matches!(
                slow.snapshot_prepare(7, &fixed, deadline()),
                Err(Error::Corrupt)
            ));
        } else {
            assert!(matches!(
                database.snapshot_prepare(7, &fixed, deadline()),
                Err(Error::Corrupt)
            ));
        }
        assert_eq!(database.read_head(deadline()).unwrap().head, base.head);
    }
}

#[test]
fn copy_fences_snapshot_mutations_without_dropping_the_table() {
    let (_, database) = fixture();
    let saved = capture(&database, 101);
    let head = database.snapshot_list(7, deadline()).unwrap();
    let copying = database
        .compact_begin(7, head.head_serial, deadline())
        .unwrap();
    let mut fresh = input(&copying, 102);
    fresh.label = "second".to_string();
    assert!(matches!(
        database.snapshot_prepare(7, &fresh, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.snapshot_capture(7, &saved.reference, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.snapshot_release(7, &saved.reference, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            copying.revision,
            30,
            SnapshotLimits::default(),
            deadline()
        ),
        Err(Error::Fenced)
    ));
    assert_eq!(
        database
            .snapshot_inspect(7, &saved.input.identity(), deadline())
            .unwrap()
            .state,
        SnapshotState::Retained
    );
    database
        .compact_abort(7, copying.storage.plan.as_ref().unwrap().serial, deadline())
        .unwrap();
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
}

#[test]
fn finite_capture_reserves_release_delete_and_terminal_serials_before_writing_a_descriptor() {
    for enough in [false, true] {
        let (objects, database) = fixture();
        let mut base = database.read_head(deadline()).unwrap().head;
        base.head_serial = u64::MAX - if enough { 4 } else { 3 };
        objects
            .inner
            .set(head_key(&scope()), encode_head(&base).unwrap());
        let fixed = input(&base, 101);
        let result = database.snapshot_prepare(7, &fixed, deadline());
        if !enough {
            assert!(matches!(result, Err(Error::Limit)));
            assert!(objects
                .get(
                    &snapshot_records::key(&scope(), &fixed.identity(), false),
                    MAX_DESCRIPTOR,
                    deadline()
                )
                .is_err());
            database.healthy().unwrap();
            continue;
        }
        let saved = result.unwrap();
        database
            .snapshot_capture(7, &saved.reference, deadline())
            .unwrap();
        let held = database.snapshot_list(7, deadline()).unwrap();
        assert!(matches!(
            database.set_snapshot_limits(
                7,
                held.revision,
                31,
                SnapshotLimits::default(),
                deadline()
            ),
            Err(Error::Limit)
        ));
        let released = database
            .snapshot_release(7, &saved.reference, deadline())
            .unwrap();
        assert_eq!(released.head.head_serial, u64::MAX - 2);
        let deleted = database
            .set_lifecycle(
                7,
                released.head.revision,
                32,
                Lifecycle::Deleted,
                deadline(),
            )
            .unwrap();
        assert_eq!(deleted.head_serial, u64::MAX - 1);
        let terminal = database
            .retire_storage(7, deleted.head_serial, deadline())
            .unwrap();
        assert_eq!(terminal.head_serial, u64::MAX);
        assert_eq!(terminal.format, 9);
        assert!(matches!(
            Database::snapshot_idle(&terminal),
            Err(Error::Fenced)
        ));
        assert_eq!(
            database
                .snapshot_inspect(7, &saved.input.identity(), deadline())
                .unwrap()
                .state,
            SnapshotState::ReleasedObserved
        );
    }
}

#[test]
fn gross_budget_counts_each_retained_point_even_when_the_payload_tree_is_shared() {
    let (_, database) = fixture();
    database.activate(7, 1, 2, deadline()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let statements = sql("CREATE TABLE payloads(value BLOB)");
    database
        .execute(
            7,
            &crate::request(1, 1, 7, &statements).unwrap(),
            &statements,
            &directory.path().join("initial"),
            deadline(),
        )
        .unwrap();
    let saved = capture(&database, 101);
    let page_bytes = saved.point.page_count as u64 * PAGE_SIZE as u64;
    assert!(page_bytes > 0);
    let head = database.snapshot_list(7, deadline()).unwrap();
    let limits = SnapshotLimits {
        max_points: 2,
        max_logical_bytes: page_bytes,
    };
    let limited = database
        .set_snapshot_limits(7, head.revision, 30, limits, deadline())
        .unwrap();
    let mut fixed = input(&limited, 102);
    fixed.label = "same-root".to_string();
    assert!(matches!(
        database.snapshot_prepare(7, &fixed, deadline()),
        Err(Error::Limit)
    ));
    let limits = SnapshotLimits {
        max_points: 2,
        max_logical_bytes: 2 * page_bytes,
    };
    let expanded = database
        .set_snapshot_limits(7, limited.revision, 31, limits, deadline())
        .unwrap();
    let mut fixed = input(&expanded, 103);
    fixed.label = "same-root".to_string();
    let second = database.snapshot_prepare(7, &fixed, deadline()).unwrap();
    assert_eq!(second.point.data_root, saved.point.data_root);
    database
        .snapshot_capture(7, &second.reference, deadline())
        .unwrap();
    let current = database.snapshot_list(7, deadline()).unwrap();
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            current.revision,
            32,
            SnapshotLimits {
                max_points: 2,
                max_logical_bytes: page_bytes
            },
            deadline()
        ),
        Err(Error::Limit)
    ));
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            current.revision,
            33,
            SnapshotLimits {
                max_points: 65,
                max_logical_bytes: page_bytes
            },
            deadline()
        ),
        Err(Error::Format(_))
    ));
}

#[test]
fn technical_capture_and_release_preserve_an_eligible_hot_native_writer() {
    let (_, database) = fixture();
    database.activate(7, 1, 2, deadline()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &directory.path().join("hot"), deadline())
        .unwrap();
    let statements = sql("CREATE TABLE payloads(value BLOB)");
    session
        .execute(
            7,
            &crate::request(1, 1, 7, &statements).unwrap(),
            &statements,
            deadline(),
        )
        .unwrap();
    let saved = capture(&database, 101);
    let statements = sql("INSERT INTO payloads VALUES(randomblob(9000))");
    let (receipt, _) = session
        .execute(
            7,
            &crate::request(1, 2, 7, &statements).unwrap(),
            &statements,
            deadline(),
        )
        .unwrap();
    assert_eq!(receipt.sequence, saved.point.sequence + 1);
    assert_eq!(
        database
            .snapshot_inspect(7, &saved.input.identity(), deadline())
            .unwrap()
            .prepared,
        saved
    );
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    let statements = sql("INSERT INTO payloads VALUES(randomblob(32))");
    let (next, _) = session
        .execute(
            7,
            &crate::request(1, 3, 7, &statements).unwrap(),
            &statements,
            deadline(),
        )
        .unwrap();
    assert_eq!(next.sequence, receipt.sequence + 1);
}

#[test]
fn provisioning_head_cannot_admit_snapshot_metadata_or_allocate_a_descriptor() {
    let (objects, database) = fixture();
    let mut head = database.read_head(deadline()).unwrap().head;
    head.lifecycle = Lifecycle::Provisioning;
    head.creation = Some(NamedCreation {
        creator: 7,
        operation: 1,
        name_hash: "a".repeat(64),
        descriptor_hash: "b".repeat(64),
    });
    objects
        .inner
        .set(head_key(&scope()), encode_head(&head).unwrap());
    let fixed = input(&head, 101);
    assert!(matches!(
        database.snapshot_list(7, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.snapshot_prepare(7, &fixed, deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.snapshot_inspect(7, &fixed.identity(), deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(matches!(
        database.set_snapshot_limits(7, head.revision, 30, SnapshotLimits::default(), deadline()),
        Err(Error::Lifecycle)
    ));
    assert!(objects
        .get(
            &snapshot_records::key(&scope(), &fixed.identity(), false),
            MAX_DESCRIPTOR,
            deadline()
        )
        .is_err());
}

#[test]
fn released_proof_cannot_claim_a_future_business_revision_or_sequence() {
    for future_revision in [false, true] {
        let (objects, database) = fixture();
        let original = database.read_head(deadline()).unwrap();
        let mut historical = original.clone();
        if future_revision {
            historical.head.revision = 2;
            historical.head.head_serial = 2;
            historical.head.transition.revision = 2;
        } else {
            historical.head.sequence = 1;
        }
        let fixed = input(&historical.head, 101);
        let descriptor =
            SnapshotDescriptor::new(&historical, &fixed, 0, SnapshotLimits::default()).unwrap();
        let proof = SnapshotProof {
            version: 1,
            scope: scope(),
            entry: descriptor.entry(),
        };
        let mut current = original.head;
        current.head_serial = 5;
        objects
            .inner
            .set(head_key(&scope()), encode_head(&current).unwrap());
        objects.inner.set(
            snapshot_records::key(&scope(), &fixed.identity(), false),
            descriptor.bytes().unwrap(),
        );
        objects.inner.set(
            snapshot_records::key(&scope(), &fixed.identity(), true),
            proof.bytes().unwrap(),
        );
        assert!(matches!(
            database.snapshot_inspect(7, &fixed.identity(), deadline()),
            Err(Error::Corrupt)
        ));
    }
}

#[test]
fn an_etag_change_with_identical_head_bytes_breaks_the_observation_barrier() {
    let (objects, database) = fixture();
    let saved = prepare(&database, 101);
    let head = database.read_head(deadline()).unwrap().head;
    let backing = objects.clone();
    let slow = delayed(
        &objects,
        head_key(&scope()),
        vec![(
            1,
            Box::new(move || {
                backing
                    .inner
                    .set(head_key(&scope()), encode_head(&head).unwrap());
            }),
        )],
    );
    assert!(matches!(
        slow.snapshot_prepare(7, &saved.input, deadline()),
        Err(Error::Conflict)
    ));
    slow.healthy().unwrap();
}

#[test]
fn accepted_proof_witnesses_missing_descriptor_after_the_entry_is_gone() {
    let (objects, database) = fixture();
    let saved = capture(&database, 101);
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
    objects.inner.remove(&snapshot_records::key(
        &scope(),
        &saved.input.identity(),
        false,
    ));
    assert!(matches!(
        database.snapshot_inspect(7, &saved.input.identity(), deadline()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn live_label_conflict_does_not_allocate_a_new_identity() {
    let (objects, database) = fixture();
    capture(&database, 101);
    let fixed = input(&database.snapshot_list(7, deadline()).unwrap(), 102);
    assert!(matches!(
        database.snapshot_prepare(7, &fixed, deadline()),
        Err(Error::Conflict)
    ));
    assert!(objects
        .get(
            &snapshot_records::key(&scope(), &fixed.identity(), false),
            MAX_DESCRIPTOR,
            deadline()
        )
        .is_err());
    database.healthy().unwrap();
}

#[test]
fn payload_context_exhaustion_is_admission_budget_and_allows_a_new_explicit_attempt() {
    let (_, database) = fixture();
    let saved = prepare(&database, 101);
    let base = database.read_head(deadline()).unwrap();
    let contexts: Vec<_> = (0..64)
        .map(|_| ObjectContext::from_snapshot(&database, &base, deadline()).unwrap())
        .collect();
    let fixed = input(&base.head, 102);
    assert!(matches!(
        database.snapshot_prepare(7, &fixed, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    assert!(matches!(
        database.snapshot_capture(7, &saved.reference, deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    database.healthy().unwrap();
    drop(contexts);
    database
        .snapshot_capture(7, &saved.reference, deadline())
        .unwrap();
}

#[test]
fn missing_manifest_stays_a_protected_payload_failure_not_a_published_point() {
    for capture_first in [false, true] {
        let (objects, database) = fixture();
        let base = database.read_head(deadline()).unwrap();
        let fixed = input(&base.head, 101);
        let saved = if capture_first {
            Some(database.snapshot_prepare(7, &fixed, deadline()).unwrap())
        } else {
            None
        };
        objects.inner.remove(&object_key(
            &scope(),
            base.head.storage.active_generation,
            &base.head.data_root,
        ));
        let result = match saved {
            Some(saved) => database
                .snapshot_capture(7, &saved.reference, deadline())
                .map(|_| ()),
            None => database.snapshot_prepare(7, &fixed, deadline()).map(|_| ()),
        };
        assert!(matches!(result, Err(Error::Store(StoreError::Missing))));
        assert_eq!(database.read_head(deadline()).unwrap().head, base.head);
        assert!(!database.quarantined.load(Ordering::Acquire));
    }
}

#[test]
fn invalid_backend_etag_and_business_counter_overflow_fail_before_control_publication() {
    let (objects, database) = fixture();
    let base = database.snapshot_list(7, deadline()).unwrap();
    let unquoted =
        Database::with_options(objects.inner.clone(), scope(), 10, test_options()).unwrap();
    assert!(matches!(
        unquoted.snapshot_prepare(7, &input(&base, 101), deadline()),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.set_snapshot_limits(7, base.revision, 0, SnapshotLimits::default(), deadline()),
        Err(Error::Format(_))
    ));
    let mut exhausted = base;
    exhausted.revision = u64::MAX;
    exhausted.head_serial = u64::MAX;
    exhausted.transition.revision = u64::MAX;
    objects
        .inner
        .set(head_key(&scope()), encode_head(&exhausted).unwrap());
    assert!(matches!(
        database.set_snapshot_limits(
            7,
            exhausted.revision,
            40,
            SnapshotLimits::default(),
            deadline()
        ),
        Err(Error::Limit)
    ));
    database.healthy().unwrap();
}

#[test]
fn candidate_builder_checks_its_whole_shape_and_capture_rechecks_capacity() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let fixed = input(&base.head, 101);
    let descriptor = SnapshotDescriptor::new(&base, &fixed, 0, SnapshotLimits::default()).unwrap();
    let mut maintenance = base.head.clone();
    maintenance.lifecycle = Lifecycle::Maintenance;
    assert!(matches!(
        Database::snapshot_capture_head(&maintenance, &descriptor),
        Err(Error::Lifecycle)
    ));
    let copying = database
        .compact_begin(7, base.head.head_serial, deadline())
        .unwrap();
    assert!(matches!(
        Database::snapshot_capture_head(&copying, &descriptor),
        Err(Error::Fenced)
    ));
    let mut exhausted = base.head.clone();
    exhausted.head_serial = u64::MAX;
    assert!(matches!(
        Database::snapshot_capture_head(&exhausted, &descriptor),
        Err(Error::Limit)
    ));
    let mut future = base.clone();
    future.head.revision = 2;
    future.head.head_serial = 2;
    future.head.transition.revision = 2;
    let future = SnapshotDescriptor::new(
        &future,
        &input(&future.head, 101),
        0,
        SnapshotLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        Database::snapshot_capture_head(&base.head, &future),
        Err(Error::Format(_))
    ));
    let mut near_end = base.head.clone();
    near_end.head_serial = u64::MAX - 3;
    objects
        .inner
        .set(head_key(&scope()), encode_head(&near_end).unwrap());
    let actual = database.read_head(deadline()).unwrap();
    let descriptor = SnapshotDescriptor::new(
        &actual,
        &input(&actual.head, 102),
        0,
        SnapshotLimits::default(),
    )
    .unwrap();
    objects.inner.set(
        snapshot_records::key(&scope(), &descriptor.input.identity(), false),
        descriptor.bytes().unwrap(),
    );
    assert!(matches!(
        database.snapshot_capture(7, &descriptor.reference(), deadline()),
        Err(Error::Limit)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, near_end);
    let (_, other) = fixture();
    let head = other.snapshot_list(7, deadline()).unwrap();
    other
        .set_snapshot_limits(
            7,
            head.revision,
            44,
            SnapshotLimits {
                max_points: 1,
                max_logical_bytes: 0,
            },
            deadline(),
        )
        .unwrap();
    capture(&other, 101);
    let head = other.read_head(deadline()).unwrap();
    let mut fixed = input(&head.head, 102);
    fixed.label = "other".to_string();
    let descriptor =
        SnapshotDescriptor::new(&head, &fixed, 0, head.head.snapshot_limits.clone().unwrap())
            .unwrap();
    assert!(matches!(
        Database::snapshot_capture_head(&head.head, &descriptor),
        Err(Error::Limit)
    ));
}

#[test]
fn pending_owner_fences_snapshot_mutations_and_preserves_the_held_root() {
    use crate::owner::{OwnerMode, OwnerNonces, OwnerPreparation, PrepareOwnerInput};
    let (objects, database) = fixture();
    let saved = capture(&database, 101);
    let head = database.snapshot_list(7, deadline()).unwrap();
    let owner = Database::with_options(objects.clone(), scope(), 20, test_options()).unwrap();
    let fixed = PrepareOwnerInput {
        creator: 7,
        operation: 201,
        expected_revision: head.revision,
        expected_head_serial: head.head_serial,
        mode: OwnerMode::Takeover,
        target_worker: 20,
        nonces: OwnerNonces {
            claim: 40,
            cancel: 41,
            activate: 42,
            abort: 43,
        },
    };
    let OwnerPreparation::Prepared(plan) = owner.owner_prepare(7, &fixed, deadline()).unwrap()
    else {
        panic!()
    };
    let claimed = owner.owner_claim(7, &plan.reference, deadline()).unwrap();
    let mut fresh = input(&claimed.head, 102);
    fresh.label = "new".to_string();
    assert!(matches!(
        database.snapshot_prepare(7, &fresh, deadline()),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.snapshot_release(7, &saved.reference, deadline()),
        Err(Error::Fenced)
    ));
    owner.owner_abort(7, &plan.reference, deadline()).unwrap();
    database
        .snapshot_release(7, &saved.reference, deadline())
        .unwrap();
}

#[test]
fn proof_readback_without_an_etag_never_releases_the_live_point() {
    struct EmptyEtag {
        inner: Arc<Quoted>,
        key: String,
        reads: AtomicUsize,
    }
    impl Objects for EmptyEtag {
        fn get(&self, key: &str, cap: usize, until: Instant) -> Result<Stored, StoreError> {
            let second = key == self.key && self.reads.fetch_add(1, Ordering::Relaxed) == 1;
            let mut stored = self.inner.get(key, cap, until)?;
            if second {
                stored.etag.clear();
            }
            Ok(stored)
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
    let (objects, database) = fixture();
    let saved = capture(&database, 101);
    let key = snapshot_records::key(&scope(), &saved.input.identity(), true);
    let bad = Database::with_options(
        Arc::new(EmptyEtag {
            inner: objects,
            key,
            reads: AtomicUsize::new(0),
        }),
        scope(),
        10,
        test_options(),
    )
    .unwrap();
    assert!(matches!(
        bad.snapshot_release(7, &saved.reference, deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(
        database
            .snapshot_list(7, deadline())
            .unwrap()
            .snapshots
            .unwrap()
            .len(),
        1
    );
}
