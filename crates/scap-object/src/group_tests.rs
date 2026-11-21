use super::*;
use crate::tests::{deadline, fixture, identity, replace_head, scope, sql, test_options, Memory};
use scap_object_sqlite::{Error as NativeError, PageBatch};
use scap_object_store::{Condition, Objects, StoreError, Stored};
use scap_sql::{TransactionResult, Value};
use std::sync::Mutex;

struct Inputs {
    statements: Vec<Vec<Statement>>,
    identities: Vec<Request>,
}

impl Inputs {
    fn new(text: &[&str]) -> Self {
        let statements: Vec<_> = text.iter().map(|text| sql(text)).collect();
        let identities = statements
            .iter()
            .enumerate()
            .map(|(index, statements)| request(1, index as u64 + 1, 7, statements).unwrap())
            .collect();
        Self {
            statements,
            identities,
        }
    }

    fn members(&self) -> Vec<GroupRequest<'_>> {
        self.identities
            .iter()
            .zip(&self.statements)
            .map(|(identity, statements)| GroupRequest {
                identity,
                statements,
            })
            .collect()
    }
}

fn execute(session: &mut Session, inputs: &Inputs) -> GroupCompletion {
    match session
        .execute_group(7, &inputs.members(), GroupLimits::default(), deadline())
        .unwrap()
    {
        GroupExecution::Completed(done) => done,
        GroupExecution::Fallback => panic!("eligible group fell back"),
    }
}

fn encoded() -> Vec<u8> {
    scap_sql::encode_result(
        &TransactionResult { statements: vec![] },
        crate::sql_limits(),
    )
    .unwrap()
}

fn empty_prefix(count: usize) -> Vec<StagedTransaction> {
    (0..count)
        .map(|_| StagedTransaction {
            batch: PageBatch {
                size_after: 0,
                pages: vec![],
            },
            result: encoded(),
        })
        .collect()
}

fn context(database: &Database, count: usize) -> GroupContext {
    let base = database.read_head(deadline()).unwrap();
    GroupContext {
        objects: ObjectContext::from_snapshot(database, &base, deadline()).unwrap(),
        base,
        requests: (1..=count).map(|id| identity(id as u64)).collect(),
        deadline: deadline(),
    }
}

#[test]
fn independent_members_publish_once_with_original_results_and_intermediate_roots() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("warm"), deadline())
        .unwrap();
    session.history_verified = false;
    let original = database.read_head(deadline()).unwrap();
    let inputs = Inputs::new(&[
        "CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)",
        "INSERT INTO items(value) VALUES(hex(randomblob(16))) RETURNING id,value",
        "SELECT id,value FROM items",
    ]);
    let before = objects.puts_for(&head_key(&scope()));
    let done = execute(&mut session, &inputs);
    assert!(format!("{done:?}").contains("GroupCommitted"));
    assert_eq!(objects.puts_for(&head_key(&scope())), before + 1);
    assert_eq!(done.results.len(), 3);
    let receipts: Vec<_> = done.results.into_iter().map(Result::unwrap).collect();
    let current = database.read_head(deadline()).unwrap();
    assert_eq!(current.head.sequence, original.head.sequence + 3);
    assert_eq!(current.head.revision, original.head.revision + 3);
    assert_eq!(current.head.head_serial, original.head.head_serial + 3);
    assert_eq!(current.head.transition, receipts[2].receipt.transition);
    assert_ne!(receipts[0].receipt.data_root, receipts[1].receipt.data_root);
    assert_eq!(receipts[1].receipt.data_root, receipts[2].receipt.data_root);
    assert_eq!(session.data_root, current.head.data_root);
    assert!(!session.invalidated);
    for (index, committed) in receipts.iter().enumerate() {
        assert_eq!(
            committed.receipt.sequence,
            original.head.sequence + index as u64 + 1
        );
        assert_eq!(
            committed.receipt.transition.revision,
            original.head.revision + index as u64 + 1
        );
        assert_eq!(committed.receipt.request, inputs.identities[index]);
        let expected = Resolution::Committed {
            receipt: committed.receipt.clone(),
            bytes: committed.bytes.clone(),
        };
        assert_eq!(
            database
                .lookup(7, &inputs.identities[index], deadline())
                .unwrap(),
            expected
        );
        assert_eq!(
            database
                .cancel(7, &inputs.identities[index], deadline())
                .unwrap(),
            expected
        );
    }
    let inserted = scap_sql::decode_result(&receipts[1].bytes, crate::sql_limits()).unwrap();
    let queried = scap_sql::decode_result(&receipts[2].bytes, crate::sql_limits()).unwrap();
    assert_eq!(inserted.statements[0].rows, queried.statements[0].rows);
    assert_eq!(
        session
            .query(7, &sql("SELECT id,value FROM items"), deadline())
            .unwrap()
            .statements[0]
            .rows,
        inserted.statements[0].rows
    );
    let single = sql("SELECT 4");
    let single_id = request(1, 4, 7, &single).unwrap();
    let (single_receipt, _) = session.execute(7, &single_id, &single, deadline()).unwrap();
    assert_eq!(single_receipt.sequence, current.head.sequence + 1);
    assert_eq!(
        single_receipt.transition.revision,
        current.head.revision + 1
    );
    assert_eq!(
        database.status(7, deadline()).unwrap().head_serial,
        current.head.head_serial + 1
    );
    drop(session);
    let mut cold = database
        .session(7, &temp.path().join("cold"), deadline())
        .unwrap();
    assert_eq!(
        cold.query(7, &sql("SELECT id,value FROM items"), deadline())
            .unwrap()
            .statements[0]
            .rows,
        inserted.statements[0].rows
    );
    assert!(format!(
        "{:?}",
        GroupExecution::Completed(GroupCompletion { results: vec![] })
    )
    .contains("Completed"));
}

#[test]
fn first_middle_and_last_sql_failures_consume_only_the_attempted_prefix() {
    for failed in 0..3 {
        let (_, database) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        let texts = (0..3)
            .map(|index| {
                if index == failed {
                    "SELECT * FROM absent"
                } else {
                    "SELECT 7"
                }
            })
            .collect::<Vec<_>>();
        let inputs = Inputs::new(&texts);
        let done = execute(&mut session, &inputs);
        assert_eq!(done.results.len(), failed + 1);
        assert!(done.results[..failed].iter().all(Result::is_ok));
        assert!(matches!(
            done.results[failed].as_ref().unwrap_err().as_ref(),
            Error::Engine(_)
        ));
        assert_eq!(
            database.status(7, deadline()).unwrap().sequence,
            failed as u64
        );
        for identity in &inputs.identities[failed..] {
            assert_eq!(
                database.lookup(7, identity, deadline()).unwrap(),
                Resolution::Unknown
            );
        }
        assert!(session.invalidated);
        assert!(matches!(
            session.query(7, &sql("SELECT 1"), deadline()),
            Err(Error::StaleSnapshot)
        ));
    }
}

#[test]
fn eligibility_falls_back_before_sql_for_identity_input_and_window_boundaries() {
    for case in 0..16 {
        let (objects, database) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        let mut inputs = Inputs::new(&["CREATE TABLE must_not_exist(x)", "SELECT 7"]);
        let mut limits = GroupLimits::default();
        match case {
            0 => {
                inputs.identities.pop();
                inputs.statements.pop();
            }
            1 => limits.max_members = 2,
            2 => inputs.identities[1].principal = 8,
            3 => inputs.identities[1].epoch = 2,
            4 => inputs.identities[1].id = inputs.identities[0].id,
            5 => inputs.identities[1].fingerprint = digest(b"other"),
            6 => inputs.identities[1].id = 0,
            7 => limits.max_input_bytes = 12,
            8 => session.database.options.sql.max_sql_bytes = 1,
            9 => {
                database
                    .cancel(7, &inputs.identities[1], deadline())
                    .unwrap();
            }
            10 => {
                database
                    .execute(
                        7,
                        &inputs.identities[1],
                        &inputs.statements[1],
                        &temp.path().join("existing"),
                        deadline(),
                    )
                    .unwrap();
            }
            11 => {
                let other = request(1, 2, 7, &sql("SELECT 8")).unwrap();
                database.cancel(7, &other, deadline()).unwrap();
            }
            12 => replace_head(&objects, &database, |head| head.retention.max_entries = 1),
            13 => replace_head(&objects, &database, |head| {
                head.retention.max_result_bytes = MAX_RESULT_BYTES as u64
            }),
            14 => {
                let statements = sql("SELECT 1");
                let saved = request(1, 99, 7, &statements).unwrap();
                database
                    .execute(
                        7,
                        &saved,
                        &statements,
                        &temp.path().join("retained"),
                        deadline(),
                    )
                    .unwrap();
                replace_head(&objects, &database, |head| {
                    head.retention.max_result_bytes =
                        MAX_RESULT_BYTES as u64 + database.options.sql.max_result_bytes as u64
                });
            }
            _ => {
                inputs.identities[0].epoch = 2;
                inputs.identities[1].epoch = 2;
            }
        }
        if case == 1 {
            inputs.statements.push(sql("SELECT 9"));
            inputs
                .identities
                .push(request(1, 3, 7, &inputs.statements[2]).unwrap());
        }
        let puts = objects.puts_for(&head_key(&scope()));
        assert!(
            matches!(
                session
                    .execute_group(7, &inputs.members(), limits, deadline())
                    .unwrap(),
                GroupExecution::Fallback
            ),
            "case {case}"
        );
        assert_eq!(objects.puts_for(&head_key(&scope())), puts);
        assert!(!session.writer.is_stopped());
        assert_eq!(session.page_count(), 0);
    }
}

#[test]
fn limits_are_bounded_and_tightened_by_options() {
    let ordinary = GroupLimits::default();
    ordinary.validate().unwrap();
    assert_eq!(ordinary, ordinary.clone());
    assert!(format!("{ordinary:?}").contains("max_members"));
    for case in 0..8 {
        let mut limits = ordinary;
        match case {
            0 => limits.max_members = 1,
            1 => limits.max_members = MAX_GROUP_MEMBERS + 1,
            2 => limits.max_input_bytes = 0,
            3 => limits.max_input_bytes = MAX_REQUEST_BYTES + 1,
            4 => limits.max_changed_pages = 0,
            5 => limits.max_changed_pages = MAX_PAGES + 1,
            6 => limits.max_result_bytes = 0,
            _ => limits.max_result_bytes = MAX_RESULT_BYTES as u64 + 1,
        }
        assert!(matches!(limits.validate(), Err(Error::Limit)));
    }
    let mut options = test_options();
    options.max_input_bytes = 12;
    options.max_changed_pages = 2;
    options.sql.max_result_bytes = 24;
    let tight = ordinary.effective(&options);
    assert_eq!(
        (
            tight.max_input_bytes,
            tight.max_changed_pages,
            tight.max_result_bytes
        ),
        (12, 2, 24)
    );
}

#[test]
fn lost_head_response_keeps_all_original_identities_and_one_shared_failure() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("warm"), deadline())
        .unwrap();
    let inputs = Inputs::new(&[
        "CREATE TABLE item(value)",
        "INSERT INTO item VALUES(7) RETURNING value",
    ]);
    let before = objects.puts_for(&head_key(&scope()));
    objects.lose_next_cas();
    let done = execute(&mut session, &inputs);
    assert_eq!(objects.puts_for(&head_key(&scope())), before + 1);
    let first = done.results[0].as_ref().unwrap_err();
    assert!(matches!(first.as_ref(), Error::Store(StoreError::Unknown)));
    assert!(Arc::ptr_eq(first, done.results[1].as_ref().unwrap_err()));
    assert!(session.invalidated);
    drop(session);
    let mut cold = database
        .session(7, &temp.path().join("cold"), deadline())
        .unwrap();
    for request in &inputs.identities {
        assert!(matches!(
            database.lookup(7, request, deadline()).unwrap(),
            Resolution::Committed { .. }
        ));
    }
    assert_eq!(
        cold.query(7, &sql("SELECT value FROM item"), deadline())
            .unwrap()
            .statements[0]
            .rows,
        vec![vec![Value::Integer(7)]]
    );
}

#[test]
fn completion_preserves_each_committed_receipt_and_failed_member() {
    let (_, database) = fixture();
    let receipts = database
        .commit_group(&context(&database, 2), &empty_prefix(2))
        .unwrap();
    let unavailable = complete(
        GroupRun {
            attempted: 3,
            staged: 2,
            member_error: Some(NativeError::InvalidSql),
            outcome: Err(NativeError::CommittedButUnavailable),
        },
        Some(Ok(receipts.clone())),
    );
    assert_eq!(unavailable.results.len(), 3);
    for (item, receipt) in unavailable.results[..2].iter().zip(&receipts) {
        match item.as_ref().unwrap_err().as_ref() {
            Error::CommittedButUnavailable(actual) => assert_eq!(actual.as_ref(), receipt),
            other => panic!("unexpected {other:?}"),
        }
    }
    for outcome in [Ok(vec![]), Err(NativeError::Interrupted)] {
        let done = complete(
            GroupRun {
                attempted: 2,
                staged: 2,
                member_error: None,
                outcome,
            },
            None,
        );
        assert_eq!(done.results.len(), 2);
        assert!(Arc::ptr_eq(
            done.results[0].as_ref().unwrap_err(),
            done.results[1].as_ref().unwrap_err()
        ));
    }
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("finish"), deadline())
        .unwrap();
    let GroupExecution::Completed(done) = session
        .finish_group(
            GroupRun {
                attempted: 2,
                staged: 2,
                member_error: None,
                outcome: Err(NativeError::CommittedButUnavailable),
            },
            Some(Ok(receipts.clone())),
        )
        .unwrap()
    else {
        panic!("accepted members must be reported")
    };
    assert!(session.invalidated);
    assert_eq!(session.data_root, receipts[1].data_root);
    assert!(done.results.iter().all(|outcome| matches!(
        outcome.as_ref().unwrap_err().as_ref(),
        Error::CommittedButUnavailable(_)
    )));
    assert!(matches!(
        session.finish_group(
            GroupRun {
                attempted: 0,
                staged: 0,
                member_error: None,
                outcome: Ok(vec![])
            },
            None
        ),
        Err(Error::Unknown)
    ));
}

type Action = Box<dyn FnOnce() + Send>;
struct Race {
    inner: Arc<Memory>,
    action: Mutex<Option<Action>>,
}

impl Objects for Race {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        self.inner.get(key, maximum, until)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        until: Instant,
    ) -> Result<String, StoreError> {
        if key == head_key(&scope()) && matches!(condition, Condition::Match(_)) {
            let action = self.action.lock().unwrap().take();
            if let Some(action) = action {
                action();
            }
        }
        self.inner.put(key, bytes, condition, until)
    }
}

#[test]
fn old_group_etag_loses_to_cancellation_acl_owner_quota_and_maintenance() {
    for case in 0..6 {
        let (objects, other) = fixture();
        let race = Arc::new(Race {
            inner: objects.clone(),
            action: Mutex::new(None),
        });
        let database = Database::with_options(race.clone(), scope(), 10, test_options()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        let inputs = Inputs::new(&[
            "CREATE TABLE discarded(x)",
            "INSERT INTO discarded VALUES(1)",
        ]);
        let cancelled = inputs.identities[1].clone();
        let base = other.status(7, deadline()).unwrap();
        *race.action.lock().unwrap() = Some(Box::new(move || match case {
            0 => {
                other.cancel(7, &cancelled, deadline()).unwrap();
            }
            1 => {
                let mut policy = base.policy;
                policy[0].write = false;
                other
                    .set_policy(7, base.revision, 90, policy, deadline())
                    .unwrap();
            }
            2 => {
                other.takeover(7, base.revision, 90, deadline()).unwrap();
            }
            3 => {
                other
                    .set_quota(
                        7,
                        base.revision,
                        90,
                        DatabaseQuota { max_bytes: None },
                        deadline(),
                    )
                    .unwrap();
            }
            4 => {
                other
                    .set_lifecycle(7, base.revision, 90, Lifecycle::Maintenance, deadline())
                    .unwrap();
            }
            _ => {
                other
                    .compact_begin(7, base.head_serial, deadline())
                    .unwrap();
            }
        }));
        let before = objects.puts_for(&head_key(&scope()));
        let done = execute(&mut session, &inputs);
        assert_eq!(
            objects.puts_for(&head_key(&scope())),
            before + 2,
            "one racing transition and one old CAS"
        );
        assert_eq!(done.results.len(), 2);
        assert!(done
            .results
            .iter()
            .all(|outcome| matches!(outcome.as_ref().unwrap_err().as_ref(), Error::Conflict)));
        assert_eq!(database.status(7, deadline()).unwrap().sequence, 0);
        assert!(session.invalidated);
    }
}

#[test]
fn dependency_failure_abandons_the_whole_staged_prefix_without_head_publication() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("warm"), deadline())
        .unwrap();
    let inputs = Inputs::new(&[
        "CREATE TABLE discarded(x)",
        "INSERT INTO discarded VALUES(1)",
    ]);
    objects.fail(true, "*".into(), StoreError::Unknown);
    let before = objects.puts_for(&head_key(&scope()));
    let done = execute(&mut session, &inputs);
    assert_eq!(objects.puts_for(&head_key(&scope())), before);
    assert!(done.results.iter().all(|outcome| matches!(
        outcome.as_ref().unwrap_err().as_ref(),
        Error::Store(StoreError::Unknown)
    )));
    assert_eq!(database.status(7, deadline()).unwrap().sequence, 0);
    assert!(session.invalidated);
}

fn candidate(base: &Snapshot, count: u64) -> Head {
    let mut head = base.head.clone();
    head.revision += count;
    head.head_serial += count;
    head.sequence += count;
    head.transition = Transition {
        revision: head.revision,
        nonce: 9,
    };
    head.windows[0].count += count as u32;
    head
}

#[test]
fn sealed_group_publication_preserves_every_metadata_field_and_ordinary_serial_rule() {
    let (objects, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    let next = candidate(&base, 2);
    assert!(matches!(
        PreparedHead::new(&database, &base, &next, deadline()),
        Err(Error::Format(FormatError::Invalid))
    ));
    for case in 0..12 {
        let mut changed = next.clone();
        match case {
            0 => changed.scope.generation += 1,
            1 => changed.owner_instance += 1,
            2 => changed.owner_epoch += 1,
            3 => changed.active = false,
            4 => changed.auth_epoch += 1,
            5 => changed.policy[0].write = false,
            6 => changed.quota.max_bytes = None,
            7 => changed.retention.max_entries += 1,
            8 => changed.lifecycle = Lifecycle::Maintenance,
            9 => changed.storage.allocated_through += 1,
            10 => changed.sequence += 1,
            _ => changed.windows[0].count -= 1,
        }
        assert!(
            matches!(
                VerifiedGroupTransition::new(base.clone(), changed, 2),
                Err(Error::Format(FormatError::Invalid))
            ),
            "case {case}"
        );
    }
    let mut with_result = base.clone();
    with_result.head.windows[0].count = 1;
    with_result.head.windows[0].result_bytes = 1;
    let mut decreased = candidate(&with_result, 2);
    decreased.windows[0].result_bytes = 0;
    assert!(matches!(
        VerifiedGroupTransition::new(with_result, decreased, 2),
        Err(Error::Format(_))
    ));
    let before = objects.puts_for(&head_key(&scope()));
    let verified = VerifiedGroupTransition::new(base.clone(), next.clone(), 2).unwrap();
    PreparedHead::group(&database, verified, deadline())
        .unwrap()
        .publish()
        .unwrap();
    assert_eq!(objects.puts_for(&head_key(&scope())), before + 1);
    assert_eq!(database.read_head(deadline()).unwrap().head, next);
}

#[test]
fn invalid_group_candidates_and_exhausted_counters_are_rejected_before_publication() {
    let (_, database) = fixture();
    let base = database.read_head(deadline()).unwrap();
    for count in [0, MAX_GROUP_MEMBERS + 1] {
        assert!(matches!(
            VerifiedGroupTransition::new(base.clone(), base.head.clone(), count),
            Err(Error::Limit)
        ));
    }
    let mut malformed = base.clone();
    malformed.head.format = 0;
    assert!(matches!(
        VerifiedGroupTransition::new(malformed, candidate(&base, 2), 2),
        Err(Error::Format(_))
    ));
    let mut malformed = candidate(&base, 2);
    malformed.format = 0;
    assert!(matches!(
        VerifiedGroupTransition::new(base.clone(), malformed, 2),
        Err(Error::Format(_))
    ));
    for counter in 0..3 {
        let mut exhausted = base.clone();
        match counter {
            0 => {
                exhausted.head.revision = u64::MAX;
                exhausted.head.head_serial = u64::MAX;
                exhausted.head.transition.revision = u64::MAX;
            }
            1 => exhausted.head.sequence = u64::MAX,
            _ => exhausted.head.head_serial = u64::MAX,
        }
        assert!(matches!(
            VerifiedGroupTransition::new(exhausted.clone(), exhausted.head, 1),
            Err(Error::Limit)
        ));
    }
    let (_, database, _) = crate::snapshot_integration_tests::fixture();
    let base = database.read_head(deadline()).unwrap();
    let mut next = candidate(&base, 2);
    next.head_serial = u64::MAX;
    assert!(matches!(
        VerifiedGroupTransition::new(base, next, 2),
        Err(Error::Limit)
    ));
}

#[test]
fn direct_group_builder_never_publishes_empty_invalid_or_unadmitted_prefixes() {
    for case in 0..11 {
        let (objects, mut database) = fixture();
        let mut context = context(&database, 2);
        let mut prefix = empty_prefix(2);
        match case {
            0 => prefix.clear(),
            1 => prefix.push(empty_prefix(1).remove(0)),
            2 => context.base.head.active = false,
            3 => context.base.head.windows[0].count = context.base.head.retention.max_entries,
            4 => context.base.head.sequence = u64::MAX,
            5 => prefix[0].batch.size_after = 65,
            6 => context.requests[0].fingerprint.clear(),
            7 => context.requests[1] = context.requests[0].clone(),
            8 => {
                context.base.head.revision = u64::MAX;
                context.base.head.head_serial = u64::MAX;
                context.base.head.transition.revision = u64::MAX;
            }
            9 => context.base.head.quota.max_bytes = Some(0),
            _ => database.scope.database += 1,
        }
        let puts = objects.puts_for(&head_key(&scope()));
        assert!(
            database.commit_group(&context, &prefix).is_err(),
            "case {case}"
        );
        assert_eq!(objects.puts_for(&head_key(&scope())), puts);
    }
    let (_, database) = fixture();
    let mut publisher = Publisher {
        context: context(&database, 2),
        database,
        outcome: None,
    };
    assert_eq!(publisher.publish(&empty_prefix(2)), GateDecision::Accepted);
    assert_eq!(publisher.publish(&empty_prefix(2)), GateDecision::Unknown);
    assert!(matches!(publisher.outcome, Some(Ok(_))));
    let (_, database, _) = crate::snapshot_integration_tests::fixture();
    let mut context = context(&database, 2);
    context.base.head.head_serial = u64::MAX - 3;
    assert!(matches!(
        database.commit_group(&context, &empty_prefix(2)),
        Err(Error::Limit)
    ));
}

#[test]
fn pre_sql_errors_and_counter_reserves_never_consume_members() {
    for case in 0..9 {
        let (objects, database) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        let inputs = Inputs::new(&["CREATE TABLE forbidden(x)", "SELECT 2"]);
        let mut limits = GroupLimits::default();
        match case {
            0 => limits.max_members = 0,
            1 => objects.fail(false, head_key(&scope()), StoreError::Unknown),
            2 => replace_head(&objects, &database, |head| head.policy[0].write = false),
            3 => replace_head(&objects, &database, |head| head.active = false),
            4 => session.invalidated = true,
            5 => {
                let base = database.read_head(deadline()).unwrap();
                objects.remove(&object_key(
                    &scope(),
                    base.head.storage.active_generation,
                    &base.head.windows[0].root,
                ));
            }
            6 => session.database.options.max_changed_pages = 0,
            7 => {
                session.history_verified = false;
                let statements = sql("SELECT 99");
                let saved = request(1, 99, 7, &statements).unwrap();
                let (receipt, _) = database
                    .execute(
                        7,
                        &saved,
                        &statements,
                        &temp.path().join("retained"),
                        deadline(),
                    )
                    .unwrap();
                objects.remove(&object_key(&scope(), 1, &receipt.result_hash));
            }
            _ => {
                replace_head(&objects, &database, |head| head.owner_epoch += 1);
            }
        }
        let before = objects.puts_for(&head_key(&scope()));
        assert!(
            session
                .execute_group(7, &inputs.members(), limits, deadline())
                .is_err(),
            "case {case}"
        );
        assert_eq!(objects.puts_for(&head_key(&scope())), before);
        assert_eq!(session.page_count(), 0);
    }
    for counter in 0..3 {
        let (objects, database) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        replace_head(&objects, &database, |head| match counter {
            0 => {
                head.revision = u64::MAX - 1;
                head.head_serial = u64::MAX - 1;
                head.transition.revision = head.revision;
            }
            1 => head.sequence = u64::MAX - 1,
            _ => head.head_serial = u64::MAX - 1,
        });
        let inputs = Inputs::new(&["SELECT 1", "SELECT 2"]);
        assert!(matches!(
            session
                .execute_group(7, &inputs.members(), GroupLimits::default(), deadline())
                .unwrap(),
            GroupExecution::Fallback
        ));
        assert!(!session.writer.is_stopped());
    }
    let (objects, database, _) = crate::snapshot_integration_tests::fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("snapshot"), deadline())
        .unwrap();
    replace_head(&objects.0, &database, |head| {
        head.head_serial = u64::MAX - 3
    });
    let inputs = Inputs::new(&["SELECT 1", "SELECT 2"]);
    assert!(matches!(
        session
            .execute_group(7, &inputs.members(), GroupLimits::default(), deadline())
            .unwrap(),
        GroupExecution::Fallback
    ));
    assert!(!session.writer.is_stopped());
}

#[test]
fn snapshots_and_compaction_keep_explicit_roots_and_original_group_receipts() {
    let (objects, database, before_point) = crate::snapshot_integration_tests::fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("warm"), deadline())
        .unwrap();
    let before = database.read_head(deadline()).unwrap();
    let inputs = Inputs::new(&["CREATE TABLE item(value)", "INSERT INTO item VALUES(7)"]);
    let committed: Vec<_> = execute(&mut session, &inputs)
        .results
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let head = database.status(7, deadline()).unwrap();
    let after_point = database
        .snapshot_prepare(
            7,
            &crate::snapshot::PrepareSnapshotInput {
                creator: 7,
                operation: 902,
                expected_revision: head.revision,
                expected_head_serial: head.head_serial,
                label: "after".into(),
            },
            deadline(),
        )
        .unwrap();
    let captured = database
        .snapshot_capture(7, &after_point.reference, deadline())
        .unwrap();
    assert_eq!(before_point.point.sequence, 0);
    assert_eq!(after_point.point.sequence, 2);
    assert_eq!(after_point.point.source_revision, before.head.revision + 2);
    assert_eq!(captured.head.head_serial, before.head.head_serial + 3);
    assert_eq!(captured.head.snapshots.as_ref().unwrap().len(), 2);
    assert_eq!(after_point.point.data_root, committed[1].receipt.data_root);
    let copying = database
        .compact_begin(7, captured.head.head_serial, deadline())
        .unwrap();
    let serial = copying.storage.plan.as_ref().unwrap().serial;
    database.compact_copy(7, serial, deadline()).unwrap();
    let promoted = database.compact_promote(7, serial, deadline()).unwrap();
    let old = before.head.storage.active_generation;
    let new = promoted.storage.active_generation;
    assert!(promoted.storage.retired(old));
    let intermediate_key = object_key(&scope(), new, &committed[0].receipt.data_root);
    assert!(
        matches!(
            objects.get(&intermediate_key, MAX_OBJECT_BYTES, deadline()),
            Err(StoreError::Missing)
        ),
        "receipt provenance is not an implicit retained-data root"
    );
    assert!(format!("{:?}", GroupExecution::Fallback).contains("Fallback"));
    for (key, _) in objects.0.entries() {
        if key.starts_with(&object_key(&scope(), old, "")) {
            objects.0.remove(&key);
        }
    }
    for (index, committed) in committed.iter().enumerate() {
        assert_eq!(
            database
                .lookup(7, &inputs.identities[index], deadline())
                .unwrap(),
            Resolution::Committed {
                receipt: committed.receipt.clone(),
                bytes: committed.bytes.clone()
            }
        );
    }
    let base = database.read_head(deadline()).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    database
        .verify_closure(&context, &base, deadline())
        .unwrap();
    let mut cold = database
        .session(7, &temp.path().join("cold"), deadline())
        .unwrap();
    assert_eq!(
        cold.query(7, &sql("SELECT value FROM item"), deadline())
            .unwrap()
            .statements[0]
            .rows,
        vec![vec![Value::Integer(7)]]
    );
    let catalogue =
        crate::catalogue::Catalogue::new(objects.clone(), 1, 2, 11, test_options()).unwrap();
    let caller = crate::catalogue::Caller {
        principal: 7,
        provision: true,
    };
    let restored = catalogue
        .prepare_restore(
            caller,
            &crate::catalogue::PrepareRestore {
                name: "group snapshot restore".into(),
                operation: 9001,
                expected_name_revision: None,
                options: crate::catalogue::CreateOptions::default(),
                source_scope: scope(),
                snapshot: after_point.reference,
            },
            deadline(),
        )
        .unwrap();
    for (number, phase) in [
        crate::catalogue::RestorePhase::Reserved,
        crate::catalogue::RestorePhase::Copying,
        crate::catalogue::RestorePhase::Copied,
        crate::catalogue::RestorePhase::Bound,
        crate::catalogue::RestorePhase::Ready,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            catalogue
                .resume_restore(
                    caller,
                    &restored.reference,
                    &temp.path().join(format!("restore-{number}")),
                    crate::catalogue::RestoreBudget::default(),
                    deadline()
                )
                .unwrap()
                .phase,
            phase
        );
    }
    let named = catalogue
        .resolve(caller, &restored.reference.creation.name, deadline())
        .unwrap();
    assert_eq!(named.head.sequence, 0);
    assert!(named.head.snapshots.as_ref().unwrap().is_empty());
    let target =
        Database::with_options(objects.clone(), named.creation.scope, 12, test_options()).unwrap();
    for (key, _) in objects.0.entries() {
        if key.starts_with(&object_key(&scope(), new, "")) {
            objects.0.remove(&key);
        }
    }
    assert_eq!(
        target
            .query(
                7,
                &sql("SELECT value FROM item"),
                &temp.path().join("target"),
                deadline()
            )
            .unwrap()
            .statements[0]
            .rows,
        vec![vec![Value::Integer(7)]]
    );
    for identity in &inputs.identities {
        assert_eq!(
            target.lookup(7, identity, deadline()).unwrap(),
            Resolution::Unknown
        );
    }
}

#[test]
fn native_aggregate_budgets_end_the_consumed_prefix_without_sql_replay() {
    for result_budget in [false, true] {
        let (_, database) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        let inputs = Inputs::new(&["CREATE TABLE too_large(x)", "SELECT 2"]);
        let mut limits = GroupLimits::default();
        if result_budget {
            limits.max_result_bytes = 1;
        } else {
            limits.max_changed_pages = 1;
        }
        let GroupExecution::Completed(done) = session
            .execute_group(7, &inputs.members(), limits, deadline())
            .unwrap()
        else {
            panic!("aggregate limit must be enforced during native staging")
        };
        assert_eq!(done.results.len(), 1);
        assert!(matches!(
            done.results[0].as_ref().unwrap_err().as_ref(),
            Error::Engine(_)
        ));
        assert!(session.invalidated);
        assert_eq!(database.status(7, deadline()).unwrap().sequence, 0);
        assert_eq!(
            database
                .lookup(7, &inputs.identities[1], deadline())
                .unwrap(),
            Resolution::Unknown
        );
    }
}

#[test]
fn pending_owner_context_capacity_and_invalid_manifest_quota_stop_before_sql() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("warm"), deadline())
        .unwrap();
    let inputs = Inputs::new(&["SELECT 1", "SELECT 2"]);
    let base = database.read_head(deadline()).unwrap();
    let holders: Vec<_> = (0..64)
        .map(|_| ObjectContext::from_snapshot(&database, &base, deadline()).unwrap())
        .collect();
    assert!(matches!(
        session.execute_group(7, &inputs.members(), GroupLimits::default(), deadline()),
        Err(Error::Store(StoreError::Budget))
    ));
    drop(holders);
    let next = Database::next(&base.head, 17).unwrap();
    let publication = PreparedHead::new(&database, &base, &next, deadline()).unwrap();
    let objects_context = ObjectContext::from_snapshot(&database, &base, deadline()).unwrap();
    let mut bad_quota = next;
    bad_quota.quota.max_bytes = Some(0);
    assert!(matches!(
        database.publish_manifest(&objects_context, &bad_quota, publication, deadline()),
        Err(Error::Format(_))
    ));
    replace_head(&objects, &database, |head| {
        head.format = 8;
        head.revision += 1;
        head.head_serial += 1;
        head.transition = Transition {
            revision: head.revision,
            nonce: 701,
        };
        head.active = false;
        head.owner_plan = Some(OwnerPlan {
            reference: OwnerPlanRef {
                creator: 7,
                operation: 101,
                descriptor_hash: digest(b"owner"),
            },
            admission: OwnerAdmission {
                kind: OwnerAdmissionKind::Claim,
                revision: head.revision,
                head_serial: head.head_serial,
            },
            phase: OwnerPhase {
                kind: OwnerPhaseKind::Claimed,
                revision: head.revision,
                head_serial: head.head_serial,
                nonce: 701,
                owner_epoch: head.owner_epoch,
                owner_instance: head.owner_instance,
            },
        });
    });
    assert!(matches!(
        session.execute_group(7, &inputs.members(), GroupLimits::default(), deadline()),
        Err(Error::Fenced)
    ));
    assert!(!session.writer.is_stopped());
}

struct PublicationBoundary {
    inner: Arc<Memory>,
    root: Mutex<String>,
    final_index: std::sync::atomic::AtomicBool,
    after_index: Mutex<Option<Action>>,
    corrupt_index: bool,
    manifest_error: Mutex<Option<StoreError>>,
}

impl Objects for PublicationBoundary {
    fn get(&self, key: &str, maximum: usize, until: Instant) -> Result<Stored, StoreError> {
        if self.final_index.load(std::sync::atomic::Ordering::Acquire)
            && key == *self.root.lock().unwrap()
        {
            if let Some(error) = self.manifest_error.lock().unwrap().take() {
                return Err(error);
            }
        }
        let mut stored = self.inner.get(key, maximum, until)?;
        if key != head_key(&scope()) {
            let envelope = decode_object(&stored.bytes, &scope(), &digest(&stored.bytes)).unwrap();
            if matches!(envelope.payload, Payload::Index(ref index) if index.summary().count == 2) {
                self.final_index
                    .store(true, std::sync::atomic::Ordering::Release);
                if let Some(action) = self.after_index.lock().unwrap().take() {
                    action();
                }
                if self.corrupt_index {
                    stored.bytes[0] ^= 1;
                }
            }
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
        let outcome = self.inner.put(key, bytes, condition, until);
        if matches!(condition, Condition::Absent) {
            let envelope = decode_object(bytes, &scope(), &digest(bytes)).unwrap();
            if matches!(envelope.payload, Payload::Manifest(_)) {
                *self.root.lock().unwrap() = key.into();
            }
        }
        outcome
    }
}

#[test]
fn final_manifest_get_and_late_quarantine_cannot_be_replaced_by_earlier_readback() {
    for cut in 0..4 {
        let (memory, original) = fixture();
        let base = original.read_head(deadline()).unwrap();
        let objects = Arc::new(PublicationBoundary {
            inner: memory.clone(),
            root: Mutex::new(object_key(&scope(), 1, &base.head.data_root)),
            final_index: std::sync::atomic::AtomicBool::new(false),
            after_index: Mutex::new(None),
            corrupt_index: cut == 2,
            manifest_error: Mutex::new(if cut == 0 {
                Some(StoreError::Unknown)
            } else {
                None
            }),
        });
        let database =
            Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let mut session = database
            .session(7, &temp.path().join("warm"), deadline())
            .unwrap();
        if cut == 1 {
            let latch = database.quarantined.clone();
            *objects.after_index.lock().unwrap() = Some(Box::new(move || {
                latch.store(true, std::sync::atomic::Ordering::Release)
            }));
        }
        let before = memory.puts_for(&head_key(&scope()));
        let inputs = Inputs::new(&["CREATE TABLE item(x)", "INSERT INTO item VALUES(1)"]);
        let done = execute(&mut session, &inputs);
        assert!(objects
            .final_index
            .load(std::sync::atomic::Ordering::Acquire));
        if cut == 3 {
            assert!(done.results.iter().all(Result::is_ok));
            assert_eq!(memory.puts_for(&head_key(&scope())), before + 1);
            assert_eq!(
                memory.gets_for(&objects.root.lock().unwrap()),
                2,
                "readback and final manifest GET"
            );
        } else {
            assert!(done.results.iter().all(Result::is_err));
            assert_eq!(memory.puts_for(&head_key(&scope())), before);
            assert_eq!(original.read_head(deadline()).unwrap().head, base.head);
            assert!(session.invalidated);
        }
    }
}
