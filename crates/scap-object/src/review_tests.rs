//! Authority regressions use the object port only. Real engine/process/S3
//! experiments are intentionally separate from these deterministic unit cases.

use super::tests::{deadline, fixture, identity, replace_head, scope, TEST_WINDOW};
use super::*;

fn original_result() -> Vec<u8> {
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

fn no_pages() -> PageBatch {
    PageBatch {
        size_after: 0,
        pages: Vec::new(),
    }
}

fn publish_no_change(database: &Database, id: u64) -> Receipt {
    let base = database.read_head(deadline()).unwrap();
    let request = Request {
        epoch: base.head.request_epoch,
        ..identity(id)
    };
    database
        .commit(
            &crate::tests::attempt(database, &base, &request, deadline()),
            &no_pages(),
            &original_result(),
        )
        .unwrap()
}

fn full_cancelled_index(epoch: u64) -> Vec<Entry> {
    (1..=TEST_WINDOW as u64)
        .map(|id| Entry {
            result_bytes: 0,
            request: Request {
                epoch,
                ..identity(id)
            },
            outcome: OutcomeRef::Cancelled {
                transition: Transition {
                    revision: 2,
                    nonce: id,
                },
            },
        })
        .collect()
}

#[test]
fn missing_retained_result_blocks_target_lookup_and_cold_publication() {
    let (objects, database) = fixture();
    let original = publish_no_change(&database, 1);
    let before = database.read_head(deadline()).unwrap();
    let missing = object_key(&scope(), 1, &original.result_hash);
    objects.fail(false, missing.clone(), StoreError::Missing);
    assert!(matches!(
        database.lookup(7, &identity(1), deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    let temp = tempfile::tempdir().unwrap();
    objects.fail(false, missing.clone(), StoreError::Missing);
    assert!(matches!(
        database.execute(
            7,
            &identity(1),
            &super::tests::sql("SELECT 1"),
            &temp.path().join("duplicate"),
            deadline()
        ),
        Err(Error::Store(StoreError::Missing))
    ));
    objects.fail(false, missing.clone(), StoreError::Missing);
    assert!(matches!(
        database.session(7, &temp.path().join("prepare-session"), deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    let database =
        Database::with_options(objects.clone(), scope(), 10, super::tests::test_options()).unwrap();
    objects.fail(false, missing.clone(), StoreError::Missing);
    assert!(matches!(
        database.execute(
            7,
            &identity(2),
            &super::tests::sql("SELECT 1"),
            &temp.path().join("first-write"),
            deadline()
        ),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, before.head);
    assert_eq!(
        database.lookup(7, &identity(2), deadline()).unwrap(),
        Resolution::Unknown
    );
    let database =
        Database::with_options(objects.clone(), scope(), 10, super::tests::test_options()).unwrap();
    let recovering = database
        .takeover(7, before.head.revision, 90, deadline())
        .unwrap();
    objects.fail(false, missing, StoreError::Missing);
    assert!(matches!(
        database.activate(7, recovering.revision, 91, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert!(!database.status(7, deadline()).unwrap().active);
}

#[test]
fn missing_closed_epoch_blocks_cold_activation_and_first_session_write() {
    let (objects, database) = fixture();
    let closed = ObjectContext::bootstrap(&database)
        .unwrap()
        .save(
            crate::tests::index_payload(1, full_cancelled_index(1)),
            deadline(),
        )
        .unwrap();
    let current =
        request_index::empty(&ObjectContext::bootstrap(&database).unwrap(), 2, deadline()).unwrap();
    replace_head(&objects, &database, |head| {
        head.revision = 3;
        head.head_serial = 3;
        head.transition = Transition {
            revision: 3,
            nonce: 31,
        };
        head.request_epoch = 2;
        head.windows[0].epoch = 2;
        head.windows[0].root = current.clone();
        head.windows.push(Window {
            epoch: 1,
            root: closed.clone(),
            count: TEST_WINDOW,
            result_bytes: 0,
        });
    });
    let before = database.read_head(deadline()).unwrap();
    let next = Request {
        epoch: 2,
        ..identity(1)
    };
    let temp = tempfile::tempdir().unwrap();
    objects.fail(false, object_key(&scope(), 1, &closed), StoreError::Missing);
    assert!(matches!(
        database.session(7, &temp.path().join("first-write"), deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(
        database.lookup(7, &next, deadline()).unwrap(),
        Resolution::Unknown
    );
    assert_eq!(database.read_head(deadline()).unwrap().head, before.head);
    let database =
        Database::with_options(objects.clone(), scope(), 10, super::tests::test_options()).unwrap();
    let recovering = database
        .takeover(7, before.head.revision, 32, deadline())
        .unwrap();
    objects.fail(false, object_key(&scope(), 1, &closed), StoreError::Missing);
    assert!(matches!(
        database.activate_session(
            7,
            recovering.revision,
            33,
            &temp.path().join("activate"),
            deadline()
        ),
        Err(Error::Store(StoreError::Missing))
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, recovering);
}

#[test]
fn authorization_and_lifecycle_changes_fence_already_prepared_writes() {
    let (_, database) = fixture();
    let before = database.read_head(deadline()).unwrap();
    let revoked = database
        .set_policy(
            7,
            before.head.revision,
            11,
            vec![Permission {
                principal: 7,
                read: false,
                write: false,
                admin: true,
            }],
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &before, &identity(1), deadline()),
            &no_pages(),
            &original_result()
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        database.lookup(7, &identity(1), deadline()),
        Err(Error::Denied)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, revoked);

    for lifecycle in [Lifecycle::Maintenance, Lifecycle::Deleted] {
        let (_, database) = fixture();
        let before = database.read_head(deadline()).unwrap();
        let changed = database
            .set_lifecycle(7, before.head.revision, 12, lifecycle, deadline())
            .unwrap();
        assert!(matches!(
            database.commit(
                &crate::tests::attempt(&database, &before, &identity(2), deadline()),
                &no_pages(),
                &original_result()
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(database.read_head(deadline()).unwrap().head, changed);
        assert_eq!(changed.sequence, 0);
    }
}

#[test]
fn takeover_and_principal_isolation_preserve_the_original_result() {
    let (objects, database) = fixture();
    let original = publish_no_change(&database, 1);
    let before = database.read_head(deadline()).unwrap();
    let replacement = Database::new(objects, scope(), 99).unwrap();
    let recovering = replacement
        .takeover(7, before.head.revision, 13, deadline())
        .unwrap();
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &before, &identity(2), deadline()),
            &no_pages(),
            &original_result()
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, recovering);
    assert_eq!(
        replacement.lookup(7, &identity(1), deadline()).unwrap(),
        Resolution::Committed {
            receipt: original.clone(),
            bytes: original_result(),
        }
    );

    let mut policy = recovering.policy.clone();
    policy.push(Permission {
        principal: 8,
        read: true,
        write: true,
        admin: false,
    });
    replacement
        .set_policy(7, recovering.revision, 14, policy, deadline())
        .unwrap();
    assert!(matches!(
        replacement.lookup(8, &identity(1), deadline()),
        Err(Error::Denied)
    ));
    let impostor = Request {
        principal: 8,
        ..identity(1)
    };
    assert!(matches!(
        replacement.lookup(8, &impostor, deadline()),
        Err(Error::RequestConflict)
    ));
    assert_eq!(
        replacement.lookup(7, &identity(1), deadline()).unwrap(),
        Resolution::Committed {
            receipt: original,
            bytes: original_result(),
        }
    );
}
