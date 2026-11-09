use super::tests::{deadline, fixture, identity, replace_head, scope, sql, test_options, Memory};
use super::*;

fn no_pages() -> PageBatch {
    PageBatch {
        size_after: 0,
        pages: vec![],
    }
}

fn execute(session: &mut Session, id: u64, text: &str) -> (Receipt, TransactionResult) {
    let statements = sql(text);
    let identity = request(1, id, 7, &statements).unwrap();
    session
        .execute(7, &identity, &statements, deadline())
        .unwrap()
}

#[test]
fn warm_session_reuses_verified_image_and_checks_current_authority() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("session");
    let mut session = database.session(7, &directory, deadline()).unwrap();
    assert_eq!(session.page_count(), 0);
    execute(
        &mut session,
        1,
        "CREATE TABLE item(id INTEGER PRIMARY KEY, value TEXT)",
    );
    let (_, inserted) = execute(
        &mut session,
        2,
        "INSERT INTO item(value) VALUES(hex(randomblob(16))) RETURNING id,value",
    );
    let read = session
        .query(7, &sql("SELECT id,value FROM item"), deadline())
        .unwrap();
    assert_eq!(read.statements[0].rows, inserted.statements[0].rows);
    assert!(session.page_count() > 0);
    objects.fail(false, head_key(&scope()), StoreError::Unknown);
    assert!(matches!(
        session.query(7, &sql("SELECT id FROM item"), deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    assert!(session
        .query(7, &sql("SELECT id FROM item"), deadline())
        .is_ok());
    let head = database.status(7, deadline()).unwrap();
    let mut policy = head.policy.clone();
    policy[0].read = false;
    database
        .set_policy(7, head.revision, 40, policy, deadline())
        .unwrap();
    assert!(matches!(
        session.query(7, &sql("SELECT id FROM item"), deadline()),
        Err(Error::Denied)
    ));
    drop(session);
    assert!(!directory.exists());
}

#[test]
fn quota_is_persisted_cas_ordered_and_never_truncates_existing_data() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("old"), deadline())
        .unwrap();
    execute(&mut session, 1, "CREATE TABLE item(x)");
    let base = database.read_head(deadline()).unwrap();
    assert!(matches!(
        database.set_quota(
            7,
            base.head.revision,
            10,
            DatabaseQuota {
                max_bytes: Some(PAGE_SIZE as u64)
            },
            deadline()
        ),
        Err(Error::Limit)
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, base.head);
    assert!(matches!(
        database.set_quota(
            7,
            base.head.revision,
            10,
            DatabaseQuota { max_bytes: Some(1) },
            deadline()
        ),
        Err(Error::Format(_))
    ));
    let changed = database
        .set_quota(
            7,
            base.head.revision,
            11,
            DatabaseQuota { max_bytes: None },
            deadline(),
        )
        .unwrap();
    assert_eq!(changed.quota.max_bytes, None);
    assert!(matches!(
        database.set_quota(
            7,
            base.head.revision,
            12,
            DatabaseQuota {
                max_bytes: Some(10 * options::GIB)
            },
            deadline()
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        session.query(7, &sql("SELECT * FROM item"), deadline()),
        Err(Error::StaleSnapshot)
    ));
    assert!(matches!(
        session.query(7, &sql("SELECT * FROM item"), deadline()),
        Err(Error::StaleSnapshot)
    ));
    let bytes =
        scap_sql::encode_result(&TransactionResult { statements: vec![] }, sql_limits()).unwrap();
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &base, &identity(2), deadline()),
            &PageBatch {
                size_after: session.page_count(),
                pages: vec![]
            },
            &bytes
        ),
        Err(Error::Conflict)
    ));

    let mut creation_options = test_options();
    creation_options.quota.max_bytes = Some(PAGE_SIZE as u64);
    let reopened = Database::with_options(objects, scope(), 10, creation_options).unwrap();
    assert_eq!(
        reopened.status(7, deadline()).unwrap().quota.max_bytes,
        None
    );
    let mut session = reopened
        .session(7, &temp.path().join("reopened"), deadline())
        .unwrap();
    execute(&mut session, 2, "INSERT INTO item VALUES(1)");
    assert!(session.page_count() > 1);
}

#[test]
fn changed_root_and_owner_epoch_require_a_new_write_session() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut first = database
        .session(7, &temp.path().join("first"), deadline())
        .unwrap();
    let mut second = database
        .session(7, &temp.path().join("second"), deadline())
        .unwrap();
    execute(&mut first, 1, "CREATE TABLE x(value)");
    assert!(matches!(
        second.query(7, &sql("SELECT 1"), deadline()),
        Err(Error::StaleSnapshot)
    ));
    let mut fresh = database
        .session(7, &temp.path().join("fresh"), deadline())
        .unwrap();
    replace_head(&objects, &database, |head| head.owner_epoch += 1);
    // Read permission is current and the exact immutable root still matches.
    fresh.query(7, &sql("SELECT * FROM x"), deadline()).unwrap();
    let statements = sql("INSERT INTO x VALUES(2)");
    let identity = request(1, 2, 7, &statements).unwrap();
    assert!(matches!(
        fresh.execute(7, &identity, &statements, deadline()),
        Err(Error::StaleSnapshot)
    ));
}

#[test]
fn ambiguous_session_never_replays_and_retained_results_ignore_lower_new_budgets() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("unknown"), deadline())
        .unwrap();
    let statements = sql("CREATE TABLE x(value)");
    let identity = request(1, 1, 7, &statements).unwrap();
    // The test port persists HEAD then loses its acknowledgement.
    objects.lose_next_cas();
    assert!(matches!(
        session.execute(7, &identity, &statements, deadline()),
        Err(Error::Store(StoreError::Unknown))
    ));
    let (receipt, _) = session
        .execute(7, &identity, &statements, deadline())
        .unwrap();
    assert_eq!(receipt.sequence, 1);
    assert!(matches!(
        session.query(7, &sql("SELECT 1"), deadline()),
        Err(Error::StaleSnapshot)
    ));
    let mut recovered = database
        .session(7, &temp.path().join("recovered"), deadline())
        .unwrap();
    let statements = sql("SELECT hex(randomblob(128))");
    let identity = request(1, 2, 7, &statements).unwrap();
    let original = recovered
        .execute(7, &identity, &statements, deadline())
        .unwrap();
    let mut options = test_options();
    options.sql.max_result_bytes = 12;
    options.max_input_bytes = 1;
    let lowered = Database::with_options(objects, scope(), 10, options).unwrap();
    assert_eq!(
        lowered
            .execute(7, &identity, &statements, temp.path(), deadline())
            .unwrap(),
        original
    );
}

#[test]
fn cold_activation_keeps_the_verified_file_and_rejects_invalid_admission() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let head = database.takeover(7, 2, 10, deadline()).unwrap();
    let (active, mut session) = database
        .activate_session(
            7,
            head.revision,
            11,
            &temp.path().join("active"),
            deadline(),
        )
        .unwrap();
    assert!(active.active);
    execute(&mut session, 1, "CREATE TABLE x(value)");
    assert!(matches!(
        database.activate_session(7, 4, 12, &temp.path().join("again"), deadline()),
        Err(Error::Conflict)
    ));
    let head = database.status(7, deadline()).unwrap();
    assert!(matches!(
        database.activate_session(
            7,
            head.revision,
            12,
            &temp.path().join("active-again"),
            deadline()
        ),
        Err(Error::Fenced)
    ));
    assert!(matches!(
        database.session(8, &temp.path().join("denied"), deadline()),
        Err(Error::Denied)
    ));
    assert!(matches!(
        database.session(7, temp.path(), deadline()),
        Err(Error::Engine(_))
    ));
    let mut options = test_options();
    options.sql.max_result_bytes = 0;
    assert!(matches!(
        Database::with_options(objects, scope(), 10, options),
        Err(Error::Sql(_))
    ));
    let objects = Arc::new(Memory::default());
    let invalid = Options {
        max_input_bytes: 0,
        ..Options::default()
    };
    assert!(matches!(
        Database::with_options(objects, scope(), 10, invalid),
        Err(Error::Limit)
    ));
}

#[test]
fn hot_writes_inherit_history_but_target_and_cold_checks_still_detect_missing_objects() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("warm"), deadline())
        .unwrap();
    let (old, _) = execute(&mut session, 1, "SELECT random()");
    let key = object_key(&scope(), 1, &old.result_hash);
    let reads = objects.gets_for(&key);
    execute(&mut session, 2, "SELECT random()");
    assert_eq!(
        objects.gets_for(&key),
        reads,
        "a hot write must not rescan unrelated retained outcomes"
    );
    // Out-of-protocol deletion violates immutability. A warm unrelated write
    // does not promise discovery; the actual target lookup must discover it.
    objects.fail(false, key.clone(), StoreError::Missing);
    execute(&mut session, 3, "SELECT random()");
    assert_eq!(objects.gets_for(&key), reads);
    assert!(matches!(
        database.lookup(7, &old.request, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
    let before = database.status(7, deadline()).unwrap();
    assert!(matches!(
        session.execute(7, &identity(4), &sql("SELECT 1"), deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.clone().cancel(7, &identity(5), deadline()),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        database.set_policy(7, before.revision, 50, before.policy.clone(), deadline()),
        Err(Error::Corrupt)
    ));
    assert_eq!(database.status(7, deadline()).unwrap(), before);
    objects.fail(false, key, StoreError::Missing);
    assert!(matches!(
        database.session(7, &temp.path().join("cold"), deadline()),
        Err(Error::Store(StoreError::Missing))
    ));
}

#[test]
fn exact_history_bytes_cancelled_entries_and_full_window_admission() {
    let (objects, database) = fixture();
    database.cancel(7, &identity(1), deadline()).unwrap();
    let head = database.read_head(deadline()).unwrap().head;
    database
        .verify_results(&ObjectContext::capture(&database, &head), &head, deadline())
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &temp.path().join("bytes"), deadline())
        .unwrap();
    execute(&mut session, 2, "SELECT 1");
    let mut head = database.read_head(deadline()).unwrap().head;
    head.windows[0].result_bytes += 1;
    assert!(matches!(
        database.verify_results(&ObjectContext::capture(&database, &head), &head, deadline()),
        Err(Error::Corrupt)
    ));
    let entry = Entry {
        result_bytes: 0,
        request: identity(3),
        outcome: OutcomeRef::Cancelled {
            transition: head.transition.clone(),
        },
    };
    assert!(matches!(
        database.append(
            &ObjectContext::capture(&database, &head),
            &mut head,
            Entry {
                result_bytes: u64::MAX,
                ..entry.clone()
            },
            deadline()
        ),
        Err(Error::Limit)
    ));
    head.windows[0].result_bytes = 0;
    assert!(matches!(
        database.append(
            &ObjectContext::capture(&database, &head),
            &mut head,
            Entry {
                result_bytes: u64::MAX,
                ..entry
            },
            deadline()
        ),
        Err(Error::WindowFull)
    ));

    let mut options = test_options();
    options.retention.max_result_bytes = MAX_RESULT_BYTES as u64;
    let bounded =
        Database::with_options(Arc::new(Memory::default()), scope(), 10, options).unwrap();
    bounded.create(7, 1, deadline()).unwrap();
    let (_, mut session) = bounded
        .activate_session(7, 1, 2, &temp.path().join("budget"), deadline())
        .unwrap();
    execute(&mut session, 1, "SELECT 1");
    let base = bounded.read_head(deadline()).unwrap();
    assert!(base.head.windows[0].full(&base.head.retention));
    assert!(matches!(
        bounded.commit(
            &crate::tests::attempt(&bounded, &base, &identity(2), deadline()),
            &no_pages(),
            b"x"
        ),
        Err(Error::WindowFull)
    ));
    let next = bounded
        .close_full(7, base.head.revision, 30, deadline())
        .unwrap();
    assert_eq!(next.windows[1].count, 1);
    assert!(matches!(
        bounded.lookup(7, &identity(1), deadline()).unwrap(),
        Resolution::Committed { .. }
    ));
    drop(objects);
}

#[test]
fn static_admission_rejects_work_before_expensive_cold_download() {
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let mut options = test_options();
    options.max_input_bytes = 12;
    let limited = Database::with_options(objects.clone(), scope(), 10, options).unwrap();
    let mut session = limited
        .session(7, &temp.path().join("limited"), deadline())
        .unwrap();
    assert!(matches!(
        limited.execute(
            7,
            &identity(1),
            &sql("SELECT 1"),
            &temp.path().join("not-created"),
            deadline()
        ),
        Err(Error::Limit)
    ));
    assert!(matches!(
        limited.query(
            7,
            &sql("SELECT 1"),
            &temp.path().join("not-created"),
            deadline()
        ),
        Err(Error::Limit)
    ));
    assert!(matches!(
        session.query(7, &sql("SELECT 1"), deadline()),
        Err(Error::Limit)
    ));
    assert!(matches!(
        session.execute(7, &identity(1), &sql("SELECT 1"), deadline()),
        Err(Error::Limit)
    ));
    assert!(!temp.path().join("not-created").exists());
    assert!(matches!(
        database.query(7, &[], &temp.path().join("empty-query"), deadline()),
        Err(Error::Sql(_))
    ));
    let mut options = test_options();
    options.sql.max_statements = 1;
    let limited = Database::with_options(objects, scope(), 10, options).unwrap();
    let statements = [sql("SELECT 1"), sql("SELECT 2")].concat();
    let request = request(1, 1, 7, &statements).unwrap();
    assert!(matches!(
        limited.execute(
            7,
            &request,
            &statements,
            &temp.path().join("too-many"),
            deadline()
        ),
        Err(Error::Sql(_))
    ));
    assert!(matches!(
        super::request(1, 1, 7, &sql(&"x".repeat(MAX_REQUEST_BYTES))),
        Err(Error::Limit)
    ));
}

#[test]
fn quota_and_corrupt_physical_image_boundaries_fail_before_publication() {
    let (_, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let base = database.read_head(deadline()).unwrap();
    let mut bad = base.clone();
    bad.head.quota.max_bytes = Some(1);
    assert!(matches!(
        database.publish(&base, &bad.head, deadline()),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.verify_closure(
            &ObjectContext::capture(&database, &bad.head),
            &bad.head,
            deadline()
        ),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.commit(
            &crate::tests::attempt(&database, &bad, &identity(1), deadline()),
            &no_pages(),
            b"x"
        ),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        database.restore(
            &ObjectContext::capture(&database, &bad.head),
            &bad,
            &temp.path().join("invalid-quota"),
            deadline()
        ),
        Err(Error::Format(_))
    ));
    // Keep a valid serial successor so this fixture reaches the unchanged
    // manifest/quota boundary instead of failing candidate admission first.
    let mut over = Database::next(&base.head, 99).unwrap();
    over.quota.max_bytes = Some(PAGE_SIZE as u64);
    over.data_root = ObjectContext::bootstrap(&database)
        .save(
            Payload::Manifest(Manifest {
                page_count: 2,
                root: Some(digest(b"missing")),
            }),
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        database.publish(&base, &over, deadline()),
        Err(Error::Limit)
    ));
    assert!(matches!(
        database.verify_closure(&ObjectContext::capture(&database, &over), &over, deadline()),
        Err(Error::Limit)
    ));
    over.quota.max_bytes = None;
    assert!(matches!(
        database.verify_closure(&ObjectContext::capture(&database, &over), &over, deadline()),
        Err(Error::Store(StoreError::Missing))
    ));

    for header_valid in [false, true] {
        let mut page = vec![0; PAGE_SIZE];
        if header_valid {
            page[..16].copy_from_slice(b"SQLite format 3\0");
            page[16..18].copy_from_slice(&[0x10, 0]);
        }
        let root = data_tree::update(
            &ObjectContext::capture(&database, &base.head),
            &base.head.data_root,
            &PageBatch {
                size_after: 1,
                pages: vec![scap_object_sqlite::PageChange {
                    number: 1,
                    bytes: page,
                }],
            },
            64,
            deadline(),
        )
        .unwrap();
        let mut malformed = base.clone();
        malformed.head.data_root = root;
        assert!(matches!(
            database.restore(
                &ObjectContext::capture(&database, &malformed.head),
                &malformed,
                &temp.path().join(format!("bad-image-{header_valid}")),
                deadline()
            ),
            Err(Error::Engine(_))
        ));
    }

    let (objects, database) = fixture();
    let mut session = database
        .session(7, &temp.path().join("source"), deadline())
        .unwrap();
    execute(&mut session, 1, "CREATE TABLE x(value)");
    let current = database.read_head(deadline()).unwrap();
    let manifest = data_tree::manifest(
        &ObjectContext::capture(&database, &current.head),
        &current.head.data_root,
        deadline(),
    )
    .unwrap();
    let lost = temp.path().join("lost-cache");
    objects.remove_directory_when_reading(
        object_key(&scope(), 1, &manifest.root.unwrap()),
        lost.clone(),
    );
    assert!(matches!(
        database.restore(
            &ObjectContext::capture(&database, &current.head),
            &current,
            &lost,
            deadline()
        ),
        Err(Error::Engine(scap_object_sqlite::Error::Io(_)))
    ));
    assert_eq!(database.read_head(deadline()).unwrap().head, current.head);
}

#[test]
fn cold_activation_rechecks_both_etag_and_body_and_current_writer_eligibility() {
    for preserve_etag in [false, true] {
        let (objects, database) = fixture();
        let temp = tempfile::tempdir().unwrap();
        let recovering = database.takeover(7, 2, 3, deadline()).unwrap();
        let mut changed = Database::next(&recovering, 4).unwrap();
        changed.auth_epoch += 1;
        objects.replace_after(
            2,
            head_key(&scope()),
            encode_head(&changed).unwrap(),
            preserve_etag,
        );
        assert!(matches!(
            database.activate_session(
                7,
                recovering.revision,
                5,
                &temp.path().join("stale"),
                deadline()
            ),
            Err(Error::Conflict)
        ));
        assert!(!temp.path().join("stale").exists());
    }
    let (objects, database) = fixture();
    let temp = tempfile::tempdir().unwrap();
    let recovering = database.takeover(7, 2, 3, deadline()).unwrap();
    let other = Database::new(objects.clone(), scope(), 99).unwrap();
    assert!(matches!(
        other.activate_session(
            7,
            recovering.revision,
            4,
            &temp.path().join("wrong-owner"),
            deadline()
        ),
        Err(Error::Fenced)
    ));
    replace_head(&objects, &database, |head| {
        head.lifecycle = Lifecycle::Maintenance
    });
    assert!(matches!(
        database.activate_session(
            7,
            recovering.revision,
            4,
            &temp.path().join("maintenance"),
            deadline()
        ),
        Err(Error::Lifecycle)
    ));
}
