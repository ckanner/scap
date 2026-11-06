use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn prepare(path: &std::path::Path, bytes: &[u8]) -> PreparedImage {
    let mut builder =
        ImageBuilder::create_new(path, (bytes.len() / PAGE_SIZE) as u32, MAX_DATABASE_PAGES)
            .unwrap();
    for (index, chunk) in bytes.chunks(32 * PAGE_SIZE).enumerate() {
        builder
            .append_pages((index * 32 + 1) as u32, chunk)
            .unwrap();
    }
    builder.finish().unwrap()
}

#[test]
fn quotas_cache_and_native_format_limits_are_independent() {
    let mut bounded = limits();
    bounded.max_database_pages = MAX_DATABASE_PAGES;
    bounded.max_changed_pages = MAX_DATABASE_PAGES;
    bounded.cache_bytes = i32::MAX as u64 * 1024;
    sql::validate_limits(bounded).unwrap();
    bounded.max_database_pages = 1;
    sql::validate_limits(bounded).unwrap();
    for field in 0..3 {
        let mut invalid = bounded;
        match field {
            0 => invalid.max_changed_pages = u32::MAX,
            1 => invalid.cache_bytes = PAGE_SIZE as u64 - 1,
            _ => invalid.cache_bytes += 1,
        }
        assert!(matches!(
            sql::validate_limits(invalid),
            Err(Error::InvalidLimits)
        ));
    }
    let root = tempfile::tempdir().unwrap();
    let native = libsql_sys::rusqlite::Connection::open(root.path().join("source")).unwrap();
    native.execute_batch("CREATE TABLE x(n)").unwrap();
    drop(native);
    let bytes = std::fs::read(root.path().join("source")).unwrap();
    let destination = root.path().join("over-quota");
    let prepared = prepare(&destination, &bytes);
    assert!(matches!(
        SqliteWriter::open(prepared, bounded, Gate(Rc::default()), uninterrupted()),
        Err(Error::InvalidImage)
    ));
    assert!(!destination.exists());
    let destination = root.path().join("invalid-options");
    let prepared = prepare(&destination, &[]);
    bounded.cache_bytes = 0;
    assert!(matches!(
        SqliteWriter::open(prepared, bounded, Gate(Rc::default()), uninterrupted()),
        Err(Error::InvalidLimits)
    ));
    assert!(!destination.exists());
    let mut large = limits();
    large.max_database_pages = (10 * 1024 * 1024 * 1024_u64 / PAGE_SIZE as u64) as u32;
    let writer = create_writer(
        &root.path().join("ten-gib-quota"),
        vec![],
        large,
        Gate(Rc::default()),
    )
    .unwrap();
    assert_eq!(
        writer
            .connection
            .query_row::<u32, _, _>("PRAGMA max_page_count", [], |row| row.get(0))
            .unwrap(),
        large.max_database_pages
    );
}

#[test]
fn actual_dirty_cache_spills_fail_before_commit_capture_or_authority() {
    for limit_dirty_instead_of_cache in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let plan = Rc::new(RefCell::new(Plan::default()));
        let mut bounded = limits();
        if limit_dirty_instead_of_cache {
            bounded.max_changed_pages = 4;
        } else {
            bounded.cache_bytes = (4 * PAGE_SIZE) as u64;
        }
        let mut writer = create_writer(
            &root.path().join("worker"),
            vec![],
            bounded,
            Gate(plan.clone()),
        )
        .unwrap();
        writer
            .execute(&[statement("CREATE TABLE x(value BLOB)")], uninterrupted())
            .unwrap();
        assert_eq!(
            writer
                .connection
                .query_row::<i64, _, _>("PRAGMA cache_size", [], |row| row.get(0))
                .unwrap(),
            -16
        );
        let error = writer
            .execute(
                &[statement("INSERT INTO x VALUES(randomblob(262144))")],
                uninterrupted(),
            )
            .unwrap_err();
        assert!(
            matches!(error, Error::Sqlite(ref e) if e.sqlite_error().unwrap().extended_code == ffi::SQLITE_TOOBIG),
            "{error:?}"
        );
        assert_eq!(
            plan.borrow().writes.len(),
            1,
            "no proposal for the rejected spill"
        );
        assert!(
            writer.state.borrow().attempt.is_none(),
            "the spill was rejected during SQL, before final capture was armed"
        );
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert_eq!(
            writer
                .connection
                .query_row::<u32, _, _>("SELECT count(*) FROM x", [], |r| r.get(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn cold_structure_scan_uses_the_original_deadline_at_every_reached_boundary() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let native = libsql_sys::rusqlite::Connection::open(&source).unwrap();
    native.execute_batch("CREATE TABLE x(n INTEGER PRIMARY KEY, value BLOB); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000) INSERT INTO x SELECT x, randomblob(64) FROM n").unwrap();
    drop(native);
    let bytes = std::fs::read(source).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let writer = SqliteWriter::open(
        prepare(&root.path().join("count"), &bytes),
        limits(),
        Gate(Rc::default()),
        Arc::new(move || {
            observed.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    let total = count.load(Ordering::Relaxed);
    assert!(
        total > 2,
        "real integrity_check must execute the native progress callback"
    );
    drop(writer);
    assert!(!root.path().join("count").exists());
    for stop in 0..total {
        let count = AtomicUsize::new(0);
        let destination = root.path().join(format!("stop-{stop}"));
        let plan = Rc::new(RefCell::new(Plan::default()));
        let result = SqliteWriter::open(
            prepare(&destination, &bytes),
            limits(),
            Gate(plan.clone()),
            Arc::new(move || count.fetch_add(1, Ordering::Relaxed) >= stop),
        );
        assert!(result.is_err(), "stop {stop}/{total}");
        assert!(!destination.exists());
        assert!(plan.borrow().writes.is_empty());
    }
}

#[test]
fn write_deadlines_fail_closed_before_and_after_authority_acceptance() {
    let statements = [
        statement("CREATE TABLE x(n)"),
        statement("INSERT INTO x VALUES(1) RETURNING n"),
    ];
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let (_root, mut writer, _plan) = setup();
    writer
        .execute(
            &statements,
            Arc::new(move || {
                observed.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
    let total = count.load(Ordering::Relaxed);
    assert!(total > 10);
    let mut accepted_failures = 0;
    for stop in 0..total {
        let (_root, mut writer, plan) = setup();
        let count = AtomicUsize::new(0);
        let result = writer.execute(
            &statements,
            Arc::new(move || count.fetch_add(1, Ordering::Relaxed) >= stop),
        );
        assert!(result.is_err(), "stop {stop}/{total}");
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        if plan.borrow().writes.is_empty() {
            assert!(!matches!(result, Err(Error::CommittedButUnavailable)));
        } else {
            accepted_failures += 1;
            assert!(
                matches!(result, Err(Error::CommittedButUnavailable)),
                "stop {stop}: {result:?}"
            );
        }
    }
    assert!(accepted_failures >= 3);
    for after in [0, 3] {
        let (_root, mut writer, plan) = setup();
        let count = AtomicUsize::new(0);
        let guard = Arc::new(move || {
            assert!(count.fetch_add(1, Ordering::Relaxed) < after);
            false
        });
        assert!(writer.execute(&[statement("SELECT 1")], guard).is_err());
        assert!(writer.is_stopped());
        assert!(plan.borrow().writes.is_empty());
    }
}

#[test]
fn warm_transactions_checkpoint_without_new_proposals_and_restore_exact_rows() {
    let (root, mut writer, plan) = setup();
    writer
        .execute(
            &[statement(
                "CREATE TABLE x(n INTEGER PRIMARY KEY, value BLOB)",
            )],
            uninterrupted(),
        )
        .unwrap();
    for n in 0..12 {
        writer
            .execute(
                &[Statement {
                    sql: "INSERT INTO x VALUES(?1,?2)".into(),
                    parameters: vec![Value::Integer(n), Value::Blob(vec![n as u8; 32 * 1024])],
                }],
                uninterrupted(),
            )
            .unwrap();
        assert_eq!(plan.borrow().writes.len(), n as usize + 2);
        assert_eq!(
            std::fs::metadata(root.path().join("worker/database.sqlite-wal"))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            std::fs::metadata(root.path().join("worker/database.sqlite"))
                .unwrap()
                .len(),
            u64::from(writer.page_count()) * PAGE_SIZE as u64
        );
    }
    let result = writer
        .query(
            &[statement(
                "SELECT n, length(value), hex(substr(value,1,1)) FROM x ORDER BY n",
            )],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(result.statements[0].rows.len(), 12);
    assert_eq!(
        plan.borrow().writes.len(),
        13,
        "read and checkpoint never call the gate"
    );
    let authoritative = captured_image(&plan.borrow());
    assert_eq!(
        std::fs::read(root.path().join("worker/database.sqlite")).unwrap(),
        authoritative
    );
    drop(writer);
    assert!(!root.path().join("worker").exists());
    let mut recovered = create_writer(
        &root.path().join("recovered"),
        authoritative,
        limits(),
        Gate(Rc::default()),
    )
    .unwrap();
    let restored = recovered
        .query(
            &[statement(
                "SELECT n, length(value), hex(substr(value,1,1)) FROM x ORDER BY n",
            )],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(restored, result);
}

#[test]
fn busy_native_checkpoint_reports_committed_but_unavailable_and_stops() {
    let (root, mut writer, plan) = setup();
    writer
        .execute(&[statement("CREATE TABLE x(n)")], uninterrupted())
        .unwrap();
    let observer =
        libsql_sys::rusqlite::Connection::open(root.path().join("worker/database.sqlite")).unwrap();
    observer.execute_batch("BEGIN DEFERRED").unwrap();
    assert_eq!(
        observer
            .query_row::<u32, _, _>("SELECT count(*) FROM x", [], |row| row.get(0))
            .unwrap(),
        0
    );
    assert!(matches!(
        writer.execute(
            &[statement("INSERT INTO x VALUES(7) RETURNING n")],
            uninterrupted()
        ),
        Err(Error::CommittedButUnavailable)
    ));
    assert_eq!(plan.borrow().writes.len(), 2);
    assert!(writer.is_stopped());
    assert!(writer.connection.is_autocommit());
    assert_eq!(
        writer
            .connection
            .query_row::<u32, _, _>("SELECT count(*) FROM x", [], |row| row.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        observer
            .query_row::<u32, _, _>("SELECT count(*) FROM x", [], |row| row.get(0))
            .unwrap(),
        0
    );
    observer.execute_batch("ROLLBACK").unwrap();
    assert!(matches!(
        writer.execute(&[statement("SELECT 1")], uninterrupted()),
        Err(Error::Stopped)
    ));
}

#[test]
fn authority_sees_the_complete_normalized_cross_boundary_batch_before_acceptance() {
    let lock = image::LOCK_BYTE_PAGE;
    for changed_limit in [1, 2] {
        let mut bounded = limits();
        bounded.max_database_pages = lock + 1;
        bounded.max_changed_pages = changed_limit;
        let plan = Rc::new(RefCell::new(Plan::default()));
        let mut state = GateState::new(Gate(plan.clone()), bounded);
        state.attempt = Some(Attempt {
            base_pages: lock - 1,
            result: empty_result(),
        });
        let native = PageBatch {
            size_after: lock + 1,
            pages: vec![PageChange {
                number: lock + 1,
                bytes: vec![9; PAGE_SIZE],
            }],
        };
        assert_eq!(state.decide_caught(native), changed_limit == 2);
        if changed_limit == 1 {
            assert!(matches!(
                state.take_error(Error::Stopped),
                Error::InvalidImage
            ));
            assert!(plan.borrow().writes.is_empty());
        } else {
            assert!(
                matches!(state.resolution, Some(Resolution::Accepted(pages)) if pages == lock + 1)
            );
            let writes = &plan.borrow().writes;
            assert_eq!(writes.len(), 1);
            assert_eq!(
                writes[0]
                    .0
                    .pages
                    .iter()
                    .map(|p| p.number)
                    .collect::<Vec<_>>(),
                [lock, lock + 1]
            );
            assert_eq!(writes[0].0.pages[0].bytes, vec![0; PAGE_SIZE]);
            assert_eq!(writes[0].0.pages[1].bytes, vec![9; PAGE_SIZE]);
            assert_eq!(writes[0].1, empty_result());
        }
    }
}
