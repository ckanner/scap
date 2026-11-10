use super::*;
use std::collections::VecDeque;

use libsql_sys::ffi;
use libsql_sys::rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use libsql_sys::rusqlite::types::ValueRef;
use scap_sql::{ResultMemoryBudget, SqlError, Value};

#[path = "capacity_tests.rs"]
mod capacity_tests;
#[path = "image_tests.rs"]
mod image_tests;
#[path = "query_tests.rs"]
mod query_tests;
#[path = "result_memory_tests.rs"]
mod result_memory_tests;

#[derive(Default)]
struct Plan {
    decisions: VecDeque<GateDecision>,
    writes: Vec<(PageBatch, Vec<u8>)>,
    panic_publish: bool,
}

struct Gate(Rc<RefCell<Plan>>);

impl CommitGate for Gate {
    fn publish(&mut self, batch: &PageBatch, result: &[u8]) -> GateDecision {
        let mut plan = self.0.borrow_mut();
        plan.writes.push((batch.clone(), result.to_vec()));
        assert!(!plan.panic_publish, "injected authority panic");
        plan.decisions.pop_front().unwrap_or(GateDecision::Accepted)
    }
}

fn limits() -> WriterLimits {
    WriterLimits {
        sql: SqlLimits {
            max_statements: 16,
            max_sql_bytes: 1_048_576,
            max_parameters: 32,
            max_columns: 32,
            max_rows: 1024,
            max_result_bytes: 1_048_576,
            max_value_bytes: 65_536,
        },
        result_memory_bytes: 4 * 1024 * 1024,
        max_vm_steps: 1_000_000,
        max_changed_pages: 1024,
        max_database_pages: 4096,
        cache_bytes: 8 * 1024 * 1024,
    }
}

fn uninterrupted() -> ReadInterrupt {
    Arc::new(|| false)
}

#[cfg(target_os = "linux")]
#[test]
fn temporary_directory_native_admission_uses_isolated_process_environment() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let root = tempfile::tempdir().unwrap();
    let local = root.path().as_os_str();
    let missing = root.path().join("absent");
    let alias = root.path().join("network-like-alias");
    symlink("/proc", &alias).unwrap();
    let cases = [
        ("allowed", local, local, root.path(), "allow"),
        (
            "selected-unsupported",
            std::ffi::OsStr::new("/proc"),
            local,
            root.path(),
            "deny",
        ),
        (
            "unused-fallback-unsupported",
            local,
            std::ffi::OsStr::new("/proc"),
            root.path(),
            "deny",
        ),
        (
            "symlink-unsupported",
            alias.as_os_str(),
            local,
            root.path(),
            "deny",
        ),
        (
            "cwd-unsupported",
            local,
            local,
            std::path::Path::new("/proc"),
            "deny",
        ),
        (
            "missing-candidate",
            missing.as_os_str(),
            local,
            root.path(),
            "allow",
        ),
        (
            "empty-candidate",
            std::ffi::OsStr::new(""),
            local,
            root.path(),
            "allow",
        ),
        ("host-global-override", local, local, root.path(), "global"),
    ];
    for (name, sqlite_tmp, tmp, cwd, expected) in cases {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::temporary_directory_native_child",
                "--nocapture",
            ])
            .env("SCAP_SQLITE_TEMP_CHILD", expected)
            .env("SCAP_SQLITE_TEMP_ROOT", root.path())
            .env("SQLITE_TMPDIR", sqlite_tmp)
            .env("TMPDIR", tmp)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn temporary_directory_native_child() {
    let Some(expected) = std::env::var_os("SCAP_SQLITE_TEMP_CHILD") else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os("SCAP_SQLITE_TEMP_ROOT").unwrap());
    if expected == "global" {
        // This exact child is a fresh process running one test. Set the host
        // override before any SCAP/native worker exists; never mutate the
        // parent test process's shared SQLite state or environment.
        let host = libsql_sys::rusqlite::Connection::open_in_memory().unwrap();
        host.pragma_update(None, "temp_store_directory", root.to_str().unwrap())
            .unwrap();
    }
    let directory = tempfile::tempdir_in(root).unwrap();
    let plan = Rc::new(RefCell::new(Plan::default()));
    let result = create_writer(
        &directory.path().join("database"),
        Vec::new(),
        limits(),
        Gate(plan.clone()),
    );
    if expected == "allow" {
        let mut writer = result.unwrap();
        writer
            .execute(
                &[statement("CREATE TABLE temp_checked (id INTEGER)")],
                uninterrupted(),
            )
            .unwrap();
        assert_eq!(plan.borrow().writes.len(), 1);
    } else {
        assert!(expected == "deny" || expected == "global");
        assert!(
            matches!(result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::Unsupported)
        );
        assert!(plan.borrow().writes.is_empty());
    }
}

fn create_writer<G: CommitGate + 'static>(
    directory: &std::path::Path,
    bytes: Vec<u8>,
    limits: WriterLimits,
    gate: G,
) -> Result<SqliteWriter<G>, Error> {
    sql::validate_limits(limits)?;
    if !bytes.len().is_multiple_of(PAGE_SIZE) {
        return Err(Error::InvalidImage);
    }
    let mut builder = ImageBuilder::create_new(
        directory,
        (bytes.len() / PAGE_SIZE) as u32,
        limits.max_database_pages,
    )?;
    if !bytes.is_empty() {
        builder.append_pages(1, &bytes)?;
    }
    SqliteWriter::open(builder.finish()?, limits, gate, uninterrupted())
}

// The test authority reconstructs small captured snapshots independently. The
// production engine holds only a page count and never clones a whole image.
fn captured_image(plan: &Plan) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (batch, _) in &plan.writes {
        bytes.resize(batch.size_after as usize * PAGE_SIZE, 0);
        for page in &batch.pages {
            let offset = (page.number as usize - 1) * PAGE_SIZE;
            bytes[offset..offset + PAGE_SIZE].copy_from_slice(&page.bytes);
        }
    }
    bytes
}

fn image() -> Vec<u8> {
    Vec::new()
}

fn statement(sql: &str) -> Statement {
    Statement {
        sql: sql.to_owned(),
        parameters: Vec::new(),
    }
}

fn setup() -> (tempfile::TempDir, SqliteWriter<Gate>, Rc<RefCell<Plan>>) {
    let root = tempfile::tempdir().unwrap();
    let plan = Rc::new(RefCell::new(Plan::default()));
    let writer = create_writer(
        &root.path().join("worker"),
        image(),
        limits(),
        Gate(plan.clone()),
    )
    .unwrap();
    (root, writer, plan)
}

fn empty_result() -> Vec<u8> {
    scap_sql::encode_result(&TransactionResult { statements: vec![] }, limits().sql).unwrap()
}

#[test]
fn unknown_rejection_and_authority_panics_never_publish_native_pages() {
    for mode in 0..3 {
        let (_root, mut writer, plan) = setup();
        match mode {
            0 => plan.borrow_mut().decisions.push_back(GateDecision::Unknown),
            1 => plan
                .borrow_mut()
                .decisions
                .push_back(GateDecision::Rejected),
            _ => plan.borrow_mut().panic_publish = true,
        }
        let error = writer
            .execute(&[statement("CREATE TABLE x(n)")], uninterrupted())
            .unwrap_err();
        if mode == 1 {
            assert!(matches!(error, Error::Rejected));
        } else {
            assert!(matches!(error, Error::OutcomeUnknown));
        }
        assert!(writer.is_stopped());
        assert_eq!(writer.page_count(), 0);
        let count: u64 = writer
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='x'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert!(matches!(
            writer.execute(&[statement("SELECT 1")], uninterrupted()),
            Err(Error::Stopped)
        ));
    }
}

#[test]
fn final_native_failure_cannot_undo_authoritative_acceptance() {
    let (_root, mut writer, _plan) = setup();
    writer.stopped = true;
    writer.state.borrow_mut().resolution = Some(Resolution::Accepted(0));
    assert!(matches!(
        writer.finish(Err(Error::InvalidSql), &uninterrupted()),
        Err(Error::CommittedButUnavailable)
    ));
    assert!(writer.is_stopped());
    assert!(matches!(
        writer.finish(Ok(()), &uninterrupted()),
        Err(Error::OutcomeUnknown)
    ));
    assert!(matches!(
        writer.finish(Err(Error::InvalidSql), &uninterrupted()),
        Err(Error::InvalidSql)
    ));
    writer.state.borrow_mut().attempt = Some(Attempt {
        base_pages: 0,
        result: vec![255],
    });
    writer.state.borrow_mut().resolution = Some(Resolution::Accepted(0));
    assert!(matches!(
        writer.finish(Ok(()), &uninterrupted()),
        Err(Error::CommittedButUnavailable)
    ));
    assert!(writer.is_stopped());
}

#[test]
fn unarmed_or_repeated_gate_calls_cannot_authorize_publication() {
    let plan = Rc::new(RefCell::new(Plan::default()));
    let mut state = GateState::new(Gate(plan.clone()), limits());
    let noop = PageBatch {
        size_after: 0,
        pages: vec![],
    };
    assert!(!state.decide_caught(noop.clone()));
    assert!(matches!(
        state.take_error(Error::Stopped),
        Error::InvalidSql
    ));
    state.attempt = Some(Attempt {
        base_pages: 0,
        result: empty_result(),
    });
    assert!(!state.decide_caught(PageBatch {
        size_after: 1,
        pages: vec![]
    }));
    assert!(matches!(
        state.take_error(Error::Stopped),
        Error::InvalidImage
    ));
    assert!(state.decide_caught(noop.clone()));
    assert!(!state.decide_caught(noop));
    assert!(matches!(
        state.take_error(Error::Stopped),
        Error::CommittedButUnavailable
    ));
    assert_eq!(plan.borrow().writes.len(), 1);
    assert!(matches!(state.take_error(Error::Stopped), Error::Stopped));
}

#[test]
fn a_closure_gate_sees_physical_facts_before_independent_readers_do() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("cache");
    let observer_path = directory.join("database.sqlite");
    let seen = Rc::new(RefCell::new(Vec::new()));
    let captured = seen.clone();
    let mut writer = create_writer(
        &directory,
        vec![],
        limits(),
        move |batch: &PageBatch, encoded: &[u8]| {
            assert_eq!(batch.size_after, 2);
            assert!(!batch.pages.is_empty());
            let result = scap_sql::decode_result(encoded, limits().sql).unwrap();
            assert_eq!(result.statements[1].rows.len(), 1);
            let reader = libsql_sys::rusqlite::Connection::open(&observer_path).unwrap();
            let count: u32 = reader
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name='x'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 0,
                "the native database must still expose the original snapshot"
            );
            captured.borrow_mut().push(result);
            GateDecision::Accepted
        },
    )
    .unwrap();
    let result = writer
        .execute(
            &[
                statement("CREATE TABLE x(n)"),
                statement("INSERT INTO x VALUES(randomblob(8)) RETURNING n"),
            ],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(seen.borrow()[0], result);
    let reader = libsql_sys::rusqlite::Connection::open(directory.join("database.sqlite")).unwrap();
    let count: u32 = reader
        .query_row("SELECT count(*) FROM x", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn invalid_restored_bytes_are_rejected_before_native_work() {
    let root = tempfile::tempdir().unwrap();
    for (n, bytes) in [vec![1], vec![0; PAGE_SIZE], vec![0; 2 * PAGE_SIZE]]
        .into_iter()
        .enumerate()
    {
        let path = root.path().join(format!("bad-{n}"));
        assert!(matches!(
            create_writer(&path, bytes, limits(), Gate(Rc::default())),
            Err(Error::InvalidImage)
        ));
        assert!(!path.exists());
    }
    let mut bad_structure = vec![0; PAGE_SIZE];
    bad_structure[..16].copy_from_slice(b"SQLite format 3\0");
    bad_structure[16] = 0x10;
    assert!(create_writer(
        &root.path().join("bad-structure"),
        bad_structure,
        limits(),
        Gate(Rc::default())
    )
    .is_err());
    for mode in 0..3 {
        let mut invalid = limits();
        match mode {
            0 => invalid.max_database_pages = 0,
            1 => invalid.max_database_pages = u32::MAX,
            _ => invalid.cache_bytes = 0,
        }
        assert!(matches!(
            sql::validate_limits(invalid),
            Err(Error::InvalidLimits)
        ));
    }
}

#[test]
fn native_open_rejects_a_restored_database_above_the_configured_page_budget() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("too-large.sqlite");
    let plain = libsql_sys::rusqlite::Connection::open(&path).unwrap();
    plain.execute_batch("CREATE TABLE x(n)").unwrap();
    drop(plain);
    let state = Rc::new(RefCell::new(GateState::new(Gate(Rc::default()), limits())));
    assert!(matches!(
        sql::open(&path, GateWal::new(state), limits(), 1, &uninterrupted()),
        Err(Error::InvalidImage)
    ));
}

#[test]
fn native_batch_buffers_typed_rows_and_owns_the_physical_baseline() {
    let (root, mut writer, plan) = setup();
    let _created = writer
        .execute(
            &[statement(
                "CREATE TABLE items(id INTEGER PRIMARY KEY, value BLOB)",
            )],
            uninterrupted(),
        )
        .unwrap();
    assert!(!writer.is_stopped());
    assert_eq!(writer.page_count(), 2);
    let executed = writer
        .execute(
            &[
                Statement {
                    sql: "INSERT INTO items(value) VALUES(?1) RETURNING id,value".into(),
                    parameters: vec![Value::Blob(vec![0, 255, 1])],
                },
                Statement {
                    sql: "SELECT ?1,?2,?3,?4,?5".into(),
                    parameters: vec![
                        Value::Null,
                        Value::Integer(i64::MAX),
                        Value::Real(1.25),
                        Value::Text("中文".into()),
                        Value::Blob(vec![8]),
                    ],
                },
            ],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(
        executed.statements[0].rows[0],
        vec![Value::Integer(1), Value::Blob(vec![0, 255, 1])]
    );
    assert_eq!(executed.statements[0].affected_rows, 1);
    assert_eq!(executed.statements[1].affected_rows, 0);
    assert_eq!(
        executed.statements[1].rows[0][3],
        Value::Text("中文".into())
    );
    assert_eq!(plan.borrow().writes.len(), 2);
    assert_eq!(
        plan.borrow().writes[1].1,
        scap_sql::encode_result(&executed, limits().sql).unwrap()
    );
    let recovered = captured_image(&plan.borrow());
    drop(writer);
    let mut second =
        create_writer(&root.path().join("next"), recovered, limits(), Gate(plan)).unwrap();
    let read = second
        .execute(&[statement("SELECT value FROM items")], uninterrupted())
        .unwrap();
    assert_eq!(
        read.statements[0].rows[0],
        vec![Value::Blob(vec![0, 255, 1])]
    );
}

#[test]
fn no_op_and_read_only_transactions_require_durable_decisions() {
    let (_root, mut writer, plan) = setup();
    let first = writer
        .execute(&[statement("SELECT 7")], uninterrupted())
        .unwrap();
    assert_eq!(first.statements[0].rows, vec![vec![Value::Integer(7)]]);
    assert_eq!(plan.borrow().writes.len(), 1);
    assert_eq!(writer.page_count(), 0);
    assert_eq!(plan.borrow().writes.len(), 1);
    plan.borrow_mut().decisions.push_back(GateDecision::Unknown);
    assert!(matches!(
        writer.execute(&[statement("SELECT 8")], uninterrupted()),
        Err(Error::OutcomeUnknown)
    ));
    assert!(writer.is_stopped());
    assert!(matches!(
        writer.execute(&[statement("SELECT 8")], uninterrupted()),
        Err(Error::Stopped)
    ));
}

#[test]
fn input_and_sql_failures_stop_and_rollback_the_whole_attempt() {
    for sql in [
        "SELECT missing",
        "SELECT 1; INVALID SQL",
        "-- empty only",
        "SELECT 1; SELECT 2",
        "BEGIN",
        "COMMIT",
        "SAVEPOINT s",
        "PRAGMA cache_spill=ON",
        "ATTACH ':memory:' AS second",
        "CREATE TEMP TABLE temp(n)",
        "SELECT load_extension('x')",
    ] {
        let (_root, mut writer, plan) = setup();
        assert!(
            writer.execute(&[statement(sql)], uninterrupted()).is_err(),
            "{sql}"
        );
        assert!(writer.is_stopped());
        assert!(plan.borrow().writes.is_empty());
    }
    let (_root, mut writer, plan) = setup();
    assert!(matches!(
        writer.execute(&[], uninterrupted()),
        Err(Error::Sql(_))
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    assert!(writer
        .execute(
            &[
                statement("CREATE TABLE x(n UNIQUE)"),
                statement("INSERT INTO x VALUES(1),(1)")
            ],
            uninterrupted()
        )
        .is_err());
    assert!(plan.borrow().writes.is_empty());
    let count: u64 = writer
        .connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='x'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let (_root, mut writer, plan) = setup();
    assert!(writer
        .execute(&[statement("SELECT ?1")], uninterrupted())
        .is_err());
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(writer
        .execute(&[statement("SELECT 1")], uninterrupted())
        .is_err());
    assert!(plan.borrow().writes.is_empty());
}

#[test]
fn encoding_failure_after_sql_rolls_back_without_publication_or_replay() {
    for refused in [
        SqlError::ResourceExhausted,
        SqlError::Limit,
        SqlError::Invalid,
        SqlError::Malformed,
    ] {
        let (_root, mut writer, plan) = setup();
        let mut attempts = 0;
        let outcome = writer.execute_with_encoder(
            &[
                statement("CREATE TABLE encoding_attempt(n INTEGER PRIMARY KEY)"),
                statement("INSERT INTO encoding_attempt VALUES(7) RETURNING n"),
            ],
            uninterrupted(),
            &mut |result, configuration| {
                attempts += 1;
                assert_eq!(result.statements[1].rows, vec![vec![Value::Integer(7)]]);
                assert_eq!(result.statements[1].affected_rows, 1);
                assert_eq!(result.statements[1].last_insert_rowid, 7);
                // SQL really produced a valid retained result; the failure is
                // deliberately at its one local encoding boundary, before CAS.
                scap_sql::plan_result(result, configuration).unwrap();
                Err(refused)
            },
        );
        assert_eq!(attempts, 1);
        match refused {
            SqlError::ResourceExhausted => {
                assert!(matches!(outcome, Err(Error::ResourceExhausted)));
            }
            other => assert!(matches!(outcome, Err(Error::Sql(error)) if error == other)),
        }
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert!(writer.state.borrow().attempt.is_none());
        assert!(writer.state.borrow().resolution.is_none());
        assert!(plan.borrow().writes.is_empty());
        let tables: u64 = writer
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='encoding_attempt'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "the complete native transaction was rolled back");
        assert!(matches!(
            writer.execute_with_encoder(
                &[statement("SELECT 1")],
                uninterrupted(),
                &mut |_, _| panic!("a stopped attempt must not execute or encode again"),
            ),
            Err(Error::Stopped)
        ));
        assert_eq!(attempts, 1);
        assert!(plan.borrow().writes.is_empty());
    }
}

#[test]
fn read_validation_counts_the_complete_wire_without_publishing() {
    // SCAPRES1 header12 + column-count4 + name-length4 + x1 + row-count4
    // + NULL tag1 + affected_rows8 + last_insert_rowid8 = 42 bytes.
    for maximum in [41, 42] {
        let (_root, mut writer, plan) = setup();
        writer.limits.sql.max_result_bytes = maximum;
        let result = writer.query(&[statement("SELECT NULL AS x")], uninterrupted());
        if maximum == 41 {
            assert!(matches!(result, Err(Error::Sql(SqlError::Limit))));
            assert!(writer.is_stopped());
        } else {
            let result = result.unwrap();
            assert_eq!(result.statements[0].columns, ["x"]);
            assert_eq!(result.statements[0].rows, vec![vec![Value::Null]]);
            assert_eq!(result.statements[0].affected_rows, 0);
            assert_eq!(result.statements[0].last_insert_rowid, 0);
            assert!(!writer.is_stopped());
        }
        assert!(plan.borrow().writes.is_empty());
        assert!(writer.connection.is_autocommit());
        assert_eq!(writer.page_count(), 0);
    }
}

#[test]
fn result_limits_and_vm_budget_prevent_unbounded_buffering() {
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_columns = 1;
    assert!(matches!(
        writer.execute(&[statement("SELECT 1,2")], uninterrupted()),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_value_bytes = 1;
    assert!(matches!(
        writer.execute(&[statement("SELECT 1 AS long_name")], uninterrupted()),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_result_bytes = 12;
    assert!(matches!(
        writer.execute(&[statement("SELECT 1 AS very_long_name")], uninterrupted()),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_rows = 1;
    assert!(matches!(
        writer.execute(&[statement("SELECT 1 UNION ALL SELECT 2")], uninterrupted()),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_value_bytes = 2;
    assert!(matches!(
        writer.execute(&[statement("SELECT 'long value' AS x")], uninterrupted()),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_result_bytes = 12;
    assert!(matches!(
        writer.execute(&[statement("SELECT NULL AS x")], uninterrupted()),
        Err(Error::Sql(SqlError::Limit))
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.max_vm_steps = 1;
    assert!(matches!(
        writer.execute(&[statement("SELECT 1")], uninterrupted()),
        Err(Error::Sqlite(_))
    ));
    assert!(plan.borrow().writes.is_empty());
}

#[test]
fn direct_affected_rows_exclude_trigger_changes_and_stale_counters() {
    let (_root, mut writer, _plan) = setup();
    let completed = writer
        .execute(&[
            statement("CREATE TABLE x(n)"),
            statement("CREATE TABLE audit(n)"),
            statement(
                "CREATE TRIGGER tr AFTER INSERT ON x BEGIN INSERT INTO audit VALUES(new.n); END",
            ),
            statement("INSERT INTO x VALUES(1),(2)"),
            statement("SELECT * FROM x"),
            statement("CREATE TABLE other(n)"),
            statement("UPDATE x SET n=9 WHERE n=8"),
        ], uninterrupted())
        .unwrap();
    let affected: Vec<_> = completed
        .statements
        .iter()
        .map(|result| result.affected_rows)
        .collect();
    assert_eq!(affected, vec![0, 0, 0, 2, 0, 0, 0]);
}

#[test]
fn fresh_directory_and_image_validation_reject_reuse_and_bad_inputs() {
    let root = tempfile::tempdir().unwrap();
    let existing = root.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("database.sqlite-wal"), b"old").unwrap();
    assert!(matches!(
        create_writer(&existing, image(), limits(), Gate(Rc::default())),
        Err(Error::Io(_))
    ));
    assert_eq!(
        std::fs::read(existing.join("database.sqlite-wal")).unwrap(),
        b"old"
    );
    assert!(matches!(
        create_writer(
            &root.path().join("missing/worker"),
            image(),
            limits(),
            Gate(Rc::default())
        ),
        Err(Error::Io(_))
    ));
    let path = root.path().join("not-sqlite");
    std::fs::write(&path, vec![1; PAGE_SIZE]).unwrap();
    let state = Rc::new(RefCell::new(GateState::new(Gate(Rc::default()), limits())));
    assert!(sql::open(&path, GateWal::new(state), limits(), 4096, &uninterrupted()).is_err());
    let db = libsql_sys::rusqlite::Connection::open(root.path().join("wide")).unwrap();
    db.execute_batch("PRAGMA page_size=8192; CREATE TABLE x(n)")
        .unwrap();
    assert!(matches!(
        sql::configure(&db, limits(), 4096),
        Err(Error::InvalidImage)
    ));
    let too_large = libsql_sys::rusqlite::Connection::open(root.path().join("large")).unwrap();
    too_large.execute_batch("CREATE TABLE x(n)").unwrap();
    assert!(matches!(
        sql::configure(&too_large, limits(), 1),
        Err(Error::InvalidImage)
    ));
}

#[test]
fn native_limit_configuration_is_bounded_and_checked() {
    let mut invalid = limits();
    invalid.sql.max_rows = 0;
    assert!(matches!(sql::validate_limits(invalid), Err(Error::Sql(_))));
    let mut invalid = limits();
    invalid.max_vm_steps = 0;
    assert!(matches!(
        sql::validate_limits(invalid),
        Err(Error::InvalidLimits)
    ));
    let mut invalid = limits();
    invalid.max_changed_pages = 0;
    assert!(matches!(
        sql::validate_limits(invalid),
        Err(Error::InvalidLimits)
    ));
    let mut invalid = limits();
    invalid.sql.max_value_bytes = u32::MAX;
    assert!(matches!(
        sql::validate_limits(invalid),
        Err(Error::InvalidLimits)
    ));
    assert!(sql::validate_limits(limits()).is_ok());
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        create_writer(
            &root.path().join("invalid"),
            image(),
            invalid,
            Gate(Rc::default())
        ),
        Err(Error::InvalidLimits)
    ));
    assert!(!root.path().join("invalid").exists());
}

#[test]
fn mode_and_capture_validate_before_copying_native_pages() {
    assert!(gate::validate_mode(4096, true).is_ok());
    assert_eq!(
        gate::validate_mode(8192, true).unwrap_err().extended_code,
        ffi::SQLITE_MISMATCH
    );
    assert_eq!(
        gate::validate_mode(4096, false).unwrap_err().extended_code,
        ffi::SQLITE_TOOBIG
    );
    let page = [3; PAGE_SIZE];
    for (size, number, bytes) in [(1, 0, &page[..]), (1, 2, &page[..]), (1, 1, &page[..1])] {
        assert_eq!(
            gate::collect(size, &mut [(number, bytes)].into_iter(), 2)
                .unwrap_err()
                .extended_code,
            ffi::SQLITE_CORRUPT
        );
    }
    assert_eq!(
        gate::collect(1, &mut [(1, &page[..]); 2].into_iter(), 1)
            .unwrap_err()
            .extended_code,
        ffi::SQLITE_TOOBIG
    );
    let collected = gate::collect(2, &mut [(2, &page[..]), (1, &page[..])].into_iter(), 2).unwrap();
    assert_eq!(collected.pages[0].number, 2);
    assert_eq!(collected.pages[1].number, 1);
    assert_eq!(collected.pages[0].bytes[0], 3);
    assert!(gate::collect(0, &mut [].into_iter(), 2)
        .unwrap()
        .pages
        .is_empty());
}

#[test]
fn ffi_boundary_catches_panics_and_keeps_native_failures() {
    assert_eq!(gate::ffi_guard(&mut || Ok(7)), Ok(7));
    let failure =
        gate::ffi_guard(&mut || Err(libsql_sys::wal::Error::new(ffi::SQLITE_IOERR_FSYNC)));
    assert_eq!(failure.unwrap_err().extended_code, ffi::SQLITE_IOERR_FSYNC);
    let panic = gate::ffi_guard(&mut || panic!("native adapter panic"));
    assert_eq!(panic.unwrap_err().extended_code, ffi::SQLITE_ABORT);
}

#[test]
fn authorizer_rejects_side_effect_surfaces_and_non_main_schemas() {
    let actions = [
        AuthAction::Select,
        AuthAction::CreateTable { table_name: "x" },
        AuthAction::CreateIndex {
            index_name: "i",
            table_name: "x",
        },
        AuthAction::CreateTrigger {
            trigger_name: "t",
            table_name: "x",
        },
        AuthAction::CreateView { view_name: "v" },
        AuthAction::Delete { table_name: "x" },
        AuthAction::DropIndex {
            index_name: "i",
            table_name: "x",
        },
        AuthAction::DropTable { table_name: "x" },
        AuthAction::DropTrigger {
            trigger_name: "t",
            table_name: "x",
        },
        AuthAction::DropView { view_name: "v" },
        AuthAction::Insert { table_name: "x" },
        AuthAction::Read {
            table_name: "x",
            column_name: "n",
        },
        AuthAction::Update {
            table_name: "x",
            column_name: "n",
        },
        AuthAction::AlterTable {
            database_name: "main",
            table_name: "x",
        },
        AuthAction::Reindex { index_name: "i" },
        AuthAction::Analyze { table_name: "x" },
        AuthAction::Recursive,
        AuthAction::Function {
            function_name: "randomblob",
        },
    ];
    for action in actions {
        assert_eq!(
            sql::authorize(AuthContext {
                action,
                database_name: Some("main"),
                accessor: None
            }),
            Authorization::Allow
        );
    }
    for database_name in [Some("other"), Some("temp")] {
        assert_eq!(
            sql::authorize(AuthContext {
                action: AuthAction::Select,
                database_name,
                accessor: None
            }),
            Authorization::Deny
        );
    }
    for function_name in [
        "LOAD_EXTENSION",
        "writefile",
        "readfile",
        "eval",
        "fts3_tokenizer",
        "sqlite_log",
        "unknown_extension",
    ] {
        assert_eq!(
            sql::authorize(AuthContext {
                action: AuthAction::Function { function_name },
                database_name: None,
                accessor: None
            }),
            Authorization::Deny
        );
    }
    assert_eq!(
        sql::authorize(AuthContext {
            action: AuthAction::Transaction {
                operation: TransactionOperation::Begin
            },
            database_name: None,
            accessor: None
        }),
        Authorization::Deny
    );
}

#[test]
fn value_copy_checks_lengths_budgets_and_utf8_before_allocating() {
    let memory = &mut ResultMemoryBudget::new(4096).unwrap();
    let cases = [
        (ValueRef::Null, Value::Null),
        (ValueRef::Integer(-1), Value::Integer(-1)),
        (ValueRef::Real(1.5), Value::Real(1.5)),
        (ValueRef::Text(b"x"), Value::Text("x".into())),
        (ValueRef::Blob(b"y"), Value::Blob(vec![b'y'])),
    ];
    for (input, expected) in cases {
        assert_eq!(
            sql::copy_value(input, &mut 100, limits(), memory).unwrap(),
            expected
        );
        assert!(matches!(
            sql::copy_value(input, &mut 0, limits(), memory),
            Err(Error::ResultLimit)
        ));
    }
    assert!(matches!(
        sql::copy_value(ValueRef::Text(&[255]), &mut 100, limits(), memory),
        Err(Error::InvalidSql)
    ));
    let mut small = limits();
    small.sql.max_value_bytes = 1;
    for value in [ValueRef::Text(b"xx"), ValueRef::Blob(b"yy")] {
        assert!(matches!(
            sql::copy_value(value, &mut 100, small, memory),
            Err(Error::ResultLimit)
        ));
    }
    let mut remaining = 2;
    assert!(sql::spend(&mut remaining, 2).is_ok());
    assert_eq!(remaining, 0);
    assert!(matches!(
        sql::spend(&mut remaining, 1),
        Err(Error::ResultLimit)
    ));
    for value in [
        ValueRef::Integer(1),
        ValueRef::Real(1.0),
        ValueRef::Text(b"x"),
        ValueRef::Blob(b"x"),
    ] {
        assert!(matches!(
            sql::copy_value(value, &mut 1, limits(), memory),
            Err(Error::ResultLimit)
        ));
    }
}

#[test]
fn vm_exhaustion_in_result_counters_never_reaches_authority() {
    let mut successes = 0;
    let mut failures = 0;
    for budget in 1..40 {
        let (_root, mut writer, plan) = setup();
        writer.limits.max_vm_steps = budget;
        match writer.execute(&[statement("SELECT 1")], uninterrupted()) {
            Ok(completed) => {
                successes += 1;
                assert_eq!(completed.statements[0].rows, vec![vec![Value::Integer(1)]]);
                assert_eq!(plan.borrow().writes.len(), 1);
            }
            Err(Error::Sqlite(_)) => {
                failures += 1;
                assert!(writer.is_stopped());
                assert!(plan.borrow().writes.is_empty());
            }
            other => panic!("unexpected budget outcome: {other:?}"),
        }
    }
    assert!(successes > 0 && failures > 0);
}

#[test]
fn native_gate_rejects_unsupported_pages_and_overlarge_capture() {
    use libsql_sys::wal::{Sqlite3WalManager, WalManager};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wide.sqlite");
    let plain = libsql_sys::rusqlite::Connection::open(&path).unwrap();
    plain
        .execute_batch("PRAGMA page_size=8192; CREATE TABLE x(n)")
        .unwrap();
    drop(plain);
    let state = Rc::new(RefCell::new(GateState::new(Gate(Rc::default()), limits())));
    let native = libsql_sys::Connection::open(
        &path,
        libsql_sys::rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        Sqlite3WalManager::default().wrap(GateWal::new(state)),
        libsql_sys::connection::NO_AUTOCHECKPOINT,
        None,
    )
    .unwrap();
    let error = native.execute("INSERT INTO x VALUES(1)", []).unwrap_err();
    assert_eq!(
        error.sqlite_error().unwrap().extended_code,
        ffi::SQLITE_MISMATCH
    );
    let (_root, mut writer, plan) = setup();
    writer.state.borrow_mut().limits.max_changed_pages = 1;
    assert!(matches!(
        writer.execute(&[statement("CREATE TABLE x(n)")], uninterrupted()),
        Err(Error::Sqlite(_))
    ));
    assert!(plan.borrow().writes.is_empty());
    assert!(writer.is_stopped());
}
