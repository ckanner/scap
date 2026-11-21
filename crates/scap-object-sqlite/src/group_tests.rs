use super::*;
use crate::group::{recoverable, GroupEffects};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn group_limits() -> GroupLimits {
    GroupLimits {
        max_members: 8,
        max_changed_pages: 64,
        max_result_bytes: 1024 * 1024,
    }
}

fn members(input: &[Vec<Statement>]) -> Vec<GroupMember<'_>> {
    input
        .iter()
        .map(|statements| GroupMember {
            statements,
            interrupt: uninterrupted(),
        })
        .collect()
}

fn sqls(input: &[&str]) -> Vec<Vec<Statement>> {
    input.iter().map(|sql| vec![statement(sql)]).collect()
}

fn flag(value: &Arc<AtomicBool>) -> ReadInterrupt {
    let value = value.clone();
    Arc::new(move || value.load(Ordering::Acquire))
}

fn invariant(run: &GroupRun, count: usize) {
    assert!(run.staged <= run.attempted && run.attempted <= count);
    assert!(run.attempted - run.staged <= 1);
    assert_eq!(run.member_error.is_some(), run.attempted != run.staged);
    if let Ok(results) = &run.outcome {
        assert_eq!(results.len(), run.staged);
    }
}

fn native_error(code: i32) -> Error {
    Error::Sqlite(libsql_sys::rusqlite::Error::SqliteFailure(
        ffi::Error::new(code),
        None,
    ))
}

#[test]
fn independent_native_commits_publish_once_and_preserve_each_original_result() {
    let (root, mut writer, ordinary) = setup();
    let input = sqls(&[
        "CREATE TABLE grouped(id INTEGER PRIMARY KEY, b BLOB)",
        "INSERT INTO grouped VALUES(1,randomblob(32)) RETURNING b",
        "SELECT b FROM grouped",
        "SELECT 37",
    ]);
    let mut captured = Plan::default();
    let mut calls = 0;
    let run = writer.execute_group(
        &members(&input),
        group_limits(),
        &mut |prefix: &[StagedTransaction]| {
            calls += 1;
            assert!(ordinary.borrow().writes.is_empty());
            assert_eq!(prefix.len(), 4);
            assert!(prefix[2].batch.pages.is_empty());
            assert!(prefix[3].batch.pages.is_empty());
            captured.writes = prefix
                .iter()
                .map(|member| (member.batch.clone(), member.result.clone()))
                .collect();
            GateDecision::Accepted
        },
        uninterrupted(),
    );
    invariant(&run, input.len());
    assert_eq!((run.attempted, run.staged, calls), (4, 4, 1));
    let bytes = run.outcome.unwrap();
    let result: Vec<_> = bytes
        .iter()
        .map(|bytes| scap_sql::decode_result(bytes, limits().sql).unwrap())
        .collect();
    assert_eq!(result[1].statements[0].rows, result[2].statements[0].rows);
    assert!(!writer.is_stopped());
    assert_eq!(
        writer.page_count(),
        captured.writes.last().unwrap().0.size_after
    );
    assert_eq!(
        writer
            .query(&[statement("SELECT b FROM grouped")], uninterrupted())
            .unwrap()
            .statements[0]
            .rows,
        result[1].statements[0].rows
    );
    // The same warm writer returns to the ordinary authority gate afterward.
    writer
        .execute(&[statement("SELECT 41")], uninterrupted())
        .unwrap();
    assert_eq!(ordinary.borrow().writes.len(), 1);
    let image = captured_image(&captured);
    drop(writer);
    let mut recovered = create_writer(
        &root.path().join("cold"),
        image,
        limits(),
        Gate(Rc::default()),
    )
    .unwrap();
    assert_eq!(
        recovered
            .query(&[statement("SELECT b FROM grouped")], uninterrupted())
            .unwrap()
            .statements[0]
            .rows,
        result[1].statements[0].rows
    );
}

#[test]
fn deferred_foreign_keys_end_at_each_member_commit_not_at_the_group_boundary() {
    let (_root, mut writer, ordinary) = setup();
    writer
        .execute(
            &[
                statement("CREATE TABLE parent(id INTEGER PRIMARY KEY)"),
                statement("CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)"),
            ],
            uninterrupted(),
        )
        .unwrap();
    let input = sqls(&[
        "INSERT INTO parent VALUES(1)",
        "INSERT INTO child VALUES(2)",
        "INSERT INTO parent VALUES(2)",
    ]);
    let mut calls = 0;
    let run = writer.execute_group(
        &members(&input),
        group_limits(),
        &mut |prefix: &[StagedTransaction]| {
            calls += 1;
            assert_eq!(prefix.len(), 1);
            GateDecision::Accepted
        },
        uninterrupted(),
    );
    invariant(&run, input.len());
    assert_eq!((run.attempted, run.staged, calls), (2, 1, 1));
    assert!(matches!(run.member_error, Some(Error::Sqlite(_))));
    assert_eq!(run.outcome.unwrap().len(), 1);
    assert!(writer.is_stopped());
    assert!(writer.connection.is_autocommit());
    assert_eq!(ordinary.borrow().writes.len(), 1);
    assert_eq!(
        writer
            .connection
            .query_row::<i64, _, _>("SELECT sum(id) FROM parent", [], |row| row.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        writer
            .connection
            .query_row::<i64, _, _>("SELECT count(*) FROM child", [], |row| row.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn first_middle_and_last_sql_failures_leave_only_the_successful_prefix() {
    for failed in 0..3 {
        let (_root, mut writer, _ordinary) = setup();
        let input: Vec<_> = (0..3)
            .map(|index| {
                vec![statement(&if index == failed {
                    "SELECT * FROM missing_table".to_owned()
                } else {
                    format!("CREATE TABLE effect_{index}(x)")
                })]
            })
            .collect();
        let mut calls = 0;
        let run = writer.execute_group(
            &members(&input),
            group_limits(),
            &mut |prefix: &[StagedTransaction]| {
                calls += 1;
                assert_eq!(prefix.len(), failed);
                GateDecision::Accepted
            },
            uninterrupted(),
        );
        invariant(&run, input.len());
        assert_eq!((run.attempted, run.staged), (failed + 1, failed));
        assert_eq!(calls, usize::from(failed != 0));
        assert!(run.member_error.is_some());
        assert_eq!(run.outcome.unwrap().len(), failed);
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        let tables: i64 = writer
            .connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tables as usize, failed);
    }
}

#[test]
fn no_op_members_get_independent_results_without_fabricated_page_changes() {
    let (_root, mut writer, ordinary) = setup();
    let input = sqls(&["SELECT randomblob(8)", "SELECT randomblob(8)"]);
    let run = writer.execute_group(
        &members(&input),
        group_limits(),
        &mut |prefix: &[StagedTransaction]| {
            for member in prefix {
                assert_eq!(member.batch.size_after, 0);
                assert!(member.batch.pages.is_empty());
            }
            GateDecision::Accepted
        },
        uninterrupted(),
    );
    invariant(&run, 2);
    assert_eq!(run.outcome.unwrap().len(), 2);
    assert_eq!(writer.page_count(), 0);
    assert!(ordinary.borrow().writes.is_empty());
}

#[derive(Default)]
struct Effects {
    commits: usize,
    fail_before: Option<(usize, i32)>,
    fail_after: Option<(usize, i32)>,
    after_commit: Option<Arc<AtomicBool>>,
    rollback_failure: bool,
    checkpoint_failure: bool,
    after_checkpoint: Option<Arc<AtomicBool>>,
    invalid_capture: Option<Rc<RefCell<GateState<Gate>>>>,
}

impl GroupEffects for Effects {
    fn commit(
        &mut self,
        connection: &libsql_sys::rusqlite::Connection,
        interrupt: &ReadInterrupt,
    ) -> Result<(), Error> {
        self.commits += 1;
        if let Some((at, code)) = self.fail_before {
            if at == self.commits {
                return Err(native_error(code));
            }
        }
        sql::commit_native(connection, interrupt)?;
        if let Some(state) = &self.invalid_capture {
            assert!(!state.borrow_mut().capture_or_publish(PageBatch {
                size_after: 1,
                pages: Vec::new(),
            }));
        }
        if let Some(value) = &self.after_commit {
            value.store(true, Ordering::Release);
        }
        if let Some((at, code)) = self.fail_after {
            if at == self.commits {
                return Err(native_error(code));
            }
        }
        Ok(())
    }

    fn rollback(&mut self, connection: &libsql_sys::rusqlite::Connection) -> Result<(), Error> {
        if self.rollback_failure {
            return Err(native_error(ffi::SQLITE_IOERR));
        }
        sql::rollback_checked(connection)
    }

    fn checkpoint(&mut self, connection: &libsql_sys::rusqlite::Connection) -> Result<(), Error> {
        if self.checkpoint_failure {
            return Err(native_error(ffi::SQLITE_IOERR));
        }
        config::checkpoint(connection)?;
        if let Some(value) = &self.after_checkpoint {
            value.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[test]
fn native_commit_and_rollback_failures_discard_all_staging_without_publication() {
    for mode in 0..4 {
        let (_root, mut writer, _ordinary) = setup();
        let input = if mode == 2 {
            sqls(&[
                "CREATE TABLE prefix(x)",
                "SELECT * FROM missing_table",
                "SELECT 99",
            ])
        } else {
            sqls(&[
                "CREATE TABLE prefix(x)",
                "INSERT INTO prefix VALUES(1)",
                "SELECT 99",
            ])
        };
        let mut effects = Effects::default();
        match mode {
            0 => effects.fail_before = Some((2, ffi::SQLITE_IOERR)),
            // Even a normally recoverable code is fatal after native frames.
            1 => effects.fail_after = Some((2, ffi::SQLITE_CONSTRAINT)),
            2 => effects.rollback_failure = true,
            _ => effects.fail_before = Some((2, ffi::SQLITE_NOMEM)),
        }
        let run = writer.execute_group_with(
            &members(&input),
            group_limits(),
            &mut |_: &[StagedTransaction]| panic!("fatal native failure must not publish"),
            uninterrupted(),
            &mut effects,
            &mut scap_sql::encode_result,
        );
        invariant(&run, 3);
        assert_eq!((run.attempted, run.staged), (2, 1));
        assert!(matches!(run.outcome, Err(Error::Stopped)));
        assert!(writer.is_stopped());
    }
}

#[test]
fn a_capture_error_is_never_promoted_even_if_a_native_adapter_reports_success() {
    let (_root, mut writer, _ordinary) = setup();
    let input = sqls(&["SELECT 1"]);
    let mut effects = Effects {
        invalid_capture: Some(writer.state.clone()),
        ..Effects::default()
    };
    let run = writer.execute_group_with(
        &members(&input),
        group_limits(),
        &mut |_: &[StagedTransaction]| panic!("invalid capture must not publish"),
        uninterrupted(),
        &mut effects,
        &mut scap_sql::encode_result,
    );
    invariant(&run, 1);
    assert!(matches!(run.member_error, Some(Error::InvalidImage)));
    assert!(matches!(run.outcome, Err(Error::Stopped)));
}

#[test]
fn group_and_member_expiration_preserve_the_native_commit_fact_and_stop_the_suffix() {
    for mode in 0..4 {
        let (_root, mut writer, _ordinary) = setup();
        let input = sqls(&["CREATE TABLE prefix(x)", "CREATE TABLE suffix(x)"]);
        let expired = Arc::new(AtomicBool::new(mode < 2));
        let group = if mode % 2 == 0 {
            flag(&expired)
        } else {
            uninterrupted()
        };
        let mut input_members = members(&input);
        if mode % 2 == 1 {
            input_members[0].interrupt = flag(&expired);
        }
        let mut effects = Effects {
            after_commit: (mode >= 2).then(|| expired.clone()),
            ..Effects::default()
        };
        let run = writer.execute_group_with(
            &input_members,
            group_limits(),
            &mut |_: &[StagedTransaction]| panic!("expired staging must not publish"),
            group,
            &mut effects,
            &mut scap_sql::encode_result,
        );
        invariant(&run, 2);
        match mode {
            0 => assert_eq!((run.attempted, run.staged), (0, 0)),
            1 => assert_eq!((run.attempted, run.staged), (1, 0)),
            _ => assert_eq!((run.attempted, run.staged), (1, 1)),
        }
        assert!(run.outcome.is_err());
        assert!(writer.is_stopped());
    }
}

#[test]
fn a_panicking_group_clock_fails_closed_before_any_sql() {
    let (_root, mut writer, _ordinary) = setup();
    let input = sqls(&["CREATE TABLE x(n)"]);
    let run = writer.execute_group(
        &members(&input),
        group_limits(),
        &mut |_: &[StagedTransaction]| panic!("must not publish"),
        Arc::new(|| panic!("broken clock")),
    );
    invariant(&run, 1);
    assert_eq!(run.attempted, 0);
    assert!(matches!(run.outcome, Err(Error::Interrupted)));
}

#[test]
fn expiration_between_staging_and_publication_never_calls_the_authority() {
    let (_root, mut writer, _ordinary) = setup();
    let input = sqls(&["CREATE TABLE staged(x)"]);
    let committed = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicUsize::new(0));
    let group: ReadInterrupt = {
        let committed = committed.clone();
        let checks = checks.clone();
        Arc::new(move || {
            committed.load(Ordering::Acquire) && checks.fetch_add(1, Ordering::AcqRel) >= 1
        })
    };
    let mut effects = Effects {
        after_commit: Some(committed),
        ..Effects::default()
    };
    let run = writer.execute_group_with(
        &members(&input),
        group_limits(),
        &mut |_: &[StagedTransaction]| panic!("expired publication must not run"),
        group,
        &mut effects,
        &mut scap_sql::encode_result,
    );
    invariant(&run, 1);
    assert_eq!((run.attempted, run.staged), (1, 1));
    assert!(run.member_error.is_none());
    assert!(matches!(run.outcome, Err(Error::Interrupted)));
    assert!(writer.is_stopped());
}

#[test]
fn rejected_unknown_and_panicking_group_publishers_never_make_a_warm_writer() {
    for mode in 0..3 {
        let (_root, mut writer, ordinary) = setup();
        let input = sqls(&["CREATE TABLE private(x)", "INSERT INTO private VALUES(9)"]);
        let mut calls = 0;
        let run = writer.execute_group(
            &members(&input),
            group_limits(),
            &mut |_: &[StagedTransaction]| {
                calls += 1;
                match mode {
                    0 => GateDecision::Rejected,
                    1 => GateDecision::Unknown,
                    _ => panic!("authority failed after a possible CAS"),
                }
            },
            uninterrupted(),
        );
        invariant(&run, 2);
        assert_eq!(calls, 1);
        if mode == 0 {
            assert!(matches!(run.outcome, Err(Error::Rejected)));
        } else {
            assert!(matches!(run.outcome, Err(Error::OutcomeUnknown)));
        }
        assert!(ordinary.borrow().writes.is_empty());
        assert!(writer.is_stopped());
        assert!(matches!(
            writer.query(&[statement("SELECT 1")], uninterrupted()),
            Err(Error::Stopped)
        ));
    }
}

#[test]
fn accepted_group_survives_checkpoint_and_late_deadline_failures_as_committed() {
    for mode in 0..4 {
        let (_root, mut writer, _ordinary) = setup();
        let input = sqls(&["CREATE TABLE accepted(x)"]);
        let expired = Arc::new(AtomicBool::new(false));
        let mut input_members = members(&input);
        let group = if mode == 3 {
            uninterrupted()
        } else {
            flag(&expired)
        };
        if mode == 3 {
            input_members[0].interrupt = flag(&expired);
        }
        let mut effects = Effects {
            checkpoint_failure: mode == 0,
            after_checkpoint: (mode == 2).then(|| expired.clone()),
            ..Effects::default()
        };
        let mut calls = 0;
        let run = writer.execute_group_with(
            &input_members,
            group_limits(),
            &mut |_: &[StagedTransaction]| {
                calls += 1;
                if mode == 1 || mode == 3 {
                    expired.store(true, Ordering::Release);
                }
                GateDecision::Accepted
            },
            group,
            &mut effects,
            &mut scap_sql::encode_result,
        );
        invariant(&run, 1);
        assert_eq!(calls, 1);
        assert!(matches!(run.outcome, Err(Error::CommittedButUnavailable)));
        assert!(writer.is_stopped());
    }
}

#[test]
fn invalid_group_configuration_and_stopped_writers_never_attempt_sql() {
    for mode in 0..7 {
        let (_root, mut writer, _ordinary) = setup();
        let mut input = sqls(&["SELECT 1", "SELECT 2"]);
        let mut configured = group_limits();
        match mode {
            0 => input.clear(),
            1 => configured.max_members = 0,
            2 => configured.max_members = 1,
            3 => configured.max_changed_pages = 0,
            4 => configured.max_changed_pages = u32::MAX,
            5 => configured.max_result_bytes = 0,
            _ => writer.stopped = true,
        }
        let run = writer.execute_group(
            &members(&input),
            configured,
            &mut |_: &[StagedTransaction]| panic!("invalid group must not publish"),
            uninterrupted(),
        );
        invariant(&run, input.len());
        assert_eq!(run.attempted, 0);
        if mode == 6 {
            assert!(matches!(run.outcome, Err(Error::Stopped)));
        } else {
            assert!(matches!(run.outcome, Err(Error::InvalidLimits)));
        }
    }
}

#[test]
fn accumulated_result_and_page_budgets_end_a_group_without_running_its_suffix() {
    for mode in 0..3 {
        let (_root, mut writer, _ordinary) = setup();
        let input = if mode == 0 {
            sqls(&["SELECT 1 AS x", "SELECT 2 AS x", "CREATE TABLE suffix(x)"])
        } else {
            sqls(&[
                "CREATE TABLE first(x)",
                "CREATE TABLE second(x)",
                "CREATE TABLE suffix(x)",
            ])
        };
        let mut configured = group_limits();
        match mode {
            0 => configured.max_result_bytes = 50,
            1 => configured.max_changed_pages = 2,
            _ => writer.limits.max_changed_pages = 2,
        }
        let mut calls = 0;
        let run = writer.execute_group(
            &members(&input),
            configured,
            &mut |prefix: &[StagedTransaction]| {
                calls += 1;
                assert_eq!(prefix.len(), if mode == 2 { 3 } else { 1 });
                GateDecision::Accepted
            },
            uninterrupted(),
        );
        invariant(&run, 3);
        assert_eq!(calls, 1);
        if mode == 2 {
            assert_eq!((run.attempted, run.staged), (3, 3));
            assert!(!writer.is_stopped());
        } else {
            assert_eq!((run.attempted, run.staged), (2, 1));
            assert!(run.member_error.is_some());
            assert!(writer.is_stopped());
        }
        assert!(run.outcome.is_ok());
    }
}

#[test]
fn result_encoding_failure_preserves_only_safe_prefixes_and_retains_member_error() {
    for mode in 0..3 {
        let (_root, mut writer, _ordinary) = setup();
        let input = sqls(&["SELECT 1", "SELECT 2", "SELECT 3"]);
        let mut encoded = 0;
        let mut calls = 0;
        let run = writer.execute_group_with(
            &members(&input),
            group_limits(),
            &mut |prefix: &[StagedTransaction]| {
                calls += 1;
                assert_eq!(prefix.len(), 1);
                GateDecision::Rejected
            },
            uninterrupted(),
            &mut Effects::default(),
            &mut |result, limits| {
                encoded += 1;
                if encoded == 2 {
                    return Err(match mode {
                        0 => SqlError::Limit,
                        1 => SqlError::ResourceExhausted,
                        _ => SqlError::Malformed,
                    });
                }
                scap_sql::encode_result(result, limits)
            },
        );
        invariant(&run, 3);
        assert_eq!((run.attempted, run.staged), (2, 1));
        assert!(run.member_error.is_some());
        assert_eq!(calls, usize::from(mode == 0));
        if mode == 0 {
            assert!(matches!(run.outcome, Err(Error::Rejected)));
        } else {
            assert!(matches!(run.outcome, Err(Error::Stopped)));
        }
    }
}

#[test]
fn invalid_member_input_and_native_result_limits_are_checked_inside_its_transaction() {
    for mode in 0..3 {
        let (_root, mut writer, _ordinary) = setup();
        let mut input = sqls(&["SELECT 1", "SELECT 2", "SELECT 3"]);
        match mode {
            0 => input[1].clear(),
            1 => input[1][0].sql = "".into(),
            _ => {
                input[1][0].sql = "SELECT zeroblob(100)".into();
                writer.limits.sql.max_value_bytes = 50;
            }
        }
        let run = writer.execute_group(
            &members(&input),
            group_limits(),
            &mut |prefix: &[StagedTransaction]| {
                assert_eq!(prefix.len(), 1);
                GateDecision::Accepted
            },
            uninterrupted(),
        );
        invariant(&run, 3);
        assert_eq!((run.attempted, run.staged), (2, 1));
        assert!(run.member_error.is_some());
        assert!(run.outcome.is_ok());
    }
}

#[test]
fn capture_state_rejects_repeated_invalid_and_growing_page_sets_without_authority() {
    let mut state = GateState::new(Gate(Rc::default()), limits());
    let empty = PageBatch {
        size_after: 0,
        pages: Vec::new(),
    };
    state.begin_staging(0, 1);
    assert!(state.capture_or_publish(empty.clone()));
    assert!(!state.capture_or_publish(empty.clone()));
    let captured = state.take_staging();
    assert!(captured.pending.is_some());
    assert!(matches!(captured.error, Some(Error::InvalidSql)));
    state.begin_staging(0, 1);
    assert!(!state.capture_or_publish(PageBatch {
        size_after: 1,
        pages: Vec::new()
    }));
    assert!(!state.capture_or_publish(empty));
    let captured = state.take_staging();
    assert!(captured.pending.is_none());
    assert!(matches!(captured.error, Some(Error::InvalidSql)));
}

#[test]
fn only_known_logical_failures_can_preserve_a_checked_prefix() {
    for code in [
        ffi::SQLITE_ERROR,
        ffi::SQLITE_CONSTRAINT,
        ffi::SQLITE_TOOBIG,
        ffi::SQLITE_MISMATCH,
        ffi::SQLITE_AUTH,
        ffi::SQLITE_RANGE,
    ] {
        assert!(recoverable(&native_error(code)));
    }
    for code in [
        ffi::SQLITE_IOERR,
        ffi::SQLITE_CORRUPT,
        ffi::SQLITE_NOMEM,
        ffi::SQLITE_BUSY,
        ffi::SQLITE_INTERRUPT,
        ffi::SQLITE_MISUSE,
    ] {
        assert!(!recoverable(&native_error(code)));
    }
    use libsql_sys::rusqlite::Error as NativeError;
    for error in [
        NativeError::InvalidParameterCount(1, 2),
        NativeError::InvalidParameterName("missing".into()),
        NativeError::NulError(std::ffi::CString::new(b"a\0b".to_vec()).unwrap_err()),
        NativeError::MultipleStatement,
        NativeError::InvalidQuery,
        NativeError::SqlInputError {
            error: ffi::Error::new(ffi::SQLITE_ERROR),
            msg: "syntax".into(),
            sql: "!".into(),
            offset: 0,
        },
    ] {
        assert!(recoverable(&Error::Sqlite(error)));
    }
    assert!(!recoverable(&Error::Sqlite(
        NativeError::QueryReturnedNoRows
    )));
    assert!(recoverable(&Error::InvalidSql));
    assert!(recoverable(&Error::ResultLimit));
    assert!(recoverable(&Error::Sql(SqlError::Invalid)));
    assert!(recoverable(&Error::Sql(SqlError::Limit)));
    assert!(!recoverable(&Error::Sql(SqlError::Malformed)));
    assert!(!recoverable(&Error::ResourceExhausted));
}

struct RollbackProbe {
    active: Cell<bool>,
    fails: bool,
    leaves_active: bool,
    calls: Cell<usize>,
}

impl sql::RollbackOps for RollbackProbe {
    fn autocommit(&self) -> bool {
        !self.active.get()
    }
    fn rollback(&self) -> libsql_sys::rusqlite::Result<()> {
        self.calls.set(self.calls.get() + 1);
        if self.fails {
            return Err(libsql_sys::rusqlite::Error::InvalidQuery);
        }
        self.active.set(self.leaves_active);
        Ok(())
    }
}

#[test]
fn checked_rollback_never_confuses_cleanup_attempt_with_a_closed_transaction() {
    for mode in 0..4 {
        let probe = RollbackProbe {
            active: Cell::new(mode != 0),
            fails: mode == 2,
            leaves_active: mode == 3,
            calls: Cell::new(0),
        };
        let result = sql::rollback_checked(&probe);
        assert_eq!(result.is_ok(), mode < 2);
        assert_eq!(probe.calls.get(), usize::from(mode != 0));
        if mode == 3 {
            assert!(matches!(result, Err(Error::Stopped)));
        }
    }
}
