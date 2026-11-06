use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn uninterrupted() -> ReadInterrupt {
    Arc::new(|| false)
}

#[test]
fn native_reads_leave_the_gate_image_and_write_revision_unchanged() {
    let (_directory, mut writer, plan) = setup();
    writer
        .execute(
            &[
                statement("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)"),
                statement("INSERT INTO items VALUES(7,'original')"),
            ],
            uninterrupted(),
        )
        .unwrap();
    let before = writer.page_count();
    let writes = plan.borrow().writes.len();
    let result = writer
        .query(
            &[
                Statement {
                    sql: "SELECT value FROM items WHERE id=?1".into(),
                    parameters: vec![Value::Integer(7)],
                },
                statement("SELECT count(*), hex(zeroblob(2)) FROM items"),
            ],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(
        result.statements[0].rows,
        vec![vec![Value::Text("original".into())]]
    );
    assert_eq!(
        result.statements[1].rows,
        vec![vec![Value::Integer(1), Value::Text("0000".into())]]
    );
    assert!(result
        .statements
        .iter()
        .all(|s| s.affected_rows == 0 && s.last_insert_rowid == 0));
    assert_eq!(writer.page_count(), before);
    assert_eq!(plan.borrow().writes.len(), writes);
    assert!(!writer.is_stopped());
    assert!(writer.connection.is_autocommit());
    // The read authorizer and read snapshot do not leak into the next write.
    writer
        .execute(
            &[statement("INSERT INTO items VALUES(8,'next')")],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(plan.borrow().writes.len(), writes + 1);
}

#[test]
fn only_read_actions_and_known_pure_functions_are_authorized() {
    let actions = [
        (
            AuthAction::Read {
                table_name: "items",
                column_name: "id",
            },
            true,
        ),
        (AuthAction::Select, true),
        (AuthAction::Recursive, true),
        (
            AuthAction::Function {
                function_name: "AbS",
            },
            true,
        ),
        (
            AuthAction::Function {
                function_name: "load_extension",
            },
            false,
        ),
        (
            AuthAction::Insert {
                table_name: "items",
            },
            false,
        ),
        (
            AuthAction::Transaction {
                operation: TransactionOperation::Begin,
            },
            false,
        ),
    ];
    for (action, allowed) in actions {
        assert_eq!(
            query::authorize(AuthContext {
                action,
                database_name: Some("main"),
                accessor: None
            }),
            if allowed {
                Authorization::Allow
            } else {
                Authorization::Deny
            },
        );
    }
    assert_eq!(
        query::authorize(AuthContext {
            action: AuthAction::Read {
                table_name: "items",
                column_name: "id"
            },
            database_name: Some("temp"),
            accessor: None,
        }),
        Authorization::Deny,
    );
}

#[test]
fn reads_reject_mutations_transaction_control_and_partial_results() {
    for denied in [
        "CREATE TABLE forbidden(id)",
        "PRAGMA journal_mode=DELETE",
        "PRAGMA user_version",
        "ATTACH ':memory:' AS other",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT one",
        "SELECT load_extension('bad')",
        "SELECT * FROM pragma_table_info('items')",
        "SELECT 1; SELECT 2",
        "-- no statement",
    ] {
        let (_directory, mut writer, plan) = setup();
        assert!(
            writer
                .query(
                    &[statement("SELECT 42"), statement(denied)],
                    uninterrupted()
                )
                .is_err(),
            "{denied}"
        );
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert_eq!(writer.page_count(), 0);
        assert!(plan.borrow().writes.is_empty());
        assert!(matches!(
            writer.query(&[statement("SELECT 1")], uninterrupted()),
            Err(Error::Stopped)
        ));
    }
    // Even with no authorizer installed, the complete VM's native read-only
    // classification rejects a writable prepared statement before it executes.
    let (_directory, writer, _plan) = setup();
    assert!(matches!(
        sql::collect_results(
            &writer.connection,
            &[statement("CREATE TABLE forbidden(id)")],
            limits(),
            true,
            &uninterrupted()
        ),
        Err(Error::InvalidSql)
    ));
    assert_eq!(
        writer
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='forbidden'",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn read_input_result_and_vm_budgets_are_enforced_without_proposals() {
    for case in 0..7 {
        let (_directory, mut writer, plan) = setup();
        let statements = match case {
            0 => vec![],
            1 => {
                writer.limits.max_vm_steps = 1;
                vec![statement("SELECT 1")]
            }
            2 => {
                writer.limits.sql.max_result_bytes = 12;
                vec![statement("SELECT 1")]
            }
            3 => vec![statement("SELECT 1e999")],
            4 => {
                writer.limits.sql.max_rows = 2;
                vec![statement("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<3) SELECT x FROM n")]
            }
            5 => {
                writer.limits.sql.max_value_bytes = 3;
                vec![statement("SELECT '1234' AS v")]
            }
            _ => vec![Statement {
                sql: "SELECT ?1".into(),
                parameters: vec![Value::Real(f64::NAN)],
            }],
        };
        assert!(
            writer.query(&statements, uninterrupted()).is_err(),
            "case {case}"
        );
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert!(plan.borrow().writes.is_empty());
    }
}

#[test]
fn native_read_checks_cancellation_at_every_execution_and_completion_boundary() {
    let statements = [statement("SELECT 1"), statement("SELECT 2")];
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let (_directory, mut writer, _plan) = setup();
    writer
        .query(
            &statements,
            Arc::new(move || {
                observed.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
    let total = count.load(Ordering::Relaxed);
    assert!(total > 10);
    // Interrupt at each guard reached by this finite two-statement request.
    // This includes pre-BEGIN, preparation/VM work, both statement ends, the
    // private COMMIT VM, and the final buffered-result publication boundary.
    for stop in 0..total {
        let (_directory, mut writer, plan) = setup();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        assert!(
            writer
                .query(
                    &statements,
                    Arc::new(move || observed.fetch_add(1, Ordering::Relaxed) >= stop)
                )
                .is_err(),
            "stop {stop}/{total}"
        );
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert!(plan.borrow().writes.is_empty());
        assert_eq!(writer.page_count(), 0);
    }
}

#[test]
fn a_preexisting_native_transaction_is_rejected_before_read_execution() {
    let (_directory, mut writer, plan) = setup();
    writer.connection.execute_batch("BEGIN DEFERRED").unwrap();
    assert!(matches!(
        writer.query(&[statement("SELECT 1")], uninterrupted()),
        Err(Error::Sqlite(_))
    ));
    assert!(writer.is_stopped());
    assert!(plan.borrow().writes.is_empty());
    sql::rollback(&writer.connection);
}

#[test]
fn panicking_read_guards_interrupt_before_and_inside_native_execution() {
    for after in [0, 3] {
        let (_directory, mut writer, plan) = setup();
        let calls = AtomicUsize::new(0);
        let guard: ReadInterrupt = Arc::new(move || {
            assert!(
                calls.fetch_add(1, Ordering::Relaxed) < after,
                "faulty read clock"
            );
            false
        });
        assert!(writer.query(&[statement("SELECT 1")], guard).is_err());
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert!(plan.borrow().writes.is_empty());
    }
}
