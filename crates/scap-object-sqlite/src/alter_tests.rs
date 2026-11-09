//! Regression contracts for statement-scoped ALTER authorization.
//! These tests use the pinned native engine and the real commit-gate adapter;
//! their result is separate from any external/system-SQLite diagnostic.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use libsql_sys::rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use scap_sql::{SqlLimits, Statement, Value};

use super::{authorize, authorize_write};
use crate::{
    CommitGate, Error, GateDecision, ImageBuilder, PageBatch, ReadInterrupt, SqliteWriter,
    WriterLimits, PAGE_SIZE,
};

const HELPERS: [&str; 6] = [
    "sqlite_rename_column",
    "sqlite_rename_table",
    "sqlite_rename_test",
    "sqlite_drop_column",
    "sqlite_rename_quotefix",
    "libsql_alter_column",
];

fn context<'a>(action: AuthAction<'a>, database_name: Option<&'a str>) -> AuthContext<'a> {
    AuthContext {
        action,
        database_name,
        accessor: None,
    }
}

fn main_alter<'a>() -> AuthContext<'a> {
    context(
        AuthAction::AlterTable {
            database_name: "main",
            table_name: "items",
        },
        None,
    )
}

#[derive(Default)]
struct Plan {
    decisions: VecDeque<GateDecision>,
    proposed: Vec<(PageBatch, Vec<u8>)>,
}

struct Gate(Rc<RefCell<Plan>>);

impl CommitGate for Gate {
    fn publish(&mut self, pages: &PageBatch, result: &[u8]) -> GateDecision {
        let mut plan = self.0.borrow_mut();
        plan.proposed.push((pages.clone(), result.to_vec()));
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
        max_database_pages: 4096,
        max_changed_pages: 1024,
        cache_bytes: 8 * 1024 * 1024,
    }
}

fn uninterrupted() -> ReadInterrupt {
    Arc::new(|| false)
}

fn statement(sql: &str) -> Statement {
    Statement {
        sql: sql.to_owned(),
        parameters: Vec::new(),
    }
}

fn open(directory: &Path, image: &[u8], plan: Rc<RefCell<Plan>>) -> SqliteWriter<Gate> {
    assert!(image.len().is_multiple_of(PAGE_SIZE));
    let mut builder = ImageBuilder::create_new(
        directory,
        (image.len() / PAGE_SIZE) as u32,
        limits().max_database_pages,
    )
    .unwrap();
    if !image.is_empty() {
        builder.append_pages(1, image).unwrap();
    }
    SqliteWriter::open(
        builder.finish().unwrap(),
        limits(),
        Gate(plan),
        uninterrupted(),
    )
    .unwrap()
}

fn setup() -> (tempfile::TempDir, SqliteWriter<Gate>, Rc<RefCell<Plan>>) {
    let root = tempfile::tempdir().unwrap();
    let plan = Rc::new(RefCell::new(Plan::default()));
    let mut writer = open(&root.path().join("writer"), &[], plan.clone());
    writer
        .execute(
            &[
                statement(
                    "CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB, obsolete TEXT)",
                ),
                statement("INSERT INTO items VALUES(1,x'00ff','old')"),
            ],
            uninterrupted(),
        )
        .unwrap();
    (root, writer, plan)
}

fn rows(writer: &mut SqliteWriter<Gate>, sql: &str) -> Vec<Vec<Value>> {
    writer
        .query(&[statement(sql)], uninterrupted())
        .unwrap()
        .statements[0]
        .rows
        .clone()
}

// Only used for accepted records in tests. This is not another production
// recovery implementation or evidence for S3 persistence.
fn accepted_image(plan: &Plan) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (batch, _) in &plan.proposed {
        bytes.resize(batch.size_after as usize * PAGE_SIZE, 0);
        for page in &batch.pages {
            let offset = (page.number as usize - 1) * PAGE_SIZE;
            bytes[offset..offset + PAGE_SIZE].copy_from_slice(&page.bytes);
        }
    }
    bytes
}

#[test]
fn alter_uses_the_action_schema_not_the_drop_column_argument_slot() {
    for fourth_argument in [None, Some("obsolete"), Some("temp"), Some("aux")] {
        let context = context(
            AuthAction::AlterTable {
                database_name: "main",
                table_name: "items",
            },
            fourth_argument,
        );
        assert_eq!(authorize(context), Authorization::Allow);
        let mut armed = false;
        assert_eq!(authorize_write(context, &mut armed), Authorization::Allow);
        assert!(armed);
    }
    for schema in ["temp", "aux"] {
        for fourth_argument in [None, Some("main")] {
            let context = context(
                AuthAction::AlterTable {
                    database_name: schema,
                    table_name: "items",
                },
                fourth_argument,
            );
            assert_eq!(authorize(context), Authorization::Deny);
            let mut armed = true;
            assert_eq!(authorize_write(context, &mut armed), Authorization::Deny);
            assert!(!armed);
        }
    }
    let mut sourced = main_alter();
    sourced.accessor = Some("user_trigger");
    let mut armed = true;
    assert_eq!(authorize_write(sourced, &mut armed), Authorization::Deny);
    assert!(!armed);
}

#[test]
fn exact_helpers_require_a_main_alter_and_never_enter_the_read_allowlist() {
    for name in HELPERS {
        for spelling in [name.to_owned(), name.to_ascii_uppercase()] {
            let helper = context(
                AuthAction::Function {
                    function_name: &spelling,
                },
                None,
            );
            let mut armed = false;
            assert_eq!(authorize(helper), Authorization::Deny);
            assert_eq!(crate::query::authorize(helper), Authorization::Deny);
            assert_eq!(authorize_write(helper, &mut armed), Authorization::Deny);
            assert_eq!(
                authorize_write(main_alter(), &mut armed),
                Authorization::Allow
            );
            assert_eq!(authorize_write(helper, &mut armed), Authorization::Allow);
            let mut from_view = helper;
            from_view.accessor = Some("user_view");
            assert_eq!(authorize_write(from_view, &mut armed), Authorization::Deny);
            let mut with_schema = helper;
            with_schema.database_name = Some("main");
            assert_eq!(
                authorize_write(with_schema, &mut armed),
                Authorization::Deny
            );
        }
    }
    let mut armed = true;
    for name in [
        "sqlite_rename_evil",
        "libsql_evil",
        "load_extension",
        "writefile",
    ] {
        assert_eq!(
            authorize_write(
                context(
                    AuthAction::Function {
                        function_name: name
                    },
                    None
                ),
                &mut armed,
            ),
            Authorization::Deny
        );
    }
    assert_eq!(
        authorize_write(
            context(
                AuthAction::Function {
                    function_name: "length"
                },
                None
            ),
            &mut armed,
        ),
        Authorization::Allow
    );
}

#[test]
fn temporary_schema_exception_is_exact_and_does_not_enable_other_actions() {
    for action in [
        AuthAction::Read {
            table_name: "sqlite_temp_master",
            column_name: "sql",
        },
        AuthAction::Update {
            table_name: "sqlite_temp_master",
            column_name: "sql",
        },
    ] {
        let schema = context(action, Some("temp"));
        let mut armed = false;
        assert_eq!(authorize_write(schema, &mut armed), Authorization::Deny);
        authorize_write(main_alter(), &mut armed);
        assert_eq!(authorize_write(schema, &mut armed), Authorization::Allow);
        let mut from_view = schema;
        from_view.accessor = Some("user_view");
        assert_eq!(authorize_write(from_view, &mut armed), Authorization::Deny);
        let mut attached = schema;
        attached.database_name = Some("aux");
        assert_eq!(authorize_write(attached, &mut armed), Authorization::Deny);
    }
    let mut armed = true;
    for action in [
        AuthAction::Read {
            table_name: "secret",
            column_name: "sql",
        },
        AuthAction::Update {
            table_name: "secret",
            column_name: "sql",
        },
        AuthAction::Read {
            table_name: "sqlite_temp_schema",
            column_name: "sql",
        },
        AuthAction::Insert {
            table_name: "sqlite_temp_master",
        },
        AuthAction::Delete {
            table_name: "sqlite_temp_master",
        },
        AuthAction::CreateTempTable {
            table_name: "secret",
        },
    ] {
        assert_eq!(
            authorize_write(context(action, Some("temp")), &mut armed),
            Authorization::Deny
        );
    }
    for action in [
        AuthAction::Attach {
            filename: ":memory:",
        },
        AuthAction::Pragma {
            pragma_name: "writable_schema",
            pragma_value: Some("ON"),
        },
        AuthAction::Transaction {
            operation: TransactionOperation::Begin,
        },
        AuthAction::Savepoint {
            operation: TransactionOperation::Begin,
            savepoint_name: "s",
        },
        AuthAction::CreateVtable {
            table_name: "v",
            module_name: "fts5",
        },
        AuthAction::Unknown {
            code: -1,
            arg1: None,
            arg2: None,
        },
    ] {
        assert_eq!(
            authorize_write(context(action, None), &mut armed),
            Authorization::Deny
        );
    }
    assert_eq!(
        authorize_write(context(AuthAction::Select, None), &mut armed),
        Authorization::Allow
    );
}

#[test]
fn native_schema_rename_preserves_views_triggers_indexes_and_foreign_keys() {
    let (_root, mut writer, plan) = setup();
    writer
        .execute(
            &[
                statement("CREATE VIEW items_view AS SELECT id,payload FROM items"),
                statement("CREATE INDEX items_payload ON items(payload)"),
                statement("CREATE TABLE audit(data BLOB)"),
                statement(
                    "CREATE TRIGGER items_update AFTER UPDATE OF payload ON items \
                 BEGIN INSERT INTO audit VALUES(new.payload); END",
                ),
                statement("CREATE TABLE child(item_id INTEGER REFERENCES items(id))"),
                statement("INSERT INTO child VALUES(1)"),
            ],
            uninterrupted(),
        )
        .unwrap();
    let before = plan.borrow().proposed.len();
    let result = writer
        .execute(
            &[
                statement("ALTER TABLE items RENAME TO records"),
                statement("ALTER TABLE records RENAME COLUMN payload TO data"),
                statement("ALTER TABLE records DROP COLUMN obsolete"),
                statement("ALTER TABLE records ADD COLUMN note TEXT DEFAULT 'kept'"),
                statement("UPDATE records SET data=x'0102' WHERE id=1 RETURNING id,hex(data),note"),
            ],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(plan.borrow().proposed.len(), before + 1);
    assert_eq!(
        result.statements[4].rows,
        vec![vec![
            Value::Integer(1),
            Value::Text("0102".into()),
            Value::Text("kept".into())
        ]]
    );
    assert_eq!(
        rows(&mut writer, "SELECT id,hex(data) FROM items_view"),
        vec![vec![Value::Integer(1), Value::Text("0102".into())]]
    );
    assert_eq!(
        rows(&mut writer, "SELECT hex(data) FROM audit"),
        vec![vec![Value::Text("0102".into())]]
    );
    assert_eq!(
        rows(&mut writer, "SELECT count(*) FROM child"),
        vec![vec![Value::Integer(1)]]
    );
    assert_eq!(
        rows(
            &mut writer,
            "SELECT count(*) FROM sqlite_schema \
             WHERE name='items_payload' AND tbl_name='records'",
        ),
        vec![vec![Value::Integer(1)]]
    );
    let decoded =
        scap_sql::decode_result(&plan.borrow().proposed.last().unwrap().1, limits().sql).unwrap();
    assert_eq!(decoded, result);
}

#[test]
fn drop_column_named_like_another_schema_still_targets_main() {
    let (_root, mut writer, _plan) = setup();
    writer
        .execute(
            &[
                statement("ALTER TABLE items ADD COLUMN temp TEXT"),
                statement("ALTER TABLE items DROP COLUMN temp"),
                statement("ALTER TABLE items ADD COLUMN aux TEXT"),
                statement("ALTER TABLE items DROP COLUMN aux"),
            ],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(
        rows(&mut writer, "SELECT id,hex(payload),obsolete FROM items"),
        vec![vec![
            Value::Integer(1),
            Value::Text("00FF".into()),
            Value::Text("old".into())
        ]]
    );
}

#[test]
fn rejected_or_unknown_schema_commit_never_becomes_visible() {
    for decision in [GateDecision::Rejected, GateDecision::Unknown] {
        let (root, mut writer, plan) = setup();
        plan.borrow_mut().decisions.push_back(decision);
        let error = writer
            .execute(
                &[statement("ALTER TABLE items RENAME TO records")],
                uninterrupted(),
            )
            .unwrap_err();
        if decision == GateDecision::Rejected {
            assert!(matches!(error, Error::Rejected));
        } else {
            assert!(matches!(error, Error::OutcomeUnknown));
        }
        assert!(writer.is_stopped());
        let reader =
            libsql_sys::rusqlite::Connection::open(root.path().join("writer/database.sqlite"))
                .unwrap();
        let count: u32 = reader
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let count: u32 = reader
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='records'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[test]
fn a_later_statement_cannot_reuse_alter_privileges_and_rolls_back_the_batch() {
    for next in [
        "SELECT sql FROM temp.sqlite_temp_master",
        "UPDATE temp.sqlite_temp_master SET sql='bad'",
        "CREATE TEMP TABLE leaked(n)",
        "ATTACH ':memory:' AS aux",
        "PRAGMA writable_schema=ON",
        "SELECT sqlite_rename_test('main','','table','records',0,'x',0)",
        "SELECT load_extension('missing')",
        "SAVEPOINT escaped",
        "COMMIT",
    ] {
        let (root, mut writer, plan) = setup();
        let before = plan.borrow().proposed.len();
        assert!(
            writer
                .execute(
                    &[
                        statement("ALTER TABLE items RENAME TO records"),
                        statement(next)
                    ],
                    uninterrupted(),
                )
                .is_err(),
            "{next}"
        );
        assert!(writer.is_stopped());
        assert_eq!(
            plan.borrow().proposed.len(),
            before,
            "nothing reached the commit gate: {next}"
        );
        let reader =
            libsql_sys::rusqlite::Connection::open(root.path().join("writer/database.sqlite"))
                .unwrap();
        let count: u32 = reader
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let count: u32 = reader
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='records'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[test]
fn successful_alter_does_not_leave_privileges_on_the_next_request_or_read_api() {
    for read_only in [false, true] {
        let (_root, mut writer, plan) = setup();
        writer
            .execute(
                &[statement("ALTER TABLE items RENAME TO records")],
                uninterrupted(),
            )
            .unwrap();
        let before = plan.borrow().proposed.len();
        let sql = [statement("SELECT sql FROM temp.sqlite_temp_master")];
        let result = if read_only {
            writer.query(&sql, uninterrupted())
        } else {
            writer.execute(&sql, uninterrupted())
        };
        assert!(result.is_err());
        assert!(writer.is_stopped());
        assert_eq!(plan.borrow().proposed.len(), before);
    }
}

#[test]
fn read_only_api_rejects_all_schema_mutations_before_the_gate() {
    for sql in [
        "ALTER TABLE items ADD COLUMN note TEXT",
        "ALTER TABLE items RENAME TO records",
        "ALTER TABLE items RENAME COLUMN payload TO data",
        "ALTER TABLE items DROP COLUMN obsolete",
    ] {
        let (root, mut writer, plan) = setup();
        let before = plan.borrow().proposed.len();
        assert!(
            writer.query(&[statement(sql)], uninterrupted()).is_err(),
            "{sql}"
        );
        assert!(writer.is_stopped());
        assert_eq!(plan.borrow().proposed.len(), before);
        let reader =
            libsql_sys::rusqlite::Connection::open(root.path().join("writer/database.sqlite"))
                .unwrap();
        let old: String = reader
            .query_row("SELECT hex(payload) FROM items WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(old, "00FF");
    }
}

#[test]
fn two_statements_in_one_input_do_not_escape_validation_after_alter() {
    let (root, mut writer, plan) = setup();
    let before = plan.borrow().proposed.len();
    assert!(writer
        .execute(
            &[statement(
                "ALTER TABLE items RENAME TO records; SELECT sql FROM temp.sqlite_temp_master",
            )],
            uninterrupted(),
        )
        .is_err());
    assert_eq!(plan.borrow().proposed.len(), before);
    let reader =
        libsql_sys::rusqlite::Connection::open(root.path().join("writer/database.sqlite")).unwrap();
    let count: u32 = reader
        .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn physical_recovery_preserves_accepted_schema_and_original_result() {
    let (root, mut writer, plan) = setup();
    let result = writer
        .execute(
            &[
                statement("ALTER TABLE items RENAME TO records"),
                statement("ALTER TABLE records RENAME COLUMN payload TO data"),
                statement("ALTER TABLE records DROP COLUMN obsolete"),
                statement("UPDATE records SET data=randomblob(16) WHERE id=1 RETURNING id,data"),
            ],
            uninterrupted(),
        )
        .unwrap();
    let encoded = plan.borrow().proposed.last().unwrap().1.clone();
    assert_eq!(
        scap_sql::decode_result(&encoded, limits().sql).unwrap(),
        result
    );
    let image = accepted_image(&plan.borrow());
    drop(writer);
    let new_plan = Rc::new(RefCell::new(Plan::default()));
    let mut restored = open(&root.path().join("fresh-worker"), &image, new_plan.clone());
    assert_eq!(
        rows(&mut restored, "SELECT id,data FROM records"),
        result.statements[3].rows
    );
    assert!(
        new_plan.borrow().proposed.is_empty(),
        "recovery query is not SQL replay"
    );
}

#[test]
fn accepted_alter_with_a_blocked_checkpoint_recovers_the_committed_schema() {
    let (root, mut writer, plan) = setup();
    let reader =
        libsql_sys::rusqlite::Connection::open(root.path().join("writer/database.sqlite")).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: u32 = reader
        .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
        .unwrap();
    assert!(matches!(
        writer.execute(
            &[statement("ALTER TABLE items RENAME TO records")],
            uninterrupted()
        ),
        Err(Error::CommittedButUnavailable)
    ));
    assert!(writer.is_stopped());
    assert_eq!(plan.borrow().proposed.len(), 2);
    let old: u32 = reader
        .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(old, 1);
    let image = accepted_image(&plan.borrow());
    drop(reader);
    drop(writer);
    let mut restored = open(&root.path().join("recovered"), &image, Rc::default());
    assert_eq!(
        rows(&mut restored, "SELECT id,hex(payload) FROM records"),
        vec![vec![Value::Integer(1), Value::Text("00FF".into())]]
    );
}
