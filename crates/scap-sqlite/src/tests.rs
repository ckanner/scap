use super::*;
use std::collections::VecDeque;

use libsql_sys::ffi;
use libsql_sys::rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use libsql_sys::rusqlite::types::ValueRef;
use scap_cell::{CellIdentity, DatabaseIdentity};
use scap_engine::{EngineIdentity, Limits as ImageLimits, PageChange, PAGE_SIZE};
use scap_sql::{SqlError, Value};

#[derive(Default)]
struct Plan {
    lookups: VecDeque<LookupDecision>,
    decisions: VecDeque<GateDecision>,
    writes: Vec<(PreparedWrite, [u8; 32], Vec<u8>)>,
    lookup_count: usize,
    panic_lookup: bool,
    panic_propose: bool,
    bad_receipt: bool,
}

struct Gate(Rc<RefCell<Plan>>);

impl CommitGate for Gate {
    fn lookup(&mut self, _: &CommitTicket, _: [u8; 32]) -> LookupDecision {
        let mut plan = self.0.borrow_mut();
        plan.lookup_count += 1;
        assert!(!plan.panic_lookup, "injected lookup panic");
        plan.lookups.pop_front().unwrap_or(LookupDecision::NotFound)
    }

    fn propose(
        &mut self,
        write: &PreparedWrite,
        fingerprint: [u8; 32],
        result: &[u8],
    ) -> GateDecision {
        let mut plan = self.0.borrow_mut();
        plan.writes
            .push((write.clone(), fingerprint, result.to_vec()));
        assert!(!plan.panic_propose, "injected propose panic");
        plan.decisions.pop_front().unwrap_or_else(|| {
            let mut receipt = CommitReceipt {
                ticket: write.ticket.clone(),
                sequence: write.ticket.predecessor + 1,
            };
            if plan.bad_receipt {
                receipt.sequence += 1;
            }
            GateDecision::Accepted(receipt)
        })
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
        max_vm_steps: 1_000_000,
        max_changed_pages: 1024,
    }
}

fn image() -> Image {
    Image::empty(
        EngineIdentity {
            cell: CellIdentity {
                cell_id: 11,
                cell_incarnation: 1,
            },
            database: DatabaseIdentity {
                database_id: 22,
                incarnation: 1,
                placement_generation: 1,
            },
        },
        ImageLimits {
            max_database_pages: 4096,
            max_changed_pages: 1024,
            max_transaction_bytes: 8_388_608,
        },
    )
    .unwrap()
}

fn ticket(revision: u64, request_id: u128) -> CommitTicket {
    CommitTicket {
        cell_id: 11,
        cell_incarnation: 1,
        database_id: 22,
        incarnation: 1,
        placement_generation: 1,
        owner_epoch: 1,
        worker_instance_id: 33,
        auth_epoch: 1,
        request_id,
        predecessor: revision,
        payload_digest: [0; 32],
    }
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
    let writer = SqliteWriter::create_new(
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

fn noop_prepared(revision: u64, request: u128) -> scap_engine::Prepared {
    assert_eq!(revision, 0);
    image()
        .prepare(
            ticket(revision, request),
            PageBatch {
                size_after: 0,
                pages: vec![],
            },
        )
        .unwrap()
}

#[test]
fn native_batch_buffers_typed_rows_and_owns_the_physical_baseline() {
    let (root, mut writer, plan) = setup();
    let created = writer
        .execute(
            ticket(0, 1),
            &[statement(
                "CREATE TABLE items(id INTEGER PRIMARY KEY, value BLOB)",
            )],
        )
        .unwrap();
    assert_eq!(created.receipt.sequence, 1);
    assert!(!created.replayed);
    assert!(!writer.is_stopped());
    assert!(writer.image().bytes().starts_with(b"SQLite format 3\0"));
    let executed = writer
        .execute(
            ticket(1, 2),
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
        )
        .unwrap();
    assert_eq!(executed.receipt.sequence, 2);
    assert_eq!(
        executed.result.statements[0].rows[0],
        vec![Value::Integer(1), Value::Blob(vec![0, 255, 1])]
    );
    assert_eq!(executed.result.statements[0].affected_rows, 1);
    assert_eq!(executed.result.statements[1].affected_rows, 0);
    assert_eq!(
        executed.result.statements[1].rows[0][3],
        Value::Text("中文".into())
    );
    assert_eq!(plan.borrow().writes.len(), 2);
    assert_eq!(
        plan.borrow().writes[1].2,
        scap_sql::encode_result(&executed.result, limits().sql).unwrap()
    );
    let recovered = writer.image().clone();
    drop(writer);
    let mut second =
        SqliteWriter::create_new(&root.path().join("next"), recovered, limits(), Gate(plan))
            .unwrap();
    let read = second
        .execute(ticket(2, 3), &[statement("SELECT value FROM items")])
        .unwrap();
    assert_eq!(
        read.result.statements[0].rows[0],
        vec![Value::Blob(vec![0, 255, 1])]
    );
    assert_eq!(read.receipt.sequence, 3);
}

#[test]
fn no_op_and_read_only_transactions_require_durable_decisions() {
    let (_root, mut writer, plan) = setup();
    let first = writer
        .execute(ticket(0, 1), &[statement("SELECT 7")])
        .unwrap();
    assert_eq!(
        first.result.statements[0].rows,
        vec![vec![Value::Integer(7)]]
    );
    assert_eq!(writer.image().head().revision, 1);
    assert!(writer.image().bytes().is_empty());
    assert_eq!(plan.borrow().writes.len(), 1);
    plan.borrow_mut().decisions.push_back(GateDecision::Unknown);
    assert!(matches!(
        writer.execute(ticket(1, 2), &[statement("SELECT 8")]),
        Err(Error::OutcomeUnknown)
    ));
    assert!(writer.is_stopped());
    assert!(matches!(
        writer.execute(ticket(1, 2), &[statement("SELECT 8")]),
        Err(Error::Stopped)
    ));
}

#[test]
fn preflight_dedup_does_not_reexecute_ddl() {
    let (_root, mut writer, plan) = setup();
    let input = [statement(
        "CREATE TABLE unique_table(id INTEGER PRIMARY KEY)",
    )];
    let first = writer.execute(ticket(0, 1), &input).unwrap();
    let result = scap_sql::encode_result(&first.result, limits().sql).unwrap();
    plan.borrow_mut()
        .lookups
        .push_back(LookupDecision::AlreadyCommitted {
            receipt: first.receipt.clone(),
            result,
        });
    let repeated = writer.execute(ticket(1, 1), &input).unwrap();
    assert!(repeated.replayed);
    assert_eq!(repeated.receipt, first.receipt);
    assert_eq!(repeated.result, first.result);
    assert_eq!(plan.borrow().writes.len(), 1);
    assert!(writer.is_stopped());
}

#[test]
fn gate_dedup_discards_new_nondeterministic_pages() {
    let (_root, mut writer, plan) = setup();
    writer
        .execute(ticket(0, 1), &[statement("CREATE TABLE x(value BLOB)")])
        .unwrap();
    let input = [statement(
        "INSERT INTO x VALUES(randomblob(8)) RETURNING value",
    )];
    let first = writer.execute(ticket(1, 2), &input).unwrap();
    let first_image = writer.image().clone();
    plan.borrow_mut()
        .decisions
        .push_back(GateDecision::AlreadyCommitted {
            receipt: first.receipt.clone(),
            result: scap_sql::encode_result(&first.result, limits().sql).unwrap(),
        });
    let repeated = writer.execute(ticket(2, 2), &input).unwrap();
    assert_eq!(repeated.result, first.result);
    assert!(repeated.replayed);
    assert_eq!(writer.image(), &first_image);
    let count: u64 = writer
        .connection
        .query_row("SELECT count(*) FROM x", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let writes = &plan.borrow().writes;
    assert_ne!(
        writes[1].0.ticket.payload_digest,
        writes[2].0.ticket.payload_digest
    );
}

#[test]
fn unknown_rejection_bad_receipt_and_callback_panic_never_ack() {
    for mode in 0..4 {
        let (_root, mut writer, plan) = setup();
        match mode {
            0 => plan.borrow_mut().decisions.push_back(GateDecision::Unknown),
            1 => plan
                .borrow_mut()
                .decisions
                .push_back(GateDecision::Rejected(Rejection::Fenced)),
            2 => plan.borrow_mut().bad_receipt = true,
            _ => plan.borrow_mut().panic_propose = true,
        }
        let error = writer
            .execute(ticket(0, 1), &[statement("CREATE TABLE x(n)")])
            .unwrap_err();
        match mode {
            1 => assert!(matches!(error, Error::Rejected(Rejection::Fenced))),
            2 => assert!(matches!(error, Error::InvalidReceipt)),
            _ => assert!(matches!(error, Error::OutcomeUnknown)),
        }
        assert!(writer.is_stopped());
        assert_eq!(writer.image().head().revision, 0);
        let count: u64 = writer
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='x'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[test]
fn lookup_failures_and_panics_do_not_execute_sql() {
    for mode in 0..3 {
        let (_root, mut writer, plan) = setup();
        match mode {
            0 => plan.borrow_mut().lookups.push_back(LookupDecision::Unknown),
            1 => plan
                .borrow_mut()
                .lookups
                .push_back(LookupDecision::Rejected(Rejection::Unauthorized)),
            _ => plan.borrow_mut().panic_lookup = true,
        }
        let error = writer
            .execute(ticket(0, 1), &[statement("CREATE TABLE x(n)")])
            .unwrap_err();
        if mode == 1 {
            assert!(matches!(error, Error::Rejected(Rejection::Unauthorized)));
        } else {
            assert!(matches!(error, Error::OutcomeUnknown));
        }
        assert!(plan.borrow().writes.is_empty());
        assert!(writer.is_stopped());
    }
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
            writer.execute(ticket(0, 1), &[statement(sql)]).is_err(),
            "{sql}"
        );
        assert!(writer.is_stopped());
        assert!(plan.borrow().writes.is_empty());
    }
    let (_root, mut writer, plan) = setup();
    assert!(matches!(
        writer.execute(ticket(0, 1), &[]),
        Err(Error::Sql(_))
    ));
    assert_eq!(plan.borrow().lookup_count, 0);
    let (_root, mut writer, plan) = setup();
    assert!(matches!(
        writer.execute(ticket(1, 1), &[statement("SELECT 1")]),
        Err(Error::Image(_))
    ));
    assert_eq!(plan.borrow().lookup_count, 0);
    let (_root, mut writer, plan) = setup();
    assert!(writer
        .execute(
            ticket(0, 1),
            &[
                statement("CREATE TABLE x(n UNIQUE)"),
                statement("INSERT INTO x VALUES(1),(1)")
            ]
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
        .execute(ticket(0, 1), &[statement("SELECT ?1")])
        .is_err());
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(writer
        .execute(ticket(0, 1), &[statement("SELECT 1")])
        .is_err());
    assert!(plan.borrow().writes.is_empty());
}

#[test]
fn result_limits_and_vm_budget_prevent_unbounded_buffering() {
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_columns = 1;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT 1,2")]),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_value_bytes = 1;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT 1 AS long_name")]),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_result_bytes = 12;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT 1 AS very_long_name")]),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_rows = 1;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT 1 UNION ALL SELECT 2")]),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_value_bytes = 2;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT 'long value' AS x")]),
        Err(Error::ResultLimit)
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_result_bytes = 12;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT NULL AS x")]),
        Err(Error::Sql(SqlError::Limit))
    ));
    assert!(plan.borrow().writes.is_empty());
    let (_root, mut writer, plan) = setup();
    writer.limits.max_vm_steps = 1;
    assert!(matches!(
        writer.execute(ticket(0, 1), &[statement("SELECT 1")]),
        Err(Error::Sqlite(_))
    ));
    assert!(plan.borrow().writes.is_empty());
}

#[test]
fn direct_affected_rows_exclude_trigger_changes_and_stale_counters() {
    let (_root, mut writer, _plan) = setup();
    let completed = writer.execute(ticket(0, 1), &[
        statement("CREATE TABLE x(n)"),
        statement("CREATE TABLE audit(n)"),
        statement("CREATE TRIGGER tr AFTER INSERT ON x BEGIN INSERT INTO audit VALUES(new.n); END"),
        statement("INSERT INTO x VALUES(1),(2)"),
        statement("SELECT * FROM x"),
        statement("CREATE TABLE other(n)"),
        statement("UPDATE x SET n=9 WHERE n=8"),
    ]).unwrap();
    let affected: Vec<_> = completed
        .result
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
        SqliteWriter::create_new(&existing, image(), limits(), Gate(Rc::default())),
        Err(Error::Io(_))
    ));
    assert_eq!(
        std::fs::read(existing.join("database.sqlite-wal")).unwrap(),
        b"old"
    );
    assert!(matches!(
        SqliteWriter::create_new(
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
    assert!(sql::open(&path, GateWal::new(state), limits(), 4096).is_err());
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
        SqliteWriter::create_new(
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
fn historical_receipts_bind_identity_and_original_sequence() {
    let request = ticket(4, 9);
    let mut original = request.clone();
    original.owner_epoch = 7;
    original.auth_epoch = 8;
    original.predecessor = 0;
    let receipt = CommitReceipt {
        ticket: original,
        sequence: 1,
    };
    assert!(gate::valid_historical_receipt(&request, &receipt));
    for field in 0..11 {
        let mut changed = receipt.clone();
        match field {
            0 => changed.ticket.cell_id += 1,
            1 => changed.ticket.cell_incarnation += 1,
            2 => changed.ticket.database_id += 1,
            3 => changed.ticket.incarnation += 1,
            4 => changed.ticket.placement_generation += 1,
            5 => changed.ticket.request_id += 1,
            6 => changed.sequence += 1,
            7 => changed.ticket.predecessor = u64::MAX,
            8 => changed.ticket.owner_epoch = 0,
            9 => changed.ticket.worker_instance_id = 0,
            _ => changed.ticket.auth_epoch = 0,
        }
        assert!(!gate::valid_historical_receipt(&request, &changed));
    }
}

#[test]
fn historical_payloads_and_receipts_fail_closed_when_malformed() {
    for mode in 0..3 {
        let (_root, mut writer, plan) = setup();
        let prepared = noop_prepared(0, 1);
        let mut receipt = CommitReceipt {
            ticket: prepared.write().ticket.clone(),
            sequence: 1,
        };
        let result = match mode {
            0 => {
                receipt.sequence += 1;
                empty_result()
            }
            1 => vec![0; limits().sql.max_result_bytes as usize + 1],
            _ => vec![1, 2, 3],
        };
        plan.borrow_mut()
            .lookups
            .push_back(LookupDecision::AlreadyCommitted { receipt, result });
        let error = writer
            .execute(ticket(0, 1), &[statement("SELECT 1")])
            .unwrap_err();
        match mode {
            0 => assert!(matches!(error, Error::InvalidReceipt)),
            _ => assert!(matches!(error, Error::CommittedButUnavailable { .. })),
        }
        assert!(writer.is_stopped());
    }
}

#[test]
fn final_native_failure_preserves_accepted_commit_classification() {
    let (_root, mut writer, _plan) = setup();
    let prepared = noop_prepared(0, 1);
    let receipt = CommitReceipt {
        ticket: prepared.write().ticket.clone(),
        sequence: 1,
    };
    writer.state.borrow_mut().resolution = Some(Resolution::Accepted {
        receipt: receipt.clone(),
        image: prepared.accepted(&receipt).unwrap(),
    });
    writer.stopped = true;
    let error = writer.finish(Err(Error::InvalidSql)).unwrap_err();
    match error {
        Error::CommittedButUnavailable { receipt: observed } => assert_eq!(*observed, receipt),
        other => panic!("wrong classification: {other:?}"),
    }
    assert!(writer.is_stopped());
    assert_eq!(writer.image().head().revision, 0);
    assert!(matches!(writer.finish(Ok(())), Err(Error::OutcomeUnknown)));
    assert!(matches!(
        writer.finish(Err(Error::InvalidSql)),
        Err(Error::InvalidSql)
    ));
    let prepared = noop_prepared(0, 2);
    let receipt = CommitReceipt {
        ticket: prepared.write().ticket.clone(),
        sequence: 1,
    };
    writer.state.borrow_mut().attempt = Some(Attempt {
        base: image(),
        ticket: ticket(0, 2),
        fingerprint: [0; 32],
        result: vec![255],
    });
    writer.state.borrow_mut().resolution = Some(Resolution::Accepted {
        receipt: receipt.clone(),
        image: prepared.accepted(&receipt).unwrap(),
    });
    assert!(matches!(
        writer.finish(Ok(())),
        Err(Error::CommittedButUnavailable { .. })
    ));
    assert_eq!(writer.image().head().revision, 0);
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
fn gate_without_attempt_and_repeated_callback_cannot_publish() {
    let plan = Rc::new(RefCell::new(Plan::default()));
    let mut state = GateState::new(Gate(plan.clone()), limits());
    assert!(!state.decide_caught(PageBatch {
        size_after: 0,
        pages: vec![]
    }));
    assert!(matches!(
        state.take_error(Error::Stopped),
        Error::InvalidSql
    ));
    state.attempt = Some(Attempt {
        base: image(),
        ticket: ticket(0, 1),
        fingerprint: [4; 32],
        result: empty_result(),
    });
    assert!(!state.decide_caught(PageBatch {
        size_after: 1,
        pages: vec![]
    }));
    assert!(matches!(state.take_error(Error::Stopped), Error::Image(_)));
    assert!(state.decide_caught(PageBatch {
        size_after: 0,
        pages: vec![]
    }));
    assert!(!state.decide_caught(PageBatch {
        size_after: 0,
        pages: vec![]
    }));
    assert!(matches!(
        state.take_error(Error::Stopped),
        Error::CommittedButUnavailable { .. }
    ));
    assert_eq!(plan.borrow().writes.len(), 1);
    assert!(matches!(state.take_error(Error::Stopped), Error::Stopped));
    let prepared = noop_prepared(0, 1);
    state.resolution = Some(Resolution::Replay {
        receipt: CommitReceipt {
            ticket: prepared.write().ticket.clone(),
            sequence: 1,
        },
        result: empty_result(),
    });
    assert!(matches!(
        state.take_error(Error::Stopped),
        Error::CommittedButUnavailable { .. }
    ));
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
    let cases = [
        (ValueRef::Null, Value::Null),
        (ValueRef::Integer(-1), Value::Integer(-1)),
        (ValueRef::Real(1.5), Value::Real(1.5)),
        (ValueRef::Text(b"x"), Value::Text("x".into())),
        (ValueRef::Blob(b"y"), Value::Blob(vec![b'y'])),
    ];
    for (input, expected) in cases {
        assert_eq!(
            sql::copy_value(input, &mut 100, limits()).unwrap(),
            expected
        );
        assert!(matches!(
            sql::copy_value(input, &mut 0, limits()),
            Err(Error::ResultLimit)
        ));
    }
    assert!(matches!(
        sql::copy_value(ValueRef::Text(&[255]), &mut 100, limits()),
        Err(Error::InvalidSql)
    ));
    let mut small = limits();
    small.sql.max_value_bytes = 1;
    for value in [ValueRef::Text(b"xx"), ValueRef::Blob(b"yy")] {
        assert!(matches!(
            sql::copy_value(value, &mut 100, small),
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
            sql::copy_value(value, &mut 1, limits()),
            Err(Error::ResultLimit)
        ));
    }
}

#[test]
fn vm_exhaustion_in_result_counters_never_reaches_consensus() {
    let mut successes = 0;
    let mut failures = 0;
    for budget in 1..40 {
        let (_root, mut writer, plan) = setup();
        writer.limits.max_vm_steps = budget;
        match writer.execute(ticket(0, 1), &[statement("SELECT 1")]) {
            Ok(completed) => {
                successes += 1;
                assert_eq!(
                    completed.result.statements[0].rows,
                    vec![vec![Value::Integer(1)]]
                );
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
        writer.execute(ticket(0, 1), &[statement("CREATE TABLE x(n)")]),
        Err(Error::Sqlite(_))
    ));
    assert!(plan.borrow().writes.is_empty());
    assert!(writer.is_stopped());
}

#[test]
fn accepted_but_invalid_sqlite_images_are_never_opened_for_execution() {
    let root = tempfile::tempdir().unwrap();
    let mut page = vec![0; PAGE_SIZE];
    page[..16].copy_from_slice(b"SQLite format 3\0");
    page[16] = 0x10;
    let prepared = image()
        .prepare(
            ticket(0, 1),
            PageBatch {
                size_after: 1,
                pages: vec![PageChange {
                    number: 1,
                    bytes: page,
                }],
            },
        )
        .unwrap();
    let receipt = CommitReceipt {
        ticket: prepared.write().ticket.clone(),
        sequence: 1,
    };
    let bad = prepared.accepted(&receipt).unwrap();
    assert!(
        SqliteWriter::create_new(&root.path().join("bad"), bad, limits(), Gate(Rc::default()))
            .is_err()
    );
    let path = root.path().join("too_large.sqlite");
    let plain = libsql_sys::rusqlite::Connection::open(&path).unwrap();
    plain.execute_batch("CREATE TABLE x(n)").unwrap();
    drop(plain);
    let state = Rc::new(RefCell::new(GateState::new(Gate(Rc::default()), limits())));
    assert!(matches!(
        sql::open(&path, GateWal::new(state), limits(), 1),
        Err(Error::InvalidImage)
    ));
}
