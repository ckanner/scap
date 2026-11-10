use super::*;
use std::mem::size_of;

fn one_null_graph_bytes() -> u64 {
    (size_of::<TransactionResult>()
        + size_of::<scap_sql::StatementResult>()
        + size_of::<String>()
        + 1 // the column name "x"
        + size_of::<Vec<Value>>()
        + size_of::<Value>()) as u64
}

#[test]
fn typed_result_budget_is_independent_of_wire_and_native_cache_limits() {
    let mut invalid = limits();
    invalid.result_memory_bytes = 0;
    assert!(matches!(
        sql::validate_limits(invalid),
        Err(Error::InvalidLimits)
    ));
    for read_only in [false, true] {
        for admitted in [false, true] {
            let (_root, mut writer, plan) = setup();
            writer.limits.result_memory_bytes = one_null_graph_bytes() - u64::from(!admitted);
            let statements = [statement("SELECT NULL AS x")];
            let result = if read_only {
                writer.query(&statements, uninterrupted())
            } else {
                writer.execute(&statements, uninterrupted())
            };
            if admitted {
                let result = result.unwrap();
                assert_eq!(result.statements[0].rows, vec![vec![Value::Null]]);
                assert!(!writer.is_stopped());
                assert_eq!(plan.borrow().writes.len(), usize::from(!read_only));
            } else {
                assert!(matches!(result, Err(Error::ResourceExhausted)));
                assert!(writer.is_stopped());
                assert!(writer.connection.is_autocommit());
                assert!(plan.borrow().writes.is_empty());
            }
        }
    }
}

#[test]
fn zero_rows_still_charge_column_names_and_statement_containers() {
    let metadata = (size_of::<TransactionResult>()
        + size_of::<scap_sql::StatementResult>()
        + size_of::<String>()
        + 1) as u64;
    for budget in [
        1,
        size_of::<TransactionResult>() as u64,
        (size_of::<TransactionResult>() + size_of::<scap_sql::StatementResult>()) as u64,
        metadata - 1,
    ] {
        let (_root, mut writer, plan) = setup();
        writer.limits.result_memory_bytes = budget;
        assert!(matches!(
            writer.query(&[statement("SELECT 1 AS x WHERE 0")], uninterrupted()),
            Err(Error::ResourceExhausted)
        ));
        assert!(plan.borrow().writes.is_empty());
        assert!(writer.is_stopped());
    }
    let (_root, mut writer, _plan) = setup();
    writer.limits.result_memory_bytes = metadata;
    let result = writer
        .query(&[statement("SELECT 1 AS x WHERE 0")], uninterrupted())
        .unwrap();
    assert_eq!(result.statements[0].columns, ["x"]);
    assert!(result.statements[0].rows.is_empty());
}

#[test]
fn column_length_prefixes_exhaust_wire_budget_even_without_rows() {
    let (_root, mut writer, plan) = setup();
    writer.limits.sql.max_result_bytes = 13;
    assert!(matches!(
        writer.query(
            &[statement("SELECT 1 AS a,2 AS b,3 AS c WHERE 0")],
            uninterrupted()
        ),
        Err(Error::ResultLimit)
    ));
    assert!(writer.is_stopped());
    assert!(writer.connection.is_autocommit());
    assert!(plan.borrow().writes.is_empty());
}

#[test]
fn cumulative_statements_cannot_reuse_the_same_result_budget() {
    let root = size_of::<TransactionResult>() as u64;
    let exact = root + 2 * (one_null_graph_bytes() - root);
    let statements = [statement("SELECT NULL AS x"), statement("SELECT NULL AS x")];
    for read_only in [false, true] {
        for budget in [exact - 1, exact] {
            let (_root, mut writer, plan) = setup();
            writer.limits.result_memory_bytes = budget;
            let result = if read_only {
                writer.query(&statements, uninterrupted())
            } else {
                writer.execute(&statements, uninterrupted())
            };
            if budget == exact {
                assert_eq!(result.unwrap().statements.len(), 2);
                assert!(!writer.is_stopped());
                assert_eq!(plan.borrow().writes.len(), usize::from(!read_only));
            } else {
                assert!(matches!(result, Err(Error::ResourceExhausted)));
                assert!(writer.is_stopped());
                assert!(plan.borrow().writes.is_empty());
            }
        }
    }
}

#[test]
fn native_collection_and_committed_decode_use_the_same_known_shape_reservations() {
    let (_root, mut writer, plan) = setup();
    writer.limits.result_memory_bytes = (size_of::<TransactionResult>()
        + size_of::<scap_sql::StatementResult>()
        + 3 * size_of::<String>()
        + 3
        + size_of::<Vec<Value>>()
        + 3 * size_of::<Value>()) as u64;
    let result = writer
        .execute(
            &[statement("SELECT NULL AS a,NULL AS b,NULL AS c")],
            uninterrupted(),
        )
        .unwrap();
    assert_eq!(result.statements[0].rows, vec![vec![Value::Null; 3]]);
    assert_eq!(plan.borrow().writes.len(), 1);
    assert!(!writer.is_stopped());
}

#[test]
fn null_and_short_row_amplification_fails_before_native_or_remote_publication() {
    let sql = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) SELECT NULL AS a,NULL AS b FROM n";
    let (_root, mut writer, plan) = setup();
    let result = writer.query(&[statement(sql)], uninterrupted()).unwrap();
    assert!(
        scap_sql::encode_result(&result, writer.limits.sql)
            .unwrap()
            .len()
            < 8192
    );
    assert_eq!(result.statements[0].rows.len(), 1000);
    writer.limits.result_memory_bytes = 16 * 1024;
    assert!(matches!(
        writer.execute(&[statement(sql)], uninterrupted()),
        Err(Error::ResourceExhausted)
    ));
    assert!(writer.connection.is_autocommit());
    assert!(writer.is_stopped());
    assert!(plan.borrow().writes.is_empty());
}

#[test]
fn rejected_returning_payload_rolls_back_prior_sql_and_never_reaches_the_gate() {
    for expression in ["zeroblob(500)", "printf('%0500d',1)"] {
        let (_root, mut writer, plan) = setup();
        writer
            .execute(&[statement("CREATE TABLE x(n)")], uninterrupted())
            .unwrap();
        let original = plan.borrow().writes[0].clone();
        writer.limits.result_memory_bytes = 400;
        let sql = format!("INSERT INTO x VALUES(1) RETURNING {expression} AS x");
        assert!(matches!(
            writer.execute(&[statement(&sql)], uninterrupted()),
            Err(Error::ResourceExhausted)
        ));
        assert!(writer.is_stopped());
        assert!(writer.connection.is_autocommit());
        assert_eq!(
            writer
                .connection
                .query_row::<u64, _, _>("SELECT count(*) FROM x", [], |row| row.get(0))
                .unwrap(),
            0
        );
        assert_eq!(plan.borrow().writes, [original]);
    }
}

#[test]
fn result_growth_reserves_the_new_rows_buffer_while_the_old_one_is_live() {
    let fixed = (size_of::<TransactionResult>()
        + size_of::<scap_sql::StatementResult>()
        + size_of::<String>()
        + 1) as u64;
    let row = size_of::<Vec<Value>>() as u64;
    let value = size_of::<Value>() as u64;
    let final_size = fixed + 4 * row + 3 * value;
    let growth_peak = fixed + (2 + 4) * row + 2 * value;
    assert!(growth_peak > final_size);
    for budget in [final_size, growth_peak] {
        let (_root, mut writer, plan) = setup();
        writer.limits.result_memory_bytes = budget;
        let result = writer.query(
            &[statement(
                "SELECT NULL AS x UNION ALL SELECT NULL UNION ALL SELECT NULL",
            )],
            uninterrupted(),
        );
        if budget == growth_peak {
            assert_eq!(result.unwrap().statements[0].rows.len(), 3);
        } else {
            assert!(matches!(result, Err(Error::ResourceExhausted)));
        }
        assert!(plan.borrow().writes.is_empty());
    }
}

#[test]
fn confirmed_result_materialization_failure_does_not_reclassify_the_commit() {
    let (_root, mut writer, plan) = setup();
    writer
        .execute(&[statement("SELECT NULL AS x")], uninterrupted())
        .unwrap();
    let confirmed = plan.borrow().writes[0].1.clone();
    writer.limits.result_memory_bytes = 1;
    writer.stopped = true;
    writer.state.borrow_mut().attempt = Some(Attempt {
        base_pages: 0,
        result: confirmed.clone(),
    });
    writer.state.borrow_mut().resolution = Some(Resolution::Accepted(0));
    assert!(matches!(
        writer.finish(Ok(()), &uninterrupted()),
        Err(Error::CommittedButUnavailable)
    ));
    assert!(writer.is_stopped());
    assert_eq!(plan.borrow().writes[0].1, confirmed);
    scap_sql::validate_result(&confirmed, limits().sql).unwrap();
}

#[test]
fn scalar_payload_checks_preserve_wire_errors_and_memory_errors_separately() {
    for value in [ValueRef::Text(b"x"), ValueRef::Blob(b"x")] {
        let mut memory = ResultMemoryBudget::new(4096).unwrap();
        assert!(matches!(
            sql::copy_value(value, &mut 5, limits(), &mut memory),
            Err(Error::ResultLimit)
        ));
        let mut memory = ResultMemoryBudget::new(size_of::<TransactionResult>() as u64).unwrap();
        assert!(matches!(
            sql::copy_value(value, &mut 100, limits(), &mut memory),
            Err(Error::ResourceExhausted)
        ));
    }
}
