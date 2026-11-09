use super::*;
use std::mem::size_of;

fn limits() -> SqlLimits {
    SqlLimits {
        max_statements: 256,
        max_sql_bytes: 4096,
        max_parameters: 128,
        max_columns: 64,
        max_rows: 10000,
        max_result_bytes: 1024 * 1024,
        max_value_bytes: 256 * 1024,
    }
}

fn result(rows: Vec<Vec<Value>>, columns: Vec<String>) -> TransactionResult {
    TransactionResult {
        statements: vec![StatementResult {
            columns,
            rows,
            affected_rows: u64::MAX,
            last_insert_rowid: i64::MIN,
        }],
    }
}

#[test]
fn one_null_charges_owned_containers_not_just_its_wire_tag() {
    let original = result(vec![vec![Value::Null]], vec!["x".into()]);
    let bytes = encode_result(&original, limits()).unwrap();
    let exact = (size_of::<TransactionResult>()
        + size_of::<StatementResult>()
        + size_of::<String>()
        + 1
        + size_of::<Vec<Value>>()
        + size_of::<Value>()) as u64;
    assert!(exact > bytes.len() as u64);
    assert_eq!(
        decode_result_with_memory_limit(&bytes, limits(), exact).unwrap(),
        original
    );
    assert_eq!(
        decode_result_with_memory_limit(&bytes, limits(), exact - 1),
        Err(SqlError::ResourceExhausted)
    );
    validate_result(&bytes, limits()).unwrap();
    assert_eq!(decode_result(&bytes, limits()).unwrap(), original);
}

#[test]
fn short_row_amplification_is_bounded_without_reclassifying_the_format() {
    let original = result(vec![vec![Value::Null]; 1024], vec![String::new()]);
    let bytes = encode_result(&original, limits()).unwrap();
    assert!(bytes.len() < 2048);
    assert_eq!(
        decode_result_with_memory_limit(&bytes, limits(), 8192),
        Err(SqlError::ResourceExhausted)
    );
    validate_result(&bytes, limits()).unwrap();
    assert_eq!(decode_result(&bytes, limits()).unwrap(), original);
}

#[test]
fn metadata_payloads_and_multiple_statements_share_one_budget() {
    let mut original = result(
        vec![vec![
            Value::Text("英".repeat(1000)),
            Value::Blob(vec![0, 255, 1, 2]),
            Value::Integer(i64::MIN),
            Value::Real(-0.0),
            Value::Null,
        ]],
        vec!["name".repeat(256); 5],
    );
    original.statements.push(original.statements[0].clone());
    let bytes = encode_result(&original, limits()).unwrap();
    assert_eq!(
        decode_result_with_memory_limit(&bytes, limits(), 12000),
        Err(SqlError::ResourceExhausted)
    );
    assert_eq!(
        decode_result_with_memory_limit(&bytes, limits(), 32768).unwrap(),
        original
    );
    let decoded = decode_result(&bytes, limits()).unwrap();
    assert_eq!(encode_result(&decoded, limits()).unwrap(), bytes);
}

#[test]
fn empty_result_still_requires_its_root_and_never_disables_the_budget() {
    let original = TransactionResult { statements: vec![] };
    let bytes = encode_result(&original, limits()).unwrap();
    for budget in [0, size_of::<TransactionResult>() as u64 - 1] {
        assert_eq!(
            decode_result_with_memory_limit(&bytes, limits(), budget),
            Err(SqlError::ResourceExhausted)
        );
    }
    assert_eq!(
        decode_result_with_memory_limit(&bytes, limits(), size_of::<TransactionResult>() as u64,)
            .unwrap(),
        original
    );
}

#[test]
fn malformed_large_count_does_not_request_a_large_row_allocation() {
    let mut bytes = b"SCAPRES1".to_vec();
    for n in [1u32, 1, 0, u32::MAX] {
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    let mut maximum = limits();
    maximum.max_rows = u32::MAX;
    assert_eq!(
        decode_result_with_memory_limit(&bytes, maximum, 1024),
        Err(SqlError::Malformed)
    );
}
