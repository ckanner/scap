use super::*;

fn limits() -> SqlLimits {
    SqlLimits {
        max_statements: 8,
        max_sql_bytes: 1024,
        max_parameters: 16,
        max_columns: 16,
        max_rows: 32,
        max_result_bytes: 4096,
        max_value_bytes: 128,
    }
}

fn example() -> TransactionResult {
    TransactionResult {
        statements: vec![
            StatementResult {
                columns: vec!["n".into(), "i".into(), "r".into(), "文".into(), "b".into()],
                rows: vec![vec![
                    Value::Null,
                    Value::Integer(i64::MIN),
                    Value::Real(-0.0),
                    Value::Text("原结果\0".into()),
                    Value::Blob(vec![0, 255, 1]),
                ]],
                affected_rows: u64::MAX,
                last_insert_rowid: i64::MIN,
            },
            StatementResult {
                columns: vec![],
                rows: vec![],
                affected_rows: 0,
                last_insert_rowid: i64::MAX,
            },
        ],
    }
}

fn assert_equivalent(bytes: &[u8], configuration: SqlLimits) {
    assert_eq!(
        validate_result(bytes, configuration),
        decode_result(bytes, configuration).map(|_| ()),
        "scanner and decoder disagree on {bytes:?}"
    );
}

fn one_value(raw: &[u8]) -> Vec<u8> {
    // Independent wire assembly: one statement, column "x", one row.
    let mut bytes = b"SCAPRES1".to_vec();
    for value in [1_u32, 1, 1] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.push(b'x');
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(raw);
    bytes.extend_from_slice(&[0; 16]);
    bytes
}

#[test]
fn valid_typed_results_and_empty_envelopes_preserve_exact_bytes() {
    for result in [example(), TransactionResult { statements: vec![] }] {
        let bytes = encode_result(&result, limits()).unwrap();
        let before = bytes.clone();
        assert_eq!(validate_result(&bytes, limits()), Ok(()));
        assert_equivalent(&bytes, limits());
        assert_eq!(bytes, before);
        assert_eq!(
            encode_result(&decode_result(&bytes, limits()).unwrap(), limits()).unwrap(),
            bytes
        );
    }
}

#[test]
fn independently_encoded_v1_integer_vector_still_validates() {
    let mut raw = vec![1];
    raw.extend_from_slice(&42_i64.to_le_bytes());
    let bytes = one_value(&raw);
    assert_eq!(validate_result(&bytes, limits()), Ok(()));
    let decoded = decode_result(&bytes, limits()).unwrap();
    assert_eq!(decoded.statements[0].rows[0][0], Value::Integer(42));
}

#[test]
fn all_truncations_and_trailing_bytes_fail_like_the_decoder() {
    let bytes = encode_result(&example(), limits()).unwrap();
    for end in 0..bytes.len() {
        assert_eq!(validate_result(&bytes[..end], limits()), Err(SqlError::Malformed));
        assert_equivalent(&bytes[..end], limits());
    }
    for suffix in [vec![0], b"SCAPRES1\0\0\0\0".to_vec()] {
        let mut changed = bytes.clone();
        changed.extend_from_slice(&suffix);
        assert_eq!(validate_result(&changed, limits()), Err(SqlError::Malformed));
        assert_equivalent(&changed, limits());
    }
}

#[test]
fn every_single_byte_substitution_matches_existing_decode_classification() {
    let bytes = encode_result(&example(), limits()).unwrap();
    for index in 0..bytes.len() {
        for replacement in 0..=u8::MAX {
            let mut changed = bytes.clone();
            changed[index] = replacement;
            assert_equivalent(&changed, limits());
        }
    }
}

#[test]
fn invalid_configuration_is_not_confused_with_wire_corruption() {
    let configuration = limits();
    for changed in [
        SqlLimits { max_statements: 0, ..configuration },
        SqlLimits { max_sql_bytes: 0, ..configuration },
        SqlLimits { max_parameters: 0, ..configuration },
        SqlLimits { max_columns: 0, ..configuration },
        SqlLimits { max_rows: 0, ..configuration },
        SqlLimits { max_result_bytes: 11, ..configuration },
        SqlLimits { max_value_bytes: 0, ..configuration },
    ] {
        assert_eq!(validate_result(b"", changed), Err(SqlError::Invalid));
        assert_equivalent(b"", changed);
    }
}

#[test]
fn exact_byte_limits_and_every_result_budget_are_checked() {
    let bytes = encode_result(&example(), limits()).unwrap();
    for maximum in 12..=bytes.len() {
        let configuration = SqlLimits { max_result_bytes: maximum as u32, ..limits() };
        let expected = if maximum == bytes.len() { Ok(()) } else { Err(SqlError::Limit) };
        assert_eq!(validate_result(&bytes, configuration), expected);
        assert_equivalent(&bytes, configuration);
    }
    for configuration in [
        SqlLimits { max_statements: 1, ..limits() },
        SqlLimits { max_columns: 4, ..limits() },
        SqlLimits { max_value_bytes: 1, ..limits() },
    ] {
        assert_eq!(validate_result(&bytes, configuration), Err(SqlError::Limit));
        assert_equivalent(&bytes, configuration);
    }
    let mut result = example();
    result.statements[1] = result.statements[0].clone();
    let bytes = encode_result(&result, limits()).unwrap();
    let configuration = SqlLimits { max_rows: 1, ..limits() };
    assert_eq!(validate_result(&bytes, configuration), Err(SqlError::Limit));
    assert_equivalent(&bytes, configuration);
}

#[test]
fn counts_never_preallocate_and_zero_width_rows_are_invalid() {
    let mut zero_columns = b"SCAPRES1".to_vec();
    for value in [1_u32, 0, 1] {
        zero_columns.extend_from_slice(&value.to_le_bytes());
    }
    zero_columns.extend_from_slice(&[0; 16]);
    assert_eq!(validate_result(&zero_columns, limits()), Err(SqlError::Malformed));
    assert_equivalent(&zero_columns, limits());

    let huge = SqlLimits {
        max_statements: u32::MAX,
        max_columns: u32::MAX,
        max_rows: u32::MAX,
        ..limits()
    };
    let mut statement_bomb = b"SCAPRES1".to_vec();
    statement_bomb.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(validate_result(&statement_bomb, huge), Err(SqlError::Malformed));
    assert_equivalent(&statement_bomb, huge);

    let mut column_bomb = b"SCAPRES1".to_vec();
    column_bomb.extend_from_slice(&1_u32.to_le_bytes());
    column_bomb.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(validate_result(&column_bomb, huge), Err(SqlError::Malformed));
    assert_equivalent(&column_bomb, huge);

    let mut row_bomb = one_value(&[]);
    row_bomb[21..25].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(validate_result(&row_bomb, huge), Err(SqlError::Malformed));
    assert_equivalent(&row_bomb, huge);
}

#[test]
fn nonfinite_reals_unknown_tags_and_invalid_utf8_are_rejected() {
    for bits in [f64::NAN.to_bits(), f64::INFINITY.to_bits(), f64::NEG_INFINITY.to_bits()] {
        let mut raw = vec![2];
        raw.extend_from_slice(&bits.to_le_bytes());
        let bytes = one_value(&raw);
        assert_eq!(validate_result(&bytes, limits()), Err(SqlError::Invalid));
        assert_equivalent(&bytes, limits());
    }
    let text = one_value(&[3, 1, 0, 0, 0, 255]);
    let unknown = one_value(&[255]);
    let mut column = one_value(&[0]);
    column[20] = 255;
    for bytes in [text, unknown, column] {
        assert_eq!(validate_result(&bytes, limits()), Err(SqlError::Malformed));
        assert_equivalent(&bytes, limits());
    }
    // The same 0xff byte is valid opaque BLOB content, not text.
    assert_eq!(validate_result(&one_value(&[4, 1, 0, 0, 0, 255]), limits()), Ok(()));
}

#[test]
fn value_payload_limits_precede_missing_bytes_without_allocation() {
    for tag in [3, 4] {
        let mut raw = vec![tag];
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        let bytes = one_value(&raw);
        assert_eq!(validate_result(&bytes, limits()), Err(SqlError::Limit));
        assert_equivalent(&bytes, limits());
    }
}
