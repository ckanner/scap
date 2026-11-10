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

fn values() -> Vec<Value> {
    vec![
        Value::Null,
        Value::Integer(i64::MIN),
        Value::Real(-0.0),
        Value::Text("原结果\0".into()),
        Value::Blob(vec![0, 255, 1]),
    ]
}

#[test]
fn version_one_request_and_result_have_fixed_wire_vectors() {
    let statement = Statement {
        sql: "SELECT ?1".into(),
        parameters: vec![Value::Integer(42)],
    };
    // Independently assembled little-endian protocol vectors. A codec change
    // must not silently change persisted results or request identity under v1.
    assert_eq!(
        request_fingerprint(&[statement], limits()).unwrap(),
        [
            181, 79, 46, 113, 131, 174, 197, 229, 175, 216, 13, 209, 244, 10, 194, 27, 109, 179,
            35, 43, 0, 112, 147, 108, 168, 209, 235, 144, 90, 195, 213, 187
        ]
    );
    let result = TransactionResult {
        statements: vec![StatementResult {
            columns: vec!["x".into()],
            rows: vec![vec![Value::Integer(42)]],
            affected_rows: 1,
            last_insert_rowid: 7,
        }],
    };
    let wire = [
        83, 67, 65, 80, 82, 69, 83, 49, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 120, 1, 0, 0, 0, 1, 42,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(encode_result(&result, limits()).unwrap(), wire);
    let plan = plan_result(&result, limits()).unwrap();
    assert_eq!(plan.encoded_len(), wire.len());
    let mut destination = vec![0xa5; wire.len() + 2];
    let backing = destination.as_ptr();
    plan.write_exact(&mut destination[1..wire.len() + 1])
        .unwrap();
    assert_eq!(destination.as_ptr(), backing);
    assert_eq!(destination[0], 0xa5);
    assert_eq!(destination[wire.len() + 1], 0xa5);
    assert_eq!(destination[1..wire.len() + 1], wire);
    assert_eq!(decode_result(&wire, limits()).unwrap(), result);
}

fn request() -> Vec<Statement> {
    vec![Statement {
        sql: "INSERT INTO items VALUES(?1,?2,?3,?4,?5) RETURNING *".into(),
        parameters: values(),
    }]
}

fn result() -> TransactionResult {
    TransactionResult {
        statements: vec![
            StatementResult {
                columns: vec!["n".into(), "i".into(), "r".into(), "文".into(), "b".into()],
                rows: vec![values()],
                affected_rows: 7,
                last_insert_rowid: -99,
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

#[test]
fn typed_results_round_trip_exactly_and_keep_signed_zero() {
    let value = result();
    let bytes = encode_result(&value, limits()).unwrap();
    let decoded = decode_result(&bytes, limits()).unwrap();
    assert_eq!(decoded, value);
    let Value::Real(real) = decoded.statements[0].rows[0][2] else {
        panic!("real lost its type");
    };
    assert_eq!(real.to_bits(), (-0.0_f64).to_bits());
    assert_eq!(encode_result(&decoded, limits()).unwrap(), bytes);
    let empty = TransactionResult { statements: vec![] };
    let encoded = encode_result(&empty, limits()).unwrap();
    assert_eq!(encoded, b"SCAPRES1\0\0\0\0");
    assert_eq!(plan_result(&empty, limits()).unwrap().encoded_len(), 12);
    assert_eq!(decode_result(&encoded, limits()).unwrap(), empty);
}

#[test]
fn counted_results_use_one_exact_reservation_after_complete_validation() {
    let original = result();
    // Header 12; first statement 93 (all five typed values, UTF-8 and NUL);
    // second statement 24, including both result metadata integers.
    assert_eq!(plan_result(&original, limits()).unwrap().encoded_len(), 129);
    let mut allocations = 0;
    let bytes = encode_result_with(&original, limits(), &mut |destination, required| {
        allocations += 1;
        assert!(destination.is_empty());
        assert_eq!(destination.capacity(), 0);
        assert_eq!(required, 129);
        destination.try_reserve_exact(required)
    })
    .unwrap();
    assert_eq!(allocations, 1);
    assert_eq!(bytes.len(), 129);
    // The repository pins Rust 1.90's exact RawVec reservation. This is a
    // backing-capacity check, not a claim about malloc/RSS rounding.
    assert_eq!(bytes.capacity(), bytes.len());
    assert_eq!(decode_result(&bytes, limits()).unwrap(), original);

    let mut invalid = original;
    invalid.statements[0].rows[0].pop();
    assert_eq!(
        encode_result_with(&invalid, limits(), &mut |_, _| {
            panic!("an invalid graph must fail before any output reservation")
        }),
        Err(SqlError::Invalid)
    );
}

#[test]
fn exact_destination_mismatch_never_writes_a_partial_prefix() {
    let original = result();
    let plan = plan_result(&original, limits()).unwrap();
    for length in [0, plan.encoded_len() - 1, plan.encoded_len() + 1] {
        let mut destination = vec![0xa5; length];
        assert_eq!(plan.write_exact(&mut destination), Err(SqlError::Invalid));
        assert!(destination.iter().all(|byte| *byte == 0xa5));
    }
    let mut destination = vec![0xa5; plan.encoded_len()];
    plan.write_exact(&mut destination).unwrap();
    assert_eq!(decode_result(&destination, limits()).unwrap(), original);
}

#[test]
fn original_limit_and_invalid_precedence_also_holds_in_counting_pass() {
    for row in [vec![Value::Real(f64::INFINITY)], vec![]] {
        let original = TransactionResult {
            statements: vec![StatementResult {
                columns: vec!["x".into()],
                rows: vec![row],
                affected_rows: 0,
                last_insert_rowid: 0,
            }],
        };
        // The row-count field ends at byte 25. The old emitter hits the
        // smaller wire limit before inspecting either malformed row/value.
        for (maximum, expected) in [(24, SqlError::Limit), (25, SqlError::Invalid)] {
            let mut configuration = limits();
            configuration.max_result_bytes = maximum;
            assert_eq!(plan_result(&original, configuration).err(), Some(expected));
            assert_eq!(
                encode_result_with(&original, configuration, &mut |_, _| {
                    panic!("count/validation failure must precede allocation")
                }),
                Err(expected)
            );
        }
    }
    let malformed = TransactionResult {
        statements: vec![StatementResult {
            columns: vec![],
            rows: vec![vec![]],
            affected_rows: 0,
            last_insert_rowid: 0,
        }],
    };
    let mut configuration = limits();
    configuration.max_result_bytes = 12;
    // This shape was rejected before attempting even the first column count.
    assert_eq!(
        plan_result(&malformed, configuration).err(),
        Some(SqlError::Invalid)
    );
}

#[test]
fn refused_result_allocation_is_resource_exhaustion_without_retry() {
    let original = result();
    let mut attempts = 0;
    let encoded = encode_result_with(&original, limits(), &mut |destination, required| {
        attempts += 1;
        assert_eq!(required, 129);
        assert!(destination.is_empty());
        assert_eq!(destination.capacity(), 0);
        // Capacity overflow returns a real TryReserveError without attempting
        // a large allocation or changing any process/global allocator state.
        Vec::<u8>::new().try_reserve_exact(usize::MAX)
    });
    assert_eq!(attempts, 1);
    assert_eq!(encoded, Err(SqlError::ResourceExhausted));
    assert_eq!(plan_result(&original, limits()).unwrap().encoded_len(), 129);
}

#[test]
fn fingerprint_is_typed_ordered_and_independent_of_physical_pages() {
    let original = request();
    let expected = request_fingerprint(&original, limits()).unwrap();
    assert_eq!(request_fingerprint(&original, limits()).unwrap(), expected);
    let mut changed = original.clone();
    changed[0].sql.push(' ');
    assert_ne!(request_fingerprint(&changed, limits()).unwrap(), expected);
    changed = original.clone();
    changed[0].parameters[0] = Value::Text(String::new());
    assert_ne!(request_fingerprint(&changed, limits()).unwrap(), expected);
    changed = original.clone();
    changed[0].parameters[2] = Value::Real(0.0);
    assert_ne!(request_fingerprint(&changed, limits()).unwrap(), expected);
    changed = original.clone();
    changed[0].parameters.swap(0, 1);
    assert_ne!(request_fingerprint(&changed, limits()).unwrap(), expected);
    changed = original.clone();
    changed.push(original[0].clone());
    assert_ne!(request_fingerprint(&changed, limits()).unwrap(), expected);
    assert_eq!(request_fingerprint(&[], limits()), Err(SqlError::Limit));
}

#[test]
fn zero_limits_and_short_result_envelopes_are_configuration_errors() {
    let mut configurations = Vec::new();
    let mut value = limits();
    value.max_statements = 0;
    configurations.push(value);
    value = limits();
    value.max_sql_bytes = 0;
    configurations.push(value);
    value = limits();
    value.max_parameters = 0;
    configurations.push(value);
    value = limits();
    value.max_columns = 0;
    configurations.push(value);
    value = limits();
    value.max_rows = 0;
    configurations.push(value);
    value = limits();
    value.max_result_bytes = 11;
    configurations.push(value);
    value = limits();
    value.max_value_bytes = 0;
    configurations.push(value);
    for configuration in configurations {
        assert_eq!(configuration.validate(), Err(SqlError::Invalid));
        assert_eq!(
            validate_statements(&request(), configuration),
            Err(SqlError::Invalid)
        );
        assert_eq!(
            encode_result(&result(), configuration),
            Err(SqlError::Invalid)
        );
        assert_eq!(
            decode_result(b"SCAPRES1\0\0\0\0", configuration),
            Err(SqlError::Invalid)
        );
    }
    assert_eq!(limits().validate(), Ok(()));
}

#[test]
fn request_limits_are_per_transaction_and_per_value_as_declared() {
    let mut configuration = limits();
    configuration.max_statements = 1;
    let original = request();
    assert_eq!(
        validate_statements(&[original[0].clone(), original[0].clone()], configuration),
        Err(SqlError::Limit)
    );
    for sql in ["", "SELECT\0 1"] {
        assert_eq!(
            validate_statements(
                &[Statement {
                    sql: sql.into(),
                    parameters: vec![]
                }],
                limits()
            ),
            Err(SqlError::Invalid)
        );
    }
    configuration = limits();
    configuration.max_sql_bytes = original[0].sql.len() as u32;
    assert_eq!(validate_statements(&original, configuration), Ok(()));
    assert_eq!(
        validate_statements(&[original[0].clone(), original[0].clone()], configuration),
        Err(SqlError::Limit)
    );
    configuration = limits();
    configuration.max_parameters = 4;
    assert_eq!(
        validate_statements(&original, configuration),
        Err(SqlError::Limit)
    );
    for value in [Value::Text("x".repeat(129)), Value::Blob(vec![0; 129])] {
        assert_eq!(
            validate_statements(
                &[Statement {
                    sql: "SELECT ?1".into(),
                    parameters: vec![value]
                }],
                limits()
            ),
            Err(SqlError::Limit)
        );
    }
    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            validate_statements(
                &[Statement {
                    sql: "SELECT ?1".into(),
                    parameters: vec![Value::Real(number)]
                }],
                limits()
            ),
            Err(SqlError::Invalid)
        );
    }
    assert_eq!(
        validate_statements(
            &[Statement {
                sql: "SELECT 1".into(),
                parameters: vec![]
            }],
            limits()
        ),
        Ok(())
    );
}

#[test]
fn every_encoded_byte_budget_is_enforced_without_partial_result() {
    let value = result();
    let bytes = encode_result(&value, limits()).unwrap();
    for maximum in 12..bytes.len() {
        let mut configuration = limits();
        configuration.max_result_bytes = maximum as u32;
        assert_eq!(encode_result(&value, configuration), Err(SqlError::Limit));
        assert_eq!(decode_result(&bytes, configuration), Err(SqlError::Limit));
    }
    let mut configuration = limits();
    configuration.max_result_bytes = bytes.len() as u32;
    assert_eq!(encode_result(&value, configuration).unwrap(), bytes);
    assert_eq!(decode_result(&bytes, configuration).unwrap(), value);
}

#[test]
fn result_shape_and_limits_are_validated_before_encoding() {
    let mut configuration = limits();
    configuration.max_statements = 1;
    assert_eq!(
        encode_result(&result(), configuration),
        Err(SqlError::Limit)
    );
    configuration = limits();
    configuration.max_columns = 4;
    assert_eq!(
        encode_result(&result(), configuration),
        Err(SqlError::Limit)
    );
    let mut value = result();
    value.statements[1] = value.statements[0].clone();
    configuration = limits();
    configuration.max_rows = 1;
    assert_eq!(encode_result(&value, configuration), Err(SqlError::Limit));
    value = result();
    value.statements[0].columns[0] = "x".repeat(129);
    assert_eq!(encode_result(&value, limits()), Err(SqlError::Limit));
    value = result();
    value.statements[0].rows[0].pop();
    assert_eq!(encode_result(&value, limits()), Err(SqlError::Invalid));
    value = result();
    value.statements[1].rows.push(vec![]);
    assert_eq!(encode_result(&value, limits()), Err(SqlError::Invalid));
    value = result();
    value.statements[0].rows[0][0] = Value::Real(f64::INFINITY);
    assert_eq!(encode_result(&value, limits()), Err(SqlError::Invalid));
    value.statements[0].rows[0][0] = Value::Blob(vec![0; 129]);
    assert_eq!(encode_result(&value, limits()), Err(SqlError::Limit));
}

#[test]
fn truncated_bad_version_and_trailing_results_are_rejected() {
    let bytes = encode_result(&result(), limits()).unwrap();
    for end in 0..bytes.len() {
        assert_eq!(
            decode_result(&bytes[..end], limits()),
            Err(SqlError::Malformed)
        );
    }
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Malformed));
    changed = bytes.clone();
    changed.push(0);
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Malformed));
    changed = bytes.clone();
    changed[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Limit));
    changed = bytes.clone();
    changed[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Limit));
    changed = bytes.clone();
    changed[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Limit));
    changed = bytes;
    changed[20] = 255;
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Malformed));
}

#[test]
fn malicious_rows_and_value_tags_cannot_allocate_from_untrusted_counts() {
    let mut bytes = b"SCAPRES1".to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    assert_eq!(decode_result(&bytes, limits()), Err(SqlError::Malformed));
    bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_result(&bytes, limits()), Err(SqlError::Limit));
    let simple = TransactionResult {
        statements: vec![StatementResult {
            columns: vec!["x".into()],
            rows: vec![vec![Value::Null]],
            affected_rows: 0,
            last_insert_rowid: 0,
        }],
    };
    let original = encode_result(&simple, limits()).unwrap();
    let mut changed = original.clone();
    changed[25] = 255;
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Malformed));
    changed = original[..25].to_vec();
    changed.push(2);
    changed.extend_from_slice(&f64::NAN.to_bits().to_le_bytes());
    changed.extend_from_slice(&[0; 16]);
    assert_eq!(decode_result(&changed, limits()), Err(SqlError::Invalid));
    for tag in [3, 4] {
        changed = original[..25].to_vec();
        changed.push(tag);
        changed.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_result(&changed, limits()), Err(SqlError::Limit));
    }
}
