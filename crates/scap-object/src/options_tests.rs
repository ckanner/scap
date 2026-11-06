use super::*;

#[test]
fn production_defaults_and_unlimited_business_quota_are_real_engine_limits() {
    let defaults = Options::default();
    defaults.validate().unwrap();
    assert_eq!(defaults.quota.max_bytes, Some(10 * GIB));
    let writer = defaults.writer(&defaults.quota).unwrap();
    assert_eq!(writer.max_database_pages, 2_621_440);
    assert_eq!(writer.max_changed_pages, 16_384);
    assert_eq!(writer.cache_bytes, 64 * 1024 * 1024);
    assert_eq!(writer.sql.max_result_bytes, 50 * 1024 * 1024);
    assert_eq!(defaults.retention.max_entries, 4096);
    assert_eq!(defaults.retention.max_result_bytes, 256 * 1024 * 1024);

    let mut options = defaults.clone();
    options.quota.max_bytes = None;
    options.max_changed_pages = MAX_PAGES;
    options.cache_bytes = i32::MAX as u64 * 1024;
    options.sql = durable_sql_limits();
    options.operation_timeout = Duration::from_secs(86400);
    options.recovery_timeout = Duration::from_secs(7 * 86400);
    options.validate().unwrap();
    assert_eq!(
        options.writer(&options.quota).unwrap().max_database_pages,
        MAX_PAGES
    );
    let small = DatabaseQuota {
        max_bytes: Some(PAGE_SIZE as u64),
    };
    assert_eq!(options.writer(&small).unwrap().max_changed_pages, MAX_PAGES);
    assert!(matches!(
        options.writer(&DatabaseQuota { max_bytes: Some(1) }),
        Err(Error::Format(_))
    ));
}

#[test]
fn invalid_options_are_rejected_at_configuration_not_during_publication() {
    let mut bad = Options::default();
    bad.quota.max_bytes = Some(1);
    assert!(matches!(bad.validate(), Err(Error::Format(_))));
    bad = Options::default();
    bad.retention.max_entries = 0;
    assert!(matches!(bad.validate(), Err(Error::Format(_))));
    bad = Options::default();
    bad.sql.max_rows = 0;
    assert!(matches!(bad.validate(), Err(Error::Sql(_))));
    let mutations: Vec<fn(&mut Options)> = vec![
        |o| o.sql.max_statements = 65537,
        |o| o.sql.max_sql_bytes = MAX_REQUEST_BYTES as u32 + 1,
        |o| o.sql.max_parameters = 32767,
        |o| o.sql.max_columns = 2001,
        |o| o.sql.max_result_bytes = MAX_RESULT_BYTES as u32 + 1,
        |o| o.sql.max_value_bytes = MAX_RESULT_BYTES as u32 + 1,
        |o| o.max_input_bytes = 0,
        |o| o.max_input_bytes = MAX_REQUEST_BYTES + 1,
        |o| o.max_changed_pages = 0,
        |o| o.max_changed_pages = u32::MAX,
        |o| o.cache_bytes = PAGE_SIZE as u64 - 1,
        |o| o.cache_bytes = i32::MAX as u64 * 1024 + 1,
        |o| o.max_vm_steps = 0,
        |o| o.operation_timeout = Duration::ZERO,
        |o| o.operation_timeout = Duration::from_secs(86401),
        |o| o.recovery_timeout = Duration::ZERO,
        |o| o.recovery_timeout = Duration::from_secs(7 * 86400 + 1),
    ];
    for change in mutations {
        let mut options = Options::default();
        change(&mut options);
        assert!(
            matches!(options.validate(), Err(Error::Limit)),
            "{options:?}"
        );
    }
}

#[test]
fn independent_original_deadlines_and_aggregate_input_budget() {
    let options = Options::default();
    let original = Instant::now() + Duration::from_secs(1);
    assert_eq!(options.deadline(original, false), original);
    assert_eq!(options.deadline(original, true), original);
    let far = Instant::now() + Duration::from_secs(3600);
    assert!(options.deadline(far, false) <= Instant::now() + options.operation_timeout);
    assert!(options.deadline(far, true) <= Instant::now() + options.recovery_timeout);
    let statements = vec![Statement {
        sql: "SELECT ?, ?, ?, ?, ?".into(),
        parameters: vec![
            Value::Null,
            Value::Integer(1),
            Value::Real(1.0),
            Value::Text("文".into()),
            Value::Blob(vec![1, 2]),
        ],
    }];
    let expected = 12 + 8 + statements[0].sql.len() + 1 + 9 + 9 + 5 + 3 + 5 + 2;
    input_budget(&statements, expected).unwrap();
    assert!(matches!(
        input_budget(&statements, expected - 1),
        Err(Error::Limit)
    ));
    assert!(matches!(input_budget(&statements, 1), Err(Error::Limit)));
    assert!(matches!(input_budget(&statements, 19), Err(Error::Limit)));
    assert!(matches!(input_budget(&statements, 20), Err(Error::Limit)));
    let empty_values = vec![Statement {
        sql: "SELECT ?,?".into(),
        parameters: vec![Value::Text(String::new()), Value::Blob(vec![])],
    }];
    assert!(matches!(input_budget(&empty_values, 39), Err(Error::Limit)));
    input_budget(&empty_values, 40).unwrap();
    input_budget(&[], 12).unwrap();
}
