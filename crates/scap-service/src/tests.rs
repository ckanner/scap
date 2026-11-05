use super::*;

pub(crate) fn limits() -> Limits {
    Limits {
        max_body_bytes: 4096,
        max_response_bytes: 32768,
        max_pipeline_requests: 16,
        max_cached_statements: 4,
        max_cached_sql_bytes: 1024,
        max_inflight: 2,
        max_token_bytes: 128,
        max_timeout: Duration::from_millis(200),
        sql: SqlLimits {
            max_statements: 8,
            max_sql_bytes: 1024,
            max_parameters: 8,
            max_columns: 8,
            max_rows: 16,
            max_result_bytes: 4096,
            max_value_bytes: 256,
        },
    }
}

pub(crate) struct EmptyBackend;
impl Backend for EmptyBackend {
    fn execute(&self, _: Call) -> BackendFuture<TransactionResult> {
        Box::pin(async { Ok(TransactionResult { statements: vec![] }) })
    }
    fn outcome(&self, _: OutcomeCall) -> BackendFuture<Outcome> {
        Box::pin(async { Ok(Outcome::Unknown) })
    }
    fn status(&self, _: RequestContext) -> BackendFuture<DatabaseStatus> {
        Box::pin(async {
            Ok(DatabaseStatus {
                revision: 0,
                request_epoch: 1,
                retained_requests: 0,
                unacknowledged_requests: 0,
                retired_revision: 0,
                base_revision: 0,
                tail_entries: 0,
                tail_bytes: 0,
                suspended: false,
                cold: false,
                owner_active: false,
                archived_revision: None,
            })
        })
    }
    fn rotate(&self, call: RotateCall) -> BackendFuture<u64> {
        Box::pin(async move { Ok(call.expected_epoch + 1) })
    }
}

#[test]
fn configuration_checks_each_bound() {
    limits().validate().unwrap();
    let mut invalids = Vec::new();
    macro_rules! bad {
        ($field:ident, $value:expr) => {{
            let mut limits = limits();
            limits.$field = $value;
            invalids.push(limits);
        }};
    }
    bad!(
        sql,
        SqlLimits {
            max_statements: 0,
            ..limits().sql
        }
    );
    for value in [0, 16 * 1024 * 1024 + 1] {
        bad!(max_body_bytes, value);
    }
    for value in [1023, 128 * 1024 * 1024 + 1] {
        bad!(max_response_bytes, value);
    }
    for value in [1, 1025] {
        bad!(max_pipeline_requests, value);
    }
    for value in [0, 1025] {
        bad!(max_cached_statements, value);
    }
    for value in [0, 4097] {
        bad!(max_cached_sql_bytes, value);
    }
    for value in [0, 1025] {
        bad!(max_inflight, value);
    }
    for value in [0, 8193] {
        bad!(max_token_bytes, value);
    }
    for value in [Duration::ZERO, Duration::from_secs(3601)] {
        bad!(max_timeout, value);
    }
    for invalid in invalids {
        assert!(Service::new(EmptyBackend, "db".into(), 1, invalid).is_err());
    }
    assert!(Service::new(EmptyBackend, "".into(), 1, limits()).is_err());
    assert!(Service::new(EmptyBackend, "db".into(), 0, limits()).is_err());
    assert!(Service::new(EmptyBackend, "db".into(), 1, limits()).is_ok());
}

#[test]
fn route_and_request_identity_validation() {
    for database in ["", &"x".repeat(65), ".", "../other", "库", "a/b", "a b"] {
        assert!(validate_database(database).is_err());
    }
    validate_database("db_01-X").unwrap();
    for id in ["", "1", &"0".repeat(33), &"g".repeat(32), &"0".repeat(32)] {
        assert!(parse_request_id(id).is_err());
    }
    assert_eq!(
        parse_request_id("0123456789abcdefABCDEF0123456789").unwrap(),
        0x0123456789abcdefabcdef0123456789
    );
    let service = Service::new(EmptyBackend, "db".into(), 1, limits()).unwrap();
    let first = service.generate_request_id().unwrap();
    assert_ne!(first, 0);
    assert_ne!(first, service.generate_request_id().unwrap());
    service.next_id.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        service.generate_request_id().unwrap_err().code,
        "OVERLOADED"
    );
}

#[test]
fn positive_unsigned_epochs_and_terminal_positions_reject_invalid_boundaries() {
    for value in [
        "",
        "123456789012345678901",
        "a",
        "+1",
        "-1",
        "1.5",
        " 1",
        "0",
        "000",
        "18446744073709551616",
    ] {
        assert!(parse_positive_u64(value).is_err(), "{value}");
    }
    assert_eq!(parse_positive_u64("1").unwrap(), 1);
    assert_eq!(parse_positive_u64("001").unwrap(), 1);
    assert_eq!(
        parse_positive_u64("18446744073709551615").unwrap(),
        u64::MAX
    );
}

#[test]
fn system_clock_and_cancellation_guard() {
    assert_eq!(
        unix_millis(UNIX_EPOCH + Duration::from_millis(123)).unwrap(),
        123
    );
    assert!(unix_millis(UNIX_EPOCH - Duration::from_secs(1)).is_err());
    assert!(unix_millis(UNIX_EPOCH + Duration::from_secs(u64::MAX / 1000 + 1)).is_err());
    let environment = SystemEnvironment;
    assert!(environment.now() <= Instant::now());
    assert!(environment.unix_millis().unwrap() > 0);
    let cancelled = Arc::new(AtomicBool::new(false));
    drop(CancelGuard(cancelled.clone()));
    assert!(cancelled.load(Ordering::Acquire));
}
