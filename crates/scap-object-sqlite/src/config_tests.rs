use std::cell::RefCell;

use libsql_sys::rusqlite::config::DbConfig;
use libsql_sys::rusqlite::limits::Limit;
use libsql_sys::rusqlite::{self, Connection};

use crate::config::{configure, ConfigOps};
use crate::{Error, SqlLimits, WriterLimits};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Settings,
    NoWait,
    PageSize,
    Integrity,
    IgnoreChecks(bool),
    MaxPages(u32),
    Option(i32, bool),
    Limit(i32, i32),
}

struct FakeConfig {
    fail_at: Vec<usize>,
    events: RefCell<Vec<Event>>,
    page_size: i64,
    integrity: &'static str,
    max_pages: u32,
    defensive: bool,
    trusted: bool,
}

impl FakeConfig {
    fn new() -> Self {
        Self {
            fail_at: Vec::new(),
            events: RefCell::default(),
            page_size: 4096,
            integrity: "ok",
            max_pages: 99,
            defensive: true,
            trusted: false,
        }
    }

    fn step(&self, event: Event) -> rusqlite::Result<()> {
        let mut events = self.events.borrow_mut();
        events.push(event);
        if self.fail_at.contains(&events.len()) {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "step {}",
                events.len()
            )));
        }
        Ok(())
    }
}

impl ConfigOps for FakeConfig {
    fn settings(&self, sql: &str) -> rusqlite::Result<()> {
        assert_eq!(sql, "PRAGMA page_size=4096; PRAGMA synchronous=FULL; PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=0; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON;");
        self.step(Event::Settings)
    }

    fn no_wait(&self) -> rusqlite::Result<()> {
        self.step(Event::NoWait)
    }

    fn page_size(&self) -> rusqlite::Result<i64> {
        self.step(Event::PageSize)?;
        Ok(self.page_size)
    }

    fn integrity(&self) -> rusqlite::Result<String> {
        self.step(Event::Integrity)?;
        Ok(self.integrity.into())
    }

    fn ignore_checks(&self, enabled: bool) -> rusqlite::Result<()> {
        self.step(Event::IgnoreChecks(enabled))
    }

    fn max_pages(&self, maximum: u32) -> rusqlite::Result<u32> {
        self.step(Event::MaxPages(maximum))?;
        Ok(self.max_pages)
    }

    fn option(&self, option: DbConfig, enabled: bool) -> rusqlite::Result<bool> {
        let code = option as i32;
        self.step(Event::Option(code, enabled))?;
        if code == DbConfig::SQLITE_DBCONFIG_DEFENSIVE as i32 {
            Ok(self.defensive)
        } else {
            assert_eq!(code, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA as i32);
            Ok(self.trusted)
        }
    }

    fn limit(&self, limit: Limit, maximum: i32) {
        self.events
            .borrow_mut()
            .push(Event::Limit(limit as i32, maximum));
    }
}

fn limits() -> WriterLimits {
    WriterLimits {
        sql: SqlLimits {
            max_statements: 8,
            max_sql_bytes: 1024,
            max_parameters: 16,
            max_columns: 32,
            max_rows: 128,
            max_result_bytes: 2048,
            max_value_bytes: 4096,
        },
        max_vm_steps: 100_000,
        max_changed_pages: 64,
        max_database_pages: 99,
    }
}

fn expected_events() -> Vec<Event> {
    vec![
        Event::Settings,
        Event::NoWait,
        Event::PageSize,
        Event::Option(DbConfig::SQLITE_DBCONFIG_DEFENSIVE as i32, true),
        Event::Option(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA as i32, false),
        Event::Limit(Limit::SQLITE_LIMIT_LENGTH as i32, 4096),
        Event::Limit(Limit::SQLITE_LIMIT_SQL_LENGTH as i32, 1024),
        Event::Limit(Limit::SQLITE_LIMIT_COLUMN as i32, 32),
        Event::Limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER as i32, 16),
        Event::Limit(Limit::SQLITE_LIMIT_ATTACHED as i32, 0),
        Event::Limit(Limit::SQLITE_LIMIT_WORKER_THREADS as i32, 0),
        Event::MaxPages(99),
        Event::IgnoreChecks(true),
        Event::Integrity,
        Event::IgnoreChecks(false),
    ]
}

#[test]
fn native_configuration_uses_the_same_ordered_effects_as_the_policy() {
    let fake = FakeConfig::new();
    configure(&fake, limits(), 99).unwrap();
    assert_eq!(*fake.events.borrow(), expected_events());

    let connection = Connection::open_in_memory().unwrap();
    configure(&connection, limits(), 99).unwrap();
    for (pragma, expected) in [
        ("page_size", 4096_i64),
        ("synchronous", 2),
        ("cache_spill", 0),
        ("wal_autocheckpoint", 0),
        ("temp_store", 2),
        ("foreign_keys", 1),
        ("busy_timeout", 0),
        ("max_page_count", 99),
        ("ignore_check_constraints", 0),
    ] {
        let actual: i64 = connection
            .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
            .unwrap();
        assert_eq!(actual, expected, "{pragma}");
    }
    assert!(connection
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .unwrap());
    assert!(!connection
        .db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)
        .unwrap());
    for (limit, expected) in [
        (Limit::SQLITE_LIMIT_LENGTH, 4096),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 1024),
        (Limit::SQLITE_LIMIT_COLUMN, 32),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        assert_eq!(Connection::limit(&connection, limit), expected);
    }
    connection
        .execute_batch("CREATE TABLE data(value BLOB)")
        .unwrap();
    // A valid input value can exceed both output and SQL-text budgets. The
    // native scalar/row limit must not accidentally use only those two bounds.
    assert_eq!(
        connection
            .execute("INSERT INTO data VALUES(?1)", [vec![7_u8; 3000]])
            .unwrap(),
        1
    );
    let length: i64 = connection
        .query_row("SELECT length(value) FROM data", [], |row| row.get(0))
        .unwrap();
    assert_eq!(length, 3000);
}

#[test]
fn every_fallible_configuration_effect_stops_the_sequence() {
    let expected = expected_events();
    for fail_at in [1, 2, 3, 4, 5, 12, 13, 14, 15] {
        let mut fake = FakeConfig::new();
        fake.fail_at = vec![fail_at];
        let Err(Error::Sqlite(rusqlite::Error::InvalidParameterName(error))) =
            configure(&fake, limits(), 99)
        else {
            panic!("wrong failure classification")
        };
        assert_eq!(error, format!("step {fail_at}"));
        let end = if fail_at == 14 { 15 } else { fail_at };
        assert_eq!(*fake.events.borrow(), expected[..end]);
    }
    let mut fake = FakeConfig::new();
    fake.fail_at = vec![14, 15];
    let Err(Error::Sqlite(rusqlite::Error::InvalidParameterName(error))) =
        configure(&fake, limits(), 99)
    else {
        panic!("wrong restoration failure")
    };
    assert_eq!(error, "step 15");
    assert_eq!(*fake.events.borrow(), expected);
}

#[test]
fn rejected_page_integrity_capacity_or_security_settings_never_continue() {
    for field in 0..5 {
        let mut fake = FakeConfig::new();
        let count = match field {
            0 => {
                fake.page_size = 8192;
                3
            }
            1 => {
                fake.integrity = "corrupt";
                15
            }
            2 => {
                fake.max_pages = 100;
                12
            }
            3 => {
                fake.defensive = false;
                4
            }
            _ => {
                fake.trusted = true;
                5
            }
        };
        assert!(matches!(
            configure(&fake, limits(), 99),
            Err(Error::InvalidImage)
        ));
        assert_eq!(*fake.events.borrow(), expected_events()[..count]);
    }
}

#[test]
fn native_effects_preserve_actual_sqlite_errors_and_constraints() {
    let connection = Connection::open_in_memory().unwrap();
    assert!(ConfigOps::settings(&connection, "invalid SQL").is_err());
    assert!(ConfigOps::settings(&connection, "PRAGMA page_size=8192; CREATE TABLE x(n)").is_ok());
    assert_eq!(ConfigOps::page_size(&connection).unwrap(), 8192);
    assert!(matches!(
        configure(&connection, limits(), 99),
        Err(Error::InvalidImage)
    ));

    let large = Connection::open_in_memory().unwrap();
    large.execute_batch("CREATE TABLE x(n)").unwrap();
    assert_eq!(ConfigOps::max_pages(&large, 1).unwrap(), 2);
    assert!(matches!(
        configure(&large, limits(), 1),
        Err(Error::InvalidImage)
    ));
}

#[test]
fn restored_structure_does_not_reexecute_connection_local_check_predicates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legal-check.sqlite");
    let original = Connection::open(&path).unwrap();
    original.execute_batch("CREATE TABLE seed(id INTEGER PRIMARY KEY); INSERT INTO seed VALUES(7); CREATE TABLE checked(x INTEGER CHECK(last_insert_rowid()=7)); INSERT INTO checked(rowid,x) VALUES(7,1)").unwrap();
    assert_eq!(ConfigOps::integrity(&original).unwrap(), "ok");
    drop(original);

    let restored = Connection::open(&path).unwrap();
    assert_eq!(restored.last_insert_rowid(), 0);
    assert_ne!(ConfigOps::integrity(&restored).unwrap(), "ok");
    configure(&restored, limits(), 99).unwrap();
    let ignored: bool = restored
        .query_row("PRAGMA ignore_check_constraints", [], |row| row.get(0))
        .unwrap();
    assert!(!ignored);
    let value: i64 = restored
        .query_row("SELECT x FROM checked", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, 1);
    assert!(restored
        .execute("INSERT INTO checked(rowid,x) VALUES(8,2)", [])
        .is_err());
    let count: i64 = restored
        .query_row("SELECT count(*) FROM checked", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);

    // Native private statements still fit even with a very small public SQL
    // budget, which validate_statements enforces before engine entry.
    let short = Connection::open_in_memory().unwrap();
    let mut small = limits();
    small.sql.max_sql_bytes = 8;
    configure(&short, small, 99).unwrap();
    assert_eq!(
        Connection::limit(&short, Limit::SQLITE_LIMIT_SQL_LENGTH),
        64
    );
    assert_eq!(
        short
            .query_row::<i64, _, _>("SELECT 1", [], |row| row.get(0))
            .unwrap(),
        1
    );
}
