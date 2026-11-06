use std::time::Duration;

use libsql_sys::rusqlite::config::DbConfig;
use libsql_sys::rusqlite::limits::Limit;
use libsql_sys::rusqlite::{self, Connection};

use crate::{Error, WriterLimits};

/// The narrow effect boundary keeps the same configuration ordering and
/// fail-closed decisions for native calls and deterministic unit I/O faults.
pub(crate) trait ConfigOps {
    fn settings(&self, sql: &str) -> rusqlite::Result<()>;
    fn no_wait(&self) -> rusqlite::Result<()>;
    fn page_size(&self) -> rusqlite::Result<i64>;
    fn integrity(&self) -> rusqlite::Result<String>;
    fn ignore_checks(&self, enabled: bool) -> rusqlite::Result<()>;
    fn max_pages(&self, maximum: u32) -> rusqlite::Result<u32>;
    fn option(&self, option: DbConfig, enabled: bool) -> rusqlite::Result<bool>;
    fn limit(&self, limit: Limit, maximum: i32);
}

impl ConfigOps for Connection {
    fn settings(&self, sql: &str) -> rusqlite::Result<()> {
        self.execute_batch(sql)
    }

    fn no_wait(&self) -> rusqlite::Result<()> {
        self.busy_timeout(Duration::ZERO)
    }

    fn page_size(&self) -> rusqlite::Result<i64> {
        self.query_row("PRAGMA page_size", [], |row| row.get(0))
    }

    fn integrity(&self) -> rusqlite::Result<String> {
        self.query_row("PRAGMA integrity_check", [], |row| row.get(0))
    }

    fn ignore_checks(&self, enabled: bool) -> rusqlite::Result<()> {
        self.pragma_update(None, "ignore_check_constraints", enabled)
    }

    fn max_pages(&self, maximum: u32) -> rusqlite::Result<u32> {
        self.query_row(&format!("PRAGMA max_page_count={maximum}"), [], |row| {
            row.get(0)
        })
    }

    fn option(&self, option: DbConfig, enabled: bool) -> rusqlite::Result<bool> {
        self.set_db_config(option, enabled)
    }

    fn limit(&self, limit: Limit, maximum: i32) {
        self.set_limit(limit, maximum);
    }
}

/// Called only after validate_limits and with the bounded database page limit.
/// A successfully created connection is not published until every step succeeds.
pub(crate) fn configure(
    connection: &impl ConfigOps,
    limits: WriterLimits,
    max_database_pages: u32,
) -> Result<(), Error> {
    connection
        .settings(
            "PRAGMA page_size=4096; PRAGMA synchronous=FULL; \
             PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=0; \
             PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON;",
        )
        .map_err(Error::Sqlite)?;
    connection.no_wait().map_err(Error::Sqlite)?;
    let page_size = connection.page_size().map_err(Error::Sqlite)?;
    if page_size != crate::PAGE_SIZE as i64 {
        return Err(Error::InvalidImage);
    }
    let defensive = connection
        .option(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(Error::Sqlite)?;
    if !defensive {
        return Err(Error::InvalidImage);
    }
    let trusted_schema = connection
        .option(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(Error::Sqlite)?;
    if trusted_schema {
        return Err(Error::InvalidImage);
    }
    // Input values can be larger than their returned result or SQL text. Keep
    // SQLite's scalar/row cap independent of only the output/text budgets.
    connection.limit(
        Limit::SQLITE_LIMIT_LENGTH,
        limits
            .sql
            .max_result_bytes
            .max(limits.sql.max_sql_bytes)
            .max(limits.sql.max_value_bytes) as i32,
    );
    connection.limit(
        Limit::SQLITE_LIMIT_SQL_LENGTH,
        // Private configuration and total_changes() SQL need a small fixed
        // budget. Public requests still obey validate_statements' exact limit.
        limits.sql.max_sql_bytes.max(64) as i32,
    );
    connection.limit(Limit::SQLITE_LIMIT_COLUMN, limits.sql.max_columns as i32);
    connection.limit(
        Limit::SQLITE_LIMIT_VARIABLE_NUMBER,
        limits.sql.max_parameters as i32,
    );
    connection.limit(Limit::SQLITE_LIMIT_ATTACHED, 0);
    connection.limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0);
    let configured_pages = connection
        .max_pages(max_database_pages)
        .map_err(Error::Sqlite)?;
    if configured_pages != max_database_pages {
        return Err(Error::InvalidImage);
    }
    // CHECK can legally use connection-local/nondeterministic builtins. A
    // physical restore must check structure without rerunning that business
    // predicate in a different connection. All security/resource limits above
    // already apply. No user work is admitted while CHECK is disabled.
    connection.ignore_checks(true).map_err(Error::Sqlite)?;
    let integrity = connection.integrity();
    // Always attempt restoration, even if checking failed. Restoration failure
    // takes priority over an earlier check error; either prevents publication
    // and the private connection must be dropped by the caller.
    connection.ignore_checks(false).map_err(Error::Sqlite)?;
    if integrity.map_err(Error::Sqlite)? != "ok" {
        return Err(Error::InvalidImage);
    }
    Ok(())
}
