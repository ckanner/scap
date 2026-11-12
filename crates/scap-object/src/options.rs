//! Admission defaults are independent of the persisted database size quota.

use std::time::{Duration, Instant};

use scap_object_sqlite::WriterLimits;
use scap_sql::{SqlLimits, Statement, Value};

use crate::format::{DatabaseQuota, Retention, MAX_PAGES, MAX_RESULT_BYTES, PAGE_SIZE};
use crate::Error;

pub const GIB: u64 = 1024 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_OWNER_RECOVERY_GETS: u64 = 1_048_576;
pub const MAX_OWNER_RECOVERY_BYTES: u64 = 64 * GIB;

/// A creation default and independent local admission/execution budgets.
/// Existing databases always use their HEAD's persisted quota and retention.
/// `cache_bytes` is a SQLite cache target, not a hard process RSS guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub quota: DatabaseQuota,
    pub retention: Retention,
    /// First-winner default used only when adopting HEAD9 snapshots.
    pub snapshot_limits: crate::snapshot_format::SnapshotLimits,
    pub sql: SqlLimits,
    pub max_input_bytes: usize,
    pub max_changed_pages: u32,
    pub cache_bytes: u64,
    /// Per-operation typed Rust result graph, separate from wire bytes and
    /// SQLite's page cache. Includes container capacities and growth overlap.
    pub result_memory_bytes: u64,
    pub max_vm_steps: u32,
    pub operation_timeout: Duration,
    pub recovery_timeout: Duration,
    /// Cumulative payload admission for one owner resume. These local budgets
    /// may be lowered to zero; they are not a logical database-size quota.
    pub owner_recovery_gets: u64,
    pub owner_recovery_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            quota: DatabaseQuota {
                max_bytes: Some(10 * GIB),
            },
            retention: Retention {
                max_entries: 4096,
                max_result_bytes: 256 * 1024 * 1024,
            },
            snapshot_limits: crate::snapshot_format::SnapshotLimits::default(),
            sql: SqlLimits {
                max_statements: 256,
                max_sql_bytes: 1024 * 1024,
                max_parameters: 32766,
                max_columns: 2000,
                max_rows: 1_000_000,
                max_result_bytes: 50 * 1024 * 1024,
                max_value_bytes: 2 * 1024 * 1024,
            },
            max_input_bytes: MAX_REQUEST_BYTES,
            max_changed_pages: 64 * 1024 * 1024 / PAGE_SIZE as u32,
            cache_bytes: 64 * 1024 * 1024,
            result_memory_bytes: scap_sql::DEFAULT_RESULT_MEMORY_BYTES,
            max_vm_steps: 100_000_000,
            operation_timeout: Duration::from_secs(30),
            recovery_timeout: Duration::from_secs(1800),
            owner_recovery_gets: MAX_OWNER_RECOVERY_GETS,
            owner_recovery_bytes: MAX_OWNER_RECOVERY_BYTES,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), Error> {
        self.quota.validate().map_err(Error::Format)?;
        self.retention.validate().map_err(Error::Format)?;
        self.snapshot_limits.validate().map_err(Error::Format)?;
        self.sql.validate().map_err(Error::Sql)?;
        let durable = durable_sql_limits();
        if self.sql.max_statements > durable.max_statements
            || self.sql.max_sql_bytes > durable.max_sql_bytes
            || self.sql.max_parameters > durable.max_parameters
            || self.sql.max_columns > durable.max_columns
            || self.sql.max_result_bytes > durable.max_result_bytes
            || self.sql.max_value_bytes > durable.max_value_bytes
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_REQUEST_BYTES
            || self.max_changed_pages == 0
            || self.max_changed_pages > MAX_PAGES
            || self.cache_bytes < PAGE_SIZE as u64
            || self.cache_bytes > i32::MAX as u64 * 1024
            || self.result_memory_bytes < std::mem::size_of::<scap_sql::TransactionResult>() as u64
            || self.max_vm_steps == 0
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(86400)
            || self.recovery_timeout.is_zero()
            || self.recovery_timeout > Duration::from_secs(7 * 86400)
            || self.owner_recovery_gets > MAX_OWNER_RECOVERY_GETS
            || self.owner_recovery_bytes > MAX_OWNER_RECOVERY_BYTES
        {
            return Err(Error::Limit);
        }
        Ok(())
    }

    pub(crate) fn writer(&self, quota: &DatabaseQuota) -> Result<WriterLimits, Error> {
        let pages = quota.max_pages().map_err(Error::Format)?;
        Ok(WriterLimits {
            sql: self.sql,
            max_vm_steps: self.max_vm_steps,
            max_database_pages: pages,
            max_changed_pages: self.max_changed_pages,
            cache_bytes: self.cache_bytes,
            result_memory_bytes: self.result_memory_bytes,
        })
    }

    pub(crate) fn deadline(&self, original: Instant, recovery: bool) -> Instant {
        let duration = if recovery {
            self.recovery_timeout
        } else {
            self.operation_timeout
        };
        original.min(Instant::now() + duration)
    }
}

/// Decode retained outcomes using format capabilities, not today's admission
/// settings. Lowering a caller's result budget never invalidates old receipts.
pub fn durable_sql_limits() -> SqlLimits {
    SqlLimits {
        max_statements: 65536,
        max_sql_bytes: MAX_REQUEST_BYTES as u32,
        max_parameters: 32766,
        max_columns: 2000,
        max_rows: u32::MAX,
        max_result_bytes: MAX_RESULT_BYTES as u32,
        max_value_bytes: MAX_RESULT_BYTES as u32,
    }
}

pub(crate) fn input_budget(statements: &[Statement], maximum: usize) -> Result<(), Error> {
    // Match the request fingerprint wire encoding, including empty values and
    // container fields. Counting payload bytes alone misses empty-value work.
    let mut remaining = maximum.checked_sub(12).ok_or(Error::Limit)?;
    for statement in statements {
        remaining = remaining.checked_sub(8).ok_or(Error::Limit)?;
        remaining = remaining
            .checked_sub(statement.sql.len())
            .ok_or(Error::Limit)?;
        for parameter in &statement.parameters {
            let size = match parameter {
                Value::Null => 1,
                Value::Integer(_) | Value::Real(_) => 9,
                Value::Text(value) => 5 + value.len(),
                Value::Blob(value) => 5 + value.len(),
            };
            remaining = remaining.checked_sub(size).ok_or(Error::Limit)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
