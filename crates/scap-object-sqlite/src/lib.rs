//! Private, bounded SQLite execution for object-authoritative commits.
//!
//! This crate has no durable authority of its own. Its trusted caller supplies a
//! verified physical image and resolves the request identity before execution.
//! Final dirty pages and the exact buffered result reach `CommitGate` before
//! SQLite publishes them. Only authoritative acceptance permits publication.

mod config;
mod file;
mod gate;
mod image;
mod query;
mod sql;
mod storage;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use libsql_sys::wal::wrapper::WrappedWal;
use libsql_sys::wal::Sqlite3Wal;
use scap_sql::{SqlLimits, Statement, TransactionResult};

pub use file::{ImageBuilder, PreparedImage};
use gate::{Attempt, GateState, GateWal, Resolution};
pub use storage::validate_cache_directory;

pub const PAGE_SIZE: usize = 4096;
/// SQLite's physical page-number limit, separate from a deployment's quota.
pub const MAX_DATABASE_PAGES: u32 = u32::MAX - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageChange {
    pub number: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageBatch {
    pub size_after: u32,
    pub pages: Vec<PageChange>,
}

/// A trusted synchronous authority adapter. The candidate is immutable and
/// bound by the caller to the original HEAD, owner, principal and request.
/// `Accepted` must mean that all dependencies and the new HEAD are durable.
/// A transport acknowledgement, local write or asynchronous upload is not enough.
pub trait CommitGate {
    fn publish(&mut self, batch: &PageBatch, result: &[u8]) -> GateDecision;
}

impl<F: FnMut(&PageBatch, &[u8]) -> GateDecision> CommitGate for F {
    fn publish(&mut self, batch: &PageBatch, result: &[u8]) -> GateDecision {
        self(batch, result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Accepted,
    /// Rejection applies to this candidate, not to any earlier in-flight use
    /// of the same business identity. The caller owns any required lookup.
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterLimits {
    pub sql: SqlLimits,
    /// Per-operation typed Rust result capacity, including growth overlap.
    /// Independent of retained encoded bytes, SQLite heap and process RSS.
    pub result_memory_bytes: u64,
    pub max_vm_steps: u32,
    pub max_database_pages: u32,
    pub max_changed_pages: u32,
    /// SQLite's page-cache target, also bounded by the changed-page budget.
    /// It is not an allocator or process RSS hard limit. Cache spill is enabled
    /// and unsupported uncommitted spills fail closed before publication.
    pub cache_bytes: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Sqlite(libsql_sys::rusqlite::Error),
    Sql(scap_sql::SqlError),
    InvalidLimits,
    InvalidSql,
    InvalidImage,
    ResultLimit,
    /// The typed result cannot be materialized within its separate memory
    /// budget, or its fallible allocation failed. This is not corruption.
    ResourceExhausted,
    Interrupted,
    Stopped,
    Rejected,
    OutcomeUnknown,
    /// Remote acceptance has happened. Local publication failed; the caller
    /// must discard this cache and resolve using its original object receipt.
    CommittedButUnavailable,
}

/// Returns true when the original request has expired or been cancelled.
/// Panics fail closed and are caught before entering a native callback.
pub type ReadInterrupt = Arc<dyn Fn() -> bool + Send + Sync>;

type NativeConnection<G> = libsql_sys::Connection<WrappedWal<GateWal<G>, Sqlite3Wal>>;

type ResultEncoder<'a> =
    dyn FnMut(&TransactionResult, SqlLimits) -> Result<Vec<u8>, scap_sql::SqlError> + 'a;

/// A thread-confined private cache. No raw connection, in-place reopen or
/// path-based public access exists. Every failure permanently stops this writer.
pub struct SqliteWriter<G: CommitGate> {
    connection: NativeConnection<G>,
    state: Rc<RefCell<GateState<G>>>,
    // Declaration order closes the native connection before removing sidecars.
    _image: PreparedImage,
    pages: u32,
    limits: WriterLimits,
    stopped: bool,
}

impl<G: CommitGate + 'static> SqliteWriter<G> {
    pub fn open(
        prepared: PreparedImage,
        limits: WriterLimits,
        gate: G,
        interrupt: ReadInterrupt,
    ) -> Result<Self, Error> {
        sql::validate_limits(limits)?;
        let pages = prepared.page_count();
        if pages > limits.max_database_pages {
            return Err(Error::InvalidImage);
        }
        let state = Rc::new(RefCell::new(GateState::new(gate, limits)));
        let connection = sql::open(
            &prepared.path(),
            GateWal::new(state.clone()),
            limits,
            limits.max_database_pages,
            &interrupt,
        )?;
        Ok(Self {
            connection,
            state,
            _image: prepared,
            pages,
            limits,
            stopped: false,
        })
    }

    pub fn page_count(&self) -> u32 {
        self.pages
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// The caller must first select a fresh authorized HEAD and materialize its
    /// exact data root. This method supplies read-only native snapshot isolation,
    /// never a read lease or authorization based on a cached writer identity.
    pub fn query(
        &mut self,
        statements: &[Statement],
        interrupt: ReadInterrupt,
    ) -> Result<TransactionResult, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        self.stopped = true;
        scap_sql::validate_statements(statements, self.limits.sql).map_err(Error::Sql)?;
        let result = query::execute(&self.connection, statements, self.limits, &interrupt)?;
        scap_sql::plan_result(&result, self.limits.sql).map_err(Error::Sql)?;
        query::check(&interrupt)?;
        self.stopped = false;
        Ok(result)
    }

    /// Runs one bounded transaction. The caller has already performed current
    /// authorization and original-identity lookup; this method never retries SQL.
    /// RETURNING rows cannot escape before both HEAD and native publication.
    pub fn execute(
        &mut self,
        statements: &[Statement],
        interrupt: ReadInterrupt,
    ) -> Result<TransactionResult, Error> {
        self.execute_with_encoder(statements, interrupt, &mut scap_sql::encode_result)
    }

    fn execute_with_encoder(
        &mut self,
        statements: &[Statement],
        interrupt: ReadInterrupt,
        encode: &mut ResultEncoder<'_>,
    ) -> Result<TransactionResult, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        self.stopped = true;
        scap_sql::validate_statements(statements, self.limits.sql).map_err(Error::Sql)?;
        self.state.borrow_mut().reset();
        let result =
            match sql::execute_transaction(&self.connection, statements, self.limits, &interrupt) {
                Ok(result) => result,
                Err(error) => {
                    sql::rollback(&self.connection);
                    return Err(self.state.borrow_mut().take_error(error));
                }
            };
        let encoded = match encode(&result, self.limits.sql) {
            Ok(encoded) => encoded,
            Err(error) => {
                sql::rollback(&self.connection);
                return Err(match error {
                    scap_sql::SqlError::ResourceExhausted => Error::ResourceExhausted,
                    other => Error::Sql(other),
                });
            }
        };
        // finish() materializes the retained result again after acceptance.
        // Release the first graph before entering that phase, rather than
        // retaining two typed graphs across native and remote publication.
        drop(result);
        self.state.borrow_mut().attempt = Some(Attempt {
            base_pages: self.pages,
            result: encoded,
        });
        if let Err(error) = sql::commit(&self.connection, &interrupt) {
            sql::rollback(&self.connection);
            return self.finish(Err(error), &interrupt);
        }
        // No-op/read-only transactions have no xFrames callback. Their exact
        // result still needs an authoritative record before it can be returned.
        if self.state.borrow().resolution.is_none() {
            self.state.borrow_mut().decide_caught(PageBatch {
                size_after: self.pages,
                pages: Vec::new(),
            });
        }
        self.finish(Ok(()), &interrupt)
    }

    fn finish(
        &mut self,
        native: Result<(), Error>,
        interrupt: &ReadInterrupt,
    ) -> Result<TransactionResult, Error> {
        let resolution = self.state.borrow_mut().resolution.take();
        match resolution {
            Some(Resolution::Accepted(pages)) => {
                if native.is_err() {
                    return Err(Error::CommittedButUnavailable);
                }
                query::check(interrupt).map_err(|_| Error::CommittedButUnavailable)?;
                config::checkpoint(&*self.connection)
                    .map_err(|_| Error::CommittedButUnavailable)?;
                query::check(interrupt).map_err(|_| Error::CommittedButUnavailable)?;
                // Only decide(), with an installed attempt, can accept.
                let encoded = self.state.borrow_mut().attempt.take().unwrap().result;
                let result = scap_sql::decode_result_with_memory_limit(
                    &encoded,
                    self.limits.sql,
                    self.limits.result_memory_bytes,
                )
                .map_err(|_| Error::CommittedButUnavailable)?;
                query::check(interrupt).map_err(|_| Error::CommittedButUnavailable)?;
                self.pages = pages;
                self.stopped = false;
                Ok(result)
            }
            Some(Resolution::Failed(error)) => Err(error),
            None => native.and(Err(Error::OutcomeUnknown)),
        }
    }
}

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod file_tests;
#[cfg(test)]
mod tests;
