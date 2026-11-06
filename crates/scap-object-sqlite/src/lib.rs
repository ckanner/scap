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

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use libsql_sys::wal::wrapper::WrappedWal;
use libsql_sys::wal::Sqlite3Wal;
use scap_sql::{SqlLimits, Statement, TransactionResult};

use gate::{Attempt, GateState, GateWal, Resolution};

pub const PAGE_SIZE: usize = 4096;

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
    pub max_vm_steps: u32,
    pub max_database_pages: u32,
    pub max_changed_pages: u32,
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

/// A thread-confined private cache. No raw connection, in-place reopen or
/// path-based public access exists. Every failure permanently stops this writer.
pub struct SqliteWriter<G: CommitGate> {
    connection: NativeConnection<G>,
    state: Rc<RefCell<GateState<G>>>,
    image: Vec<u8>,
    limits: WriterLimits,
    stopped: bool,
}

impl<G: CommitGate + 'static> SqliteWriter<G> {
    pub fn create_new(
        directory: &Path,
        image: Vec<u8>,
        limits: WriterLimits,
        gate: G,
    ) -> Result<Self, Error> {
        sql::validate_limits(limits)?;
        image::validate(&image, limits.max_database_pages)?;
        let path = file::materialize(directory, &image)?;
        let state = Rc::new(RefCell::new(GateState::new(gate, limits)));
        let connection = sql::open(
            &path,
            GateWal::new(state.clone()),
            limits,
            limits.max_database_pages,
        )?;
        Ok(Self {
            connection,
            state,
            image,
            limits,
            stopped: false,
        })
    }

    pub fn image(&self) -> &[u8] {
        &self.image
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
        scap_sql::encode_result(&result, self.limits.sql).map_err(Error::Sql)?;
        query::check(&interrupt)?;
        self.stopped = false;
        Ok(result)
    }

    /// Runs one bounded transaction. The caller has already performed current
    /// authorization and original-identity lookup; this method never retries SQL.
    /// RETURNING rows cannot escape before both HEAD and native publication.
    pub fn execute(&mut self, statements: &[Statement]) -> Result<TransactionResult, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        self.stopped = true;
        scap_sql::validate_statements(statements, self.limits.sql).map_err(Error::Sql)?;
        self.state.borrow_mut().reset();
        let result = match sql::execute_transaction(&self.connection, statements, self.limits) {
            Ok(result) => result,
            Err(error) => {
                sql::rollback(&self.connection);
                return Err(self.state.borrow_mut().take_error(error));
            }
        };
        let encoded = match scap_sql::encode_result(&result, self.limits.sql) {
            Ok(encoded) => encoded,
            Err(error) => {
                sql::rollback(&self.connection);
                return Err(Error::Sql(error));
            }
        };
        self.state.borrow_mut().attempt = Some(Attempt {
            base: self.image.clone(),
            result: encoded,
        });
        if let Err(error) = self.connection.execute_batch("COMMIT") {
            sql::rollback(&self.connection);
            return self.finish(Err(Error::Sqlite(error)));
        }
        // No-op/read-only transactions have no xFrames callback. Their exact
        // result still needs an authoritative record before it can be returned.
        if self.state.borrow().resolution.is_none() {
            self.state.borrow_mut().decide_caught(PageBatch {
                size_after: (self.image.len() / PAGE_SIZE) as u32,
                pages: Vec::new(),
            });
        }
        self.finish(Ok(()))
    }

    fn finish(&mut self, native: Result<(), Error>) -> Result<TransactionResult, Error> {
        let resolution = self.state.borrow_mut().resolution.take();
        match resolution {
            Some(Resolution::Accepted(image)) => {
                if native.is_err() {
                    return Err(Error::CommittedButUnavailable);
                }
                // Only decide(), with an installed attempt, can accept.
                let encoded = self.state.borrow_mut().attempt.take().unwrap().result;
                let result = scap_sql::decode_result(&encoded, self.limits.sql)
                    .map_err(|_| Error::CommittedButUnavailable)?;
                self.image = image;
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
