//! A bounded native SQLite writer with a synchronous, before-visibility gate.
//!
//! Connections are private. Every invocation is one explicit transaction and
//! all results remain buffered until durable acceptance and SQLite completion.
//! A worker starts only in a newly created, exclusively owned directory from a
//! verified physical image. Reopening a previous worker's cache is unsupported.

mod config;
mod file;
mod gate;
mod query;
mod sql;

#[cfg(test)]
mod config_tests;

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use libsql_sys::wal::wrapper::WrappedWal;
use libsql_sys::wal::Sqlite3Wal;
use scap_core::{CommitReceipt, CommitTicket, PreparedWrite, Rejection};
use scap_engine::{Image, PageBatch};
use scap_sql::{SqlLimits, Statement, TransactionResult};

use gate::{Attempt, GateState, GateWal, Resolution};

/// This trusted adapter must distinguish durable business acceptance from a
/// transport acknowledgement. It also authenticates and authorizes every call,
/// including historical results. Lookup must verify current READ and WRITE
/// authority for this write-transaction API, not just permission to see an old
/// result. A timeout is always `Unknown`.
pub trait CommitGate {
    /// Current authorization and a linearizable lookup precede SQL execution,
    /// including DDL and unique inserts which cannot safely be reexecuted.
    fn lookup(&mut self, ticket: &CommitTicket, request_fingerprint: [u8; 32]) -> LookupDecision;

    fn propose(
        &mut self,
        write: &PreparedWrite,
        request_fingerprint: [u8; 32],
        result: &[u8],
    ) -> GateDecision;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupDecision {
    /// Absent in this read view, not a persistent cancellation or proof that a
    /// concurrent/in-flight proposal cannot commit. The final gate checks again.
    NotFound,
    AlreadyCommitted {
        receipt: CommitReceipt,
        result: Vec<u8>,
    },
    Rejected(Rejection),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Accepted(CommitReceipt),
    AlreadyCommitted {
        receipt: CommitReceipt,
        result: Vec<u8>,
    },
    Rejected(Rejection),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterLimits {
    pub sql: SqlLimits,
    /// SQLite VM instructions while executing supplied statements and collecting
    /// their results. BEGIN/COMMIT, native I/O and synchronous consensus require
    /// their own execution/deadline budgets.
    pub max_vm_steps: u32,
    /// Bounds copying from native page headers before the image codec runs.
    pub max_changed_pages: u32,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Sqlite(libsql_sys::rusqlite::Error),
    Sql(scap_sql::SqlError),
    Image(scap_engine::Error),
    InvalidLimits,
    InvalidSql,
    ResultLimit,
    /// A read was cancelled or its original deadline/clock guard failed. A
    /// read-only invocation cannot have created a new database commit.
    Interrupted,
    /// A trusted Engine adapter has not implemented the independent read API.
    ReadUnsupported,
    InvalidImage,
    Stopped,
    InvalidReceipt,
    /// Rejection of this attempt. Another proposal with the same request ID
    /// may already be committed; this is not a persistent cancellation fence.
    Rejected(Rejection),
    OutcomeUnknown,
    /// Acceptance is already durable. Never report this as a rolled-back write.
    CommittedButUnavailable {
        receipt: Box<CommitReceipt>,
    },
}

/// Historical results stop this writer: its staged pages were discarded and it
/// must be reconstructed from current authority before any further operation.
#[derive(Debug, PartialEq)]
pub struct Completed {
    pub receipt: CommitReceipt,
    pub result: TransactionResult,
    pub replayed: bool,
}

/// Trusted wall-clock/cancellation check for one bounded read invocation. The
/// callback must retain the original request deadline; a panic interrupts the
/// request and retires the writer instead of escaping a native callback.
/// It is checked before BEGIN, between statements, during VM execution and
/// before returning the complete buffered result.
pub type ReadInterrupt = Arc<dyn Fn() -> bool + Send + Sync>;

type NativeConnection<G> = libsql_sys::Connection<WrappedWal<GateWal<G>, Sqlite3Wal>>;

/// Deliberately thread-confined. Construct and use it on a bounded SQLite worker,
/// never on the network executor. No raw connection or arbitrary reopen exists.
pub struct SqliteWriter<G: CommitGate> {
    connection: NativeConnection<G>,
    state: Rc<RefCell<GateState<G>>>,
    image: Image,
    limits: WriterLimits,
    stopped: bool,
}

impl<G: CommitGate + 'static> SqliteWriter<G> {
    pub fn create_new(
        directory: &Path,
        image: Image,
        limits: WriterLimits,
        gate: G,
    ) -> Result<Self, Error> {
        sql::validate_limits(limits)?;
        let path = file::materialize(directory, image.bytes())?;
        let state = Rc::new(RefCell::new(GateState::new(gate, limits)));
        let connection = sql::open(
            &path,
            GateWal::new(state.clone()),
            limits,
            image.limits().max_database_pages,
        )?;
        Ok(Self {
            connection,
            state,
            image,
            limits,
            stopped: false,
        })
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Executes a bounded read-only snapshot on this exclusively owned cache.
    /// The trusted caller must first bind a fresh Safe ReadIndex, READ authority,
    /// owner and exact physical head to this writer. This method supplies native
    /// read isolation and budgets; it is not a public authorization boundary.
    /// Successful reads do not enter CommitGate or advance the image revision.
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
        // Apply the same exact serialized size and finite-number contract as
        // writes, without retaining or replicating a read result.
        scap_sql::encode_result(&result, self.limits.sql).map_err(Error::Sql)?;
        query::check(&interrupt)?;
        self.stopped = false;
        Ok(result)
    }

    /// Runs a bounded statement batch as a single explicit transaction. Even a
    /// read-only/no-op batch records its exact result through the consensus gate;
    /// use the separately authorized `query` API for ReadIndex-only SQL reads.
    pub fn execute(
        &mut self,
        ticket: CommitTicket,
        statements: &[Statement],
    ) -> Result<Completed, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        self.stopped = true;
        let fingerprint =
            scap_sql::request_fingerprint(statements, self.limits.sql).map_err(Error::Sql)?;
        self.state.borrow_mut().reset();
        let size_after = (self.image.bytes().len() / scap_engine::PAGE_SIZE) as u32;
        // Validate the authority binding and local predecessor before either
        // requesting a historical result or executing SQL.
        self.image
            .prepare(
                ticket.clone(),
                PageBatch {
                    size_after,
                    pages: Vec::new(),
                },
            )
            .map_err(Error::Image)?;
        if !self.state.borrow_mut().lookup_caught(&ticket, fingerprint) {
            return self.finish(Err(Error::OutcomeUnknown));
        }
        let result = sql::execute_transaction(&self.connection, statements, self.limits);
        let result = match result {
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
            ticket,
            fingerprint,
            result: encoded,
        });

        let completion = self.connection.execute_batch("COMMIT");
        if let Err(error) = completion {
            sql::rollback(&self.connection);
            return self.finish(Err(Error::Sqlite(error)));
        }
        // A transaction with no dirty pages has no xFrames callback. Its result
        // still needs an ordered durable record before it can leave this worker.
        if self.state.borrow().resolution.is_none() {
            let size_after = (self.image.bytes().len() / scap_engine::PAGE_SIZE) as u32;
            self.state.borrow_mut().decide_caught(PageBatch {
                size_after,
                pages: Vec::new(),
            });
        }
        self.finish(Ok(()))
    }

    fn finish(&mut self, native: Result<(), Error>) -> Result<Completed, Error> {
        let resolution = self.state.borrow_mut().resolution.take();
        match resolution {
            Some(Resolution::Accepted { receipt, image }) => {
                if native.is_err() {
                    return Err(Error::CommittedButUnavailable {
                        receipt: Box::new(receipt),
                    });
                }
                let encoded = self.state.borrow_mut().attempt.take().unwrap().result;
                let result = scap_sql::decode_result(&encoded, self.limits.sql).map_err(|_| {
                    Error::CommittedButUnavailable {
                        receipt: Box::new(receipt.clone()),
                    }
                })?;
                self.image = image;
                self.stopped = false;
                Ok(Completed {
                    receipt,
                    result,
                    replayed: false,
                })
            }
            Some(Resolution::Replay { receipt, result }) => {
                let result = scap_sql::decode_result(&result, self.limits.sql).map_err(|_| {
                    Error::CommittedButUnavailable {
                        receipt: Box::new(receipt.clone()),
                    }
                })?;
                Ok(Completed {
                    receipt,
                    result,
                    replayed: true,
                })
            }
            Some(Resolution::Failed(error)) => Err(error),
            None => native.and(Err(Error::OutcomeUnknown)),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod file_tests;
