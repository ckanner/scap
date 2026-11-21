//! Private native staging for independent transactions with one authority gate.
//!
//! Staging commits affect only this writer's inaccessible private image. The
//! ordinary CommitGate is never told that these local commits are authoritative.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use libsql_sys::{ffi, rusqlite};
use scap_sql::{Statement, TransactionResult};

use crate::{
    config, query, sql, CommitGate, Error, GateDecision, PageBatch, ReadInterrupt, ResultEncoder,
    SqliteWriter, MAX_DATABASE_PAGES,
};

/// Bounds on retained staging, separate from every member's WriterLimits.
/// Changed pages count every captured version, even repeated page numbers in
/// different members. The current typed result remains independently bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupLimits {
    pub max_members: usize,
    pub max_changed_pages: u32,
    pub max_result_bytes: u64,
}

pub struct GroupMember<'a> {
    pub statements: &'a [Statement],
    pub interrupt: ReadInterrupt,
}

/// One actually committed private transaction, relative to its predecessor.
/// These bytes are visible only to the trusted authority adapter, never an ACK.
#[derive(Debug)]
pub struct StagedTransaction {
    pub batch: PageBatch,
    pub result: Vec<u8>,
}

/// Publish the complete successful prefix using one original authority basis.
/// Accepted has exactly the same durable-authority meaning as CommitGate.
pub trait GroupCommitGate {
    fn publish(&mut self, prefix: &[StagedTransaction]) -> GateDecision;
}

impl<F: FnMut(&[StagedTransaction]) -> GateDecision> GroupCommitGate for F {
    fn publish(&mut self, prefix: &[StagedTransaction]) -> GateDecision {
        self(prefix)
    }
}

/// attempted - staged is zero or one; member_error exists exactly when it is
/// one. An unattempted suffix has never run SQL. A fatal member error leaves its
/// cause in member_error and uses Stopped for the unusable whole-group outcome.
/// Accepted publication followed by local failure is CommittedButUnavailable.
#[derive(Debug)]
pub struct GroupRun {
    pub attempted: usize,
    pub staged: usize,
    pub member_error: Option<Error>,
    pub outcome: Result<Vec<Vec<u8>>, Error>,
}

/// Only native completion/cleanup effects vary in deterministic fault tests.
/// SQL execution, prefix selection, budgets and publication ordering do not.
pub(crate) trait GroupEffects {
    fn commit(
        &mut self,
        connection: &rusqlite::Connection,
        interrupt: &ReadInterrupt,
    ) -> Result<(), Error>;
    fn rollback(&mut self, connection: &rusqlite::Connection) -> Result<(), Error>;
    fn checkpoint(&mut self, connection: &rusqlite::Connection) -> Result<(), Error>;
}

struct NativeEffects;

impl GroupEffects for NativeEffects {
    fn commit(
        &mut self,
        connection: &rusqlite::Connection,
        interrupt: &ReadInterrupt,
    ) -> Result<(), Error> {
        sql::commit_native(connection, interrupt)
    }

    fn rollback(&mut self, connection: &rusqlite::Connection) -> Result<(), Error> {
        sql::rollback_checked(connection)
    }

    fn checkpoint(&mut self, connection: &rusqlite::Connection) -> Result<(), Error> {
        config::checkpoint(connection)
    }
}

struct MemberFailure {
    error: Error,
    fatal: bool,
}

impl<G: CommitGate + 'static> SqliteWriter<G> {
    /// Execute a bounded sequence of independent BEGIN/COMMIT transactions in
    /// a private staging image. No ordinary operation or result can observe the
    /// staged state before the group gate accepts and local finalization ends.
    pub fn execute_group(
        &mut self,
        members: &[GroupMember<'_>],
        limits: GroupLimits,
        gate: &mut dyn GroupCommitGate,
        group_interrupt: ReadInterrupt,
    ) -> GroupRun {
        self.execute_group_with(
            members,
            limits,
            gate,
            group_interrupt,
            &mut NativeEffects,
            &mut scap_sql::encode_result,
        )
    }

    pub(crate) fn execute_group_with(
        &mut self,
        members: &[GroupMember<'_>],
        limits: GroupLimits,
        gate: &mut dyn GroupCommitGate,
        group_interrupt: ReadInterrupt,
        effects: &mut dyn GroupEffects,
        encode: &mut ResultEncoder<'_>,
    ) -> GroupRun {
        let mut run = GroupRun {
            attempted: 0,
            staged: 0,
            member_error: None,
            outcome: Err(Error::Stopped),
        };
        if self.stopped {
            return run;
        }
        self.stopped = true;
        if let Err(error) = validate(limits, members.len()) {
            run.outcome = Err(error);
            return run;
        }
        let mut prefix = Vec::with_capacity(members.len());
        let mut pages = self.pages;
        let mut remaining_pages = limits.max_changed_pages;
        let mut remaining_bytes = limits.max_result_bytes;
        for member in members {
            if let Err(error) = query::check(&group_interrupt) {
                run.outcome = Err(error);
                return run;
            }
            let group = group_interrupt.clone();
            let original = member.interrupt.clone();
            let interrupt: ReadInterrupt = Arc::new(move || group() || original());
            run.attempted += 1;
            self.state
                .borrow_mut()
                .begin_staging(pages, remaining_pages.min(self.limits.max_changed_pages));
            match self.stage_member(
                member.statements,
                remaining_bytes,
                &interrupt,
                effects,
                encode,
            ) {
                Ok(staged) => {
                    remaining_pages -= staged.batch.pages.len() as u32;
                    remaining_bytes -= staged.result.len() as u64;
                    pages = staged.batch.size_after;
                    prefix.push(staged);
                    run.staged += 1;
                    if let Err(error) = query::check(&interrupt) {
                        run.outcome = Err(error);
                        return run;
                    }
                }
                Err(failure) => {
                    run.member_error = Some(failure.error);
                    if failure.fatal {
                        return run;
                    }
                    break;
                }
            }
        }
        if prefix.is_empty() {
            run.outcome = Ok(Vec::new());
            return run;
        }
        let published_members = &members[..run.staged];
        if let Err(error) = check_members(published_members, &group_interrupt) {
            run.outcome = Err(error);
            return run;
        }
        let decision = catch_unwind(AssertUnwindSafe(|| gate.publish(&prefix)))
            .unwrap_or(GateDecision::Unknown);
        let error = match decision {
            GateDecision::Accepted => None,
            GateDecision::Rejected => Some(Error::Rejected),
            GateDecision::Unknown => Some(Error::OutcomeUnknown),
        };
        if let Some(error) = error {
            run.outcome = Err(error);
            return run;
        }
        let finalized = check_members(published_members, &group_interrupt)
            .and_then(|()| effects.checkpoint(&self.connection))
            .and_then(|()| check_members(published_members, &group_interrupt));
        if finalized.is_err() {
            run.outcome = Err(Error::CommittedButUnavailable);
            return run;
        }
        self.pages = pages;
        self.stopped = run.member_error.is_some();
        run.outcome = Ok(prefix.into_iter().map(|staged| staged.result).collect());
        run
    }

    fn stage_member(
        &mut self,
        statements: &[Statement],
        remaining_bytes: u64,
        interrupt: &ReadInterrupt,
        effects: &mut dyn GroupEffects,
        encode: &mut ResultEncoder<'_>,
    ) -> Result<StagedTransaction, MemberFailure> {
        let executed = (|| {
            query::check(interrupt)?;
            scap_sql::validate_statements(statements, self.limits.sql).map_err(Error::Sql)?;
            let result: TransactionResult =
                sql::execute_transaction(&self.connection, statements, self.limits, interrupt)?;
            let encoded = encode(&result, self.limits.sql).map_err(|error| match error {
                scap_sql::SqlError::ResourceExhausted => Error::ResourceExhausted,
                other => Error::Sql(other),
            })?;
            drop(result);
            if encoded.len() as u64 > remaining_bytes {
                return Err(Error::ResultLimit);
            }
            // Native success is recorded before any post-COMMIT interruption.
            // A later deadline cannot remove a committed member from the image.
            effects.commit(&self.connection, interrupt)?;
            Ok(encoded)
        })();
        let mut captured = self.state.borrow_mut().take_staging();
        let executed = match captured.error.take() {
            Some(error) => Err(error),
            None => executed,
        };
        match executed {
            Ok(result) => Ok(StagedTransaction {
                batch: captured.pending.unwrap_or(PageBatch {
                    size_after: captured.base_pages,
                    pages: Vec::new(),
                }),
                result,
            }),
            Err(error) => {
                let fatal = captured.pending.is_some() || !recoverable(&error);
                match effects.rollback(&self.connection) {
                    Ok(()) => Err(MemberFailure { error, fatal }),
                    Err(error) => Err(MemberFailure { error, fatal: true }),
                }
            }
        }
    }
}

fn validate(limits: GroupLimits, count: usize) -> Result<(), Error> {
    if count == 0
        || limits.max_members == 0
        || count > limits.max_members
        || limits.max_changed_pages == 0
        || limits.max_changed_pages > MAX_DATABASE_PAGES
        || limits.max_result_bytes == 0
    {
        return Err(Error::InvalidLimits);
    }
    Ok(())
}

fn check_members(members: &[GroupMember<'_>], interrupt: &ReadInterrupt) -> Result<(), Error> {
    query::check(interrupt)?;
    for member in members {
        query::check(&member.interrupt)?;
    }
    Ok(())
}

/// Only known SQL/request failures may preserve a prefix, and only after
/// checked rollback. Storage, allocation, corruption and unknown errors stop
/// the whole group. Native frame publication followed by any error is fatal.
pub(crate) fn recoverable(error: &Error) -> bool {
    match error {
        Error::InvalidSql | Error::ResultLimit => true,
        Error::Sql(scap_sql::SqlError::Invalid | scap_sql::SqlError::Limit) => true,
        Error::Sqlite(error) => match error {
            rusqlite::Error::SqliteFailure(error, _)
            | rusqlite::Error::SqlInputError { error, .. } => [
                ffi::SQLITE_ERROR,
                ffi::SQLITE_CONSTRAINT,
                ffi::SQLITE_TOOBIG,
                ffi::SQLITE_MISMATCH,
                ffi::SQLITE_AUTH,
                ffi::SQLITE_RANGE,
            ]
            .contains(&(error.extended_code & 0xff)),
            rusqlite::Error::InvalidParameterCount(_, _)
            | rusqlite::Error::InvalidParameterName(_)
            | rusqlite::Error::NulError(_)
            | rusqlite::Error::MultipleStatement
            | rusqlite::Error::InvalidQuery => true,
            _ => false,
        },
        _ => false,
    }
}
