//! Native read-only transactions. Authority is supplied by the trusted worker;
//! this layer enforces the private SQLite snapshot and execution boundaries.

use std::panic::{catch_unwind, AssertUnwindSafe};

use libsql_sys::rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use libsql_sys::rusqlite::Connection;
use scap_sql::{Statement, TransactionResult};

use crate::{sql, Error, ReadInterrupt, WriterLimits};

pub(crate) fn check(interrupt: &ReadInterrupt) -> Result<(), Error> {
    // A faulty clock/cancellation provider cannot silently grant more time or
    // unwind through SQLite's C callback. Its state is never reused after panic.
    if catch_unwind(AssertUnwindSafe(|| interrupt())).unwrap_or(true) {
        return Err(Error::Interrupted);
    }
    Ok(())
}

pub(crate) fn authorize(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Read { .. }
        | AuthAction::Select
        | AuthAction::Recursive
        | AuthAction::Function { .. } => sql::authorize(context),
        _ => Authorization::Deny,
    }
}

pub(crate) fn execute(
    connection: &Connection,
    statements: &[Statement],
    limits: WriterLimits,
    interrupt: &ReadInterrupt,
) -> Result<TransactionResult, Error> {
    check(interrupt)?;
    connection
        .execute_batch("BEGIN DEFERRED")
        .map_err(Error::Sqlite)?;
    let mut remaining_steps = limits.max_vm_steps;
    let progress = AssertUnwindSafe(interrupt.clone());
    connection.progress_handler(
        1,
        Some(move || {
            let exhausted = remaining_steps == 0;
            remaining_steps = remaining_steps.saturating_sub(1);
            exhausted || check(&progress).is_err()
        }),
    );
    connection.authorizer(Some(authorize));
    let result = sql::collect_results(connection, statements, limits, Some(interrupt));
    // User SQL cannot submit transaction-control commands. Only this boundary
    // removes the authorizer for the private, read-only COMMIT. Keep the VM and
    // cancellation guard active through COMMIT, and remove both before cleanup.
    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    let result = result.and_then(|result| {
        check(interrupt)?;
        connection.execute_batch("COMMIT").map_err(Error::Sqlite)?;
        check(interrupt)?;
        Ok(result)
    });
    connection.progress_handler(0, None::<fn() -> bool>);
    if result.is_err() {
        sql::rollback(connection);
    }
    result
}
