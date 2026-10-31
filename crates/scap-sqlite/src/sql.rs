use std::path::Path;

use libsql_sys::rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use libsql_sys::rusqlite::types::{Value as NativeValue, ValueRef};
use libsql_sys::rusqlite::{self, Batch, OpenFlags};
use libsql_sys::wal::{Sqlite3WalManager, WalManager};
use scap_sql::{Statement, StatementResult, TransactionResult, Value};

pub(crate) use crate::config::configure;
use crate::gate::GateWal;
use crate::{CommitGate, Error, NativeConnection, WriterLimits};

pub(crate) fn validate_limits(limits: WriterLimits) -> Result<(), Error> {
    limits.sql.validate().map_err(Error::Sql)?;
    if limits.max_vm_steps == 0 || limits.max_changed_pages == 0 {
        return Err(Error::InvalidLimits);
    }
    for value in [
        limits.sql.max_sql_bytes,
        limits.sql.max_parameters,
        limits.sql.max_columns,
        limits.sql.max_result_bytes,
        limits.sql.max_value_bytes,
    ] {
        if value > i32::MAX as u32 {
            return Err(Error::InvalidLimits);
        }
    }
    Ok(())
}

pub(crate) fn open<G: CommitGate + 'static>(
    path: &Path,
    gate: GateWal<G>,
    limits: WriterLimits,
    max_database_pages: u32,
) -> Result<NativeConnection<G>, Error> {
    let manager = Sqlite3WalManager::default().wrap(gate);
    let connection = libsql_sys::Connection::open(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        manager,
        libsql_sys::connection::NO_AUTOCHECKPOINT,
        None,
    )
    .map_err(Error::Sqlite)?;
    configure(&*connection, limits, max_database_pages)?;
    Ok(connection)
}

pub(crate) fn authorize(context: AuthContext<'_>) -> Authorization {
    if let Some(database) = context.database_name {
        if database != "main" {
            return Authorization::Deny;
        }
    }
    match context.action {
        AuthAction::CreateIndex { .. }
        | AuthAction::CreateTable { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::Delete { .. }
        | AuthAction::DropIndex { .. }
        | AuthAction::DropTable { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::DropView { .. }
        | AuthAction::Insert { .. }
        | AuthAction::Read { .. }
        | AuthAction::Select
        | AuthAction::Update { .. }
        | AuthAction::AlterTable { .. }
        | AuthAction::Reindex { .. }
        | AuthAction::Analyze { .. }
        | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Function { function_name } => {
            // Initial compatibility is an explicit side-effect-free builtin
            // set. Unknown/extension functions do not gain authority merely
            // because SQLite can resolve their names.
            if [
                "abs",
                "avg",
                "changes",
                "char",
                "coalesce",
                "concat",
                "concat_ws",
                "count",
                "date",
                "datetime",
                "format",
                "glob",
                "group_concat",
                "hex",
                "if",
                "ifnull",
                "iif",
                "instr",
                "julianday",
                "last_insert_rowid",
                "length",
                "like",
                "likelihood",
                "likely",
                "lower",
                "ltrim",
                "max",
                "min",
                "nullif",
                "octet_length",
                "printf",
                "quote",
                "random",
                "randomblob",
                "replace",
                "round",
                "rtrim",
                "sign",
                "soundex",
                "sqlite_compileoption_get",
                "sqlite_compileoption_used",
                "sqlite_source_id",
                "sqlite_version",
                "strftime",
                "string_agg",
                "substr",
                "substring",
                "sum",
                "time",
                "timediff",
                "total",
                "total_changes",
                "trim",
                "typeof",
                "unhex",
                "unicode",
                "unixepoch",
                "unlikely",
                "upper",
                "zeroblob",
                "json",
                "json_array",
                "json_array_length",
                "json_error_position",
                "json_extract",
                "json_group_array",
                "json_group_object",
                "json_insert",
                "json_object",
                "json_patch",
                "json_pretty",
                "json_quote",
                "json_remove",
                "json_replace",
                "json_set",
                "json_type",
                "json_valid",
                "jsonb",
                "jsonb_array",
                "jsonb_extract",
                "jsonb_group_array",
                "jsonb_group_object",
                "jsonb_insert",
                "jsonb_object",
                "jsonb_patch",
                "jsonb_remove",
                "jsonb_replace",
                "jsonb_set",
                "->",
                "->>",
                "row_number",
                "rank",
                "dense_rank",
                "percent_rank",
                "cume_dist",
                "ntile",
                "lag",
                "lead",
                "first_value",
                "last_value",
                "nth_value",
            ]
            .iter()
            .any(|allowed| function_name.eq_ignore_ascii_case(allowed))
            {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        _ => Authorization::Deny,
    }
}

pub(crate) fn execute_transaction(
    connection: &rusqlite::Connection,
    statements: &[Statement],
    limits: WriterLimits,
) -> Result<TransactionResult, Error> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(Error::Sqlite)?;
    let mut remaining_steps = limits.max_vm_steps;
    connection.progress_handler(
        1,
        Some(move || {
            let exhausted = remaining_steps == 0;
            remaining_steps = remaining_steps.saturating_sub(1);
            exhausted
        }),
    );
    connection.authorizer(Some(authorize));
    let result = collect_results(connection, statements, limits);
    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    connection.progress_handler(0, None::<fn() -> bool>);
    result
}

fn collect_results(
    connection: &rusqlite::Connection,
    statements: &[Statement],
    limits: WriterLimits,
) -> Result<TransactionResult, Error> {
    let mut result = TransactionResult {
        statements: Vec::new(),
    };
    let mut remaining_bytes = limits.sql.max_result_bytes as usize;
    let mut remaining_rows = limits.sql.max_rows as usize;
    for statement in statements {
        let mut batch = Batch::new(connection, &statement.sql);
        let mut prepared = batch
            .next()
            .map_err(Error::Sqlite)?
            .ok_or(Error::InvalidSql)?;
        if batch.next().map_err(Error::Sqlite)?.is_some() {
            return Err(Error::InvalidSql);
        }
        let count = prepared.column_count();
        if count > limits.sql.max_columns as usize {
            return Err(Error::ResultLimit);
        }
        let mut columns = Vec::new();
        for name in prepared.column_names() {
            check_value_length(name.len(), limits)?;
            spend(&mut remaining_bytes, name.len() + 4)?;
            columns.push(name.to_owned());
        }
        let before: u64 = connection
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .map_err(Error::Sqlite)?;
        let parameters = statement.parameters.iter().map(native_value);
        let mut native_rows = prepared
            .query(rusqlite::params_from_iter(parameters))
            .map_err(Error::Sqlite)?;
        let mut rows = Vec::new();
        while let Some(row) = native_rows.next().map_err(Error::Sqlite)? {
            spend(&mut remaining_rows, 1)?;
            let mut values = Vec::new();
            for index in 0..count {
                values.push(copy_value(
                    // This private connection holds BEGIN IMMEDIATE and every
                    // index comes from this same statement's column_count.
                    // The pinned API's only usize lookup error is out-of-range;
                    // no independently supplied index crosses this boundary.
                    row.get_ref_unwrap(index),
                    &mut remaining_bytes,
                    limits,
                )?);
            }
            rows.push(values);
        }
        drop(native_rows);
        drop(prepared);
        let after: u64 = connection
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .map_err(Error::Sqlite)?;
        result.statements.push(StatementResult {
            columns,
            rows,
            // DDL/SELECT preserve sqlite3_changes(), so a total-change boundary
            // distinguishes them from DML while the direct counter excludes
            // trigger side effects, matching ordinary SQLite SDK semantics.
            affected_rows: if after == before {
                0
            } else {
                connection.changes()
            },
            last_insert_rowid: connection.last_insert_rowid(),
        });
    }
    Ok(result)
}

pub(crate) fn native_value(value: &Value) -> NativeValue {
    match value {
        Value::Null => NativeValue::Null,
        Value::Integer(value) => NativeValue::Integer(*value),
        Value::Real(value) => NativeValue::Real(*value),
        Value::Text(value) => NativeValue::Text(value.clone()),
        Value::Blob(value) => NativeValue::Blob(value.clone()),
    }
}

pub(crate) fn spend(remaining: &mut usize, amount: usize) -> Result<(), Error> {
    if amount > *remaining {
        return Err(Error::ResultLimit);
    }
    *remaining -= amount;
    Ok(())
}

fn check_value_length(length: usize, limits: WriterLimits) -> Result<(), Error> {
    if length > limits.sql.max_value_bytes as usize {
        return Err(Error::ResultLimit);
    }
    Ok(())
}

pub(crate) fn copy_value(
    value: ValueRef<'_>,
    remaining: &mut usize,
    limits: WriterLimits,
) -> Result<Value, Error> {
    spend(remaining, 1)?;
    match value {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Integer(value) => {
            spend(remaining, 8)?;
            Ok(Value::Integer(value))
        }
        ValueRef::Real(value) => {
            spend(remaining, 8)?;
            Ok(Value::Real(value))
        }
        ValueRef::Text(value) => {
            check_value_length(value.len(), limits)?;
            spend(remaining, value.len() + 4)?;
            let value = std::str::from_utf8(value).map_err(|_| Error::InvalidSql)?;
            Ok(Value::Text(value.to_owned()))
        }
        ValueRef::Blob(value) => {
            check_value_length(value.len(), limits)?;
            spend(remaining, value.len() + 4)?;
            Ok(Value::Blob(value.to_owned()))
        }
    }
}

pub(crate) fn rollback(connection: &rusqlite::Connection) {
    // Always stop after a failure; rollback is resource cleanup, never evidence
    // that a proposal with an unknown outcome did not commit in the cell.
    let _ = connection.execute_batch("ROLLBACK");
}
