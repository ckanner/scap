use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use scap_sql::{Statement, StatementResult, TransactionResult, Value as SqlValue};
use serde_json::{json, Map, Value};

use crate::{invalid, unsupported, Limits, Mode, Outcome, ServiceError};

type Object = Map<String, Value>;

pub(crate) struct Plan {
    pub statements: Vec<Statement>,
    pub mode: Mode,
    results: Vec<Value>,
    slot: usize,
    rows: Vec<bool>,
    batch: bool,
}

pub(crate) fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Object, ServiceError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("expected JSON object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(unsupported());
    }
    Ok(object)
}

fn field<'a>(value: &'a Object, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}
fn string(value: &Value) -> Result<&str, ServiceError> {
    value.as_str().ok_or_else(|| invalid("expected string"))
}
fn array(value: &Value) -> Result<&Vec<Value>, ServiceError> {
    value.as_array().ok_or_else(|| invalid("expected array"))
}

fn sql_id(value: &Value) -> Result<u32, ServiceError> {
    let value = value
        .as_u64()
        .ok_or_else(|| invalid("invalid SQL cache ID"))?;
    if value > i32::MAX as u64 {
        return Err(invalid("invalid SQL cache ID"));
    }
    Ok(value as u32)
}

fn parameter(value: &Value) -> Result<SqlValue, ServiceError> {
    let value = object(value, &["type", "value", "base64"])?;
    let kind = string(field(value, "type"))?;
    let data = field(value, "value");
    Ok(match kind {
        "null" => {
            if !data.is_null() || !field(value, "base64").is_null() {
                return Err(invalid("invalid null parameter"));
            }
            SqlValue::Null
        }
        "integer" => SqlValue::Integer(
            string(data)?
                .parse()
                .map_err(|_| invalid("integer outside SQLite range"))?,
        ),
        "float" => SqlValue::Real(
            data.as_f64()
                .ok_or_else(|| invalid("invalid float parameter"))?,
        ),
        "text" => SqlValue::Text(string(data)?.to_owned()),
        "blob" => SqlValue::Blob(
            STANDARD
                .decode(string(field(value, "base64"))?)
                .map_err(|_| invalid("invalid base64 parameter"))?,
        ),
        _ => return Err(unsupported()),
    })
}

fn statement(
    value: &Value,
    cache: &BTreeMap<u32, String>,
) -> Result<(Statement, bool), ServiceError> {
    let value = object(
        value,
        &[
            "sql",
            "sql_id",
            "args",
            "named_args",
            "want_rows",
            "replication_index",
        ],
    )?;
    let named = field(value, "named_args");
    if !named.is_null() && !array(named)?.is_empty() {
        return Err(unsupported());
    }
    if !field(value, "replication_index").is_null() {
        return Err(unsupported());
    }
    let sql = match (field(value, "sql"), field(value, "sql_id")) {
        (Value::String(sql), Value::Null) => sql.clone(),
        (Value::Null, id) if !id.is_null() => cache
            .get(&sql_id(id)?)
            .cloned()
            .ok_or_else(|| invalid("unknown SQL cache ID"))?,
        _ => return Err(invalid("supply exactly one SQL text or cache ID")),
    };
    let arguments = field(value, "args");
    let parameters = if arguments.is_null() {
        Vec::new()
    } else {
        array(arguments)?
            .iter()
            .map(parameter)
            .collect::<Result<_, _>>()?
    };
    let rows = match field(value, "want_rows") {
        Value::Null => true,
        Value::Bool(value) => *value,
        _ => return Err(invalid("want_rows must be boolean")),
    };
    Ok((Statement { sql, parameters }, rows))
}

fn batch(
    value: &Value,
    cache: &BTreeMap<u32, String>,
    limits: Limits,
    mode: Mode,
) -> Result<(Vec<Statement>, Vec<bool>, Mode), ServiceError> {
    let value = object(value, &["steps", "replication_index"])?;
    if !field(value, "replication_index").is_null() {
        return Err(unsupported());
    }
    let steps = array(field(value, "steps"))?;
    if steps.len() < 4 || steps.len() > limits.sql.max_statements as usize + 3 {
        return Err(unsupported());
    }
    let mut statements = Vec::new();
    let mut rows = Vec::new();
    let mut selected_mode = mode;
    for (index, step) in steps.iter().enumerate() {
        let step = object(step, &["stmt", "condition"])?;
        let condition = field(step, "condition");
        let (stmt, want_rows) = statement(field(step, "stmt"), cache)?;
        if index == 0 {
            if !condition.is_null() || !stmt.parameters.is_empty() || want_rows {
                return Err(unsupported());
            }
            match stmt.sql.as_str() {
                "BEGIN TRANSACTION READONLY" => selected_mode = Mode::Read,
                "BEGIN DEFERRED" | "BEGIN IMMEDIATE" => {}
                _ => return Err(unsupported()),
            }
        } else if index == steps.len() - 1 {
            if condition != &json!({"type":"not","cond":{"type":"ok","step":index-1}})
                || stmt.sql != "ROLLBACK"
                || !stmt.parameters.is_empty()
                || want_rows
            {
                return Err(unsupported());
            }
        } else {
            if condition != &json!({"type":"ok","step":index-1}) {
                return Err(unsupported());
            }
            if index == steps.len() - 2 {
                if stmt.sql != "COMMIT" || !stmt.parameters.is_empty() || want_rows {
                    return Err(unsupported());
                }
            } else {
                statements.push(stmt);
                rows.push(want_rows);
            }
        }
    }
    Ok((statements, rows, selected_mode))
}

/// Parse and validate the complete program before invoking any SQL effect.
pub(crate) fn pipeline(value: &Value, limits: Limits, mode: Mode) -> Result<Plan, ServiceError> {
    let value = object(value, &["baton", "requests"])?;
    if !field(value, "baton").is_null() {
        return Err(unsupported());
    }
    let requests = array(field(value, "requests"))?;
    if requests.len() < 2 || requests.len() > limits.max_pipeline_requests {
        return Err(unsupported());
    }
    let mut cache = BTreeMap::new();
    let mut cache_bytes = 0;
    let mut execution = None;
    let mut results = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        let request = object(request, &["type", "stmt", "batch", "sql_id", "sql"])?;
        let kind = string(field(request, "type"))?;
        if index == requests.len() - 1 && kind != "close" {
            return Err(unsupported());
        }
        match kind {
            "close" => {
                if index != requests.len() - 1 || request.len() != 1 {
                    return Err(unsupported());
                }
            }
            "store_sql" => {
                if request.len() != 3 {
                    return Err(invalid("invalid SQL cache store"));
                }
                let id = sql_id(field(request, "sql_id"))?;
                let sql = string(field(request, "sql"))?;
                if cache.contains_key(&id)
                    || cache.len() == limits.max_cached_statements
                    || sql.len() > limits.max_cached_sql_bytes - cache_bytes
                {
                    return Err(invalid("SQL cache limit or duplicate ID"));
                }
                cache_bytes += sql.len();
                cache.insert(id, sql.to_owned());
            }
            "close_sql" => {
                if request.len() != 2 {
                    return Err(invalid("invalid SQL cache close"));
                }
                let removed = cache
                    .remove(&sql_id(field(request, "sql_id"))?)
                    .ok_or_else(|| invalid("unknown SQL cache ID"))?;
                cache_bytes -= removed.len();
            }
            "execute" | "batch" => {
                if execution.is_some() || request.len() != 2 {
                    return Err(unsupported());
                }
                let (statements, rows, selected_mode) = if kind == "execute" {
                    let (stmt, rows) = statement(field(request, "stmt"), &cache)?;
                    (vec![stmt], vec![rows], mode)
                } else {
                    batch(field(request, "batch"), &cache, limits, mode)?
                };
                scap_sql::validate_statements(&statements, limits.sql)
                    .map_err(|_| invalid("SQL request exceeds limits or is invalid"))?;
                execution = Some((index, statements, rows, kind == "batch", selected_mode));
            }
            _ => return Err(unsupported()),
        }
        results.push(json!({"type":"ok","response":{"type":kind}}));
    }
    let (slot, statements, rows, batch, mode) = execution.ok_or_else(unsupported)?;
    Ok(Plan {
        statements,
        mode,
        results,
        slot,
        rows,
        batch,
    })
}

fn value(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => json!({"type":"null"}),
        SqlValue::Integer(value) => json!({"type":"integer","value":value.to_string()}),
        SqlValue::Real(value) => json!({"type":"float","value":value}),
        SqlValue::Text(value) => json!({"type":"text","value":value}),
        SqlValue::Blob(value) => json!({"type":"blob","base64":STANDARD.encode(value)}),
    }
}

fn statement_result(result: &StatementResult, want_rows: bool) -> Value {
    let rows = if want_rows {
        result
            .rows
            .iter()
            .map(|row| row.iter().map(value).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let columns = result
        .columns
        .iter()
        .map(|name| json!({"name":name,"decltype":null}))
        .collect::<Vec<_>>();
    json!({"cols":columns,"rows":rows,"affected_row_count":result.affected_rows,"last_insert_rowid":result.last_insert_rowid.to_string()})
}

fn empty_result() -> Value {
    json!({"cols":[],"rows":[],"affected_row_count":0,"last_insert_rowid":null})
}

fn validate_result(result: &TransactionResult, limits: Limits) -> Result<(), ServiceError> {
    scap_sql::encode_result(result, limits.sql).map_err(|_| {
        ServiceError::new(
            "COMMITTED_RESULT_UNAVAILABLE",
            "backend returned an invalid or oversized result",
        )
    })?;
    if result
        .statements
        .iter()
        .any(|stmt| stmt.affected_rows > (1_u64 << 53) - 1)
    {
        return Err(ServiceError::new(
            "COMMITTED_RESULT_UNAVAILABLE",
            "affected row count is outside SDK range",
        ));
    }
    Ok(())
}

impl Plan {
    pub(crate) fn finish(
        mut self,
        result: Result<TransactionResult, ServiceError>,
        limits: Limits,
    ) -> Value {
        let response = result.and_then(|result| {
            validate_result(&result, limits)?;
            if result.statements.len() != self.rows.len() { return Err(ServiceError::new("COMMITTED_RESULT_UNAVAILABLE", "backend result count mismatch")); }
            let mut statements = result.statements.iter().zip(&self.rows).map(|(stmt, rows)| statement_result(stmt, *rows)).collect::<Vec<_>>();
            if self.batch {
                statements.insert(0, empty_result());
                statements.push(empty_result());
                statements.push(Value::Null);
                let errors = vec![Value::Null; statements.len()];
                Ok(json!({"type":"batch","result":{"step_results":statements,"step_errors":errors}}))
            } else {
                Ok(json!({"type":"execute","result":statements.remove(0)}))
            }
        });
        self.results[self.slot] = match response {
            Ok(response) => json!({"type":"ok","response":response}),
            Err(error) => {
                json!({"type":"error","error":{"code":error.code,"message":error.message}})
            }
        };
        json!({"baton":null,"base_url":null,"results":self.results})
    }
}

pub(crate) fn outcome_request(
    body: &Value,
    limits: Limits,
) -> Result<(Vec<Statement>, bool), ServiceError> {
    let body = object(body, &["action", "statements"])?;
    let resolve = match string(field(body, "action"))? {
        "lookup" => false,
        "resolve_or_cancel" => true,
        _ => return Err(unsupported()),
    };
    let statements = array(field(body, "statements"))?
        .iter()
        .map(|stmt| statement(stmt, &BTreeMap::new()).map(|(stmt, _)| stmt))
        .collect::<Result<Vec<_>, _>>()?;
    scap_sql::validate_statements(&statements, limits.sql)
        .map_err(|_| invalid("invalid outcome statements"))?;
    Ok((statements, resolve))
}

pub(crate) fn outcome_result(outcome: Outcome, limits: Limits) -> Result<Value, ServiceError> {
    Ok(match outcome {
        Outcome::Unknown => json!({"state":"unknown"}),
        Outcome::Cancelled => json!({"state":"cancelled"}),
        Outcome::Committed { result, sequence } => {
            validate_result(&result, limits)?;
            json!({"state":"committed","sequence":sequence.to_string(),"results":result.statements.iter().map(|stmt| statement_result(stmt,true)).collect::<Vec<_>>()})
        }
    })
}

#[cfg(test)]
mod tests;
