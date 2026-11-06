//! Independent process fixture. Every database algorithm remains in the
//! production crates; this binary translates test commands and observations.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_object::format::{head_key, object_key, Scope, MAX_OBJECT_BYTES};
use scap_object::{request, sql_limits, Database, Receipt, Resolution};
use scap_object_store::{Condition, Objects, S3Config, S3};
use scap_sql::{Statement, TransactionResult, Value as SqlValue};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    scope: Scope,
    worker: u64,
    principal: u64,
    cache_root: PathBuf,
}

fn receipt(value: &Receipt) -> Value {
    json!({"scope": value.scope, "request": value.request, "sequence": value.sequence,
        "transition": value.transition, "data_root": value.data_root, "result_hash": value.result_hash})
}

fn result(value: &TransactionResult) -> Value {
    let rows: Vec<_> = value
        .statements
        .iter()
        .map(|statement| {
            let rows: Vec<_> = statement
                .rows
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|value| match value {
                            SqlValue::Null => Value::Null,
                            SqlValue::Integer(number) => json!(number),
                            SqlValue::Real(number) => json!(number),
                            SqlValue::Text(text) => json!(text),
                            SqlValue::Blob(bytes) => json!({"blob": bytes}),
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            json!({"columns": statement.columns, "rows": rows})
        })
        .collect();
    json!({"encoded": scap_sql::encode_result(value, sql_limits()).unwrap(), "statements": rows})
}

fn resolution(value: Resolution) -> Value {
    match value {
        Resolution::Committed {
            receipt: proof,
            bytes,
        } => {
            json!({"state":"committed", "receipt": receipt(&proof), "encoded":bytes})
        }
        Resolution::Cancelled { transition } => {
            json!({"state":"cancelled", "transition":transition})
        }
        Resolution::Unknown => json!({"state":"unknown"}),
        Resolution::Closed => json!({"state":"closed"}),
        Resolution::Retired => json!({"state":"retired"}),
    }
}

fn perform(
    config: &Config,
    objects: &S3,
    database: &Database,
    cmd: Value,
) -> Result<Value, String> {
    let deadline =
        Instant::now() + Duration::from_millis(cmd["budget_ms"].as_u64().unwrap_or(8000));
    let op = cmd["op"].as_str().unwrap();
    let principal = config.principal;
    let number = |name: &str| cmd[name].as_u64().unwrap();
    let text = |name: &str| cmd[name].as_str().unwrap();
    let map = |error| format!("{error:?}");
    let statement = || {
        vec![Statement {
            sql: text("sql").into(),
            parameters: Vec::new(),
        }]
    };
    match op {
        "store_get" => objects
            .get(text("key"), MAX_OBJECT_BYTES, deadline)
            .map(|stored| json!({"bytes":stored.bytes,"etag":stored.etag}))
            .map_err(|error| format!("{error:?}")),
        "store_put" => {
            let bytes: Vec<u8> = serde_json::from_value(cmd["bytes"].clone()).unwrap();
            let condition = match cmd["etag"].as_str() {
                Some(etag) => Condition::Match(etag),
                None => Condition::Absent,
            };
            objects
                .put(text("key"), &bytes, condition, deadline)
                .map(|etag| json!({"etag":etag}))
                .map_err(|error| format!("{error:?}"))
        }
        "create" => database
            .create(principal, number("nonce"), deadline)
            .map(|head| json!(head))
            .map_err(map),
        "status" => database
            .status(principal, deadline)
            .map(|head| json!(head))
            .map_err(map),
        "authority_keys" => database.status(principal, deadline).map(|head| {
            json!({"head":head_key(&config.scope), "data_root":object_key(&config.scope, &head.data_root)})
        }).map_err(map),
        "activate" => database
            .activate(principal, number("revision"), number("nonce"), deadline)
            .map(|head| json!(head))
            .map_err(map),
        "takeover" => database
            .takeover(principal, number("revision"), number("nonce"), deadline)
            .map(|head| json!(head))
            .map_err(map),
        "execute" => {
            let sql = statement();
            let identity = request(number("epoch"), number("id"), principal, &sql).map_err(map)?;
            let directory = config.cache_root.join(text("directory"));
            database
                .execute(principal, &identity, &sql, &directory, deadline)
                .map(|(proof, data)| json!({"receipt":receipt(&proof),"result":result(&data)}))
                .map_err(map)
        }
        "query" => {
            let directory = config.cache_root.join(text("directory"));
            database
                .query(principal, &statement(), &directory, deadline)
                .map(|data| result(&data))
                .map_err(map)
        }
        "lookup" | "cancel" => {
            let identity =
                request(number("epoch"), number("id"), principal, &statement()).map_err(map)?;
            let observed = if op == "lookup" {
                database.lookup(principal, &identity, deadline)
            } else {
                database.cancel(principal, &identity, deadline)
            };
            observed.map(resolution).map_err(map)
        }
        _ => Err("unknown fixture command".into()),
    }
}

fn main() {
    assert!(
        std::env::var_os("LLVM_PROFILE_FILE").is_none(),
        "fault experiments cannot contribute to unit coverage"
    );
    let path = std::env::args()
        .nth(1)
        .expect("private fixture configuration path");
    let config: Config = serde_json::from_slice(&std::fs::read(Path::new(&path)).unwrap()).unwrap();
    let objects = S3::new(S3Config {
        endpoint: config.endpoint.clone(),
        region: config.region.clone(),
        bucket: config.bucket.clone(),
        access_key: config.access_key.clone(),
        secret_key: config.secret_key.clone(),
        session_token: None,
        timeout: Duration::from_secs(8),
        max_object_bytes: MAX_OBJECT_BYTES,
        allow_http: true,
    })
    .unwrap();
    let database = Database::new(
        Arc::new(objects.clone()),
        config.scope.clone(),
        config.worker,
    )
    .unwrap();
    println!("{{\"ready\":true}}");
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let command = serde_json::from_str(&line.unwrap()).unwrap();
        let result = match perform(&config, &objects, &database, command) {
            Ok(value) => json!({"ok":true,"value":value}),
            Err(error) => json!({"ok":false,"error":error}),
        };
        println!("{result}");
        std::io::stdout().flush().unwrap();
    }
}
