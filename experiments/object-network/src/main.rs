//! Independent process fixture. Every database algorithm remains in the
//! production crates; this binary translates test commands and observations.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use scap_object::format::{
    decode_object, digest, head_key, object_key, Payload, Permission, Request, Scope,
    MAX_OBJECT_BYTES,
};
use scap_object::{request, sql_limits, Database, Options, Receipt, Resolution, Session};
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
    fixture_limits: Option<FixtureLimits>,
    resource_log: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureLimits {
    quota_bytes: u64,
    retention_entries: u32,
    retention_result_bytes: u64,
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

fn receipt(value: &Receipt) -> Value {
    json!({"scope": value.scope, "request": value.request, "sequence": value.sequence,
        "transition": value.transition, "data_root": value.data_root, "result_hash": value.result_hash})
}

fn scalar(value: &SqlValue, hash_blobs: bool) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(number) => json!(number),
        SqlValue::Real(number) => json!(number),
        SqlValue::Text(text) => json!(text),
        SqlValue::Blob(bytes) if hash_blobs => {
            json!({"blob_bytes": bytes.len(), "sha256": digest(bytes)})
        }
        SqlValue::Blob(bytes) => json!({"blob": bytes}),
    }
}

fn result(value: &TransactionResult, hash_blobs: bool) -> Value {
    let statements: Vec<_> = value
        .statements
        .iter()
        .map(|statement| {
            let rows: Vec<_> = statement
                .rows
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|value| scalar(value, hash_blobs))
                        .collect::<Vec<_>>()
                })
                .collect();
            json!({"columns": statement.columns, "rows": rows,
                "affected_rows": statement.affected_rows,
                "last_insert_rowid": statement.last_insert_rowid})
        })
        .collect();
    if hash_blobs {
        // Query observations do not need a second giant JSON byte array. The
        // client compares every returned BLOB digest to its independent input.
        json!({"statements": statements})
    } else {
        json!({"encoded": scap_sql::encode_result(value, sql_limits()).unwrap(), "statements": statements})
    }
}

fn parameter(value: &Value) -> Result<SqlValue, String> {
    match value["type"].as_str().ok_or("fixture parameter type")? {
        "null" => Ok(SqlValue::Null),
        "integer" => Ok(SqlValue::Integer(
            value["value"].as_i64().ok_or("fixture integer")?,
        )),
        "real" => Ok(SqlValue::Real(
            value["value"].as_f64().ok_or("fixture real")?,
        )),
        "text" => Ok(SqlValue::Text(
            value["value"].as_str().ok_or("fixture text")?.into(),
        )),
        "blob_file" => {
            let length = value["length"].as_u64().ok_or("fixture blob length")?;
            if length > 2 * 1024 * 1024 {
                return Err("fixture BLOB exceeds production default value budget".into());
            }
            let path = value["path"].as_str().ok_or("fixture blob path")?;
            let offset = value["offset"].as_u64().ok_or("fixture blob offset")?;
            let mut file = File::open(path).map_err(debug)?;
            file.seek(SeekFrom::Start(offset)).map_err(debug)?;
            let mut bytes = vec![0; length as usize];
            file.read_exact(&mut bytes).map_err(debug)?;
            if digest(&bytes) != value["sha256"].as_str().ok_or("fixture blob digest")? {
                return Err("fixture BLOB digest mismatch before invocation".into());
            }
            Ok(SqlValue::Blob(bytes))
        }
        _ => Err("unknown fixture parameter type".into()),
    }
}

fn statements(command: &Value) -> Result<Vec<Statement>, String> {
    let one = |value: &Value| -> Result<Statement, String> {
        let parameters = match value["parameters"].as_array() {
            Some(values) => values.iter().map(parameter).collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        Ok(Statement {
            sql: value["sql"].as_str().ok_or("fixture SQL")?.into(),
            parameters,
        })
    };
    match command["statements"].as_array() {
        Some(values) => values.iter().map(one).collect(),
        None => Ok(vec![one(command)?]),
    }
}

fn resolution(value: Resolution) -> Value {
    match value {
        Resolution::Committed {
            receipt: proof,
            bytes,
        } => json!({"state":"committed", "receipt":receipt(&proof), "encoded":bytes}),
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
    session: &mut Option<Session>,
    cmd: Value,
) -> Result<Value, String> {
    let deadline =
        Instant::now() + Duration::from_millis(cmd["budget_ms"].as_u64().unwrap_or(8000));
    let op = cmd["op"].as_str().ok_or("fixture operation")?;
    let principal = config.principal;
    let number = |name: &str| cmd[name].as_u64().unwrap();
    let text = |name: &str| cmd[name].as_str().unwrap();
    match op {
        "store_get" => objects
            .get(text("key"), MAX_OBJECT_BYTES, deadline)
            .map(|stored| json!({"bytes":stored.bytes,"etag":stored.etag}))
            .map_err(debug),
        "store_put" => {
            let bytes: Vec<u8> = serde_json::from_value(cmd["bytes"].clone()).map_err(debug)?;
            let condition = match cmd["etag"].as_str() {
                Some(etag) => Condition::Match(etag),
                None => Condition::Absent,
            };
            objects
                .put(text("key"), &bytes, condition, deadline)
                .map(|etag| json!({"etag":etag}))
                .map_err(debug)
        }
        "create" => database
            .create(principal, number("nonce"), deadline)
            .map(|head| json!(head))
            .map_err(debug),
        "status" => database.status(principal, deadline).map(|head| json!(head)).map_err(debug),
        "authority_keys" => database.status(principal, deadline).map(|head| {
            json!({"head":head_key(&config.scope), "data_root":object_key(&config.scope, &head.data_root)})
        }).map_err(debug),
        "authority_info" => {
            let head = database.status(principal, deadline).map_err(debug)?;
            let root = objects.get(&object_key(&config.scope, &head.data_root), MAX_OBJECT_BYTES, deadline).map_err(debug)?;
            let manifest = decode_object(&root.bytes, &config.scope, &head.data_root).map_err(debug)?;
            match manifest.payload {
                Payload::Manifest(manifest) => Ok(json!({"head":head, "page_count":manifest.page_count,
                    "database_bytes":u64::from(manifest.page_count) * 4096})),
                _ => Err("fixture expected official Manifest".into()),
            }
        }
        "activate" => database
            .activate(principal, number("revision"), number("nonce"), deadline)
            .map(|head| json!(head)).map_err(debug),
        "takeover" => database
            .takeover(principal, number("revision"), number("nonce"), deadline)
            .map(|head| json!(head)).map_err(debug),
        "set_policy" => {
            let policy: Vec<Permission> = serde_json::from_value(cmd["policy"].clone()).map_err(debug)?;
            database.set_policy(principal, number("revision"), number("nonce"), policy, deadline)
                .map(|head| json!(head)).map_err(debug)
        }
        "session_open" => {
            *session = None;
            *session = Some(database.session(principal, &config.cache_root.join(text("directory")), deadline).map_err(debug)?);
            Ok(json!({"opened":true}))
        }
        "session_close" => {
            *session = None;
            Ok(json!({"closed":true}))
        }
        "activate_session" => {
            *session = None;
            let (head, opened) = database.activate_session(principal, number("revision"), number("nonce"),
                &config.cache_root.join(text("directory")), deadline).map_err(debug)?;
            *session = Some(opened);
            Ok(json!(head))
        }
        "session_info" => Ok(json!({"page_count":session.as_ref().ok_or("fixture has no session")?.page_count()})),
        "prepare_request" => request(number("epoch"), number("id"), principal, &statements(&cmd)?)
            .map(|identity| json!(identity)).map_err(debug),
        "execute" | "session_execute" => {
            let sql = statements(&cmd)?;
            let identity = request(number("epoch"), number("id"), principal, &sql).map_err(debug)?;
            let executed = if op == "session_execute" {
                session.as_mut().ok_or("fixture has no session")?.execute(principal, &identity, &sql, deadline)
            } else {
                database.execute(principal, &identity, &sql, &config.cache_root.join(text("directory")), deadline)
            };
            executed.map(|(proof, data)| json!({"receipt":receipt(&proof),"result":result(&data, false)})).map_err(debug)
        }
        "query" | "session_query" => {
            let sql = statements(&cmd)?;
            let data = if op == "session_query" {
                session.as_mut().ok_or("fixture has no session")?.query(principal, &sql, deadline)
            } else {
                database.query(principal, &sql, &config.cache_root.join(text("directory")), deadline)
            }.map_err(debug)?;
            Ok(result(&data, cmd["hash_blobs"].as_bool().unwrap_or(false)))
        }
        "lookup" | "cancel" => {
            let identity = request(number("epoch"), number("id"), principal, &statements(&cmd)?).map_err(debug)?;
            let observed = if op == "lookup" {
                database.lookup(principal, &identity, deadline)
            } else {
                database.cancel(principal, &identity, deadline)
            };
            observed.map(resolution).map_err(debug)
        }
        "lookup_identity" | "cancel_identity" => {
            let identity: Request = serde_json::from_value(cmd["identity"].clone()).map_err(debug)?;
            if identity.principal != principal {
                return Err("fixture invocation principal mismatch".into());
            }
            let observed = if op == "lookup_identity" {
                database.lookup(principal, &identity, deadline)
            } else {
                database.cancel(principal, &identity, deadline)
            };
            observed.map(resolution).map_err(debug)
        }
        _ => Err("unknown fixture command".into()),
    }
}

fn resources() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .unwrap()
    };
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let start = stat
        .split_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    json!({"proc_pid":field("Pid:"),"namespace_pid":std::process::id(),"start_ticks":start,
        "rss_kib":field("VmRSS:"),"hwm_kib":field("VmHWM:")})
}

fn resource_recorder(config: &Config) -> Arc<AtomicBool> {
    let failed = Arc::new(AtomicBool::new(false));
    if let Some(path) = &config.resource_log {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let failure = failed.clone();
        let worker = config.worker;
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {
                let value = json!({"worker":worker, "wall_time_ns":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                    "source":"worker_self_procfs", "resources":resources()});
                let mut line = serde_json::to_vec(&value).unwrap();
                line.push(b'\n');
                if file
                    .write_all(&line)
                    .and_then(|()| file.sync_data())
                    .is_err()
                {
                    return Err::<(), ()>(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }));
            if !matches!(outcome, Ok(Ok(()))) {
                failure.store(true, Ordering::SeqCst);
            }
        });
    }
    failed
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
    let resource_failed = resource_recorder(&config);
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
    let mut options = Options::default();
    if let Some(limits) = &config.fixture_limits {
        options.quota.max_bytes = Some(limits.quota_bytes);
        options.retention.max_entries = limits.retention_entries;
        options.retention.max_result_bytes = limits.retention_result_bytes;
    }
    let database = Database::with_options(
        Arc::new(objects.clone()),
        config.scope.clone(),
        config.worker,
        options,
    )
    .unwrap();
    let mut session = None;
    println!("{}", json!({"ready":true,"resources":resources()}));
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let command = serde_json::from_str(&line.unwrap()).unwrap();
        let started = Instant::now();
        let result = if resource_failed.load(Ordering::SeqCst) {
            Err("fixture resource recorder failed".into())
        } else {
            perform(&config, &objects, &database, &mut session, command)
        };
        let result = if resource_failed.load(Ordering::SeqCst) {
            Err("fixture resource recorder failed during operation".into())
        } else {
            result
        };
        let response = match result {
            Ok(value) => {
                json!({"ok":true,"value":value,"resources":resources(),"elapsed_ms":started.elapsed().as_secs_f64()*1000.0})
            }
            Err(error) => {
                json!({"ok":false,"error":error,"resources":resources(),"elapsed_ms":started.elapsed().as_secs_f64()*1000.0})
            }
        };
        println!("{response}");
        std::io::stdout().flush().unwrap();
    }
}
