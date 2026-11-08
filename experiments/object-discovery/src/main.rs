//! Root-only fixture assembly. Discovery and recovery are production algorithms.
//! There is no command/config field for a name, Scope, object key or ACK list.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_object::catalogue::{
    DiscoveredRecord, RecoveredDatabase, RecoveryBudget, RecoveryCapability, RecoveryCompletion,
    RecoveryJob, RecoveryUsage, TenantReaders,
};
use scap_object::format::{digest, MAX_OBJECT_BYTES};
use scap_object::{sql_limits, Options};
use scap_object_store::{S3Config, S3};
use scap_sql::Statement;
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
    deployment: u64,
    worker: u64,
    readers: BTreeMap<u64, u64>,
    cache_root: PathBuf,
    artifact_root: PathBuf,
    job_budget_ms: u64,
}

struct Readers {
    deployment: u64,
    principals: BTreeMap<u64, u64>,
}

impl TenantReaders for Readers {
    fn principal(&self, deployment: u64, tenant: u64) -> Option<u64> {
        (deployment == self.deployment)
            .then(|| self.principals.get(&tenant).copied())
            .flatten()
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Step { budget_ms: u64 },
    Query { budget_ms: u64, sql: String },
    DropImage,
}

fn deadline(milliseconds: u64) -> Result<Instant, String> {
    if !(1..=30_000).contains(&milliseconds) {
        return Err("fixture step deadline outside 1..30000 ms".into());
    }
    Ok(Instant::now() + Duration::from_millis(milliseconds))
}

fn record(value: &DiscoveredRecord) -> Value {
    json!({"key":value.key,"kind":format!("{:?}",value.kind),"state":format!("{:?}",value.state),
        "creation":value.creation,"scope":value.scope,"binding_revision":value.binding_revision,
        "head_revision":value.head_revision,"control":value.control.as_ref().map(|control|json!({
            "kind":control.kind,"principal":control.principal,"operation":control.operation,
            "expected_name_revision":control.expected_name_revision,
            "expected_head_revision":control.expected_head_revision,"nonce":control.nonce}))})
}

fn completion(value: &RecoveryCompletion) -> Value {
    json!({"traversal_exhausted":value.traversal_exhausted,
        "preexisting_slots_covered":value.preexisting_slots_covered,
        "metadata_classified":value.metadata_classified,"heads_classified":value.heads_classified,
        "data_verified":value.data_verified,"data_not_required":value.data_not_required,
        "pending_scope":value.pending_scope,"permission_blocked":value.permission_blocked,
        "recovery_complete":value.recovery_complete})
}

fn usage(value: &RecoveryUsage) -> Value {
    json!({"list_pages":value.list_pages,"candidates":value.candidates,
        "exact_gets":value.exact_gets,"list_bytes":value.list_bytes,
        "metadata_bytes":value.metadata_bytes,"data_bytes":value.data_bytes})
}

fn resources() -> Value {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let number = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let start = stat
        .split_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    json!({"namespace_pid":std::process::id(),"proc_pid":number("Pid:"),
        "start_ticks":start,"rss_kib":number("VmRSS:"),"hwm_kib":number("VmHWM:")})
}

fn native_image(directory: &Path, artifacts: &Path, step: u64) -> Result<Value, String> {
    let source = directory.join("database.sqlite");
    // Fixture databases are deliberately small. Production restoration itself
    // streams; this independent evidence copy is not the product memory budget.
    if fs::metadata(&source)
        .map_err(|error| format!("{error:?}"))?
        .len()
        > 8 * 1024 * 1024
    {
        return Err("fixture native evidence exceeds 8 MiB".into());
    }
    let raw = fs::read(&source).map_err(|error| format!("{error:?}"))?;
    let name = format!("image-{step}.sqlite");
    let destination = artifacts.join(&name);
    let mut saved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("{error:?}"))?;
    saved
        .write_all(&raw)
        .and_then(|()| saved.sync_all())
        .map_err(|error| format!("{error:?}"))?;
    File::open(artifacts)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("{error:?}"))?;
    Ok(json!({"file":name,"bytes":raw.len(),"sha256":digest(&raw)}))
}

fn main() {
    assert!(
        std::env::var_os("LLVM_PROFILE_FILE").is_none(),
        "real recovery cannot contribute to unit coverage"
    );
    let path = std::env::args().nth(1).expect("private configuration path");
    let raw = fs::read(path).unwrap();
    assert!(raw.len() <= 65_536);
    let config: Config = serde_json::from_slice(&raw).unwrap();
    let configuration_sha256 = digest(&raw);
    let public_configuration = json!({"endpoint":config.endpoint,"region":config.region,
        "bucket":config.bucket,"deployment":config.deployment,"worker":config.worker,
        "readers":config.readers,"cache_root":config.cache_root,"artifact_root":config.artifact_root,
        "job_budget_ms":config.job_budget_ms});
    assert!((1..=3_600_000).contains(&config.job_budget_ms));
    assert!(config
        .readers
        .iter()
        .all(|(tenant, principal)| *tenant != 0 && *principal != 0));
    fs::create_dir_all(&config.cache_root).unwrap();
    fs::create_dir(&config.artifact_root).unwrap();
    let objects = Arc::new(
        S3::new(S3Config {
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
        .unwrap(),
    );
    let readers = Arc::new(Readers {
        deployment: config.deployment,
        principals: config.readers,
    });
    let capability =
        RecoveryCapability::trusted_deployment(config.deployment, config.worker).unwrap();
    let mut job = RecoveryJob::new(
        objects.clone(),
        objects,
        capability,
        readers,
        Options::default(),
        RecoveryBudget::default(),
        Instant::now() + Duration::from_millis(config.job_budget_ms),
    )
    .unwrap();
    let mut image: Option<RecoveredDatabase> = None;
    let mut step = 0_u64;
    println!(
        "{}",
        json!({"ready":true,"resources":resources(),"configuration_schema":"deployment-root-only-v1",
            "configuration_sha256":configuration_sha256,"configuration":public_configuration})
    );
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        assert!(line.len() <= 65_536);
        let started = Instant::now();
        let result = (|| -> Result<Value, String> {
            let command: Command =
                serde_json::from_str(&line).map_err(|error| format!("{error:?}"))?;
            match command {
                Command::Step { budget_ms } => {
                    step += 1;
                    let directory = config.cache_root.join(format!("step-{step}"));
                    let observation = job
                        .step(&directory, deadline(budget_ms)?)
                        .map_err(|error| format!("{error:?}"))?;
                    let native = if observation.recovered.is_some() {
                        Some(native_image(&directory, &config.artifact_root, step)?)
                    } else {
                        None
                    };
                    let result = json!({"step":step,"metadata":observation.metadata.as_ref().map(record),
                        "completion":completion(&observation.completion),"usage":usage(&observation.usage),
                        "stopped":observation.stopped.map(|value|format!("{value:?}")),
                        "recovered_head":observation.recovered.as_ref().map(|value|value.head()),"native":native});
                    image = observation.recovered;
                    Ok(result)
                }
                Command::Query { budget_ms, sql } => {
                    let statements = [Statement {
                        sql,
                        parameters: vec![],
                    }];
                    let result = image
                        .as_mut()
                        .ok_or("fixture has no recovered image")?
                        .query(&statements, deadline(budget_ms)?)
                        .map_err(|error| format!("{error:?}"))?;
                    let bytes = scap_sql::encode_result(&result, sql_limits())
                        .map_err(|error| format!("{error:?}"))?;
                    Ok(json!({"encoded":bytes}))
                }
                Command::DropImage => {
                    image = None;
                    Ok(json!({"dropped":true}))
                }
            }
        })();
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
