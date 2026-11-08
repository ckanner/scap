//! Only assemble the production deletion transport. Retirement, live database
//! GC and physical cost convergence are deliberately outside this fixture.

use std::io::{BufRead, Read, Write};
use std::time::{Duration, Instant};

use scap_object_store::{GcS3, S3Config, MAX_DELETE_BATCH, MAX_GC_RESPONSE_BYTES};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    deployment: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    hash: String,
    etag: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    id: u64,
    prefix: String,
    deadline_ms: u64,
    candidates: Vec<Candidate>,
}

fn execute(store: &GcS3, command: Command) -> Value {
    // Permit one extra candidate to exercise the actual production batch cap.
    if command.candidates.len() > MAX_DELETE_BATCH + 1 || command.deadline_ms > 5000 {
        return json!({"id": command.id, "ok": false, "error": "FIXTURE_INPUT"});
    }
    let deadline = Instant::now() + Duration::from_millis(command.deadline_ms);
    let mut batch = match store.begin_batch(&command.prefix, deadline) {
        Ok(batch) => batch,
        Err(error) => return json!({"id":command.id,"ok":false,"error":format!("{error:?}")}),
    };
    let outcomes: Vec<_> = command
        .candidates
        .iter()
        .map(
            |candidate| match batch.delete(&candidate.hash, &candidate.etag) {
                Ok(outcome) => json!({"ok":true,"outcome":format!("{outcome:?}")}),
                Err(error) => json!({"ok":false,"error":format!("{error:?}")}),
            },
        )
        .collect();
    json!({"id":command.id,"ok":true,"outcomes":outcomes})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("private config path required")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("private config too large".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    let store = GcS3::new(
        S3Config {
            endpoint: config.endpoint,
            bucket: config.bucket,
            access_key: config.access_key,
            secret_key: config.secret_key,
            region: "us-east-1".into(),
            session_token: None,
            timeout: Duration::from_secs(5),
            max_object_bytes: 1024,
            allow_http: true,
        },
        config.deployment,
    )
    .map_err(|error| format!("GC transport construction: {error:?}"))?;
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "{}",
        json!({"ready":true,"max_delete_batch":MAX_DELETE_BATCH,"max_gc_response_bytes":MAX_GC_RESPONSE_BYTES})
    )?;
    output.flush()?;
    let mut input = std::io::stdin().lock();
    loop {
        let mut line = Vec::new();
        Read::by_ref(&mut input)
            .take(65537)
            .read_until(b'\n', &mut line)?;
        if line.is_empty() {
            break;
        }
        if line.len() > 65536 || line.last() != Some(&b'\n') {
            return Err("bounded complete command required".into());
        }
        let command: Command = serde_json::from_slice(&line)?;
        writeln!(output, "{}", execute(&store, command))?;
        output.flush()?;
    }
    Ok(())
}
