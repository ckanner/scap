//! LIST transport fixture: commands only assemble the production storage port.

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use scap_object_store::{
    Condition, ListEnd, ListKind, ListMode, ListRequest, Listings, Objects, S3Config, S3,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: String,
    bucket: String,
    access_key: String,
    secret_key: String,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Put {
        id: u64,
        key: String,
        value: String,
    },
    Get {
        id: u64,
        key: String,
    },
    List {
        id: u64,
        prefix: String,
        children: bool,
        after: Option<String>,
        deadline_ms: u64,
    },
}

fn execute(s3: &S3, command: Command) -> Value {
    let bound = || Instant::now() + Duration::from_secs(3);
    match command {
        Command::Put { id, key, value } => {
            match s3.put(&key, value.as_bytes(), Condition::Absent, bound()) {
                Ok(etag) => json!({"id": id, "ok": true, "etag": etag}),
                Err(error) => json!({"id": id, "ok": false, "error": format!("{error:?}")}),
            }
        }
        Command::Get { id, key } => match s3.get(&key, 1024, bound()) {
            Ok(value) => json!({"id": id, "ok": true, "bytes": value.bytes, "etag": value.etag}),
            Err(error) => json!({"id": id, "ok": false, "error": format!("{error:?}")}),
        },
        Command::List {
            id,
            prefix,
            children,
            after,
            deadline_ms,
        } => {
            let request = ListRequest {
                prefix: &prefix,
                mode: if children {
                    ListMode::Children
                } else {
                    ListMode::Keys
                },
                after: after.as_deref(),
            };
            let deadline = Instant::now() + Duration::from_millis(deadline_ms.min(5000));
            match s3.list_page(&request, deadline) {
                Ok(page) => {
                    let entries: Vec<_> = page.entries.iter().map(|entry| json!({
                        "key": entry.key,
                        "kind": match entry.kind { ListKind::Object => "object", ListKind::Prefix => "prefix" },
                    })).collect();
                    let end = match page.end {
                        ListEnd::Exhausted => json!({"kind": "exhausted"}),
                        ListEnd::More { after } => json!({"kind": "more", "after": after}),
                    };
                    json!({"id": id, "ok": true, "entries": entries, "end": end, "response_bytes": page.response_bytes})
                }
                Err(error) => json!({"id": id, "ok": false, "error": format!("{error:?}")}),
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("private config path required")?;
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let s3 = S3::new(S3Config {
        endpoint: config.endpoint,
        region: "us-east-1".into(),
        bucket: config.bucket,
        access_key: config.access_key,
        secret_key: config.secret_key,
        session_token: None,
        timeout: Duration::from_secs(3),
        max_object_bytes: 1024,
        allow_http: true,
    })
    .map_err(|error| format!("store construction failed: {error:?}"))?;
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "{}",
        json!({"ready": true, "max_entries": 32, "max_response_bytes": 1048576})
    )?;
    output.flush()?;
    for line in std::io::stdin().lock().lines() {
        let command: Command = serde_json::from_str(&line?)?;
        writeln!(output, "{}", execute(&s3, command))?;
        output.flush()?;
    }
    Ok(())
}
