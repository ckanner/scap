//! Shared deterministic, synthetic configuration. Paths are placeholders until
//! a test explicitly replaces them with its own temporary files.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::Config;

pub(crate) const TOKEN: &str = "scap-unit-alpha-token";

pub(crate) fn config_json() -> Value {
    json!({
        "version": 1,
        "cluster_id": format!("{:032x}", 1),
        "cell_id": format!("{:032x}", 2),
        "cell_incarnation": 1,
        "node_id": 1,
        "administrator_id": format!("{:032x}", 100),
        "service_credential_id": format!("{:032x}", 101),
        "data_dir": "/tmp/scap-server-unit/data",
        "http_listen": "127.0.0.1:0",
        "peer_listen": "127.0.0.1:0",
        "certificate_pem": "/tmp/scap-server-unit/node.pem",
        "private_key_pem": "/tmp/scap-server-unit/node.key",
        "ca_pem": "/tmp/scap-server-unit/ca.pem",
        "idle_seconds": 5,
        "peers": [
            {"node_id": 1, "uri": "https://127.0.0.1:30101", "certificate_der": "/tmp/scap-server-unit/1.der"},
            {"node_id": 2, "uri": "https://127.0.0.1:30102", "certificate_der": "/tmp/scap-server-unit/2.der"},
            {"node_id": 3, "uri": "https://127.0.0.1:30103", "certificate_der": "/tmp/scap-server-unit/3.der"},
        ],
        "databases": [{
            "name": "alpha", "database_id": format!("{:032x}", 3),
            "incarnation": 1, "placement_generation": 1,
            "tokens": [{
                "sha256": format!("{:x}", Sha256::digest(TOKEN.as_bytes())),
                "principal_id": format!("{:032x}", 200),
                "credential_id": format!("{:032x}", 201),
                "auth_epoch": 1, "permissions": 3,
            }],
        }],
    })
}

pub(crate) fn config() -> Config {
    Config::decode(&serde_json::to_vec(&config_json()).unwrap()).unwrap()
}

pub(crate) fn context(database: &str, request_id: u128) -> scap_service::RequestContext {
    scap_service::RequestContext {
        database: database.into(),
        credential: TOKEN.into(),
        request_id,
        deadline: Instant::now() + Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}

pub(crate) fn sql(text: &str) -> scap_sql::Statement {
    scap_sql::Statement {
        sql: text.into(),
        parameters: vec![],
    }
}
