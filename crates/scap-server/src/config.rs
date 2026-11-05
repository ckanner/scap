use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use scap_cell::{CellIdentity, DatabaseIdentity};
use scap_service::ServiceError;
use serde_json::Value;

use crate::failure;

#[derive(Clone, Debug)]
pub struct TokenConfig {
    pub digest: [u8; 32],
    pub principal_id: u128,
    pub credential_id: u128,
    pub auth_epoch: u64,
    pub permissions: u8,
}

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub name: String,
    pub identity: DatabaseIdentity,
    pub tokens: Vec<TokenConfig>,
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub node_id: u64,
    pub uri: String,
    /// An explicitly pinned public leaf, never a peer-supplied identity.
    pub certificate_der: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ArchiveConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_env: String,
    pub secret_key_env: String,
    pub allow_http: bool,
}

#[derive(Clone, Debug)]
pub struct ManagementConfig {
    /// Management is deliberately separate from the tenant HTTP listener.
    pub listen: SocketAddr,
    pub token_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Config {
    pub cluster_id: u128,
    pub cell: CellIdentity,
    pub node_id: u64,
    pub administrator_id: u128,
    pub service_credential_id: u128,
    pub data_dir: PathBuf,
    pub http_listen: SocketAddr,
    pub peer_listen: SocketAddr,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
    pub ca_pem: PathBuf,
    pub peers: Vec<PeerConfig>,
    /// Initial voters only. Existing storage always uses its durable ConfState.
    pub bootstrap_voters: Vec<u64>,
    pub databases: Vec<DatabaseConfig>,
    pub idle_timeout: Duration,
    pub archive: Option<ArchiveConfig>,
    pub management: Option<ManagementConfig>,
}

impl Config {
    /// Administrative configuration is bounded and contains only token hashes.
    /// Replica/database identities are explicit and must match on every node.
    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        if bytes.len() > 1024 * 1024 {
            return Err(failure("CONFIG_LIMIT"));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| failure("CONFIG_JSON"))?;
        if integer(&value, "version")? != 1 {
            return Err(failure("CONFIG_VERSION"));
        }
        let cluster_id = identity(&value, "cluster_id")?;
        let node_id = integer(&value, "node_id")?;
        let administrator_id = identity(&value, "administrator_id")?;
        let service_credential_id = identity(&value, "service_credential_id")?;
        let peers = array(&value, "peers", 16)?
            .iter()
            .map(|peer| {
                Ok(PeerConfig {
                    node_id: integer(peer, "node_id")?,
                    uri: string(peer, "uri")?.into(),
                    certificate_der: path(peer, "certificate_der")?,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        let members: BTreeSet<_> = peers.iter().map(|peer| peer.node_id).collect();
        if members.len() < 3
            || members.len() != peers.len()
            || members.contains(&0)
            || !members.contains(&node_id)
        {
            return Err(failure("CONFIG_MEMBERS"));
        }
        let bootstrap_voters = bootstrap_voters(&value, &members)?;
        for peer in &peers {
            scap_raft_transport::PeerEndpoint {
                uri: peer.uri.clone(),
                cluster_id,
                node_id: peer.node_id,
            }
            .validate()
            .map_err(|_| failure("CONFIG_PEER"))?;
        }
        let mut names = BTreeSet::new();
        let mut databases = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let configured = array(&value, "databases", 32)?
            .iter()
            .map(|db| {
                let name = string(db, "name")?;
                let database_id = identity(db, "database_id")?;
                if name.len() > 64
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || !names.insert(name.to_owned())
                    || !databases.insert(database_id)
                {
                    return Err(failure("CONFIG_DATABASE"));
                }
                let tokens = array(db, "tokens", 32)?
                    .iter()
                    .map(|token| {
                        let digest = digest(string(token, "sha256")?)?;
                        let principal_id = identity(token, "principal_id")?;
                        let permissions = integer(token, "permissions")?;
                        let credential_id = identity(token, "credential_id")?;
                        let retention_admin = match token.get("retention_admin") {
                            None | Some(Value::Bool(false)) => false,
                            Some(Value::Bool(true)) => true,
                            _ => return Err(failure("CONFIG_TOKEN")),
                        };
                        // Existing tenant tokens keep their original read/write
                        // scope. Retiring results is a separate explicit credential
                        // bound to this database and the immutable administrator.
                        let permitted = if retention_admin {
                            principal_id == administrator_id
                                && permissions == u64::from(scap_cell::READ | scap_cell::ADMIN)
                                && credential_id != service_credential_id
                        } else {
                            principal_id != administrator_id && (1..=3).contains(&permissions)
                        };
                        if digest == [0; 32] || !digests.insert(digest) || !permitted {
                            return Err(failure("CONFIG_TOKEN"));
                        }
                        Ok(TokenConfig {
                            digest,
                            principal_id,
                            credential_id,
                            auth_epoch: nonzero(token, "auth_epoch")?,
                            permissions: permissions as u8,
                        })
                    })
                    .collect::<Result<Vec<_>, ServiceError>>()?;
                Ok(DatabaseConfig {
                    name: name.into(),
                    identity: DatabaseIdentity {
                        database_id,
                        incarnation: nonzero(db, "incarnation")?,
                        placement_generation: nonzero(db, "placement_generation")?,
                    },
                    tokens,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        let http_listen: SocketAddr = string(&value, "http_listen")?
            .parse()
            .map_err(|_| failure("CONFIG_ADDRESS"))?;
        // Public HTTPS termination belongs to the explicitly configured proxy.
        // An unmarked public cleartext bearer-token listener is never started.
        if !http_listen.ip().is_loopback()
            && value.get("proxy_terminates_tls").and_then(Value::as_bool) != Some(true)
        {
            return Err(failure("CONFIG_TLS_PROXY"));
        }
        let idle_seconds = integer(&value, "idle_seconds")?;
        if !(5..=86_400).contains(&idle_seconds) {
            return Err(failure("CONFIG_IDLE"));
        }
        let management = management(&value, &digests)?;
        Ok(Self {
            cluster_id,
            cell: CellIdentity {
                cell_id: identity(&value, "cell_id")?,
                cell_incarnation: nonzero(&value, "cell_incarnation")?,
            },
            node_id,
            administrator_id,
            service_credential_id,
            data_dir: path(&value, "data_dir")?,
            http_listen,
            peer_listen: string(&value, "peer_listen")?
                .parse()
                .map_err(|_| failure("CONFIG_ADDRESS"))?,
            certificate_pem: path(&value, "certificate_pem")?,
            private_key_pem: path(&value, "private_key_pem")?,
            ca_pem: path(&value, "ca_pem")?,
            peers,
            bootstrap_voters,
            databases: configured,
            idle_timeout: Duration::from_secs(idle_seconds),
            archive: value
                .get("archive")
                .map(|archive| {
                    Ok(ArchiveConfig {
                        endpoint: string(archive, "endpoint")?.into(),
                        region: string(archive, "region")?.into(),
                        bucket: string(archive, "bucket")?.into(),
                        access_key_env: string(archive, "access_key_env")?.into(),
                        secret_key_env: string(archive, "secret_key_env")?.into(),
                        allow_http: archive.get("allow_http").and_then(Value::as_bool)
                            == Some(true),
                    })
                })
                .transpose()?,
            management,
        })
    }
}

fn bootstrap_voters(value: &Value, peers: &BTreeSet<u64>) -> Result<Vec<u64>, ServiceError> {
    let voters = match value.get("bootstrap_voters") {
        None if peers.len() == 3 => peers.iter().copied().collect(),
        Some(Value::Array(voters)) => voters
            .iter()
            .map(|node| node.as_u64().ok_or_else(|| failure("CONFIG_BOOTSTRAP")))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(failure("CONFIG_BOOTSTRAP")),
    };
    let unique: BTreeSet<_> = voters.iter().copied().collect();
    if voters.len() != 3 || unique.len() != 3 || !unique.is_subset(peers) {
        return Err(failure("CONFIG_BOOTSTRAP"));
    }
    Ok(unique.into_iter().collect())
}

fn management(
    value: &Value,
    tenant_tokens: &BTreeSet<[u8; 32]>,
) -> Result<Option<ManagementConfig>, ServiceError> {
    let value = match value.get("management") {
        None | Some(Value::Bool(false)) => return Ok(None),
        Some(value) => value,
    };
    let listen: SocketAddr = string(value, "listen")?
        .parse()
        .map_err(|_| failure("CONFIG_MANAGEMENT_ADDRESS"))?;
    if !listen.ip().is_loopback() {
        return Err(failure("CONFIG_MANAGEMENT_ADDRESS"));
    }
    let token_digest = digest(string(value, "token_sha256")?)?;
    if token_digest == [0; 32] || tenant_tokens.contains(&token_digest) {
        return Err(failure("CONFIG_MANAGEMENT_TOKEN"));
    }
    Ok(Some(ManagementConfig {
        listen,
        token_digest,
    }))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ServiceError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or_else(|| failure("CONFIG_STRING"))
}

fn integer(value: &Value, key: &str) -> Result<u64, ServiceError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| failure("CONFIG_INTEGER"))
}

fn nonzero(value: &Value, key: &str) -> Result<u64, ServiceError> {
    let number = integer(value, key)?;
    if number == 0 {
        return Err(failure("CONFIG_ID"));
    }
    Ok(number)
}

fn identity(value: &Value, key: &str) -> Result<u128, ServiceError> {
    let text = string(value, key)?;
    if text.len() != 32 {
        return Err(failure("CONFIG_ID"));
    }
    if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failure("CONFIG_ID"));
    }
    // Exactly 32 ASCII hex digits fit u128; signs and prefixes were rejected.
    let number = u128::from_str_radix(text, 16).unwrap();
    if number == 0 {
        return Err(failure("CONFIG_ID"));
    }
    Ok(number)
}

fn path(value: &Value, key: &str) -> Result<PathBuf, ServiceError> {
    let path = PathBuf::from(string(value, key)?);
    if !path.is_absolute() {
        return Err(failure("CONFIG_PATH"));
    }
    Ok(path)
}

fn array<'a>(value: &'a Value, key: &str, max: usize) -> Result<&'a [Value], ServiceError> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| failure("CONFIG_ARRAY"))?;
    if values.is_empty() || values.len() > max {
        return Err(failure("CONFIG_LIMIT"));
    }
    Ok(values)
}

pub(crate) fn digest(text: &str) -> Result<[u8; 32], ServiceError> {
    if text.len() != 64 || !text.is_ascii() {
        return Err(failure("CONFIG_DIGEST"));
    }
    if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failure("CONFIG_DIGEST"));
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        // Each slice contains exactly two validated ASCII hexadecimal digits.
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    Ok(result)
}

pub(crate) fn cell_limits() -> scap_cell::Limits {
    scap_cell::Limits {
        max_state_bytes: 8 * 1024 * 1024,
        max_command_bytes: 4 * 1024 * 1024,
        max_databases: 32,
        max_policy_grants: 33,
        max_admin_operations: 4096,
        max_requests_per_database: 128,
        max_transaction_bytes: 300 * 1024,
        max_result_bytes: 64 * 1024,
    }
}

pub(crate) fn worker_limits() -> scap_sql_worker::WorkerLimits {
    scap_sql_worker::WorkerLimits {
        engine: scap_engine::Limits {
            max_database_pages: 64,
            max_changed_pages: 64,
            max_transaction_bytes: 300 * 1024,
        },
        sqlite: scap_sqlite::WriterLimits {
            sql: scap_sql::SqlLimits {
                max_statements: 32,
                max_sql_bytes: 64 * 1024,
                max_parameters: 128,
                max_columns: 64,
                max_rows: 1024,
                max_result_bytes: 64 * 1024,
                max_value_bytes: 32 * 1024,
            },
            max_vm_steps: 500_000,
            max_changed_pages: 64,
        },
    }
}

#[cfg(test)]
mod tests;
