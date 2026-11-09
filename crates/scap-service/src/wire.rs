//! Lossless v1 wire values. JSON numbers never carry database identities.

use base64::{engine::general_purpose::STANDARD, Engine};
use scap_object::format::{Head, Permission, Request, Scope};
use scap_object::{Receipt, Resolution};
use scap_sql::{Statement, TransactionResult, Value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value as Json};

use crate::Failure;

/// Serialize an owned or borrowed value without constructing a second JSON tree.
#[derive(Serialize)]
pub(crate) struct Success<T> {
    ok: bool,
    value: T,
}

pub(crate) fn success<T>(value: T) -> Success<T> {
    Success { ok: true, value }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal(pub u64);

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let number = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if number.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical decimal"));
        }
        Ok(Self(number))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireScope {
    pub deployment: Decimal,
    pub tenant: Decimal,
    pub database: Decimal,
    pub incarnation: Decimal,
    pub generation: Decimal,
}

impl WireScope {
    pub fn native(&self) -> Result<Scope, Failure> {
        let scope = Scope {
            deployment: self.deployment.0,
            tenant: self.tenant.0,
            database: self.database.0,
            incarnation: self.incarnation.0,
            generation: self.generation.0,
        };
        scope.validate().map_err(|_| Failure::new("INVALID"))?;
        Ok(scope)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub epoch: Decimal,
    pub id: Decimal,
    pub principal: Decimal,
    pub fingerprint: String,
}

impl Identity {
    pub fn native(&self, principal: u64) -> Result<Request, Failure> {
        if self.principal.0 != principal {
            return Err(Failure::new("DENIED"));
        }
        let request = Request {
            epoch: self.epoch.0,
            id: self.id.0,
            principal,
            fingerprint: self.fingerprint.clone(),
        };
        request.validate().map_err(|_| Failure::new("INVALID"))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Parameter {
    Null {},
    Integer { value: String },
    Real { bits: String },
    Text { value: String },
    Blob { base64: String },
}

impl Parameter {
    fn native(&self) -> Result<Value, Failure> {
        Ok(match self {
            Self::Null {} => Value::Null,
            Self::Integer { value } => {
                let number = value.parse::<i64>().map_err(|_| Failure::new("INVALID"))?;
                if number.to_string() != *value {
                    return Err(Failure::new("INVALID"));
                }
                Value::Integer(number)
            }
            Self::Real { bits } => {
                let number = u64::from_str_radix(bits, 16).map_err(|_| Failure::new("INVALID"))?;
                let real = f64::from_bits(number);
                if format!("{number:016x}") != *bits || !real.is_finite() {
                    return Err(Failure::new("INVALID"));
                }
                Value::Real(real)
            }
            Self::Text { value } => Value::Text(value.clone()),
            Self::Blob { base64 } => {
                // The fixed STANDARD engine requires canonical padding and
                // zero trailing bits; no permissive decoder is used here.
                let bytes = STANDARD
                    .decode(base64)
                    .map_err(|_| Failure::new("INVALID"))?;
                Value::Blob(bytes)
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireStatement {
    pub sql: String,
    pub params: Vec<Parameter>,
}

pub fn statements(wire: &[WireStatement]) -> Result<Vec<Statement>, Failure> {
    wire.iter()
        .map(|statement| {
            Ok(Statement {
                sql: statement.sql.clone(),
                parameters: statement
                    .params
                    .iter()
                    .map(Parameter::native)
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePermission {
    pub principal: Decimal,
    pub read: bool,
    pub write: bool,
    pub admin: bool,
}

impl WirePermission {
    pub fn native(&self) -> Permission {
        Permission {
            principal: self.principal.0,
            read: self.read,
            write: self.write,
            admin: self.admin,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Create {
        nonce: Decimal,
    },
    Status {
        #[serde(default, deserialize_with = "present_worker")]
        expected_worker_instance: Option<Decimal>,
    },
    Open {},
    Query {
        statements: Vec<WireStatement>,
    },
    Execute {
        request: Identity,
        statements: Vec<WireStatement>,
    },
    Lookup {
        request: Identity,
    },
    Cancel {
        request: Identity,
    },
    Activate {
        expected_revision: Decimal,
        nonce: Decimal,
        #[serde(default, deserialize_with = "present_worker")]
        expected_worker_instance: Option<Decimal>,
    },
    Takeover {
        expected_revision: Decimal,
        nonce: Decimal,
        #[serde(default, deserialize_with = "present_worker")]
        expected_worker_instance: Option<Decimal>,
    },
    CloseFull {
        expected_revision: Decimal,
        nonce: Decimal,
    },
    Policy {
        expected_revision: Decimal,
        nonce: Decimal,
        permissions: Vec<WirePermission>,
    },
    Quota {
        expected_revision: Decimal,
        nonce: Decimal,
        #[serde(deserialize_with = "required_quota")]
        max_bytes: Option<Decimal>,
    },
    Lifecycle {
        expected_revision: Decimal,
        nonce: Decimal,
        lifecycle: scap_object::format::Lifecycle,
    },
}

impl Action {
    /// Optional destination identity, checked before any authority effect.
    pub fn expected_worker(&self) -> Option<u64> {
        match self {
            Self::Status {
                expected_worker_instance,
            }
            | Self::Activate {
                expected_worker_instance,
                ..
            }
            | Self::Takeover {
                expected_worker_instance,
                ..
            } => expected_worker_instance.map(|value| value.0),
            _ => None,
        }
    }

    /// Reject malformed control values before any provisioning objects or HEAD
    /// reads. A client typo is INVALID, not evidence of corrupted durable data.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.expected_worker() == Some(0) {
            return Err(Failure::new("INVALID"));
        }
        if matches!(
            self,
            Self::Lifecycle {
                lifecycle: scap_object::format::Lifecycle::Provisioning,
                ..
            }
        ) {
            return Err(Failure::new("INVALID"));
        }
        let transition = match self {
            Self::Create { nonce } => Some((1, nonce.0)),
            Self::Activate {
                expected_revision,
                nonce,
                ..
            }
            | Self::Takeover {
                expected_revision,
                nonce,
                ..
            }
            | Self::CloseFull {
                expected_revision,
                nonce,
            }
            | Self::Policy {
                expected_revision,
                nonce,
                ..
            }
            | Self::Quota {
                expected_revision,
                nonce,
                ..
            }
            | Self::Lifecycle {
                expected_revision,
                nonce,
                ..
            } => Some((expected_revision.0, nonce.0)),
            _ => None,
        };
        if let Some((revision, nonce)) = transition {
            if revision == 0 || nonce == 0 {
                return Err(Failure::new("INVALID"));
            }
        }
        if let Self::Policy { permissions, .. } = self {
            if permissions.len() > scap_object::format::MAX_PRINCIPALS
                || !permissions.iter().any(|entry| entry.admin)
            {
                return Err(Failure::new("INVALID"));
            }
            let mut identities = std::collections::BTreeSet::new();
            for permission in permissions {
                if permission.principal.0 == 0 || !identities.insert(permission.principal.0) {
                    return Err(Failure::new("INVALID"));
                }
            }
        }
        if let Self::Quota { max_bytes, .. } = self {
            scap_object::format::DatabaseQuota {
                max_bytes: max_bytes.map(|value| value.0),
            }
            .validate()
            .map_err(|_| Failure::new("INVALID"))?;
        }
        Ok(())
    }

    pub fn priority(&self) -> bool {
        !matches!(
            self,
            Self::Query { .. } | Self::Execute { .. } | Self::Create { .. }
        )
    }

    pub fn admission(&self) -> &'static str {
        match self {
            Self::Open {} | Self::Activate { .. } => "recovery",
            Self::Query { .. } | Self::Execute { .. } | Self::Create { .. } => "data",
            _ => "control",
        }
    }
}

fn present_worker<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Decimal>, D::Error> {
    Decimal::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug)]
pub struct Call {
    pub version: u8,
    pub scope: WireScope,
    pub action: Action,
}

impl<'de> Deserialize<'de> for Call {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Envelope;
        impl<'de> serde::de::Visitor<'de> for Envelope {
            type Value = Call;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a versioned SCAP request object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Call, M::Error> {
                use serde::de::Error;
                let mut version = None;
                let mut scope = None;
                let mut action =
                    std::collections::BTreeMap::<String, Box<serde_json::value::RawValue>>::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => {
                            if version.is_some() {
                                return Err(M::Error::duplicate_field("version"));
                            }
                            version = Some(map.next_value()?);
                        }
                        "scope" => {
                            if scope.is_some() {
                                return Err(M::Error::duplicate_field("scope"));
                            }
                            scope = Some(map.next_value()?);
                        }
                        _ => {
                            if action.contains_key(&key) {
                                return Err(M::Error::custom("duplicate action field"));
                            }
                            action.insert(key, map.next_value()?);
                        }
                    }
                }
                // Preserve raw nested JSON so duplicate fields inside scope,
                // statements, parameters and identities still reach their
                // strict typed decoders. serde(flatten) silently ignores some
                // unknown fields on internally tagged enums and is unsuitable.
                let bytes = serde_json::to_vec(&action).expect("raw JSON map serializes");
                Ok(Call {
                    version: version.ok_or_else(|| M::Error::missing_field("version"))?,
                    scope: scope.ok_or_else(|| M::Error::missing_field("scope"))?,
                    action: serde_json::from_slice(&bytes).map_err(M::Error::custom)?,
                })
            }
        }
        deserializer.deserialize_map(Envelope)
    }
}

fn required_quota<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Decimal>, D::Error> {
    Option::<Decimal>::deserialize(deserializer)
}

pub fn parse(bytes: &[u8]) -> Result<Call, Failure> {
    let call: Call = serde_json::from_slice(bytes).map_err(|_| Failure::new("INVALID"))?;
    if call.version != 1 {
        return Err(Failure::new("VERSION"));
    }
    call.scope.native()?;
    call.action.validate()?;
    Ok(call)
}

pub fn scope(scope: &Scope) -> Json {
    json!({ "deployment": Decimal(scope.deployment), "tenant": Decimal(scope.tenant),
        "database": Decimal(scope.database), "incarnation": Decimal(scope.incarnation),
        "generation": Decimal(scope.generation) })
}

pub fn receipt(receipt: &Receipt) -> Json {
    json!({ "scope": scope(&receipt.scope),
        "request": { "epoch": Decimal(receipt.request.epoch), "id": Decimal(receipt.request.id),
            "principal": Decimal(receipt.request.principal), "fingerprint": receipt.request.fingerprint },
        "sequence": Decimal(receipt.sequence),
        "transition": { "revision": Decimal(receipt.transition.revision), "nonce": Decimal(receipt.transition.nonce) },
        "data_root": receipt.data_root, "result_hash": receipt.result_hash })
}

/// Public status contains no ETag, bucket credentials or complete policy list.
pub fn status(head: &Head) -> Json {
    json!({ "scope": scope(&head.scope), "revision": Decimal(head.revision),
        "sequence": Decimal(head.sequence), "owner_epoch": Decimal(head.owner_epoch),
        "owner_instance": Decimal(head.owner_instance), "active": head.active,
        "auth_epoch": Decimal(head.auth_epoch), "lifecycle": head.lifecycle,
        "request_epoch": Decimal(head.request_epoch), "max_bytes": head.quota.max_bytes.map(Decimal),
        "transition": { "revision": Decimal(head.transition.revision), "nonce": Decimal(head.transition.nonce) },
        "retention": { "max_entries": head.retention.max_entries,
            "max_result_bytes": Decimal(head.retention.max_result_bytes),
            "oldest_epoch": Decimal(head.windows.last().map_or(head.request_epoch, |window| window.epoch)) } })
}

pub fn result(result: &TransactionResult) -> Result<String, Failure> {
    let bytes = scap_sql::encode_result(result, scap_object::options::durable_sql_limits())
        .map_err(|_| Failure::new("CORRUPT"))?;
    Ok(STANDARD.encode(bytes))
}

pub fn resolved(resolution: Resolution) -> Json {
    match resolution {
        Resolution::Committed {
            receipt: value,
            bytes,
        } => Json::Object(Map::from_iter([
            ("state".into(), Json::String("committed".into())),
            ("receipt".into(), receipt(&value)),
            ("result".into(), Json::String(STANDARD.encode(bytes))),
        ])),
        Resolution::Cancelled { transition } => json!({ "state": "cancelled", "transition": {
            "revision": Decimal(transition.revision), "nonce": Decimal(transition.nonce) } }),
        Resolution::Unknown => json!({ "state": "unknown" }),
        Resolution::Closed => json!({ "state": "closed" }),
        Resolution::Retired => json!({ "state": "retired" }),
    }
}

pub fn failed(error: &Failure) -> Json {
    let mut body = json!({ "code": error.code, "message": error.code });
    if let Some(value) = &error.receipt {
        body["receipt"] = receipt(value);
    }
    json!({ "ok": false, "error": body })
}

#[cfg(test)]
mod tests;
