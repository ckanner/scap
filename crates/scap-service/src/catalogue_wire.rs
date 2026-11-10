//! Strict, lossless public catalogue intents. Internal authority proofs stay private.

use scap_object::catalogue as core;
use scap_object::format::{DatabaseQuota, Retention};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::{auth::Principal, wire, wire::Decimal, Failure};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Creation {
    pub creator: Decimal,
    pub operation: Decimal,
    pub name: String,
    pub scope: wire::WireScope,
    #[serde(deserialize_with = "required_revision")]
    pub expected_name_revision: Option<Decimal>,
}

impl Creation {
    pub fn native(&self) -> Result<core::Creation, Failure> {
        name(&self.name)?;
        nonzero(self.creator.0)?;
        nonzero(self.operation.0)?;
        revision(self.expected_name_revision)?;
        Ok(core::Creation {
            creator: self.creator.0,
            operation: self.operation.0,
            name: self.name.clone(),
            scope: self.scope.native()?,
            expected_name_revision: self.expected_name_revision.map(|value| value.0),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Quota {
    Default {},
    Unlimited {},
    Limited { max_bytes: Decimal },
}

impl Quota {
    pub(crate) fn native(&self) -> Result<core::QuotaChoice, Failure> {
        Ok(match self {
            Self::Default {} => core::QuotaChoice::Default,
            Self::Unlimited {} => core::QuotaChoice::Unlimited,
            Self::Limited { max_bytes } => {
                DatabaseQuota {
                    max_bytes: Some(max_bytes.0),
                }
                .validate()
                .map_err(|_| Failure::new("INVALID"))?;
                core::QuotaChoice::Limited {
                    max_bytes: max_bytes.0,
                }
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOptions {
    pub quota: Quota,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    PrepareCreate {
        name: String,
        create_operation: Decimal,
        #[serde(deserialize_with = "required_revision")]
        expected_name_revision: Option<Decimal>,
        options: CreateOptions,
    },
    ResumeCreate {
        creation: Creation,
    },
    AbortCreate {
        creation: Creation,
        control_operation: Decimal,
        expected_name_revision: Decimal,
        nonce: Decimal,
    },
    InspectCreateOperation {
        create_operation: Decimal,
    },
    ResolveName {
        name: String,
    },
    DeleteName {
        creation: Creation,
        control_operation: Decimal,
        expected_name_revision: Decimal,
        expected_head_revision: Decimal,
        nonce: Decimal,
    },
    NamedStorageStatus {
        creation: Creation,
    },
    RetireNamedStorage {
        creation: Creation,
        expected_head_serial: Decimal,
    },
}

/// Validated public inputs projected once into the formal runtime's types.
/// These are identities and conditions, never trusted authority proofs.
pub(crate) enum NativeAction {
    Prepare(core::PrepareCreate),
    Resume(core::Creation),
    Abort(core::AbortCreate),
    Inspect(u64),
    Resolve(String),
    Delete(core::DeleteNamed),
    StorageStatus(core::Creation),
    RetireStorage(core::RetireNamedStorage),
}

impl Action {
    /// Unknown-name inspection is deliberately not assigned a caller-chosen
    /// scheduling hint. The queue reserves its conservative tenant/name cost.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::PrepareCreate { name, .. } | Self::ResolveName { name } => Some(name),
            Self::ResumeCreate { creation }
            | Self::AbortCreate { creation, .. }
            | Self::DeleteName { creation, .. }
            | Self::NamedStorageStatus { creation }
            | Self::RetireNamedStorage { creation, .. } => Some(&creation.name),
            Self::InspectCreateOperation { .. } => None,
        }
    }

    pub fn validate(&self) -> Result<(), Failure> {
        self.native().map(|_| ())
    }

    pub(crate) fn native(&self) -> Result<NativeAction, Failure> {
        Ok(match self {
            Self::PrepareCreate {
                name: value,
                create_operation,
                expected_name_revision,
                options,
            } => {
                name(value)?;
                nonzero(create_operation.0)?;
                revision(*expected_name_revision)?;
                NativeAction::Prepare(core::PrepareCreate {
                    name: value.clone(),
                    operation: create_operation.0,
                    expected_name_revision: expected_name_revision.map(|value| value.0),
                    options: core::CreateOptions {
                        quota: options.quota.native()?,
                    },
                })
            }
            Self::ResumeCreate { creation } => NativeAction::Resume(creation.native()?),
            Self::AbortCreate {
                creation,
                control_operation,
                expected_name_revision,
                nonce,
            } => {
                let creation = creation.native()?;
                nonzero(control_operation.0)?;
                nonzero(expected_name_revision.0)?;
                nonzero(nonce.0)?;
                NativeAction::Abort(core::AbortCreate {
                    creation,
                    operation: control_operation.0,
                    expected_name_revision: expected_name_revision.0,
                    nonce: nonce.0,
                })
            }
            Self::InspectCreateOperation { create_operation } => {
                nonzero(create_operation.0)?;
                NativeAction::Inspect(create_operation.0)
            }
            Self::ResolveName { name: value } => {
                name(value)?;
                NativeAction::Resolve(value.clone())
            }
            Self::DeleteName {
                creation,
                control_operation,
                expected_name_revision,
                expected_head_revision,
                nonce,
            } => {
                let creation = creation.native()?;
                nonzero(control_operation.0)?;
                nonzero(expected_name_revision.0)?;
                nonzero(expected_head_revision.0)?;
                nonzero(nonce.0)?;
                NativeAction::Delete(core::DeleteNamed {
                    creation,
                    operation: control_operation.0,
                    expected_name_revision: expected_name_revision.0,
                    expected_head_revision: expected_head_revision.0,
                    nonce: nonce.0,
                })
            }
            Self::NamedStorageStatus { creation } => {
                NativeAction::StorageStatus(creation.native()?)
            }
            Self::RetireNamedStorage {
                creation,
                expected_head_serial,
            } => {
                let creation = creation.native()?;
                nonzero(expected_head_serial.0)?;
                NativeAction::RetireStorage(core::RetireNamedStorage {
                    creation,
                    expected_head_serial: expected_head_serial.0,
                })
            }
        })
    }

    pub fn authorize(&self, principal: &Principal) -> Result<(), Failure> {
        match self {
            Self::PrepareCreate { .. } | Self::InspectCreateOperation { .. } => {
                provision(principal)?;
            }
            Self::ResumeCreate { creation } | Self::AbortCreate { creation, .. } => {
                provision(principal)?;
                if creation.creator.0 != principal.principal {
                    return Err(Failure::new("DENIED"));
                }
                principal.authorize(&creation.scope.native()?)?;
            }
            Self::DeleteName { creation, .. }
            | Self::NamedStorageStatus { creation }
            | Self::RetireNamedStorage { creation, .. } => {
                // Deleting ADMIN may differ from creator and need not provision.
                // Only the core's fresh HEAD read can grant this permission.
                principal.authorize(&creation.scope.native()?)?;
            }
            Self::ResolveName { .. } => {}
        }
        Ok(())
    }
}

fn provision(principal: &Principal) -> Result<(), Failure> {
    if !principal.provision {
        return Err(Failure::new("DENIED"));
    }
    Ok(())
}

fn nonzero(value: u64) -> Result<(), Failure> {
    if value == 0 {
        return Err(Failure::new("INVALID"));
    }
    Ok(())
}

fn name(value: &str) -> Result<(), Failure> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(Failure::new("INVALID"));
    }
    Ok(())
}

fn revision(value: Option<Decimal>) -> Result<(), Failure> {
    if let Some(value) = value {
        nonzero(value.0)?;
    }
    Ok(())
}

fn required_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Decimal>, D::Error> {
    Option::<Decimal>::deserialize(deserializer)
}

#[derive(Clone, Debug)]
pub struct Call {
    pub version: u8,
    pub action: Action,
}

impl<'de> Deserialize<'de> for Call {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Envelope;
        impl<'de> serde::de::Visitor<'de> for Envelope {
            type Value = Call;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a versioned SCAP catalogue request object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Call, M::Error> {
                use serde::de::Error;
                let mut version = None;
                let mut action =
                    std::collections::BTreeMap::<String, Box<serde_json::value::RawValue>>::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key == "version" {
                        if version.is_some() {
                            return Err(M::Error::duplicate_field("version"));
                        }
                        version = Some(map.next_value()?);
                    } else {
                        if action.contains_key(&key) {
                            return Err(M::Error::custom("duplicate action field"));
                        }
                        action.insert(key, map.next_value()?);
                    }
                }
                let bytes = serde_json::to_vec(&action).expect("raw JSON map serializes");
                Ok(Call {
                    version: version.ok_or_else(|| M::Error::missing_field("version"))?,
                    action: serde_json::from_slice(&bytes).map_err(M::Error::custom)?,
                })
            }
        }
        deserializer.deserialize_map(Envelope)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Call, Failure> {
    let call: Call = serde_json::from_slice(bytes).map_err(|_| Failure::new("INVALID"))?;
    if call.version != 1 {
        return Err(Failure::new("VERSION"));
    }
    call.action.validate()?;
    Ok(call)
}

pub fn creation(value: &core::Creation) -> Value {
    json!({"creator":Decimal(value.creator), "operation":Decimal(value.operation),
        "name":value.name, "scope":wire::scope(&value.scope),
        "expected_name_revision":value.expected_name_revision.map(Decimal)})
}

fn quota(value: &DatabaseQuota) -> Value {
    json!({"max_bytes":value.max_bytes.map(Decimal)})
}

fn retention(value: &Retention) -> Value {
    json!({"max_entries":value.max_entries,"max_result_bytes":Decimal(value.max_result_bytes)})
}

pub fn prepared(value: core::PreparedCreate) -> Value {
    json!({"creation":creation(&value.creation),"initial_quota":quota(&value.initial_quota),
        "retention":retention(&value.retention)})
}

pub fn progress(value: core::CreationProgress) -> Value {
    json!({"creation":creation(&value.creation),"phase":value.phase,
        "binding_revision":value.binding_revision.map(Decimal),"head_revision":value.head_revision.map(Decimal),
        "initial_quota":quota(&value.initial_quota),"retention":retention(&value.retention)})
}

pub fn aborted(value: core::AbortProgress) -> Value {
    json!({"creation":creation(&value.creation),"operation":Decimal(value.operation),"nonce":Decimal(value.nonce),
        "phase":value.phase,"binding_revision":value.binding_revision.map(Decimal),
        "head_revision":value.head_revision.map(Decimal)})
}

pub fn deleted(value: core::DeletionProgress) -> Value {
    json!({"creation":creation(&value.creation),"operation":Decimal(value.operation),"nonce":Decimal(value.nonce),
        "phase":value.phase,"binding_revision":value.binding_revision.map(Decimal),
        "head_revision":value.head_revision.map(Decimal)})
}

pub fn named(value: core::Named) -> Value {
    json!({"creation":creation(&value.creation),"binding_revision":Decimal(value.binding_revision),
        "head":wire::status(&value.head)})
}

#[cfg(test)]
mod tests;
