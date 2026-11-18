//! Restore wire values retain original intent identities; copy proofs stay private.

use scap_object::catalogue as core;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{catalogue_wire as catalogue, snapshot_wire as snapshot, wire, wire::Decimal, Failure};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub creation: catalogue::Creation,
    pub descriptor_hash: String,
}

impl Reference {
    pub fn native(&self) -> Result<core::RestoreRef, Failure> {
        let creation = self.creation.native();
        let Ok(creation) = creation else {
            return Err(creation.expect_err("creation validation failed"));
        };
        let reference = core::RestoreRef {
            creation,
            descriptor_hash: self.descriptor_hash.clone(),
        };
        if let Err(error) = reference.validate() {
            return Err(error.into());
        }
        Ok(reference)
    }
}

pub fn reference(value: &core::RestoreRef) -> Value {
    json!({"creation":catalogue::creation(&value.creation), "descriptor_hash":value.descriptor_hash})
}

pub fn input(value: &core::PrepareRestore) -> Value {
    let quota = if let core::QuotaChoice::Limited { max_bytes } = value.options.quota {
        json!({"mode":"limited", "max_bytes":Decimal(max_bytes)})
    } else if value.options.quota == core::QuotaChoice::Unlimited {
        json!({"mode":"unlimited"})
    } else {
        json!({"mode":"default"})
    };
    let expected_name_revision = if let Some(revision) = value.expected_name_revision {
        json!(Decimal(revision))
    } else {
        Value::Null
    };
    json!({"name":value.name, "restore_operation":Decimal(value.operation),
        "expected_name_revision":expected_name_revision,
        "options":{"quota":quota}, "source_scope":wire::scope(&value.source_scope),
        "snapshot":snapshot::reference(&value.snapshot)})
}

pub fn prepared(value: &core::PreparedRestore) -> Value {
    json!({"reference":reference(&value.reference), "input":input(&value.input),
        "initial_quota":catalogue::quota(&value.initial_quota),
        "retention":catalogue::retention(&value.retention), "point":snapshot::point(&value.point)})
}

pub fn progress(value: &core::RestoreProgress) -> Value {
    let binding_revision = if let Some(revision) = value.binding_revision {
        json!(Decimal(revision))
    } else {
        Value::Null
    };
    let head_revision = if let Some(revision) = value.head_revision {
        json!(Decimal(revision))
    } else {
        Value::Null
    };
    json!({"prepared":prepared(&value.prepared), "phase":value.phase,
        "binding_revision":binding_revision, "head_revision":head_revision})
}

#[cfg(test)]
mod tests;
