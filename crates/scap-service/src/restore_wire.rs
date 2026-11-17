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
        let reference = core::RestoreRef {
            creation: self.creation.native()?,
            descriptor_hash: self.descriptor_hash.clone(),
        };
        reference.validate()?;
        Ok(reference)
    }
}

pub fn reference(value: &core::RestoreRef) -> Value {
    json!({"creation":catalogue::creation(&value.creation), "descriptor_hash":value.descriptor_hash})
}

pub fn input(value: &core::PrepareRestore) -> Value {
    let quota = match value.options.quota {
        core::QuotaChoice::Default => json!({"mode":"default"}),
        core::QuotaChoice::Unlimited => json!({"mode":"unlimited"}),
        core::QuotaChoice::Limited { max_bytes } => {
            json!({"mode":"limited", "max_bytes":Decimal(max_bytes)})
        }
    };
    json!({"name":value.name, "restore_operation":Decimal(value.operation),
        "expected_name_revision":value.expected_name_revision.map(Decimal),
        "options":{"quota":quota}, "source_scope":wire::scope(&value.source_scope),
        "snapshot":snapshot::reference(&value.snapshot)})
}

pub fn prepared(value: &core::PreparedRestore) -> Value {
    json!({"reference":reference(&value.reference), "input":input(&value.input),
        "initial_quota":catalogue::quota(&value.initial_quota),
        "retention":catalogue::retention(&value.retention), "point":snapshot::point(&value.point)})
}

pub fn progress(value: &core::RestoreProgress) -> Value {
    json!({"prepared":prepared(&value.prepared), "phase":value.phase,
        "binding_revision":value.binding_revision.map(Decimal),
        "head_revision":value.head_revision.map(Decimal)})
}

#[cfg(test)]
mod tests;
