//! Read-only discovery pages with explicit incomplete results and opaque cursors.

use scap_object::catalogue as core;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use crate::{catalogue_wire, discovery_cursor::View, wire, wire::Decimal, Failure};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum Operation {
    #[serde(rename = "list_names")]
    Names,
    #[serde(rename = "deployment_inventory")]
    Inventory,
}

impl Operation {
    pub fn view(self) -> View {
        match self {
            Self::Names => View::Names,
            Self::Inventory => View::Inventory,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub version: u8,
    pub operation: Operation,
    #[serde(deserialize_with = "required_cursor")]
    pub cursor: Option<String>,
}

fn required_cursor<'de, D: Deserializer<'de>>(value: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(value)
}

pub fn parse(bytes: &[u8]) -> Result<Call, Failure> {
    let value: Call = serde_json::from_slice(bytes).map_err(|_| Failure::new("INVALID"))?;
    if value.version != 1 {
        return Err(Failure::new("VERSION"));
    }
    Ok(value)
}

pub fn error(value: core::DiscoveryError) -> Failure {
    use core::DiscoveryError::*;
    Failure::new(match value {
        Invalid => "INVALID",
        Denied => "DENIED",
        Limit => "LIMIT",
        Conflict => "CONFLICT",
        Unknown => "UNKNOWN",
        Corrupt => "CORRUPT",
        SnapshotExpired => "SNAPSHOT_EXPIRED",
    })
}

pub fn names(page: &core::NamePage, cursor: Option<String>) -> Value {
    let names: Vec<_> = page
        .names
        .iter()
        .map(|item| {
            json!({"creation":catalogue_wire::creation(&item.creation),
            "binding_revision":Decimal(item.binding_revision),
            "head_revision":Decimal(item.head_revision)})
        })
        .collect();
    // Ordinary users never receive denied counts, physical keys or raw scan
    // frontiers. Their cursor is encrypted and every new page resolves READ.
    json!({"names":names,"cursor":cursor,"traversal_exhausted":page.traversal_exhausted,
        "stopped":page.stopped.map(|value| error(value).code)})
}

pub fn inventory(page: &core::InventoryPage, cursor: Option<String>) -> Value {
    let records: Vec<_> = page.records.iter().map(record).collect();
    let completion = &page.completion;
    let usage = &page.usage;
    let data_recovery = match completion.data_recovery {
        core::DataRecovery::NotRun => "not_run",
    };
    json!({"records":records,"cursor":cursor,
        "completion":{"traversal_exhausted":completion.traversal_exhausted,
            "preexisting_slots_covered":completion.preexisting_slots_covered,
            "metadata_classified":Decimal(completion.metadata_classified),
            "data_recovery":data_recovery,"recovery_complete":completion.recovery_complete},
        "usage":{"list_pages":usage.list_pages,"candidates":usage.candidates,
            "exact_gets":usage.exact_gets,"list_bytes":usage.list_bytes,
            "metadata_bytes":usage.metadata_bytes},
        "stopped":page.stopped.map(|value| error(value).code)})
}

fn record(value: &core::DiscoveredRecord) -> Value {
    use core::RecordKind::*;
    let kind = match value.kind {
        Name => "name",
        Create => "create",
        Control => "control",
        AbortProof => "abort_proof",
        Head => "head",
        OrphanPrefix => "orphan_prefix",
    };
    json!({"key":value.key,"kind":kind,"state":state(value.state),
        "creation":value.creation.as_ref().map(catalogue_wire::creation),
        "scope":value.scope.as_ref().map(wire::scope),
        "control":value.control.as_ref().map(control),
        "binding_revision":value.binding_revision.map(Decimal),
        "head_revision":value.head_revision.map(Decimal)})
}

fn control(value: &core::ObservedControl) -> Value {
    json!({"kind":value.kind,"principal":Decimal(value.principal),
        "operation":Decimal(value.operation),"expected_name_revision":Decimal(value.expected_name_revision),
        "expected_head_revision":value.expected_head_revision.map(Decimal),"nonce":Decimal(value.nonce)})
}

fn state(value: core::MetadataState) -> &'static str {
    use core::MetadataState::*;
    match value {
        DescriptorOnly => "descriptor_only",
        Reserved => "reserved",
        Provisioning => "provisioning",
        RestoreCopying => "restore_copying",
        RestoreCopied => "restore_copied",
        Bound => "bound",
        Ready => "ready",
        Maintenance => "maintenance",
        Aborting => "aborting",
        Aborted => "aborted",
        Deleting => "deleting",
        Deleted => "deleted",
        NameConflict => "name_conflict",
        IdentityConflict => "identity_conflict",
        ControlAdmitted => "control_admitted",
        Orphan => "orphan",
    }
}

#[cfg(test)]
mod tests;
