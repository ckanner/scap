//! Bounded retained-snapshot metadata. Wire counters never round through f64.

use scap_object::format::{
    Head, SnapshotEntry, SnapshotIdentity, SnapshotLimits, SnapshotPoint, SnapshotRef,
};
use scap_object::snapshot::{
    PrepareSnapshotInput, PreparedSnapshot, SnapshotObservation, SnapshotState,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::wire::{self, Decimal};
use crate::Failure;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub creator: Decimal,
    pub operation: Decimal,
    pub expected_revision: Decimal,
    pub expected_head_serial: Decimal,
    pub label: String,
}

impl Prepare {
    pub fn native(&self) -> Result<PrepareSnapshotInput, Failure> {
        let input = PrepareSnapshotInput {
            creator: self.creator.0,
            operation: self.operation.0,
            expected_revision: self.expected_revision.0,
            expected_head_serial: self.expected_head_serial.0,
            label: self.label.clone(),
        };
        if input.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(input)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub creator: Decimal,
    pub operation: Decimal,
}

impl Identity {
    pub fn native(&self) -> Result<SnapshotIdentity, Failure> {
        let identity = SnapshotIdentity {
            creator: self.creator.0,
            operation: self.operation.0,
        };
        if identity.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub creator: Decimal,
    pub operation: Decimal,
    pub capture_serial: Decimal,
    pub descriptor_hash: String,
}

impl Reference {
    pub fn native(&self) -> Result<SnapshotRef, Failure> {
        let reference = SnapshotRef {
            creator: self.creator.0,
            operation: self.operation.0,
            capture_serial: self.capture_serial.0,
            descriptor_hash: self.descriptor_hash.clone(),
        };
        if reference.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(reference)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_points: u32,
    pub max_logical_bytes: Decimal,
}

impl Limits {
    pub fn native(&self) -> Result<SnapshotLimits, Failure> {
        let limits = SnapshotLimits {
            max_points: self.max_points,
            max_logical_bytes: self.max_logical_bytes.0,
        };
        if limits.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(limits)
    }
}

pub fn reference(value: &SnapshotRef) -> Value {
    json!({"creator": Decimal(value.creator), "operation": Decimal(value.operation),
        "capture_serial": Decimal(value.capture_serial), "descriptor_hash": value.descriptor_hash})
}

pub fn input(value: &PrepareSnapshotInput) -> Value {
    json!({"creator": Decimal(value.creator), "operation": Decimal(value.operation),
        "expected_revision": Decimal(value.expected_revision),
        "expected_head_serial": Decimal(value.expected_head_serial), "label": value.label})
}

pub fn point(value: &SnapshotPoint) -> Value {
    json!({"data_root": value.data_root, "page_count": value.page_count,
        "sequence": Decimal(value.sequence), "source_revision": Decimal(value.source_revision)})
}

pub fn entry(value: &SnapshotEntry) -> Value {
    json!({"reference": reference(&value.reference), "label": value.label, "point": point(&value.point)})
}

pub fn limits(value: &SnapshotLimits) -> Value {
    json!({"max_points": value.max_points, "max_logical_bytes": Decimal(value.max_logical_bytes)})
}

pub fn prepared(value: &PreparedSnapshot) -> Value {
    json!({"scope": wire::scope(&value.scope), "input": input(&value.input),
        "reference": reference(&value.reference), "point": point(&value.point)})
}

pub fn observation(value: &SnapshotObservation) -> Value {
    let state = if value.state == SnapshotState::Prepared {
        "prepared"
    } else if value.state == SnapshotState::Retained {
        "retained"
    } else if value.state == SnapshotState::ReleasedObserved {
        "released_observed"
    } else {
        "fenced"
    };
    let accepted = if let Some(accepted) = &value.accepted {
        entry(accepted)
    } else {
        Value::Null
    };
    json!({"state": state, "status": wire::status(&value.head), "prepared": prepared(&value.prepared),
        "accepted": accepted})
}

pub fn listing(head: &Head) -> Value {
    let snapshots = if let Some(snapshots) = &head.snapshots {
        snapshots.iter().map(entry).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let limits = if let Some(limit) = &head.snapshot_limits {
        limits(limit)
    } else {
        Value::Null
    };
    json!({"status": wire::status(head),
        "snapshots": snapshots, "limits": limits})
}

#[cfg(test)]
#[path = "snapshot_wire/tests.rs"]
mod tests;
