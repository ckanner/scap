//! Strict retained-point metadata and finite cleanup capacity for HEAD9.
//!
//! Snapshot policy is durable. Local read/copy budgets must never decide
//! whether an already-published HEAD is a valid persisted record.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::format::{
    hash_valid, FormatError, Head, Lifecycle, SweepDisposition, MAX_PAGES, PAGE_SIZE,
};

pub const MAX_SNAPSHOT_POINTS: u32 = 64;
pub const MAX_SNAPSHOT_LABEL_BYTES: usize = 128;
pub const MAX_SNAPSHOT_LOGICAL_BYTES: u64 =
    MAX_SNAPSHOT_POINTS as u64 * MAX_PAGES as u64 * PAGE_SIZE as u64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotLimits {
    pub max_points: u32,
    pub max_logical_bytes: u64,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_points: MAX_SNAPSHOT_POINTS,
            max_logical_bytes: 32 * 1024 * 1024 * 1024,
        }
    }
}

impl SnapshotLimits {
    pub fn validate(&self) -> Result<(), FormatError> {
        valid(self.max_points <= MAX_SNAPSHOT_POINTS)?;
        valid(self.max_logical_bytes <= MAX_SNAPSHOT_LOGICAL_BYTES)
    }

    pub(crate) fn fits(&self, entries: &[SnapshotEntry]) -> Result<(), FormatError> {
        self.validate()?;
        let bytes = gross_bytes(entries)?;
        valid(entries.len() <= self.max_points as usize)?;
        valid(bytes <= self.max_logical_bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIdentity {
    pub creator: u64,
    pub operation: u64,
}

impl SnapshotIdentity {
    pub fn validate(&self) -> Result<(), FormatError> {
        valid(self.creator != 0 && self.operation != 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRef {
    pub creator: u64,
    pub operation: u64,
    pub capture_serial: u64,
    pub descriptor_hash: String,
}

impl SnapshotRef {
    pub fn identity(&self) -> SnapshotIdentity {
        SnapshotIdentity {
            creator: self.creator,
            operation: self.operation,
        }
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        self.identity().validate()?;
        valid(self.capture_serial != 0 && hash_valid(&self.descriptor_hash))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPoint {
    pub data_root: String,
    pub page_count: u32,
    pub sequence: u64,
    pub source_revision: u64,
}

impl SnapshotPoint {
    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        valid(hash_valid(&self.data_root))?;
        valid(self.page_count <= MAX_PAGES && self.source_revision != 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEntry {
    pub reference: SnapshotRef,
    pub label: String,
    pub point: SnapshotPoint,
}

impl SnapshotEntry {
    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        self.reference.validate()?;
        label(&self.label)?;
        self.point.validate()?;
        valid(self.point.source_revision < self.reference.capture_serial)
    }
}

pub(crate) fn label(value: &str) -> Result<(), FormatError> {
    valid(!value.is_empty() && value.len() <= MAX_SNAPSHOT_LABEL_BYTES)?;
    valid(!value.chars().any(char::is_control))
}

pub(crate) fn gross_bytes(entries: &[SnapshotEntry]) -> Result<u64, FormatError> {
    // Multiplication cannot overflow: a u32 page count times 4096 fits u64.
    // The format cap of 64 roots bounds the total independently of live quota.
    valid(entries.len() <= MAX_SNAPSHOT_POINTS as usize)?;
    Ok(entries
        .iter()
        .map(|entry| entry.point.page_count as u64 * PAGE_SIZE as u64)
        .sum())
}

/// Preserve absence as a separate wire state. Explicit null is invalid for
/// the list and limits, while S1 admits only the mandatory-null origin.
pub(crate) fn present_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<SnapshotEntry>>, D::Error> {
    Vec::deserialize(deserializer).map(Some)
}

pub(crate) fn present_limits<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SnapshotLimits>, D::Error> {
    SnapshotLimits::deserialize(deserializer).map(Some)
}

pub(crate) fn present_null_origin<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<()>, D::Error> {
    <()>::deserialize(deserializer).map(Some)
}

pub(crate) fn validate_head(head: &Head) -> Result<(), FormatError> {
    if head.format != 9 {
        return valid(
            head.snapshots.is_none()
                && head.snapshot_limits.is_none()
                && head.restore_origin.is_none(),
        );
    }
    let entries = head.snapshots.as_ref().ok_or(FormatError::Invalid)?;
    let limits = head.snapshot_limits.as_ref().ok_or(FormatError::Invalid)?;
    valid(head.restore_origin.is_some())?;
    limits.fits(entries)?;
    valid(
        entries.is_empty()
            || (head.storage.terminal.is_none() && head.lifecycle != Lifecycle::Provisioning),
    )?;
    let mut serial = 0;
    let mut identities = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for entry in entries {
        entry.validate()?;
        valid(
            serial < entry.reference.capture_serial
                && entry.reference.capture_serial <= head.head_serial,
        )?;
        valid(
            entry.point.source_revision <= head.revision && entry.point.sequence <= head.sequence,
        )?;
        valid(identities.insert((entry.reference.creator, entry.reference.operation)))?;
        valid(labels.insert(entry.label.as_str()))?;
        serial = entry.reference.capture_serial;
    }
    valid(cleanup_room(head))
}

/// A finite release/abort/delete/seal/GC path must remain representable.
/// Every actual candidate and static HEAD9 validator uses this same rule.
pub(crate) fn cleanup_room(head: &Head) -> bool {
    if head.format != 9 {
        return true;
    }
    let points = head
        .snapshots
        .as_ref()
        .map_or(0, |entries| entries.len() as u64);
    if points > MAX_SNAPSHOT_POINTS as u64 {
        return false;
    }
    let pending = u64::from(head.owner_plan.as_ref().is_some_and(|plan| plan.pending()));
    let copying = u64::from(head.storage.plan.is_some());
    let checkpoint = head.storage.sweep.as_ref().map_or(0, |sweep| {
        if sweep
            .entries
            .iter()
            .any(|entry| entry.disposition == SweepDisposition::Pending)
        {
            2
        } else {
            1
        }
    });
    let deletion = u64::from(head.lifecycle != Lifecycle::Deleted);
    let seal = u64::from(head.storage.terminal.is_none());
    // Each debt is bounded above before addition; malformed candidate lists
    // cannot overflow arithmetic even when this helper precedes validation.
    let serial_debt = points + pending + copying + checkpoint + deletion + seal;
    head.revision.checked_add(pending + deletion).is_some()
        && head.head_serial.checked_add(serial_debt).is_some()
        && (head.creation.is_none() || deletion == 0 || head.owner_epoch < u64::MAX)
}

pub(crate) fn valid(value: bool) -> Result<(), FormatError> {
    if value {
        Ok(())
    } else {
        Err(FormatError::Invalid)
    }
}

#[cfg(test)]
#[path = "snapshot_format_tests.rs"]
mod tests;
