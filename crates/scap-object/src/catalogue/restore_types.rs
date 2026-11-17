//! Public restore identities describe an intent, never a completed-copy proof.

use serde::{Deserialize, Serialize};

use super::{CatalogueError, CreateOptions, Creation};
use crate::format::{DatabaseQuota, Retention, Scope, SnapshotPoint, SnapshotRef, PAGE_SIZE};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRestore {
    pub name: String,
    pub operation: u64,
    pub expected_name_revision: Option<u64>,
    pub options: CreateOptions,
    pub source_scope: Scope,
    pub snapshot: SnapshotRef,
}

impl PrepareRestore {
    pub fn validate(&self) -> Result<(), CatalogueError> {
        super::records::name_valid(&self.name)?;
        super::records::valid(self.operation != 0 && self.expected_name_revision != Some(0))?;
        self.expected_name_revision
            .unwrap_or(0)
            .checked_add(3)
            .ok_or(CatalogueError::Limit)?;
        self.source_scope
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        self.options
            .effective_quota(&DatabaseQuota { max_bytes: None })
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        self.snapshot
            .validate()
            .map_err(|_| CatalogueError::Invalid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRef {
    pub creation: Creation,
    pub descriptor_hash: String,
}

impl RestoreRef {
    pub fn validate(&self) -> Result<(), CatalogueError> {
        super::records::creation_valid(&self.creation)?;
        super::records::valid(crate::format::hash_valid(&self.descriptor_hash))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRestore {
    pub reference: RestoreRef,
    pub input: PrepareRestore,
    pub initial_quota: DatabaseQuota,
    pub retention: Retention,
    pub point: SnapshotPoint,
}

impl PreparedRestore {
    /// One full logical image. A deployment reserves sidecar/filesystem overhead
    /// separately; this value is not a promise about process RSS or disk blocks.
    pub fn image_bytes(&self) -> u64 {
        u64::from(self.point.page_count) * PAGE_SIZE as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePhase {
    NotReserved,
    Reserved,
    Copying,
    Copied,
    Bound,
    Ready,
    Aborting,
    Aborted,
    Deleting,
    Deleted,
    NameConflict,
    IdentityConflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreProgress {
    pub prepared: PreparedRestore,
    pub phase: RestorePhase,
    pub binding_revision: Option<u64>,
    pub head_revision: Option<u64>,
}

/// Independent conservative I/O budgets for one explicit, nonresumable copy.
/// These may be lowered, including to zero, but never increased above defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreBudget {
    pub source_gets: u64,
    pub source_bytes: u64,
    pub target_puts: u64,
    pub target_put_bytes: u64,
    pub target_gets: u64,
    pub target_get_bytes: u64,
    pub max_image_bytes: u64,
}

impl Default for RestoreBudget {
    fn default() -> Self {
        Self {
            source_gets: 1_048_576,
            source_bytes: 64 * 1024 * 1024 * 1024,
            target_puts: 1_048_576,
            target_put_bytes: 64 * 1024 * 1024 * 1024,
            target_gets: 1_048_576,
            target_get_bytes: 64 * 1024 * 1024 * 1024,
            max_image_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}

impl RestoreBudget {
    pub fn validate(&self) -> Result<(), CatalogueError> {
        let maximum = Self::default();
        super::records::valid(
            self.source_gets <= maximum.source_gets
                && self.source_bytes <= maximum.source_bytes
                && self.target_puts <= maximum.target_puts
                && self.target_put_bytes <= maximum.target_put_bytes
                && self.target_gets <= maximum.target_gets
                && self.target_get_bytes <= maximum.target_get_bytes
                && self.max_image_bytes <= maximum.max_image_bytes,
        )
    }
}
