//! Public catalogue identities contain no object keys, ETags or trusted proofs.

use serde::{Deserialize, Serialize};

use crate::format::{DatabaseQuota, Head, Retention, Scope};

/// Supplied by trusted authentication on every call, never from client JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub principal: u64,
    pub provision: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogueError {
    Invalid,
    Denied,
    NotFound,
    Conflict,
    IdentityConflict,
    Corrupt,
    Limit,
    Unknown,
    SnapshotExpired,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuotaChoice {
    #[default]
    Default,
    Unlimited,
    Limited {
        max_bytes: u64,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOptions {
    pub quota: QuotaChoice,
}

impl CreateOptions {
    pub(super) fn effective_quota(&self, default: &DatabaseQuota) -> DatabaseQuota {
        match self.quota {
            QuotaChoice::Default => default.clone(),
            QuotaChoice::Unlimited => DatabaseQuota { max_bytes: None },
            QuotaChoice::Limited { max_bytes } => DatabaseQuota {
                max_bytes: Some(max_bytes),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareCreate {
    pub name: String,
    pub operation: u64,
    pub expected_name_revision: Option<u64>,
    pub options: CreateOptions,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Creation {
    pub creator: u64,
    pub operation: u64,
    pub name: String,
    pub scope: Scope,
    pub expected_name_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedCreate {
    pub creation: Creation,
    pub initial_quota: DatabaseQuota,
    pub retention: Retention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortCreate {
    pub creation: Creation,
    pub operation: u64,
    pub expected_name_revision: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteNamed {
    pub creation: Creation,
    pub operation: u64,
    pub expected_name_revision: u64,
    pub expected_head_revision: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireNamedStorage {
    pub creation: Creation,
    pub expected_head_serial: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationPhase {
    NotReserved,
    Reserved,
    Provisioning,
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
pub struct CreationProgress {
    pub creation: Creation,
    pub phase: CreationPhase,
    pub binding_revision: Option<u64>,
    pub head_revision: Option<u64>,
    pub initial_quota: DatabaseQuota,
    pub retention: Retention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortPhase {
    NotReserved,
    CannotAbortBound,
    Aborting,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortProgress {
    pub creation: Creation,
    pub operation: u64,
    pub nonce: u64,
    pub phase: AbortPhase,
    pub binding_revision: Option<u64>,
    pub head_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionPhase {
    NotDeleted,
    Deleting,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionProgress {
    pub creation: Creation,
    pub operation: u64,
    pub nonce: u64,
    pub phase: DeletionPhase,
    pub binding_revision: Option<u64>,
    pub head_revision: Option<u64>,
}

/// Deliberately not a wire DTO: HTTP must project the authorized public HEAD
/// fields rather than serialize its internal creation/deletion proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    pub creation: Creation,
    pub binding_revision: u64,
    pub head: Head,
}
