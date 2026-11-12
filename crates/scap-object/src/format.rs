//! Strict live v6 / terminal v7 HEADs and unchanged v2 immutable frames.
//! Large chunk and original-result bytes are raw, never JSON byte arrays.

pub use crate::snapshot_format::{
    SnapshotEntry, SnapshotIdentity, SnapshotLimits, SnapshotPoint, SnapshotRef,
    MAX_SNAPSHOT_LABEL_BYTES, MAX_SNAPSHOT_LOGICAL_BYTES, MAX_SNAPSHOT_POINTS,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub use crate::owner_format::{
    OwnerAdmission, OwnerAdmissionKind, OwnerPhase, OwnerPhaseKind, OwnerPlan, OwnerPlanRef,
};

#[path = "object_frame.rs"]
mod object_frame;
pub(crate) use object_frame::ValidatedFrame;

#[path = "storage.rs"]
mod storage;
pub use storage::{
    CopyBasis, CopyPhase, CopyPlan, Storage, SweepCheckpoint, SweepDisposition, SweepEntry,
    TerminalSeal, MAX_SWEEP_ENTRIES,
};

pub const PAGE_SIZE: usize = 4096;
pub const CHUNK_PAGES: u32 = 32;
pub const CHUNK_BYTES: usize = PAGE_SIZE * CHUNK_PAGES as usize;
pub const TREE_FANOUT: usize = 256;
/// Zero-based node level: level 0 references chunks; level 3 is the fourth
/// node layer and can address every page supported by the native engine.
pub const MAX_TREE_LEVEL: u8 = 3;
pub const MAX_PAGES: u32 = u32::MAX - 1;
pub const MAX_REQUESTS: u32 = 65_536;
pub const REQUEST_LEAF_CAPACITY: usize = 128;
pub const REQUEST_BRANCH_CAPACITY: usize = 32;
/// Leaves are level zero. A level-four root would require at least
/// 2 * 16^3 * 64 = 524,288 entries, beyond MAX_REQUESTS.
pub const MAX_REQUEST_INDEX_LEVEL: u8 = 3;
pub const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_HEAD_BYTES: usize = 256 * 1024;
pub const MAX_OBJECT_BYTES: usize = MAX_RESULT_BYTES + 64 * 1024;
pub const MAX_PRINCIPALS: usize = 1024;
/// Initial physical namespace. HEAD6 allocates later namespaces monotonically;
/// logical Scope generations identify independent databases, not compactions.
pub const INITIAL_STORAGE_GENERATION: u64 = 1;
const MAGIC: &[u8; 8] = b"SCAPOBJ2";
const FRAME_BYTES: usize = 20;
const SMALL_METADATA_BYTES: usize = 64 * 1024 - FRAME_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    Invalid,
    Limit,
    Corrupt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub deployment: u64,
    pub tenant: u64,
    pub database: u64,
    pub incarnation: u64,
    pub generation: u64,
}

impl Scope {
    pub fn validate(&self) -> Result<(), FormatError> {
        nonzero(&[
            self.deployment,
            self.tenant,
            self.database,
            self.incarnation,
            self.generation,
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub revision: u64,
    pub nonce: u64,
}

impl Transition {
    fn validate(&self) -> Result<(), FormatError> {
        nonzero(&[self.revision, self.nonce])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub epoch: u64,
    pub id: u64,
    pub principal: u64,
    pub fingerprint: String,
}

impl Request {
    pub fn validate(&self) -> Result<(), FormatError> {
        nonzero(&[self.epoch, self.id, self.principal])?;
        check(hash_valid(&self.fingerprint))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseQuota {
    /// None removes the SCAP business quota, never the native page-number bound.
    /// The field itself is mandatory: omitting it must not disable a quota.
    #[serde(deserialize_with = "required_option")]
    pub max_bytes: Option<u64>,
}

impl DatabaseQuota {
    pub fn validate(&self) -> Result<(), FormatError> {
        if let Some(bytes) = self.max_bytes {
            check(bytes != 0 && bytes.is_multiple_of(PAGE_SIZE as u64))?;
            check(bytes / PAGE_SIZE as u64 <= MAX_PAGES as u64)?;
        }
        Ok(())
    }

    pub fn max_pages(&self) -> Result<u32, FormatError> {
        self.validate()?;
        Ok(self
            .max_bytes
            .map_or(MAX_PAGES, |bytes| (bytes / PAGE_SIZE as u64) as u32))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub max_entries: u32,
    pub max_result_bytes: u64,
}

impl Retention {
    pub fn validate(&self) -> Result<(), FormatError> {
        check(self.max_entries != 0 && self.max_entries <= MAX_REQUESTS)?;
        check(self.max_result_bytes >= MAX_RESULT_BYTES as u64)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub principal: u64,
    pub read: bool,
    pub write: bool,
    pub admin: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Provisioning,
    Ready,
    Maintenance,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCreation {
    pub creator: u64,
    pub operation: u64,
    pub name_hash: String,
    pub descriptor_hash: String,
}

impl NamedCreation {
    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        nonzero(&[self.creator, self.operation])?;
        check(hash_valid(&self.name_hash))?;
        check(hash_valid(&self.descriptor_hash))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedDeletionKind {
    Abort,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedDeletion {
    pub kind: NamedDeletionKind,
    pub principal: u64,
    pub operation: u64,
    pub expected_name_revision: u64,
    #[serde(deserialize_with = "required_option")]
    pub expected_head_revision: Option<u64>,
    pub nonce: u64,
    pub descriptor_hash: String,
}

impl NamedDeletion {
    fn validate(&self) -> Result<(), FormatError> {
        nonzero(&[
            self.principal,
            self.operation,
            self.expected_name_revision,
            self.nonce,
        ])?;
        check(hash_valid(&self.descriptor_hash))?;
        match self.kind {
            NamedDeletionKind::Abort => check(self.expected_head_revision.is_none()),
            NamedDeletionKind::Delete => check(self.expected_head_revision.is_some_and(|r| r != 0)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub epoch: u64,
    pub root: String,
    pub count: u32,
    pub result_bytes: u64,
}

impl Window {
    /// A full window cannot promise admission space for the largest result.
    /// Callers validate the retention policy and counters before using this.
    pub fn full(&self, retention: &Retention) -> bool {
        self.count == retention.max_entries
            || self.result_bytes
                > retention
                    .max_result_bytes
                    .saturating_sub(MAX_RESULT_BYTES as u64)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub format: u32,
    pub scope: Scope,
    pub head_serial: u64,
    pub storage: Storage,
    pub revision: u64,
    pub transition: Transition,
    pub sequence: u64,
    pub owner_epoch: u64,
    pub owner_instance: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::owner_format::present_owner"
    )]
    pub owner_plan: Option<OwnerPlan>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::snapshot_format::present_entries"
    )]
    pub snapshots: Option<Vec<crate::snapshot_format::SnapshotEntry>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::snapshot_format::present_limits"
    )]
    pub snapshot_limits: Option<crate::snapshot_format::SnapshotLimits>,
    /// S1 recognizes only null. Cross-Scope restore origins require S2's
    /// complete creation/inspection/publication consumers before admission.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::snapshot_format::present_null_origin"
    )]
    pub restore_origin: Option<()>,
    pub active: bool,
    pub auth_epoch: u64,
    pub policy: Vec<Permission>,
    pub lifecycle: Lifecycle,
    #[serde(deserialize_with = "required_option")]
    pub creation: Option<NamedCreation>,
    #[serde(deserialize_with = "required_option")]
    pub deletion: Option<NamedDeletion>,
    pub data_root: String,
    pub quota: DatabaseQuota,
    pub retention: Retention,
    pub request_epoch: u64,
    pub windows: Vec<Window>,
}

impl Head {
    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        check(matches!(self.format, 6..=9))?;
        if self.format != 9 {
            check((self.format == 8) == self.owner_plan.is_some())?;
        }
        self.scope.validate()?;
        nonzero(&[
            self.head_serial,
            self.revision,
            self.owner_epoch,
            self.owner_instance,
            self.auth_epoch,
            self.request_epoch,
        ])?;
        check(self.head_serial >= self.revision)?;
        self.transition.validate()?;
        check(self.transition.revision == self.revision)?;
        check(hash_valid(&self.data_root))?;
        self.quota.validate()?;
        self.retention.validate()?;
        budget(self.policy.len(), MAX_PRINCIPALS)?;
        let mut principals = BTreeSet::new();
        for permission in &self.policy {
            nonzero(&[permission.principal])?;
            check(principals.insert(permission.principal))?;
        }
        check(self.policy.iter().any(|permission| permission.admin))?;
        budget(self.windows.len(), 3)?;
        check(self.windows.len() as u64 == self.request_epoch.min(3))?;
        for (offset, window) in self.windows.iter().enumerate() {
            check(window.epoch == self.request_epoch - offset as u64)?;
            check(hash_valid(&window.root))?;
            budget(window.count as usize, self.retention.max_entries as usize)?;
            check(window.result_bytes <= self.retention.max_result_bytes)?;
            // Cancelled entries use zero bytes; a zero-entry index cannot
            // declare bytes, and every result is independently format-bounded.
            check(window.result_bytes <= window.count as u64 * MAX_RESULT_BYTES as u64)?;
            if offset != 0 {
                check(window.full(&self.retention))?;
            }
        }
        self.validate_named()?;
        self.storage.validate(self)?;
        if let Some(plan) = &self.owner_plan {
            plan.validate_head(self)?;
        }
        crate::snapshot_format::validate_head(self)?;
        Ok(())
    }

    fn validate_named(&self) -> Result<(), FormatError> {
        if let Some(creation) = &self.creation {
            creation.validate()?;
        }
        if self.lifecycle == Lifecycle::Provisioning {
            check(self.creation.is_some())?;
            check(!self.active && self.sequence == 0 && self.request_epoch == 1)?;
            check(self.windows[0].count == 0 && self.windows[0].result_bytes == 0)?;
        }
        match (&self.creation, &self.deletion, &self.lifecycle) {
            (Some(creation), Some(deletion), Lifecycle::Deleted) => {
                deletion.validate()?;
                check(!self.active && self.transition.nonce == deletion.nonce)?;
                check(
                    self.policy
                        .iter()
                        .any(|p| p.principal == deletion.principal && p.admin),
                )?;
                match deletion.kind {
                    NamedDeletionKind::Abort => {
                        check(deletion.principal == creation.creator)?;
                        check(self.revision <= 2 && self.sequence == 0 && self.request_epoch == 1)?;
                        check(self.windows[0].count == 0 && self.windows[0].result_bytes == 0)
                    }
                    NamedDeletionKind::Delete => check(
                        deletion
                            .expected_head_revision
                            .and_then(|r| r.checked_add(1))
                            == Some(self.revision),
                    ),
                }
            }
            (Some(_), None, Lifecycle::Deleted) | (_, Some(_), _) => Err(FormatError::Invalid),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub page_count: u32,
    #[serde(deserialize_with = "required_option")]
    pub root: Option<String>,
}

impl Manifest {
    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        budget(self.page_count as usize, MAX_PAGES as usize)?;
        check((self.page_count == 0) == self.root.is_none())?;
        if let Some(root) = &self.root {
            check(hash_valid(root))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredResult {
    pub request: Request,
    pub sequence: u64,
    pub transition: Transition,
    pub data_root: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutcomeRef {
    Committed { result: String },
    Cancelled { transition: Transition },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub request: Request,
    pub outcome: OutcomeRef,
    /// Exact original Result payload length; cancelled entries carry zero.
    pub result_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexSummary {
    pub first: u64,
    pub last: u64,
    pub count: u32,
    pub result_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexChild {
    pub hash: String,
    pub summary: IndexSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestIndex {
    Leaf {
        epoch: u64,
        entries: Vec<Entry>,
    },
    Branch {
        epoch: u64,
        level: u8,
        children: Vec<IndexChild>,
    },
}

impl RequestIndex {
    pub(crate) fn epoch(&self) -> u64 {
        match self {
            Self::Leaf { epoch, .. } | Self::Branch { epoch, .. } => *epoch,
        }
    }

    pub(crate) fn level(&self) -> u8 {
        match self {
            Self::Leaf { .. } => 0,
            Self::Branch { level, .. } => *level,
        }
    }

    /// Only the root may be under half full. Edge verification enforces the
    /// non-root minimum; the codec validates each independently stored node.
    pub(crate) fn occupancy(&self) -> (usize, usize) {
        match self {
            Self::Leaf { entries, .. } => (entries.len(), REQUEST_LEAF_CAPACITY),
            Self::Branch { children, .. } => (children.len(), REQUEST_BRANCH_CAPACITY),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        nonzero(&[self.epoch()])?;
        let mut previous = 0;
        match self {
            Self::Leaf { epoch, entries } => {
                budget(entries.len(), REQUEST_LEAF_CAPACITY)?;
                for entry in entries {
                    entry.request.validate()?;
                    check(entry.request.epoch == *epoch)?;
                    check(entry.request.id > previous)?;
                    previous = entry.request.id;
                    check(entry.result_bytes <= MAX_RESULT_BYTES as u64)?;
                    match &entry.outcome {
                        OutcomeRef::Committed { result } => check(hash_valid(result))?,
                        OutcomeRef::Cancelled { transition } => {
                            transition.validate()?;
                            check(entry.result_bytes == 0)?;
                        }
                    }
                }
            }
            Self::Branch {
                level, children, ..
            } => {
                check(*level != 0 && *level <= MAX_REQUEST_INDEX_LEVEL)?;
                check(children.len() >= 2)?;
                budget(children.len(), REQUEST_BRANCH_CAPACITY)?;
                let minimum = (REQUEST_LEAF_CAPACITY / 2) as u32
                    * (REQUEST_BRANCH_CAPACITY as u32 / 2).pow(*level as u32 - 1);
                let maximum = REQUEST_LEAF_CAPACITY as u32
                    * (REQUEST_BRANCH_CAPACITY as u32).pow(*level as u32 - 1);
                let mut count = 0_u32;
                for child in children {
                    check(hash_valid(&child.hash))?;
                    let summary = &child.summary;
                    check(summary.first > previous && summary.last >= summary.first)?;
                    check(summary.count >= minimum && summary.count <= maximum)?;
                    check(summary.last - summary.first >= summary.count as u64 - 1)?;
                    check(summary.result_bytes <= summary.count as u64 * MAX_RESULT_BYTES as u64)?;
                    previous = summary.last;
                    count += summary.count;
                }
                budget(count as usize, MAX_REQUESTS as usize)?;
            }
        }
        Ok(())
    }

    /// Called only after local validation. All sums fit: at most 65,536
    /// independently bounded 64 MiB results, and at most 32 bounded children.
    pub(crate) fn summary(&self) -> IndexSummary {
        match self {
            Self::Leaf { entries, .. } => IndexSummary {
                first: entries.first().map_or(0, |entry| entry.request.id),
                last: entries.last().map_or(0, |entry| entry.request.id),
                count: entries.len() as u32,
                result_bytes: entries.iter().map(|entry| entry.result_bytes).sum(),
            },
            Self::Branch { children, .. } => IndexSummary {
                first: children[0].summary.first,
                last: children[children.len() - 1].summary.last,
                count: children.iter().map(|child| child.summary.count).sum(),
                result_bytes: children
                    .iter()
                    .map(|child| child.summary.result_bytes)
                    .sum(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Payload {
    Chunk {
        first_page: u32,
        bytes: Vec<u8>,
    },
    Node {
        level: u8,
        first_chunk: u32,
        children: Vec<String>,
    },
    Manifest(Manifest),
    Result(StoredResult),
    Index(RequestIndex),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: u32,
    pub scope: Scope,
    pub payload: Payload,
}

impl Envelope {
    fn validate(&self) -> Result<(), FormatError> {
        let raw_len = match &self.payload {
            Payload::Chunk { bytes, .. } | Payload::Result(StoredResult { bytes, .. }) => {
                bytes.len()
            }
            _ => 0,
        };
        self.validate_with_raw_len(raw_len)
    }

    /// Shared semantic checks for owned payloads and frames whose raw bytes
    /// have not been copied into the metadata yet. Frame parsing separately
    /// requires empty embedded bytes and no raw bytes for non-raw variants.
    fn validate_with_raw_len(&self, raw_len: usize) -> Result<(), FormatError> {
        check(self.format == 2)?;
        self.scope.validate()?;
        match &self.payload {
            Payload::Chunk { first_page, .. } => {
                check(*first_page != 0 && (*first_page - 1).is_multiple_of(CHUNK_PAGES))?;
                check(raw_len != 0 && raw_len.is_multiple_of(PAGE_SIZE))?;
                budget(raw_len, CHUNK_BYTES)?;
                check(*first_page as u64 + (raw_len / PAGE_SIZE) as u64 - 1 <= MAX_PAGES as u64)?;
            }
            Payload::Node {
                level,
                first_chunk,
                children,
            } => {
                check(*level <= MAX_TREE_LEVEL)?;
                check(*first_chunk < MAX_PAGES.div_ceil(CHUNK_PAGES))?;
                check(!children.is_empty())?;
                budget(children.len(), TREE_FANOUT)?;
                for child in children {
                    check(hash_valid(child))?;
                }
            }
            Payload::Manifest(manifest) => manifest.validate()?,
            Payload::Result(result) => {
                result.request.validate()?;
                nonzero(&[result.sequence])?;
                result.transition.validate()?;
                check(hash_valid(&result.data_root))?;
                budget(raw_len, MAX_RESULT_BYTES)?;
            }
            Payload::Index(index) => index.validate()?,
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format: u32,
    scope: Scope,
    payload: Payload,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Authority identity does not change with a data-layout version. In particular,
/// incarnation, generation or a new wire format cannot bypass a HEAD tombstone.
pub fn head_key(scope: &Scope) -> String {
    format!(
        "scap-object/v1/{}/{}/{}/head",
        scope.deployment, scope.tenant, scope.database
    )
}

pub fn object_key(scope: &Scope, storage_generation: u64, hash: &str) -> String {
    format!(
        "scap-object/v1/{}/{}/{}/inc/{}/gen/{}/storage/{}/objects/{}",
        scope.deployment,
        scope.tenant,
        scope.database,
        scope.incarnation,
        scope.generation,
        storage_generation,
        hash
    )
}

pub fn encode_head(head: &Head) -> Result<Vec<u8>, FormatError> {
    head.validate()?;
    encode(head, MAX_HEAD_BYTES)
}

pub fn decode_head(bytes: &[u8], scope: &Scope) -> Result<Head, FormatError> {
    let head = decode_head_slot(bytes, scope)?;
    check(head.scope == *scope).map_err(|_| FormatError::Corrupt)?;
    Ok(head)
}

/// Internal identity-slot inspection must not confuse another incarnation with
/// a missing HEAD. The public database path still checks the complete Scope.
pub(crate) fn decode_head_slot(bytes: &[u8], scope: &Scope) -> Result<Head, FormatError> {
    decode_head_at_slot(
        bytes,
        &DatabaseSlot {
            deployment: scope.deployment,
            tenant: scope.tenant,
            database: scope.database,
        },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseSlot {
    pub deployment: u64,
    pub tenant: u64,
    pub database: u64,
}

/// Discovery knows the permanent physical slot, not an expected incarnation.
/// Validate the complete stored Scope without manufacturing a placeholder.
pub(crate) fn decode_head_at_slot(bytes: &[u8], slot: &DatabaseSlot) -> Result<Head, FormatError> {
    budget(bytes.len(), MAX_HEAD_BYTES)?;
    let head: Head = serde_json::from_slice(bytes).map_err(|_| FormatError::Corrupt)?;
    head.validate().map_err(|_| FormatError::Corrupt)?;
    check(
        head.scope.deployment == slot.deployment
            && head.scope.tenant == slot.tenant
            && head.scope.database == slot.database,
    )
    .map_err(|_| FormatError::Corrupt)?;
    Ok(head)
}

pub fn encode_object(envelope: &Envelope) -> Result<Vec<u8>, FormatError> {
    envelope.validate()?;
    let (payload, raw) = match &envelope.payload {
        Payload::Chunk { first_page, bytes } => (
            Payload::Chunk {
                first_page: *first_page,
                bytes: Vec::new(),
            },
            bytes.as_slice(),
        ),
        Payload::Result(result) => (
            Payload::Result(StoredResult {
                request: result.request.clone(),
                sequence: result.sequence,
                transition: result.transition.clone(),
                data_root: result.data_root.clone(),
                bytes: Vec::new(),
            }),
            result.bytes.as_slice(),
        ),
        payload => (payload.clone(), &[][..]),
    };
    encode_frame(
        &Metadata {
            format: envelope.format,
            scope: envelope.scope.clone(),
            payload,
        },
        raw,
        SMALL_METADATA_BYTES,
    )
}

fn encode_frame(
    metadata: &impl Serialize,
    raw: &[u8],
    maximum_metadata: usize,
) -> Result<Vec<u8>, FormatError> {
    let metadata = encode(metadata, maximum_metadata)?;
    let length = FRAME_BYTES + metadata.len() + raw.len();
    budget(length, MAX_OBJECT_BYTES)?;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    bytes.extend(metadata);
    bytes.extend_from_slice(raw);
    Ok(bytes)
}

pub fn decode_object(
    bytes: &[u8],
    scope: &Scope,
    expected_hash: &str,
) -> Result<Envelope, FormatError> {
    object_frame::ValidatedFrame::parse(bytes, scope, expected_hash)
        .map(object_frame::ValidatedFrame::into_envelope)
}

fn encode(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, FormatError> {
    let bytes = serde_json::to_vec(value).expect("wire DTO serialization is infallible");
    budget(bytes.len(), maximum)?;
    Ok(bytes)
}

fn required_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

pub(crate) fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn nonzero(values: &[u64]) -> Result<(), FormatError> {
    check(values.iter().all(|value| *value != 0))
}

fn check(valid: bool) -> Result<(), FormatError> {
    if valid {
        Ok(())
    } else {
        Err(FormatError::Invalid)
    }
}

fn budget(used: usize, maximum: usize) -> Result<(), FormatError> {
    if used <= maximum {
        Ok(())
    } else {
        Err(FormatError::Limit)
    }
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod tests;
