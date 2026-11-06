//! Strict v2 authority values and length-delimited immutable object frames.
//! Large chunk and original-result bytes are raw, never JSON byte arrays.

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PAGE_SIZE: usize = 4096;
pub const CHUNK_PAGES: u32 = 32;
pub const CHUNK_BYTES: usize = PAGE_SIZE * CHUNK_PAGES as usize;
pub const TREE_FANOUT: usize = 256;
/// Zero-based node level: level 0 references chunks; level 3 is the fourth
/// node layer and can address every page supported by the native engine.
pub const MAX_TREE_LEVEL: u8 = 3;
pub const MAX_PAGES: u32 = u32::MAX - 1;
pub const MAX_REQUESTS: u32 = 65_536;
pub const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_HEAD_BYTES: usize = 256 * 1024;
pub const MAX_OBJECT_BYTES: usize = MAX_RESULT_BYTES + 64 * 1024;
pub const MAX_PRINCIPALS: usize = 1024;
const MAGIC: &[u8; 8] = b"SCAPOBJ2";
const FRAME_BYTES: usize = 20;
const SMALL_METADATA_BYTES: usize = 64 * 1024 - FRAME_BYTES;
const INDEX_METADATA_BYTES: usize = MAX_REQUESTS as usize * 512 + SMALL_METADATA_BYTES;

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
    Ready,
    Maintenance,
    Deleted,
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
    pub revision: u64,
    pub transition: Transition,
    pub sequence: u64,
    pub owner_epoch: u64,
    pub owner_instance: u64,
    pub active: bool,
    pub auth_epoch: u64,
    pub policy: Vec<Permission>,
    pub lifecycle: Lifecycle,
    pub data_root: String,
    pub quota: DatabaseQuota,
    pub retention: Retention,
    pub request_epoch: u64,
    pub windows: Vec<Window>,
}

impl Head {
    fn validate(&self) -> Result<(), FormatError> {
        check(self.format == 2)?;
        self.scope.validate()?;
        nonzero(&[
            self.revision,
            self.owner_epoch,
            self.owner_instance,
            self.auth_epoch,
            self.request_epoch,
        ])?;
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
        Ok(())
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
    Index(Vec<Entry>),
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
        check(self.format == 2)?;
        self.scope.validate()?;
        match &self.payload {
            Payload::Chunk { first_page, bytes } => {
                check(*first_page != 0 && (*first_page - 1).is_multiple_of(CHUNK_PAGES))?;
                check(!bytes.is_empty() && bytes.len().is_multiple_of(PAGE_SIZE))?;
                budget(bytes.len(), CHUNK_BYTES)?;
                check(
                    *first_page as u64 + (bytes.len() / PAGE_SIZE) as u64 - 1 <= MAX_PAGES as u64,
                )?;
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
                budget(result.bytes.len(), MAX_RESULT_BYTES)?;
            }
            Payload::Index(entries) => {
                budget(entries.len(), MAX_REQUESTS as usize)?;
                let mut identities = BTreeSet::new();
                let mut epoch = None;
                for entry in entries {
                    entry.request.validate()?;
                    check(identities.insert(entry.request.id))?;
                    check(*epoch.get_or_insert(entry.request.epoch) == entry.request.epoch)?;
                    match &entry.outcome {
                        OutcomeRef::Committed { result } => check(hash_valid(result))?,
                        OutcomeRef::Cancelled { transition } => transition.validate()?,
                    }
                }
            }
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

pub fn object_key(scope: &Scope, hash: &str) -> String {
    format!(
        "scap-object/v1/{}/{}/{}/inc/{}/gen/{}/objects/{}",
        scope.deployment, scope.tenant, scope.database, scope.incarnation, scope.generation, hash
    )
}

pub fn encode_head(head: &Head) -> Result<Vec<u8>, FormatError> {
    head.validate()?;
    encode(head, MAX_HEAD_BYTES)
}

pub fn decode_head(bytes: &[u8], scope: &Scope) -> Result<Head, FormatError> {
    budget(bytes.len(), MAX_HEAD_BYTES)?;
    let head: Head = serde_json::from_slice(bytes).map_err(|_| FormatError::Corrupt)?;
    head.validate().map_err(|_| FormatError::Corrupt)?;
    check(head.scope == *scope).map_err(|_| FormatError::Corrupt)?;
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
    let maximum = metadata_limit(&payload);
    encode_frame(
        &Metadata {
            format: envelope.format,
            scope: envelope.scope.clone(),
            payload,
        },
        raw,
        maximum,
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
    budget(bytes.len(), MAX_OBJECT_BYTES)?;
    check(digest(bytes) == expected_hash).map_err(|_| FormatError::Corrupt)?;
    check(bytes.len() >= FRAME_BYTES).map_err(|_| FormatError::Corrupt)?;
    check(&bytes[..8] == MAGIC).map_err(|_| FormatError::Corrupt)?;
    let metadata_len =
        u32::from_le_bytes(bytes[8..12].try_into().expect("fixed frame field")) as usize;
    let raw_len = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed frame field"));
    check(metadata_len <= INDEX_METADATA_BYTES).map_err(|_| FormatError::Corrupt)?;
    check(raw_len <= MAX_RESULT_BYTES as u64).map_err(|_| FormatError::Corrupt)?;
    check(bytes.len() == FRAME_BYTES + metadata_len + raw_len as usize)
        .map_err(|_| FormatError::Corrupt)?;
    let metadata: Metadata =
        serde_json::from_slice(&bytes[FRAME_BYTES..FRAME_BYTES + metadata_len])
            .map_err(|_| FormatError::Corrupt)?;
    budget(metadata_len, metadata_limit(&metadata.payload)).map_err(|_| FormatError::Corrupt)?;
    let raw = &bytes[FRAME_BYTES + metadata_len..];
    let mut payload = metadata.payload;
    match &mut payload {
        Payload::Chunk { bytes, .. } | Payload::Result(StoredResult { bytes, .. }) => {
            check(bytes.is_empty()).map_err(|_| FormatError::Corrupt)?;
            bytes.extend_from_slice(raw);
        }
        _ => check(raw.is_empty()).map_err(|_| FormatError::Corrupt)?,
    }
    let envelope = Envelope {
        format: metadata.format,
        scope: metadata.scope,
        payload,
    };
    envelope.validate().map_err(|_| FormatError::Corrupt)?;
    check(envelope.scope == *scope).map_err(|_| FormatError::Corrupt)?;
    Ok(envelope)
}

fn metadata_limit(payload: &Payload) -> usize {
    if matches!(payload, Payload::Index(_)) {
        INDEX_METADATA_BYTES
    } else {
        SMALL_METADATA_BYTES
    }
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

fn hash_valid(hash: &str) -> bool {
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
