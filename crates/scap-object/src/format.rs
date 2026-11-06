//! Versioned, bounded object-authority wire values.
//!
//! Object names address the exact encoded bytes. ETags are deliberately absent:
//! they are opaque transport values obtained with the corresponding HEAD GET.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PAGE_SIZE: usize = 4096;
pub const MAX_PAGES: usize = 64;
pub const MAX_REQUESTS: usize = 128;
pub const MAX_RESULT_BYTES: usize = 65_536;
pub const MAX_HEAD_BYTES: usize = 16_384;
/// JSON represents byte vectors as numbers. The 64 KiB result limit therefore
/// needs more than 256 KiB of wire space in the worst case, including metadata.
pub const MAX_OBJECT_BYTES: usize = 524_288;
pub const MAX_PRINCIPALS: usize = 16;

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
    pub request_epoch: u64,
    pub windows: Vec<Window>,
}

impl Head {
    fn validate(&self) -> Result<(), FormatError> {
        check(self.format == 1)?;
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
            // The exact window-count check above proves this subtraction safe.
            check(window.epoch == self.request_epoch - offset as u64)?;
            check(hash_valid(&window.root))?;
            budget(window.count as usize, MAX_REQUESTS)?;
            if offset != 0 {
                check(window.count as usize == MAX_REQUESTS)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// One content-addressed Page envelope per logical SQLite page, in order.
    pub pages: Vec<String>,
    pub image_hash: String,
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
    Page(Vec<u8>),
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
        check(self.format == 1)?;
        self.scope.validate()?;
        match &self.payload {
            Payload::Page(bytes) => check(bytes.len() == PAGE_SIZE)?,
            Payload::Manifest(manifest) => {
                budget(manifest.pages.len(), MAX_PAGES)?;
                check(hash_valid(&manifest.image_hash))?;
                for page in &manifest.pages {
                    check(hash_valid(page))?;
                }
            }
            Payload::Result(result) => {
                result.request.validate()?;
                nonzero(&[result.sequence])?;
                result.transition.validate()?;
                check(hash_valid(&result.data_root))?;
                budget(result.bytes.len(), MAX_RESULT_BYTES)?;
            }
            Payload::Index(entries) => {
                budget(entries.len(), MAX_REQUESTS)?;
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

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Incarnation and generation stay in the body: recreation must never evade an
/// existing HEAD or its tombstone by selecting another key.
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
    encode(envelope, MAX_OBJECT_BYTES)
}

pub fn decode_object(
    bytes: &[u8],
    scope: &Scope,
    expected_hash: &str,
) -> Result<Envelope, FormatError> {
    budget(bytes.len(), MAX_OBJECT_BYTES)?;
    check(digest(bytes) == expected_hash).map_err(|_| FormatError::Corrupt)?;
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| FormatError::Corrupt)?;
    envelope.validate().map_err(|_| FormatError::Corrupt)?;
    check(envelope.scope == *scope).map_err(|_| FormatError::Corrupt)?;
    Ok(envelope)
}

fn encode(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, FormatError> {
    // The validated DTOs contain only JSON-supported integers, booleans,
    // strings, vectors and structs. No custom serializer or float can fail.
    let bytes = serde_json::to_vec(value).expect("wire DTO serialization is infallible");
    budget(bytes.len(), maximum)?;
    Ok(bytes)
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
