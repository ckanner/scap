//! Permanent first-winner snapshot records, separate from payload generations.

use crate::format::{
    digest, encode_head, hash_valid, FormatError, Scope, SnapshotEntry, SnapshotIdentity,
    SnapshotLimits, SnapshotPoint, SnapshotRef, PAGE_SIZE,
};
use crate::snapshot_format::{label, valid};
use crate::Snapshot;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_DESCRIPTOR: usize = 16 * 1024;
pub(crate) const MAX_PROOF: usize = 8 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareSnapshotInput {
    pub creator: u64,
    pub operation: u64,
    pub expected_revision: u64,
    pub expected_head_serial: u64,
    pub label: String,
}

impl PrepareSnapshotInput {
    pub fn validate(&self) -> Result<(), FormatError> {
        self.identity().validate()?;
        valid(self.expected_revision != 0 && self.expected_revision <= self.expected_head_serial)?;
        label(&self.label)
    }

    pub fn identity(&self) -> SnapshotIdentity {
        SnapshotIdentity {
            creator: self.creator,
            operation: self.operation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotBase {
    pub head_hash: String,
    pub etag: String,
    pub revision: u64,
    pub head_serial: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotDescriptor {
    pub version: u32,
    pub scope: Scope,
    pub input: PrepareSnapshotInput,
    pub base: SnapshotBase,
    pub point: SnapshotPoint,
    // The first winner fixes defaults during adoption; another instance's
    // later Options never rewrites the descriptor or its original candidate.
    pub limits: SnapshotLimits,
    pub input_digest: String,
}

impl SnapshotDescriptor {
    pub(crate) fn new(
        base: &Snapshot,
        input: &PrepareSnapshotInput,
        page_count: u32,
        limits: SnapshotLimits,
    ) -> Result<Self, FormatError> {
        let mut descriptor = Self {
            version: 1,
            scope: base.head.scope.clone(),
            input: input.clone(),
            base: SnapshotBase {
                head_hash: digest(&encode_head(&base.head)?),
                etag: base.etag.clone(),
                revision: base.head.revision,
                head_serial: base.head.head_serial,
            },
            point: SnapshotPoint {
                data_root: base.head.data_root.clone(),
                page_count,
                sequence: base.head.sequence,
                source_revision: base.head.revision,
            },
            limits,
            input_digest: String::new(),
        };
        descriptor.input_digest = descriptor.digest();
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn digest(&self) -> String {
        digest(
            &serde_json::to_vec(&(
                self.version,
                &self.scope,
                &self.input,
                &self.base,
                &self.point,
                &self.limits,
            ))
            .expect("typed snapshot input serializes"),
        )
    }

    fn validate(&self) -> Result<(), FormatError> {
        valid(self.version == 1)?;
        self.scope.validate()?;
        self.input.validate()?;
        self.point.validate()?;
        self.limits.validate()?;
        valid(
            self.base.revision == self.input.expected_revision
                && self.base.head_serial == self.input.expected_head_serial
                && self.base.head_serial < u64::MAX
                && self.point.source_revision == self.base.revision
                && hash_valid(&self.base.head_hash)
                && valid_etag(&self.base.etag),
        )?;
        valid(
            self.limits.max_points != 0
                && self.point.page_count as u64 * PAGE_SIZE as u64 <= self.limits.max_logical_bytes,
        )?;
        valid(self.input_digest == self.digest())
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        bounded(self, MAX_DESCRIPTOR)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let descriptor: Self = parse(bytes, MAX_DESCRIPTOR)?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(crate) fn reference(&self) -> SnapshotRef {
        SnapshotRef {
            creator: self.input.creator,
            operation: self.input.operation,
            capture_serial: self.base.head_serial + 1,
            descriptor_hash: digest(
                &serde_json::to_vec(self).expect("typed snapshot descriptor serializes"),
            ),
        }
    }

    pub(crate) fn entry(&self) -> SnapshotEntry {
        SnapshotEntry {
            reference: self.reference(),
            label: self.input.label.clone(),
            point: self.point.clone(),
        }
    }

    pub(crate) fn matches(&self, base: &Snapshot) -> bool {
        base.head.scope == self.scope
            && base.head.revision == self.base.revision
            && base.head.head_serial == self.base.head_serial
            && base.etag == self.base.etag
            && base.head.data_root == self.point.data_root
            && base.head.sequence == self.point.sequence
            && base
                .head
                .snapshot_limits
                .as_ref()
                .is_none_or(|limits| limits == &self.limits)
            && digest(&serde_json::to_vec(&base.head).expect("HEAD serializes"))
                == self.base.head_hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotProof {
    pub version: u32,
    pub scope: Scope,
    pub entry: SnapshotEntry,
}

impl SnapshotProof {
    fn validate(&self) -> Result<(), FormatError> {
        valid(self.version == 1)?;
        self.scope.validate()?;
        self.entry.validate()
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        bounded(self, MAX_PROOF)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let proof: Self = parse(bytes, MAX_PROOF)?;
        proof.validate()?;
        Ok(proof)
    }
}

pub(crate) fn prefix(scope: &Scope) -> String {
    format!(
        "scap-object/v1/{}/{}/{}/inc/{}/gen/{}/snapshot/v1/",
        scope.deployment, scope.tenant, scope.database, scope.incarnation, scope.generation
    )
}

pub(crate) fn key(scope: &Scope, identity: &SnapshotIdentity, proof: bool) -> String {
    format!(
        "{}{}/{}/{}",
        prefix(scope),
        if proof { "proof" } else { "descriptor" },
        identity.creator,
        identity.operation
    )
}

fn valid_etag(etag: &str) -> bool {
    etag.len() >= 2
        && etag.len() <= 1024
        && etag.starts_with('"')
        && etag.ends_with('"')
        && etag.as_bytes()[1..etag.len() - 1]
            .iter()
            .all(|byte| *byte != b'"' && (0x21..=0x7e).contains(byte))
}

fn bounded(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, FormatError> {
    let bytes = serde_json::to_vec(value).expect("typed snapshot record serializes");
    if bytes.len() > maximum {
        Err(FormatError::Limit)
    } else {
        Ok(bytes)
    }
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], maximum: usize) -> Result<T, FormatError> {
    if bytes.len() > maximum {
        return Err(FormatError::Limit);
    }
    serde_json::from_slice(bytes).map_err(|_| FormatError::Invalid)
}

#[cfg(test)]
#[path = "snapshot_records_tests.rs"]
mod tests;
