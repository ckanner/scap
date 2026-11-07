//! Bounded, canonical and strictly typed catalogue authority records.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::*;
use crate::format::{
    self, DatabaseQuota, NamedCreation, NamedDeletion, NamedDeletionKind, Retention, Scope,
    Transition,
};

pub(super) const MAX_RECORD_BYTES: usize = 64 * 1024;

pub(super) trait Record: Serialize + DeserializeOwned {
    fn validate(&self) -> Result<(), CatalogueError>;
}

pub(super) fn valid(condition: bool) -> Result<(), CatalogueError> {
    if condition {
        Ok(())
    } else {
        Err(CatalogueError::Invalid)
    }
}

pub(super) fn name_valid(name: &str) -> Result<(), CatalogueError> {
    if name.len() > 128 {
        return Err(CatalogueError::Limit);
    }
    valid(!name.is_empty() && !name.chars().any(char::is_control))
}

pub(super) fn scope_from_hash(
    deployment: u64,
    tenant: u64,
    hash: &[u8; 32],
) -> Result<Scope, CatalogueError> {
    let mut database = [0; 8];
    database.copy_from_slice(&hash[..8]);
    let mut incarnation = [0; 8];
    incarnation.copy_from_slice(&hash[8..16]);
    let scope = Scope {
        deployment,
        tenant,
        database: u64::from_be_bytes(database),
        incarnation: u64::from_be_bytes(incarnation),
        generation: 1,
    };
    scope.validate().map_err(|_| CatalogueError::Invalid)?;
    Ok(scope)
}

pub(super) fn derive_scope(
    deployment: u64,
    tenant: u64,
    creator: u64,
    operation: u64,
) -> Result<Scope, CatalogueError> {
    valid(creator != 0 && operation != 0)?;
    let mut hash = Sha256::new();
    hash.update(b"SCAP-NAMED-ID-v1\0");
    for value in [deployment, tenant, creator, operation] {
        hash.update(value.to_be_bytes());
    }
    scope_from_hash(deployment, tenant, &hash.finalize().into())
}

pub(super) fn creation_valid(creation: &Creation) -> Result<(), CatalogueError> {
    name_valid(&creation.name)?;
    valid(creation.expected_name_revision != Some(0))?;
    creation
        .expected_name_revision
        .unwrap_or(0)
        .checked_add(3)
        .ok_or(CatalogueError::Limit)?;
    let scope = derive_scope(
        creation.scope.deployment,
        creation.scope.tenant,
        creation.creator,
        creation.operation,
    )?;
    valid(scope == creation.scope)
}

pub(super) fn encode<R: Record>(record: &R) -> Result<Vec<u8>, CatalogueError> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(|_| CatalogueError::Invalid)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CatalogueError::Limit);
    }
    Ok(bytes)
}

pub(super) fn decode<R: Record>(bytes: &[u8]) -> Result<R, CatalogueError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CatalogueError::Corrupt);
    }
    let record: R = serde_json::from_slice(bytes).map_err(|_| CatalogueError::Corrupt)?;
    let canonical = encode(&record).map_err(|_| CatalogueError::Corrupt)?;
    if canonical != bytes {
        return Err(CatalogueError::Corrupt);
    }
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    pub format: u32,
    pub creation: Creation,
    pub options: CreateOptions,
    pub initial_quota: DatabaseQuota,
    pub retention: Retention,
}

impl Record for Descriptor {
    fn validate(&self) -> Result<(), CatalogueError> {
        valid(self.format == 1)?;
        creation_valid(&self.creation)?;
        self.initial_quota
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        self.retention
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        match self.options.quota {
            QuotaChoice::Default => Ok(()),
            QuotaChoice::Unlimited => valid(self.initial_quota.max_bytes.is_none()),
            QuotaChoice::Limited { max_bytes } => {
                valid(self.initial_quota.max_bytes == Some(max_bytes))
            }
        }
    }
}

impl Descriptor {
    pub fn origin(&self) -> Result<NamedCreation, CatalogueError> {
        Ok(NamedCreation {
            creator: self.creation.creator,
            operation: self.creation.operation,
            name_hash: format::digest(self.creation.name.as_bytes()),
            descriptor_hash: format::digest(&encode(self)?),
        })
    }

    pub fn prepared(&self) -> PreparedCreate {
        PreparedCreate {
            creation: self.creation.clone(),
            initial_quota: self.initial_quota.clone(),
            retention: self.retention.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Control {
    pub format: u32,
    pub creation: Creation,
    pub origin: NamedCreation,
    pub kind: NamedDeletionKind,
    pub principal: u64,
    pub operation: u64,
    pub expected_name_revision: u64,
    pub expected_head_revision: Option<u64>,
    pub nonce: u64,
}

pub(super) fn origin_valid(
    creation: &Creation,
    origin: &NamedCreation,
) -> Result<(), CatalogueError> {
    creation_valid(creation)?;
    origin.validate().map_err(|_| CatalogueError::Invalid)?;
    valid(
        origin.creator == creation.creator
            && origin.operation == creation.operation
            && origin.name_hash == format::digest(creation.name.as_bytes()),
    )
}

impl Record for Control {
    fn validate(&self) -> Result<(), CatalogueError> {
        valid(self.format == 1)?;
        origin_valid(&self.creation, &self.origin)?;
        valid(
            self.principal != 0
                && self.operation != 0
                && self.expected_name_revision != 0
                && self.nonce != 0,
        )?;
        match self.kind {
            NamedDeletionKind::Abort => valid(
                self.principal == self.creation.creator && self.expected_head_revision.is_none(),
            ),
            NamedDeletionKind::Delete => valid(self.expected_head_revision.is_some_and(|r| r != 0)),
        }
    }
}

impl Control {
    pub fn mark(&self) -> Result<NamedDeletion, CatalogueError> {
        Ok(NamedDeletion {
            kind: self.kind.clone(),
            principal: self.principal,
            operation: self.operation,
            expected_name_revision: self.expected_name_revision,
            expected_head_revision: self.expected_head_revision,
            nonce: self.nonce,
            descriptor_hash: format::digest(&encode(self)?),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BindingState {
    Reserved,
    Bound,
    Aborting,
    Tombstone,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub format: u32,
    pub creation: Creation,
    pub origin: NamedCreation,
    pub revision: u64,
    pub state: BindingState,
    pub control: Option<Control>,
    pub proof: Option<String>,
}

impl Record for Binding {
    fn validate(&self) -> Result<(), CatalogueError> {
        valid(self.format == 1)?;
        origin_valid(&self.creation, &self.origin)?;
        let reserved = self.creation.expected_name_revision.unwrap_or(0) + 1;
        let expected = match self.state {
            BindingState::Reserved => reserved,
            BindingState::Bound | BindingState::Aborting => reserved + 1,
            BindingState::Tombstone => reserved + 2,
        };
        valid(self.revision == expected)?;
        match self.state {
            BindingState::Reserved | BindingState::Bound => {
                valid(self.control.is_none() && self.proof.is_none())
            }
            BindingState::Aborting | BindingState::Tombstone => {
                let control = self.control.as_ref().ok_or(CatalogueError::Invalid)?;
                control.validate()?;
                valid(control.creation == self.creation && control.origin == self.origin)?;
                match control.kind {
                    NamedDeletionKind::Abort => {
                        valid(control.expected_name_revision == reserved)?;
                        if self.state == BindingState::Aborting {
                            valid(self.proof.is_none())
                        } else {
                            valid(self.proof.as_ref().is_some_and(|p| {
                                p.len() == 64
                                    && p.bytes()
                                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                            }))
                        }
                    }
                    NamedDeletionKind::Delete => valid(
                        self.state == BindingState::Tombstone
                            && control.expected_name_revision == reserved + 1
                            && self.proof.is_none(),
                    ),
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Barrier {
    OwnDeleted {
        transition: Transition,
    },
    ForeignOccupied {
        scope: Scope,
        creation: Option<NamedCreation>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AbortProof {
    pub format: u32,
    pub control: Control,
    pub barrier: Barrier,
}

impl Record for AbortProof {
    fn validate(&self) -> Result<(), CatalogueError> {
        valid(self.format == 1 && self.control.kind == NamedDeletionKind::Abort)?;
        self.control.validate()?;
        match &self.barrier {
            Barrier::OwnDeleted { transition } => valid(
                (1..=2).contains(&transition.revision) && transition.nonce == self.control.nonce,
            ),
            Barrier::ForeignOccupied { scope, creation } => {
                scope.validate().map_err(|_| CatalogueError::Invalid)?;
                let original = &self.control.creation.scope;
                valid(
                    scope.deployment == original.deployment
                        && scope.tenant == original.tenant
                        && scope.database == original.database,
                )?;
                if let Some(origin) = creation {
                    origin.validate().map_err(|_| CatalogueError::Invalid)?;
                }
                valid(scope != original || creation.as_ref() != Some(&self.control.origin))
            }
        }
    }
}
