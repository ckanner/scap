//! Strict, bounded owner control records. Payload objects remain SCAPOBJ2.

use crate::format::{digest, encode_head, hash_valid, FormatError, Head, Lifecycle, Scope};
use crate::Snapshot;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

pub(crate) const MAX_DESCRIPTOR: usize = 16 * 1024;
pub(crate) const MAX_PROOF: usize = 8 * 1024;
const MAX_MARKER: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerMode {
    Takeover,
    Activate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerNonces {
    pub claim: u64,
    pub cancel: u64,
    pub activate: u64,
    pub abort: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareOwnerInput {
    pub creator: u64,
    pub operation: u64,
    pub expected_revision: u64,
    pub expected_head_serial: u64,
    pub mode: OwnerMode,
    pub target_worker: u64,
    pub nonces: OwnerNonces,
}

impl PrepareOwnerInput {
    pub fn validate(&self) -> Result<(), FormatError> {
        valid(
            self.creator != 0
                && self.operation != 0
                && self.expected_revision != 0
                && self.expected_revision <= self.expected_head_serial
                && self.target_worker != 0,
        )?;
        let nonces = [
            self.nonces.claim,
            self.nonces.cancel,
            self.nonces.activate,
            self.nonces.abort,
        ];
        valid(!nonces.contains(&0) && nonces.into_iter().collect::<BTreeSet<_>>().len() == 4)
    }

    pub(crate) fn identity(&self) -> OwnerIdentity {
        OwnerIdentity {
            creator: self.creator,
            operation: self.operation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    pub creator: u64,
    pub operation: u64,
}

impl OwnerIdentity {
    pub fn validate(&self) -> Result<(), FormatError> {
        valid(self.creator != 0 && self.operation != 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPlanRef {
    pub creator: u64,
    pub operation: u64,
    pub descriptor_hash: String,
}

impl OwnerPlanRef {
    pub(crate) fn identity(&self) -> OwnerIdentity {
        OwnerIdentity {
            creator: self.creator,
            operation: self.operation,
        }
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        self.identity().validate()?;
        valid(hash_valid(&self.descriptor_hash))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerAdmissionKind {
    Claim,
    Cancel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAdmission {
    pub kind: OwnerAdmissionKind,
    pub revision: u64,
    pub head_serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerPhaseKind {
    Claimed,
    Cancelling,
    Active,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPhase {
    pub kind: OwnerPhaseKind,
    pub revision: u64,
    pub head_serial: u64,
    pub nonce: u64,
    pub owner_epoch: u64,
    pub owner_instance: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPlan {
    pub reference: OwnerPlanRef,
    pub admission: OwnerAdmission,
    pub phase: OwnerPhase,
}

impl OwnerPlan {
    pub fn pending(&self) -> bool {
        matches!(
            self.phase.kind,
            OwnerPhaseKind::Claimed | OwnerPhaseKind::Cancelling
        )
    }

    pub(crate) fn validate(&self) -> Result<(), FormatError> {
        self.reference.validate()?;
        valid(
            self.admission.revision >= 2
                && self.admission.revision <= self.admission.head_serial
                && self.phase.revision <= self.phase.head_serial
                && self.phase.nonce != 0
                && self.phase.owner_epoch != 0
                && self.phase.owner_instance != 0,
        )?;
        let expected = match self.phase.kind {
            OwnerPhaseKind::Claimed => OwnerAdmissionKind::Claim,
            OwnerPhaseKind::Cancelling => OwnerAdmissionKind::Cancel,
            OwnerPhaseKind::Active => OwnerAdmissionKind::Claim,
            OwnerPhaseKind::Aborted => self.admission.kind,
        };
        valid(self.admission.kind == expected)?;
        if self.pending() {
            valid(
                self.phase.revision == self.admission.revision
                    && self.phase.head_serial == self.admission.head_serial,
            )?;
        } else {
            valid(
                self.phase.revision > self.admission.revision
                    && self.phase.head_serial > self.admission.head_serial,
            )?;
        }
        // Between admission and terminal only business metadata may advance.
        valid(
            self.phase.revision - self.admission.revision
                == self.phase.head_serial - self.admission.head_serial,
        )?;
        bounded(self, MAX_MARKER).map(|_| ())
    }

    pub(crate) fn validate_head(&self, head: &Head) -> Result<(), FormatError> {
        self.validate()?;
        valid(
            self.phase.revision <= head.revision
                && self.phase.head_serial <= head.head_serial
                && head.lifecycle != Lifecycle::Provisioning,
        )?;
        // Technical serial changes preserve the last business transition.
        // A later business revision may legitimately carry a different nonce.
        valid(self.phase.revision != head.revision || self.phase.nonce == head.transition.nonce)?;
        if self.phase.kind != OwnerPhaseKind::Active {
            valid(!head.active)?;
        }
        if self.pending() {
            valid(
                head.lifecycle == Lifecycle::Ready
                    && head.storage.plan.is_none()
                    && head.storage.sweep.is_none()
                    && head.storage.terminal.is_none()
                    && head.owner_epoch == self.phase.owner_epoch
                    && head.owner_instance == self.phase.owner_instance,
            )?;
            valid(head.revision < u64::MAX && head.head_serial < u64::MAX)?;
            valid(
                head.revision - self.phase.revision == head.head_serial - self.phase.head_serial,
            )?;
        }
        // Named deletion may increase today's epoch. Terminal tuples remain
        // historical; do not rebuild their proof from today's owner fields.
        Ok(())
    }
}

pub(crate) fn present_owner<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<OwnerPlan>, D::Error> {
    OwnerPlan::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerBase {
    pub head_hash: String,
    pub etag: String,
    pub revision: u64,
    pub head_serial: u64,
    pub owner_epoch: u64,
    pub owner_instance: u64,
    pub active: bool,
    #[serde(deserialize_with = "required_option")]
    pub previous_marker: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerDescriptor {
    pub version: u32,
    pub scope: Scope,
    pub input: PrepareOwnerInput,
    pub base: OwnerBase,
    pub input_digest: String,
}

impl OwnerDescriptor {
    pub(crate) fn new(base: &Snapshot, input: &PrepareOwnerInput) -> Result<Self, FormatError> {
        let head = &base.head;
        let mut descriptor = Self {
            version: 1,
            scope: head.scope.clone(),
            input: input.clone(),
            base: OwnerBase {
                head_hash: digest(&encode_head(head)?),
                etag: base.etag.clone(),
                revision: head.revision,
                head_serial: head.head_serial,
                owner_epoch: head.owner_epoch,
                owner_instance: head.owner_instance,
                active: head.active,
                previous_marker: marker_hash(head.owner_plan.as_ref()),
            },
            input_digest: String::new(),
        };
        descriptor.input_digest = descriptor.digest();
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn digest(&self) -> String {
        digest(
            &serde_json::to_vec(&(self.version, &self.scope, &self.input, &self.base))
                .expect("typed owner input serializes"),
        )
    }

    fn validate(&self) -> Result<(), FormatError> {
        valid(self.version == 1)?;
        self.scope.validate()?;
        self.input.validate()?;
        valid(
            self.base.revision == self.input.expected_revision
                && self.base.head_serial == self.input.expected_head_serial
                && self.base.owner_epoch != 0
                && self.base.owner_instance != 0
                && hash_valid(&self.base.head_hash)
                && valid_etag(&self.base.etag),
        )?;
        if let Some(previous) = &self.base.previous_marker {
            valid(hash_valid(previous))?;
        }
        valid(self.base.revision <= u64::MAX - 2 && self.base.head_serial <= u64::MAX - 2)?;
        match self.input.mode {
            OwnerMode::Takeover => valid(self.base.owner_epoch != u64::MAX)?,
            OwnerMode::Activate => {
                valid(!self.base.active && self.input.target_worker == self.base.owner_instance)?
            }
        }
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

    pub(crate) fn reference(&self) -> OwnerPlanRef {
        OwnerPlanRef {
            creator: self.input.creator,
            operation: self.input.operation,
            descriptor_hash: digest(
                &serde_json::to_vec(self).expect("typed descriptor serializes"),
            ),
        }
    }

    pub(crate) fn matches(&self, snapshot: &Snapshot) -> bool {
        snapshot.head.scope == self.scope
            && snapshot.head.revision == self.base.revision
            && snapshot.head.head_serial == self.base.head_serial
            && snapshot.head.owner_epoch == self.base.owner_epoch
            && snapshot.head.owner_instance == self.base.owner_instance
            && snapshot.head.active == self.base.active
            && marker_hash(snapshot.head.owner_plan.as_ref()) == self.base.previous_marker
            && snapshot.etag == self.base.etag
            && digest(&serde_json::to_vec(&snapshot.head).expect("HEAD serializes"))
                == self.base.head_hash
    }

    pub(crate) fn marker(&self, plan: &OwnerPlan) -> Result<(), FormatError> {
        plan.validate()?;
        valid(plan.reference == self.reference())?;
        valid(
            plan.admission.revision == self.base.revision + 1
                && plan.admission.head_serial == self.base.head_serial + 1,
        )?;
        let (epoch, instance) = if plan.admission.kind == OwnerAdmissionKind::Cancel {
            (self.base.owner_epoch, self.base.owner_instance)
        } else {
            match self.input.mode {
                OwnerMode::Takeover => (self.base.owner_epoch + 1, self.input.target_worker),
                OwnerMode::Activate => (self.base.owner_epoch, self.base.owner_instance),
            }
        };
        let nonce = match plan.phase.kind {
            OwnerPhaseKind::Claimed => self.input.nonces.claim,
            OwnerPhaseKind::Cancelling => self.input.nonces.cancel,
            OwnerPhaseKind::Active => self.input.nonces.activate,
            OwnerPhaseKind::Aborted => self.input.nonces.abort,
        };
        valid(
            plan.phase.owner_epoch == epoch
                && plan.phase.owner_instance == instance
                && plan.phase.nonce == nonce,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerProof {
    pub version: u32,
    pub scope: Scope,
    pub marker: OwnerPlan,
}

impl OwnerProof {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        bounded(self, MAX_PROOF)
    }

    fn validate(&self) -> Result<(), FormatError> {
        valid(self.version == 1)?;
        self.scope.validate()?;
        self.marker.validate()?;
        valid(!self.marker.pending())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let proof: Self = parse(bytes, MAX_PROOF)?;
        proof.validate()?;
        Ok(proof)
    }
}

pub(crate) fn prefix(scope: &Scope) -> String {
    format!(
        "scap-object/v1/{}/{}/{}/inc/{}/gen/{}/owner/v1/",
        scope.deployment, scope.tenant, scope.database, scope.incarnation, scope.generation,
    )
}

pub(crate) fn key(scope: &Scope, identity: &OwnerIdentity, proof: bool) -> String {
    // Five Scope and two identity u64 decimals plus fixed separators fit <512.
    format!(
        "{}{}/{}/{}",
        prefix(scope),
        if proof { "proof" } else { "descriptor" },
        identity.creator,
        identity.operation,
    )
}

fn marker_hash(marker: Option<&OwnerPlan>) -> Option<String> {
    marker.map(|plan| digest(&serde_json::to_vec(plan).expect("typed marker serializes")))
}

fn required_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
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

fn valid(condition: bool) -> Result<(), FormatError> {
    if condition {
        Ok(())
    } else {
        Err(FormatError::Invalid)
    }
}

fn bounded(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, FormatError> {
    let bytes = serde_json::to_vec(value).expect("typed owner record serializes");
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
#[path = "owner_format_tests.rs"]
mod tests;
