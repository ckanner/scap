//! HEAD6 physical namespaces. Only the current active/copy namespaces are live.
//! Explicit retained roots are not admitted by this format.

use super::{
    budget, check, hash_valid, object_key, DatabaseQuota, FormatError, Head, Lifecycle, Retention,
    Window,
};
use serde::{Deserialize, Serialize};

pub const MAX_SWEEP_ENTRIES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub active_generation: u64,
    pub allocated_through: u64,
    #[serde(deserialize_with = "super::required_option")]
    pub plan: Option<CopyPlan>,
    #[serde(deserialize_with = "super::required_option")]
    pub sweep: Option<SweepCheckpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyPhase {
    Copying,
    Sealed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyBasis {
    pub data_root: String,
    pub windows: Vec<Window>,
    pub sequence: u64,
    pub revision: u64,
    pub quota: DatabaseQuota,
    pub retention: Retention,
    pub request_epoch: u64,
}

impl CopyBasis {
    pub(crate) fn capture(head: &Head) -> Self {
        Self {
            data_root: head.data_root.clone(),
            windows: head.windows.clone(),
            sequence: head.sequence,
            revision: head.revision,
            quota: head.quota.clone(),
            retention: head.retention.clone(),
            request_epoch: head.request_epoch,
        }
    }

    pub(crate) fn matches(&self, head: &Head) -> bool {
        self.data_root == head.data_root
            && self.windows == head.windows
            && self.sequence == head.sequence
            && self.revision <= head.revision
            && self.quota == head.quota
            && self.retention == head.retention
            && self.request_epoch == head.request_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyPlan {
    pub serial: u64,
    pub source: u64,
    pub target: u64,
    pub phase: CopyPhase,
    pub basis: CopyBasis,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepDisposition {
    Pending,
    Applied,
    ObservedAbsent,
    ConditionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SweepEntry {
    pub key: String,
    pub hash: String,
    pub etag: String,
    pub disposition: SweepDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SweepCheckpoint {
    pub serial: u64,
    pub generation: u64,
    #[serde(deserialize_with = "super::required_option")]
    pub next_after: Option<String>,
    pub exhausted: bool,
    pub entries: Vec<SweepEntry>,
}

impl Storage {
    /// Retirement does not depend on LIST, clocks, process death or g < A.
    /// Deleted's final active generation deliberately remains protected.
    pub fn retired(&self, generation: u64) -> bool {
        generation != 0
            && generation <= self.allocated_through
            && generation != self.active_generation
            && self
                .plan
                .as_ref()
                .is_none_or(|plan| generation != plan.target)
    }

    pub(crate) fn validate(&self, head: &Head) -> Result<(), FormatError> {
        check(
            self.active_generation != 0
                && self.active_generation <= self.allocated_through
                && self.allocated_through <= head.head_serial,
        )?;
        check(self.plan.is_none() || self.sweep.is_none())?;
        if let Some(plan) = &self.plan {
            check(head.lifecycle == Lifecycle::Ready && !head.active)?;
            check(plan.serial != 0 && plan.serial <= head.head_serial)?;
            check(
                plan.source == self.active_generation
                    && plan.target == self.allocated_through
                    && plan.target > plan.source,
            )?;
            check(
                plan.basis.revision != 0
                    && plan.basis.revision <= plan.serial
                    && plan.basis.matches(head),
            )?;
        }
        if let Some(sweep) = &self.sweep {
            check(head.lifecycle == Lifecycle::Ready && self.retired(sweep.generation))?;
            check(sweep.serial != 0 && sweep.serial <= head.head_serial)?;
            check(sweep.exhausted == sweep.next_after.is_none())?;
            check(!sweep.entries.is_empty())?;
            budget(sweep.entries.len(), MAX_SWEEP_ENTRIES)?;
            if let Some(after) = &sweep.next_after {
                check(hash_valid(after))?;
            }
            let mut previous = None;
            for entry in &sweep.entries {
                check(hash_valid(&entry.hash))?;
                check(entry.key == object_key(&head.scope, sweep.generation, &entry.hash))?;
                check(valid_etag(&entry.etag))?;
                check(previous.is_none_or(|old: &str| old < entry.hash.as_str()))?;
                previous = Some(entry.hash.as_str());
            }
        }
        Ok(())
    }
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
