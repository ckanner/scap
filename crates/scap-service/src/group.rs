//! Explicit, opportunistic grouping of independent queued write requests.

use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::{
    auth::Principal,
    output::OutputContext,
    scheduler::Limits,
    wire::{Call, Identity, Parameter, WireStatement},
    Failure,
};

/// Absence preserves single-request execution. Collection never waits for a
/// future arrival. Core additionally intersects these aggregate budgets with
/// the current Options; enabling a group cannot widen execution limits.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub max_members: usize,
    pub max_input_bytes: usize,
    pub max_changed_pages: u32,
    pub max_result_bytes: u64,
}

impl Profile {
    pub fn limits(self) -> scap_object::GroupLimits {
        scap_object::GroupLimits {
            max_members: self.max_members,
            max_input_bytes: self.max_input_bytes,
            max_changed_pages: self.max_changed_pages,
            max_result_bytes: self.max_result_bytes,
        }
    }

    pub fn validate(self, queues: Limits) -> Result<(), Failure> {
        queues.validate()?;
        self.limits()
            .validate()
            .map_err(|_| Failure::new("CONFIG"))?;
        if self.version != 1
            || self.max_members > queues.queued_per_database - queues.reserved_controls
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }
}

/// Conservative encoded/native input extent, computed without decoding or
/// cloning payloads. Both the queue collector and direct Engine group calls
/// must bound the complete input before allocating native parameters. This is
/// not a process RSS claim; core checks canonical SQL input again.
pub(crate) fn input_remaining(
    request: &Identity,
    statements: &[WireStatement],
    maximum: usize,
) -> Option<usize> {
    let mut remaining = maximum
        .checked_sub(128)?
        .checked_sub(request.fingerprint.len())?;
    for statement in statements {
        remaining = remaining.checked_sub(8)?.checked_sub(statement.sql.len())?;
        for parameter in &statement.params {
            let bytes = match parameter {
                Parameter::Null {} => 1,
                Parameter::Integer { value } => value.len().max(9),
                Parameter::Real { bits } => bits.len().max(9),
                Parameter::Text { value } => 5 + value.len(),
                Parameter::Blob { base64 } => 5 + base64.len(),
            };
            remaining = remaining.checked_sub(bytes)?;
        }
    }
    Some(remaining)
}

/// Every member retains its original identity, deadline and output lease.
/// The call is borrowed so a declined or unstarted member remains unchanged.
pub struct Member<'a> {
    pub principal: &'a Principal,
    pub call: &'a Call,
    pub deadline: Instant,
    pub output: Option<&'a mut OutputContext>,
}

pub enum Outcome {
    /// No member SQL has started. Only the first original job may fall back
    /// to the single-request path; every other member returns to its queue.
    Declined,
    /// One outcome per consumed member, including any failed execution.
    /// The nonempty prefix may be shorter than the supplied slice. Its suffix
    /// has never started SQL and is the only work eligible to return to queue.
    Completed(Vec<Result<Value, Failure>>),
}
