//! Decimal-only owner-plan inputs and bounded, non-capability observations.

use scap_object::format::OwnerPlan;
use scap_object::owner::{
    OwnerIdentity, OwnerMode, OwnerNonces, OwnerObservation, OwnerPlanRef, OwnerPreparation,
    OwnerState, PrepareOwnerInput, PreparedOwner,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::wire::{self, Decimal};
use crate::Failure;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nonces {
    pub claim: Decimal,
    pub cancel: Decimal,
    pub activate: Decimal,
    pub abort: Decimal,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepare {
    pub creator: Decimal,
    pub operation: Decimal,
    pub expected_revision: Decimal,
    pub expected_head_serial: Decimal,
    pub mode: OwnerMode,
    pub target_worker: Decimal,
    pub nonces: Nonces,
}

impl Prepare {
    pub fn native(&self) -> Result<PrepareOwnerInput, Failure> {
        let input = PrepareOwnerInput {
            creator: self.creator.0,
            operation: self.operation.0,
            expected_revision: self.expected_revision.0,
            expected_head_serial: self.expected_head_serial.0,
            mode: self.mode,
            target_worker: self.target_worker.0,
            nonces: OwnerNonces {
                claim: self.nonces.claim.0,
                cancel: self.nonces.cancel.0,
                activate: self.nonces.activate.0,
                abort: self.nonces.abort.0,
            },
        };
        if input.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(input)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub creator: Decimal,
    pub operation: Decimal,
}

impl Identity {
    pub fn native(&self) -> Result<OwnerIdentity, Failure> {
        let identity = OwnerIdentity {
            creator: self.creator.0,
            operation: self.operation.0,
        };
        if identity.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub creator: Decimal,
    pub operation: Decimal,
    pub descriptor_hash: String,
}

impl Reference {
    pub fn native(&self) -> Result<OwnerPlanRef, Failure> {
        let reference = OwnerPlanRef {
            creator: self.creator.0,
            operation: self.operation.0,
            descriptor_hash: self.descriptor_hash.clone(),
        };
        if reference.validate().is_err() {
            return Err(Failure::new("INVALID"));
        }
        Ok(reference)
    }
}

pub fn reference(reference: &OwnerPlanRef) -> Value {
    json!({"creator": Decimal(reference.creator), "operation": Decimal(reference.operation),
        "descriptor_hash": reference.descriptor_hash})
}

pub fn input(input: &PrepareOwnerInput) -> Value {
    json!({"creator": Decimal(input.creator), "operation": Decimal(input.operation),
        "expected_revision": Decimal(input.expected_revision),
        "expected_head_serial": Decimal(input.expected_head_serial), "mode": input.mode,
        "target_worker": Decimal(input.target_worker),
        "nonces": {"claim": Decimal(input.nonces.claim), "cancel": Decimal(input.nonces.cancel),
            "activate": Decimal(input.nonces.activate), "abort": Decimal(input.nonces.abort)}})
}

pub fn plan(plan: &OwnerPlan) -> Value {
    json!({"reference": reference(&plan.reference),
        "admission": {"kind": plan.admission.kind, "revision": Decimal(plan.admission.revision),
            "head_serial": Decimal(plan.admission.head_serial)},
        "phase": {"kind": plan.phase.kind, "revision": Decimal(plan.phase.revision),
            "head_serial": Decimal(plan.phase.head_serial), "nonce": Decimal(plan.phase.nonce),
            "owner_epoch": Decimal(plan.phase.owner_epoch),
            "owner_instance": Decimal(plan.phase.owner_instance)}})
}

pub fn prepared(prepared: &PreparedOwner) -> Value {
    json!({"scope": wire::scope(&prepared.scope), "input": input(&prepared.input),
        "reference": reference(&prepared.reference)})
}

pub fn preparation(value: &OwnerPreparation) -> Value {
    match value {
        OwnerPreparation::Prepared(value) => {
            json!({"state": "prepared", "prepared": prepared(value)})
        }
        OwnerPreparation::Pending(value) => {
            json!({"state": "pending", "reference": reference(value)})
        }
    }
}

/// The accepted marker is historical. Today's status remains separate, and no
/// wire field can materialize a native Session or turn a past UNKNOWN into ACK.
pub fn observation(value: &OwnerObservation) -> Value {
    let state = if value.state == OwnerState::Prepared {
        "prepared"
    } else if value.state == OwnerState::Claimed {
        "claimed"
    } else if value.state == OwnerState::Cancelling {
        "cancelling"
    } else if value.state == OwnerState::Active {
        "active"
    } else if value.state == OwnerState::Aborted {
        "aborted"
    } else {
        "fenced"
    };
    let accepted = if let Some(accepted) = &value.accepted {
        plan(accepted)
    } else {
        Value::Null
    };
    json!({"state": state, "status": wire::status(&value.head),
        "prepared": prepared(&value.prepared), "accepted": accepted})
}

#[cfg(test)]
#[path = "owner_wire/tests.rs"]
mod tests;
