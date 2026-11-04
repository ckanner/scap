//! A deliberately bounded three-voter replacement protocol. Transport trust is
//! checked by the runtime; only committed Raft entries change these voters.

use raft::eraftpb::{
    ConfChangeSingle, ConfChangeTransition, ConfChangeType, ConfChangeV2, ConfState,
};

use crate::Error;
use protobuf::Message as ProtobufMessage;

pub const MAX_MEMBERS: usize = 16;
/// Conservative retained-result and mailbox reservation for a bounded view.
pub const MEMBERSHIP_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipChange {
    AddLearner { node_id: u64 },
    ReplaceVoter { remove_id: u64, learner_id: u64 },
    LeaveJoint,
}

impl MembershipChange {
    /// Encode the only supported management actions. This does not authorize
    /// admission: the driver checks the current configuration and progress.
    pub fn to_conf_change(self) -> ConfChangeV2 {
        let mut change = ConfChangeV2::default();
        match self {
            Self::AddLearner { node_id } => {
                change
                    .changes
                    .push(single(node_id, ConfChangeType::AddLearnerNode));
            }
            Self::ReplaceVoter {
                remove_id,
                learner_id,
            } => {
                change.set_transition(ConfChangeTransition::Explicit);
                change
                    .changes
                    .push(single(learner_id, ConfChangeType::AddNode));
                change
                    .changes
                    .push(single(remove_id, ConfChangeType::RemoveNode));
            }
            Self::LeaveJoint => {}
        }
        change
    }
}

fn single(node_id: u64, kind: ConfChangeType) -> ConfChangeSingle {
    let mut change = ConfChangeSingle {
        node_id,
        ..Default::default()
    };
    change.set_change_type(kind);
    change
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipTicket {
    pub boot_id: u128,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MembershipResult {
    pub ticket: MembershipTicket,
    pub index: u64,
    pub term: u64,
    /// The exact configuration produced by this entry, published only after
    /// application, ConfState and applied position have persisted together.
    pub conf_state: ConfState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberProgress {
    pub node_id: u64,
    pub matched: u64,
    pub is_learner: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MembershipStatus {
    pub conf_state: ConfState,
    pub term: u64,
    pub applied: u64,
    pub commit: u64,
    pub snapshot_index: u64,
    pub leader_id: u64,
    pub pending_conf_index: u64,
    /// Leader observations of durable log replication, not remote application
    /// acknowledgements. A fresh runtime read establishes the view's barrier.
    pub progress: Vec<MemberProgress>,
}

/// Ordering is not configuration identity. Bound and reject ambiguous input
/// before cloning; comparison against the validated durable ConfState rejects
/// any inconsistent cross-set shape without inventing a second Raft changer.
pub(crate) fn canonical(conf: &ConfState) -> Result<ConfState, Error> {
    if conf.get_unknown_fields().iter().next().is_some() {
        return Err(Error::MembershipInvalid("unknown membership fields"));
    }
    let mut result = ConfState::default();
    for (source, destination) in [
        (&conf.voters, &mut result.voters),
        (&conf.learners, &mut result.learners),
        (&conf.voters_outgoing, &mut result.voters_outgoing),
        (&conf.learners_next, &mut result.learners_next),
    ] {
        if source.len() > MAX_MEMBERS {
            return Err(Error::InputLimit);
        }
        destination.extend_from_slice(source);
        destination.sort_unstable();
        if destination.contains(&0) || destination.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::MembershipInvalid(
                "duplicate or zero membership identity",
            ));
        }
    }
    result.auto_leave = conf.auto_leave;
    Ok(result)
}

pub(crate) fn target(
    current: &ConfState,
    expected: &ConfState,
    change: MembershipChange,
    leader_id: u64,
) -> Result<ConfState, Error> {
    let current = canonical(current)?;
    if current != canonical(expected)? {
        return Err(Error::MembershipConflict);
    }
    if current.voters.len() != 3
        || current.learners.len() > 1
        || !current.learners_next.is_empty()
        || current.auto_leave
    {
        return Err(Error::MembershipInvalid(
            "membership requires the three-voter replacement profile",
        ));
    }
    let mut next = current.clone();
    match change {
        MembershipChange::AddLearner { node_id } => {
            stable(&current)?;
            // Every replacement retains a newly larger maximum, so retired IDs
            // cannot be reused after restart, snapshots or an ABA cycle; no
            // separate tombstone log is required. Comparison also handles
            // u64::MAX without overflow.
            if !current.learners.is_empty() || node_id <= current.voters[2] {
                return Err(Error::MembershipInvalid(
                    "learner must have a fresh increasing identity",
                ));
            }
            next.learners.push(node_id);
        }
        MembershipChange::ReplaceVoter {
            remove_id,
            learner_id,
        } => {
            stable(&current)?;
            if current.learners.as_slice() != [learner_id]
                || learner_id <= current.voters[2]
                || !current.voters.contains(&remove_id)
                || remove_id == leader_id
            {
                return Err(Error::MembershipInvalid(
                    "replacement requires the sole learner and another voter",
                ));
            }
            next.voters_outgoing = current.voters.clone();
            next.voters.retain(|id| *id != remove_id);
            next.voters.push(learner_id);
            next.voters.sort_unstable();
            next.learners.clear();
        }
        MembershipChange::LeaveJoint => {
            if current.voters_outgoing.len() != 3
                || !current.learners.is_empty()
                || current
                    .voters
                    .iter()
                    .filter(|id| current.voters_outgoing.contains(id))
                    .count()
                    != 2
                || current.voters[2] <= current.voters_outgoing[2]
            {
                return Err(Error::MembershipInvalid(
                    "leave requires an explicit replacement joint configuration",
                ));
            }
            next.voters_outgoing.clear();
        }
    }
    Ok(next)
}

fn stable(conf: &ConfState) -> Result<(), Error> {
    if !conf.voters_outgoing.is_empty() {
        return Err(Error::MembershipPending);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
