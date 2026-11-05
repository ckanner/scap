//! Versioned peer routing, certificate authorization and bounded Raft decoding.
//!
//! Certificate signatures and chain trust must already have been verified by
//! the mTLS adapter. This policy binds that verified leaf to one configured
//! node and rechecks validity and revocation for every message. An authorized
//! message is only transport input, never a durable or business acknowledgement.

mod certificate;
mod codec;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display};

use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{
    ConfChangeTransition, ConfChangeV2, ConfState, EntryType, Message, MessageType,
};
use sha2::{Digest, Sha256};

pub use certificate::{certificate_identity, CertificateIdentity};
pub use codec::{decode_envelope, encode_envelope, HEADER_BYTES};

/// Generation 3 requires acknowledged request retirement on every participant.
/// Earlier generations cannot preserve its permanent request-epoch fences and
/// can make different capacity decisions, so mixed peers fail before decoding
/// any inner Raft message, including votes and snapshots.
pub const VERSION: u32 = 3;
/// Fixed raft-rs ad13f3d9 / rust-protobuf 2.28 opaque bytes, without compression.
pub const CODEC: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub version: u32,
    pub codec: u32,
    pub cluster_id: u128,
    pub cell_id: u128,
    pub cell_incarnation: u64,
    pub from_node: u64,
    pub to_node: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub cluster_id: u128,
    pub cell_id: u128,
    pub cell_incarnation: u64,
    pub node_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub node_id: u64,
    pub fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_payload_bytes: usize,
    pub max_entries: usize,
    /// Counts tags in known nested messages and packed configuration members.
    pub max_fields: usize,
    pub max_certificate_bytes: usize,
    /// Bounds the immutable trusted peer set and active certificate pins.
    pub max_bindings: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Limit(&'static str),
    Malformed(&'static str),
    Unsupported(&'static str),
    Unauthorized,
    CertificateTime,
    PolicyChanged,
    RevisionExhausted,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// An immutable trusted peer directory with replaceable certificate pins.
///
/// `new` retains the fixed bootstrap membership contract. The explicit
/// `with_trusted_peers` mode admits bounded membership changes within that
/// directory, without granting voting rights. A stale local Raft ConfState is
/// never used as the trust directory: it can omit a newly elected member before
/// a lagging replica receives the intervening log.
/// A containing lock must cover both policy admission and queue reservation;
/// consumers revalidate under the same lock before handing input to RawNode.
pub struct Policy {
    scope: Scope,
    members: BTreeSet<u64>,
    membership: [u8; 32],
    allow_changes: bool,
    bindings: BTreeMap<[u8; 32], u64>,
    limits: Limits,
    revision: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedMessage {
    revision: u64,
    limits: Limits,
    membership: [u8; 32],
    certificate: CertificateIdentity,
    envelope: Envelope,
    message: Message,
}

impl AuthorizedMessage {
    pub fn peer_node(&self) -> u64 {
        self.envelope.from_node
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn certificate(&self) -> CertificateIdentity {
        self.certificate
    }

    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn into_message(self) -> Message {
        self.message
    }
}

impl Policy {
    pub fn new(
        scope: Scope,
        member_ids: Vec<u64>,
        bindings: Vec<Binding>,
        limits: Limits,
    ) -> Result<Self, Error> {
        validate_limits(limits)?;
        if scope.cluster_id == 0
            || scope.cell_id == 0
            || scope.cell_incarnation == 0
            || scope.node_id == 0
        {
            return Err(Error::Invalid("zero scope identity"));
        }
        if member_ids.is_empty() || member_ids.len() > limits.max_bindings {
            return Err(Error::Limit("bootstrap members"));
        }
        let mut members = BTreeSet::new();
        for id in member_ids {
            if id == 0 || !members.insert(id) {
                return Err(Error::Invalid("bootstrap member identity"));
            }
        }
        if !members.contains(&scope.node_id) {
            return Err(Error::Invalid("local node is not a bootstrap member"));
        }
        let bindings = validate_bindings(bindings, &members, limits.max_bindings)?;
        let membership = membership_fingerprint(&members, false);
        Ok(Self {
            scope,
            members,
            membership,
            allow_changes: false,
            bindings,
            limits,
            revision: 1,
        })
    }

    /// Admit Raft membership changes only among these pre-registered peers.
    /// This does not initialize, replace or enlarge the actual Raft ConfState.
    /// The local node must be registered even before it joins as a learner.
    pub fn with_trusted_peers(
        scope: Scope,
        trusted_peer_ids: Vec<u64>,
        bindings: Vec<Binding>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut policy = Self::new(scope, trusted_peer_ids, bindings, limits)?;
        policy.allow_changes = true;
        policy.membership = membership_fingerprint(&policy.members, true);
        Ok(policy)
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The immutable communication allowlist, not the currently applied voters.
    pub fn members(&self) -> &BTreeSet<u64> {
        &self.members
    }

    pub fn allows_membership_changes(&self) -> bool {
        self.allow_changes
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Check a cryptographically verified peer against the current pins and
    /// certificate time. Outgoing connection reuse must call this for every
    /// request; a prior handshake or a saved policy revision grants no lease.
    /// The caller binds its endpoint to this policy's cluster before calling.
    pub fn authorize_peer(
        &self,
        certificate: CertificateIdentity,
        peer_node: u64,
        now: i64,
    ) -> Result<(), Error> {
        if now < certificate.not_before || now > certificate.not_after {
            return Err(Error::CertificateTime);
        }
        if peer_node == self.scope.node_id
            || self.bindings.get(&certificate.fingerprint) != Some(&peer_node)
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Atomically replace certificate pins after validating the whole candidate.
    /// Multiple pins can overlap during rotation. Empty pins revoke all peers.
    /// Any successful replacement invalidates messages already waiting in queues.
    pub fn replace_bindings(&mut self, bindings: Vec<Binding>) -> Result<u64, Error> {
        let replacement = validate_bindings(bindings, &self.members, self.limits.max_bindings)?;
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        self.bindings = replacement;
        self.revision = revision;
        Ok(revision)
    }

    pub fn authorize(
        &self,
        certificate: CertificateIdentity,
        now_unix_seconds: i64,
        envelope: Envelope,
    ) -> Result<AuthorizedMessage, Error> {
        self.check_peer(certificate, now_unix_seconds, &envelope)?;
        if envelope.payload.len() > self.limits.max_payload_bytes {
            return Err(Error::Limit("Raft payload"));
        }
        codec::preflight_raft(&envelope.payload, self.limits)?;
        let message = Message::parse_from_bytes(&envelope.payload)
            .map_err(|_| Error::Malformed("Raft protobuf"))?;
        if message.from != envelope.from_node || message.to != envelope.to_node {
            return Err(Error::Malformed("Raft endpoint mismatch"));
        }
        if !network_message(message.get_msg_type()) {
            return Err(Error::Unsupported("local or forwarded request"));
        }
        self.check_membership(&message)?;
        Ok(AuthorizedMessage {
            revision: self.revision,
            limits: self.limits,
            membership: self.membership,
            certificate,
            envelope,
            message,
        })
    }

    /// Recheck just before dequeue/step. This does not reparse or copy payloads.
    pub fn revalidate(
        &self,
        accepted: &AuthorizedMessage,
        now_unix_seconds: i64,
    ) -> Result<(), Error> {
        if accepted.revision != self.revision
            || accepted.limits != self.limits
            || accepted.membership != self.membership
        {
            return Err(Error::PolicyChanged);
        }
        self.check_peer(accepted.certificate, now_unix_seconds, &accepted.envelope)
    }

    /// Check a nonempty, applied configuration or a snapshot configuration.
    /// An uninitialized joining node needs a separate explicit startup mode;
    /// an empty configuration is never a valid installed snapshot.
    pub fn validate_configuration(&self, conf: &ConfState) -> Result<(), Error> {
        if !self.allow_changes {
            if conf.voters.len() != self.members.len()
                || conf.voters.iter().copied().collect::<BTreeSet<_>>() != self.members
                || !conf.learners.is_empty()
                || !conf.voters_outgoing.is_empty()
                || !conf.learners_next.is_empty()
                || conf.auto_leave
            {
                return Err(Error::Unsupported("snapshot bootstrap membership"));
            }
            return Ok(());
        }
        if conf.voters.is_empty() {
            return Err(Error::Invalid("empty voters"));
        }
        let voters = self.configuration_members(&conf.voters)?;
        let outgoing = self.configuration_members(&conf.voters_outgoing)?;
        let learners = self.configuration_members(&conf.learners)?;
        let next = self.configuration_members(&conf.learners_next)?;
        if !learners.is_disjoint(&voters)
            || !learners.is_disjoint(&outgoing)
            || !next.is_subset(&outgoing)
            || !next.is_disjoint(&voters)
        {
            return Err(Error::Invalid("overlapping configuration roles"));
        }
        if outgoing.is_empty() && conf.auto_leave {
            return Err(Error::Invalid("auto leave outside joint configuration"));
        }
        Ok(())
    }

    /// Decode the bounded V2 administrative entry format before proposing or
    /// accepting replication. This validates trusted identities and framing;
    /// the driver must still authorize the operator and validate the transition
    /// against its current applied configuration before proposing it.
    pub fn decode_membership_change(&self, bytes: &[u8]) -> Result<ConfChangeV2, Error> {
        if !self.allow_changes {
            return Err(Error::Unsupported("Raft membership changes"));
        }
        if bytes.len() > self.limits.max_payload_bytes {
            return Err(Error::Limit("configuration change bytes"));
        }
        codec::preflight_conf_change(bytes, self.limits)?;
        let change = ConfChangeV2::parse_from_bytes(bytes)
            .map_err(|_| Error::Malformed("configuration change protobuf"))?;
        if change.changes.is_empty() && change.get_transition() != ConfChangeTransition::Auto {
            return Err(Error::Invalid("empty joint change"));
        }
        let mut nodes = BTreeSet::new();
        for single in &change.changes {
            if !self.members.contains(&single.node_id) || !nodes.insert(single.node_id) {
                return Err(Error::Invalid("configuration change peer identity"));
            }
        }
        Ok(change)
    }

    fn configuration_members(&self, ids: &[u64]) -> Result<BTreeSet<u64>, Error> {
        if ids.len() > self.members.len() {
            return Err(Error::Limit("configuration members"));
        }
        let mut members = BTreeSet::new();
        for id in ids {
            if !self.members.contains(id) || !members.insert(*id) {
                return Err(Error::Invalid("configuration peer identity"));
            }
        }
        Ok(members)
    }

    fn check_membership(&self, message: &Message) -> Result<(), Error> {
        for entry in &message.entries {
            match entry.get_entry_type() {
                EntryType::EntryNormal => (),
                EntryType::EntryConfChange => {
                    return Err(Error::Unsupported("Raft membership changes"));
                }
                EntryType::EntryConfChangeV2 => {
                    self.decode_membership_change(&entry.data)?;
                }
            }
        }
        let snapshot = message.get_snapshot();
        if !snapshot.is_empty() {
            self.validate_configuration(snapshot.get_metadata().get_conf_state())?;
        }
        Ok(())
    }

    fn check_peer(
        &self,
        certificate: CertificateIdentity,
        now: i64,
        envelope: &Envelope,
    ) -> Result<(), Error> {
        if envelope.version != VERSION || envelope.codec != CODEC {
            return Err(Error::Unsupported("peer wire version"));
        }
        if envelope.cluster_id != self.scope.cluster_id
            || envelope.cell_id != self.scope.cell_id
            || envelope.cell_incarnation != self.scope.cell_incarnation
            || envelope.to_node != self.scope.node_id
            || envelope.from_node == self.scope.node_id
        {
            return Err(Error::Unauthorized);
        }
        self.authorize_peer(certificate, envelope.from_node, now)
    }
}

fn validate_limits(limits: Limits) -> Result<(), Error> {
    if limits.max_payload_bytes == 0
        || limits.max_entries == 0
        || limits.max_fields == 0
        || limits.max_certificate_bytes == 0
        || limits.max_bindings == 0
    {
        return Err(Error::Invalid("zero wire limit"));
    }
    Ok(())
}

fn validate_bindings(
    bindings: Vec<Binding>,
    members: &BTreeSet<u64>,
    max_bindings: usize,
) -> Result<BTreeMap<[u8; 32], u64>, Error> {
    if bindings.len() > max_bindings {
        return Err(Error::Limit("certificate bindings"));
    }
    let mut result = BTreeMap::new();
    for binding in bindings {
        if !members.contains(&binding.node_id) {
            return Err(Error::Invalid("certificate node is not a bootstrap member"));
        }
        if result
            .insert(binding.fingerprint, binding.node_id)
            .is_some()
        {
            return Err(Error::Invalid("duplicate certificate fingerprint"));
        }
    }
    Ok(result)
}

fn membership_fingerprint(members: &BTreeSet<u64>, allow_changes: bool) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"SCAPMEM1");
    digest.update([u8::from(allow_changes)]);
    digest.update((members.len() as u64).to_le_bytes());
    for member in members {
        digest.update(member.to_le_bytes());
    }
    digest.finalize().into()
}

fn network_message(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::MsgAppend
            | MessageType::MsgAppendResponse
            | MessageType::MsgRequestVote
            | MessageType::MsgRequestVoteResponse
            | MessageType::MsgSnapshot
            | MessageType::MsgHeartbeat
            | MessageType::MsgHeartbeatResponse
            | MessageType::MsgTimeoutNow
            | MessageType::MsgRequestPreVote
            | MessageType::MsgRequestPreVoteResponse
    )
}

#[cfg(test)]
mod tests;
