//! Bounded synchronous Raft storage policy for the G0 feasibility gate.
//!
//! The backend must atomically replace one complete, versioned image with WAL
//! and synchronous durability. This deliberately bounded implementation rewrites
//! the image: it is not a scalable production log engine. The native backend and
//! real RawNode driver have independent contract tests. No SQLite acceptance or
//! durable quorum is implied by a local successful write.

use std::collections::BTreeSet;
use std::fmt::{self, Display};

use protobuf::Message as ProtobufMessage;
use raft::eraftpb::{ConfState, Entry, EntryType, HardState, Snapshot};
use raft::{GetEntriesContext, RaftState, Storage, StorageError};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"SCAPRAFT";
const VERSION: u32 = 1;

/// Identity of one local replica of a cell incarnation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub cluster_id: u128,
    pub cell_id: u128,
    pub cell_incarnation: u64,
    pub node_id: u64,
}

/// All bounds are mandatory and are part of the admitted store configuration.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_image_bytes: usize,
    pub max_entry_bytes: usize,
    pub max_entries: usize,
    pub max_application_bytes: usize,
}

/// `Empty` means the entire exclusively owned backend namespace is empty.
/// A missing image alongside any other data must return `Unrecognized`.
pub enum LoadState {
    Empty,
    Image(Vec<u8>),
    Unrecognized,
}

/// The only side-effect boundary. Successful replacement must be atomic and
/// synchronously durable. An error may mean either the old or new image survived;
/// callers must reopen and validate rather than retry through the same Store.
pub trait AtomicBackend {
    type Error: Display;

    /// Reject an oversized image before copying it into the returned owned Vec.
    /// Native backend caching/allocation is a separately measured resource bound.
    fn load(&mut self, max_image_bytes: usize) -> Result<LoadState, Self::Error>;
    fn replace_sync(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Backend(String),
    Decode(String),
    Stopped,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// The validated durable view. Store only exposes an immutable reference.
/// Application bytes are opaque; their deterministic semantics belong to the
/// state-machine adapter. Snapshot data is a complete earlier application image.
#[derive(Clone, Debug, PartialEq)]
pub struct State {
    pub identity: Identity,
    pub hard_state: HardState,
    pub conf_state: ConfState,
    pub applied: u64,
    pub snapshot: Snapshot,
    pub entries: Vec<Entry>,
    pub application: Vec<u8>,
}

pub struct Store<B> {
    backend: B,
    state: State,
    limits: Limits,
    stopped: bool,
}

impl<B: AtomicBackend> Store<B> {
    /// Bootstrap is explicit. Every founding replica must receive the same
    /// configuration and genesis checkpoint (index=term=1, empty application).
    pub fn create_new(
        backend: B,
        identity: Identity,
        conf_state: ConfState,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::create_new_with_application(backend, identity, conf_state, limits, Vec::new())
    }

    /// Bootstrap a new group with a complete application checkpoint. Every
    /// founding replica must receive byte-identical application/configuration
    /// at index=term=1; authorizing that bootstrap belongs to the caller.
    /// Opening an existing image never invokes this initialization path.
    pub fn create_new_with_application(
        mut backend: B,
        identity: Identity,
        conf_state: ConfState,
        limits: Limits,
        application: Vec<u8>,
    ) -> Result<Self, Error> {
        validate_limits(limits)?;
        if application.len() > limits.max_application_bytes {
            return Err(Error::Invalid(
                "genesis application exceeds configured bound",
            ));
        }
        match backend
            .load(limits.max_image_bytes)
            .map_err(backend_error)?
        {
            LoadState::Empty => {}
            _ => return Err(Error::Invalid("backend is not empty")),
        }
        let mut snapshot = Snapshot::default();
        snapshot.mut_metadata().index = 1;
        snapshot.mut_metadata().term = 1;
        snapshot.mut_metadata().set_conf_state(conf_state.clone());
        snapshot.data = application.clone().into();
        let hard_state = HardState {
            term: 1,
            commit: 1,
            ..Default::default()
        };
        let state = State {
            identity,
            hard_state,
            conf_state,
            applied: 1,
            snapshot,
            entries: Vec::new(),
            application,
        };
        validate_state(&state, limits)?;
        let image = encode(&state, limits)?;
        backend.replace_sync(&image).map_err(backend_error)?;
        Ok(Self {
            backend,
            state,
            limits,
            stopped: false,
        })
    }

    /// Open never initializes, repairs, advances commit, or applies a log tail.
    pub fn open_existing(
        mut backend: B,
        expected_identity: Identity,
        limits: Limits,
    ) -> Result<Self, Error> {
        validate_limits(limits)?;
        let bytes = match backend
            .load(limits.max_image_bytes)
            .map_err(backend_error)?
        {
            LoadState::Image(bytes) => bytes,
            _ => return Err(Error::Invalid("no recognized existing image")),
        };
        let state = decode(&bytes, limits)?;
        validate_state(&state, limits)?;
        if state.identity != expected_identity {
            return Err(Error::Invalid("replica identity mismatch"));
        }
        Ok(Self {
            backend,
            state,
            limits,
            stopped: false,
        })
    }

    pub fn view(&self) -> Result<&State, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        Ok(&self.state)
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Persist one serial Ready before its persisted messages or advance_append.
    /// A received snapshot is installed with its complete application/ConfState
    /// and matching HardState in the same atomic image. Empty snapshots use None.
    pub fn persist_ready(
        &mut self,
        entries: &[Entry],
        hard_state: Option<&HardState>,
        snapshot: Option<&Snapshot>,
    ) -> Result<(), Error> {
        let limits = self.limits;
        self.transact(|next| {
            check_entries_size(entries, limits)?;
            let old_hard = next.hard_state.clone();
            if let Some(incoming) = hard_state {
                validate_hard_transition(&old_hard, incoming)?;
                next.hard_state = incoming.clone();
            }
            if let Some(incoming) = snapshot {
                if incoming.compute_size() as usize > limits.max_image_bytes {
                    return Err(Error::Invalid("snapshot exceeds image bound"));
                }
                let metadata = incoming.get_metadata();
                if metadata.index <= old_hard.commit {
                    return Err(Error::Invalid("snapshot does not advance committed state"));
                }
                next.snapshot = incoming.clone();
                next.applied = metadata.index;
                next.conf_state = metadata.get_conf_state().clone();
                next.application = incoming.data.to_vec();
                next.entries.clear();
            }
            if let Some(first) = entries.first() {
                let base = next.snapshot.get_metadata().index;
                let last = last_index(next);
                if first.index <= base || first.index > last + 1 {
                    return Err(Error::Invalid("append outside recoverable range"));
                }
                let mut expected = first.index;
                for entry in entries {
                    if entry.index != expected || entry.index == u64::MAX {
                        return Err(Error::Invalid("non-contiguous appended entries"));
                    }
                    expected += 1;
                }
                for entry in entries
                    .iter()
                    .take_while(|entry| entry.index <= old_hard.commit)
                {
                    let offset = (entry.index - base - 1) as usize;
                    if next.entries.get(offset) != Some(entry) {
                        return Err(Error::Invalid("committed entry replacement"));
                    }
                }
                next.entries.truncate((first.index - base - 1) as usize);
                next.entries.extend_from_slice(entries);
            }
            Ok(())
        })
    }

    /// Atomically publish commit, exact committed entries' application result,
    /// full membership, and applied. Empty entries may advance only commit.
    /// This method does not decide Raft commitment or execute business commands.
    /// The caller must derive configuration using RawNode::apply_conf_change for
    /// the matching committed configuration entry. The store rejects changes in
    /// a normal-only batch but does not reimplement Raft's membership algorithm.
    pub fn apply_committed(
        &mut self,
        commit: u64,
        entries: &[Entry],
        application: &[u8],
        conf_state: &ConfState,
    ) -> Result<(), Error> {
        let limits = self.limits;
        self.transact(|next| {
            check_entries_size(entries, limits)?;
            if application.len() > limits.max_application_bytes
                || conf_state.compute_size() as usize > limits.max_image_bytes
            {
                return Err(Error::Invalid("application or configuration exceeds bound"));
            }
            if commit < next.hard_state.commit {
                return Err(Error::Invalid("commit regression"));
            }
            if entries.is_empty() {
                if application != next.application || conf_state != &next.conf_state {
                    return Err(Error::Invalid(
                        "application changed without applied progress",
                    ));
                }
            } else {
                if conf_state != &next.conf_state
                    && !entries.iter().any(|entry| {
                        matches!(
                            entry.get_entry_type(),
                            EntryType::EntryConfChange | EntryType::EntryConfChangeV2
                        )
                    })
                {
                    return Err(Error::Invalid(
                        "configuration changed without configuration entry",
                    ));
                }
                let base = next.snapshot.get_metadata().index;
                let mut expected = next.applied + 1;
                for entry in entries {
                    if entry.index != expected {
                        return Err(Error::Invalid("non-contiguous applied entries"));
                    }
                    if next.entries.get((entry.index - base - 1) as usize) != Some(entry) {
                        return Err(Error::Invalid("applied entry differs from durable log"));
                    }
                    expected += 1;
                }
                next.applied = expected - 1;
                next.application = application.to_vec();
                next.conf_state = conf_state.clone();
            }
            next.hard_state.commit = commit;
            Ok(())
        })
    }

    /// Capture the durable applied view and compact its covered log atomically.
    /// Unapplied and uncommitted suffixes remain. No external files are published.
    pub fn checkpoint_and_compact(&mut self) -> Result<(), Error> {
        self.transact(|next| {
            // `next` starts as a validated private view; its applied position is
            // already within the retained checkpoint/log range.
            let term = retained_term(next, next.applied);
            let mut snapshot = Snapshot::default();
            snapshot.mut_metadata().index = next.applied;
            snapshot.mut_metadata().term = term;
            snapshot
                .mut_metadata()
                .set_conf_state(next.conf_state.clone());
            snapshot.data = next.application.clone().into();
            next.entries.retain(|entry| entry.index > next.applied);
            next.snapshot = snapshot;
            Ok(())
        })
    }

    fn transact(
        &mut self,
        change: impl FnOnce(&mut State) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.view()?;
        // Set before invoking code/IO: errors and caught backend panics are fatal
        // to this handle. A completed synchronous replacement alone clears it.
        self.stopped = true;
        let mut next = self.state.clone();
        change(&mut next)?;
        validate_state(&next, self.limits)?;
        let image = encode(&next, self.limits)?;
        self.backend.replace_sync(&image).map_err(backend_error)?;
        self.state = next;
        self.stopped = false;
        Ok(())
    }

    fn raft_view(&self) -> raft::Result<&State> {
        self.view()
            .map_err(|error| raft::Error::Store(StorageError::Other(Box::new(error))))
    }
}

impl<B: AtomicBackend> Storage for Store<B> {
    fn initial_state(&self) -> raft::Result<RaftState> {
        let state = self.raft_view()?;
        Ok(RaftState {
            hard_state: state.hard_state.clone(),
            conf_state: state.conf_state.clone(),
        })
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        _context: GetEntriesContext,
    ) -> raft::Result<Vec<Entry>> {
        let state = self.raft_view()?;
        let first = state.snapshot.get_metadata().index + 1;
        if low < first {
            return Err(StorageError::Compacted.into());
        }
        if high > last_index(state) + 1 || low > high {
            return Err(StorageError::Unavailable.into());
        }
        let mut entries = state.entries[(low - first) as usize..(high - first) as usize].to_vec();
        raft::util::limit_size(&mut entries, max_size.into());
        Ok(entries)
    }

    fn term(&self, index: u64) -> raft::Result<u64> {
        let state = self.raft_view()?;
        if index < state.snapshot.get_metadata().index {
            return Err(StorageError::Compacted.into());
        }
        if index > last_index(state) {
            return Err(StorageError::Unavailable.into());
        }
        Ok(retained_term(state, index))
    }

    fn first_index(&self) -> raft::Result<u64> {
        Ok(self.raft_view()?.snapshot.get_metadata().index + 1)
    }

    fn last_index(&self) -> raft::Result<u64> {
        Ok(last_index(self.raft_view()?))
    }

    fn snapshot(&self, request_index: u64, _to: u64) -> raft::Result<Snapshot> {
        let state = self.raft_view()?;
        if request_index > state.snapshot.get_metadata().index {
            return Err(StorageError::SnapshotTemporarilyUnavailable.into());
        }
        Ok(state.snapshot.clone())
    }
}

fn backend_error(error: impl Display) -> Error {
    Error::Backend(error.to_string())
}

fn last_index(state: &State) -> u64 {
    state
        .entries
        .last()
        .map_or(state.snapshot.get_metadata().index, |entry| entry.index)
}

/// Lookup after the caller has established the retained range. Storage::term
/// validates untrusted query positions; checkpoint uses the private validated
/// applied watermark. Neither path can request a missing applied log entry.
fn retained_term(state: &State, index: u64) -> u64 {
    let base = state.snapshot.get_metadata().index;
    if index == base {
        return state.snapshot.get_metadata().term;
    }
    state.entries[(index - base - 1) as usize].term
}

fn validate_limits(limits: Limits) -> Result<(), Error> {
    if limits.max_image_bytes == 0
        || limits.max_image_bytes > u32::MAX as usize
        || limits.max_entry_bytes == 0
        || limits.max_entries == 0
        || limits.max_application_bytes == 0
        || limits.max_entry_bytes > limits.max_image_bytes
        || limits.max_entries > limits.max_image_bytes
        || limits.max_application_bytes > limits.max_image_bytes
    {
        return Err(Error::Invalid("invalid store limits"));
    }
    Ok(())
}

fn validate_configuration(configuration: &ConfState) -> Result<(), Error> {
    let groups = [
        &configuration.voters,
        &configuration.voters_outgoing,
        &configuration.learners,
        &configuration.learners_next,
    ];
    for group in groups {
        let unique: BTreeSet<_> = group.iter().copied().collect();
        if unique.contains(&0) || unique.len() != group.len() {
            return Err(Error::Invalid("zero or duplicate member"));
        }
    }
    if configuration.voters.is_empty() {
        return Err(Error::Invalid("empty voter configuration"));
    }
    for learner in &configuration.learners {
        if configuration.voters.contains(learner)
            || configuration.voters_outgoing.contains(learner)
            || configuration.learners_next.contains(learner)
        {
            return Err(Error::Invalid("learner overlaps voter or pending learner"));
        }
    }
    for learner in &configuration.learners_next {
        if !configuration.voters_outgoing.contains(learner)
            || configuration.voters.contains(learner)
        {
            return Err(Error::Invalid("invalid pending learner"));
        }
    }
    if configuration.voters_outgoing.is_empty() && configuration.auto_leave {
        return Err(Error::Invalid("joint fields outside joint configuration"));
    }
    Ok(())
}

fn validate_hard_transition(previous: &HardState, next: &HardState) -> Result<(), Error> {
    if next.term < previous.term || next.commit < previous.commit {
        return Err(Error::Invalid("hard state regression"));
    }
    if next.term == previous.term && previous.vote != 0 && next.vote != previous.vote {
        return Err(Error::Invalid("vote changed in one term"));
    }
    Ok(())
}

fn check_entries_size(entries: &[Entry], limits: Limits) -> Result<(), Error> {
    if entries.len() > limits.max_entries {
        return Err(Error::Invalid("entry count exceeds bound"));
    }
    let mut bytes = 0usize;
    for entry in entries {
        if entry.compute_size() as usize > limits.max_entry_bytes {
            return Err(Error::Invalid("entry exceeds bound"));
        }
        bytes = bytes
            .saturating_add(4)
            .saturating_add(entry.compute_size() as usize);
        if bytes > limits.max_image_bytes {
            return Err(Error::Invalid("entries exceed image bound"));
        }
    }
    Ok(())
}

fn validate_state(state: &State, limits: Limits) -> Result<(), Error> {
    let identity = &state.identity;
    if identity.cluster_id == 0
        || identity.cell_id == 0
        || identity.cell_incarnation == 0
        || identity.node_id == 0
    {
        return Err(Error::Invalid("zero replica identity"));
    }
    check_entries_size(&state.entries, limits)?;
    if state.application.len() > limits.max_application_bytes
        || state.snapshot.data.len() > limits.max_application_bytes
    {
        return Err(Error::Invalid("application exceeds bound"));
    }
    validate_configuration(&state.conf_state)?;
    validate_configuration(state.snapshot.get_metadata().get_conf_state())?;
    if state.conf_state.compute_size() as usize > limits.max_image_bytes
        || state.snapshot.compute_size() as usize > limits.max_image_bytes
    {
        return Err(Error::Invalid("configuration or snapshot exceeds bound"));
    }
    let metadata = state.snapshot.get_metadata();
    if metadata.index == 0
        || metadata.index == u64::MAX
        || metadata.term == 0
        || metadata.term > state.hard_state.term
    {
        return Err(Error::Invalid("invalid snapshot position"));
    }
    let mut expected = metadata.index + 1;
    let mut previous_term = metadata.term;
    for entry in &state.entries {
        if entry.index != expected || entry.index == u64::MAX {
            return Err(Error::Invalid("non-contiguous log"));
        }
        if entry.term < previous_term || entry.term > state.hard_state.term {
            return Err(Error::Invalid("invalid log term"));
        }
        expected += 1;
        previous_term = entry.term;
    }
    if state.applied < metadata.index
        || state.applied > state.hard_state.commit
        || state.hard_state.commit > last_index(state)
    {
        return Err(Error::Invalid("snapshot/applied/commit/log order"));
    }
    if state.applied == metadata.index
        && (state.application != state.snapshot.data
            || state.conf_state != *metadata.get_conf_state())
    {
        return Err(Error::Invalid("checkpoint application mismatch"));
    }
    Ok(())
}

// An unkeyed digest detects accidental corruption; it does not authenticate the
// writer or prevent an intact old image from being rolled back.
fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn append_blob(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn append_message(output: &mut Vec<u8>, message: &impl ProtobufMessage) {
    // Fixed eraftpb messages have no required fields; serialization to Vec has
    // no external I/O failure. Size/admission is bounded before this operation.
    append_blob(
        output,
        &message
            .write_to_bytes()
            .expect("in-memory eraftpb encoding"),
    );
}

fn encode(state: &State, limits: Limits) -> Result<Vec<u8>, Error> {
    let size = state.entries.iter().fold(
        120usize
            .saturating_add(state.hard_state.compute_size() as usize)
            .saturating_add(state.conf_state.compute_size() as usize)
            .saturating_add(state.snapshot.compute_size() as usize)
            .saturating_add(state.application.len()),
        |size, entry| {
            size.saturating_add(4)
                .saturating_add(entry.compute_size() as usize)
        },
    );
    if size > limits.max_image_bytes {
        return Err(Error::Invalid("encoded image exceeds bound"));
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&state.identity.cluster_id.to_be_bytes());
    bytes.extend_from_slice(&state.identity.cell_id.to_be_bytes());
    bytes.extend_from_slice(&state.identity.cell_incarnation.to_be_bytes());
    bytes.extend_from_slice(&state.identity.node_id.to_be_bytes());
    bytes.extend_from_slice(&state.applied.to_be_bytes());
    append_message(&mut bytes, &state.hard_state);
    append_message(&mut bytes, &state.conf_state);
    append_message(&mut bytes, &state.snapshot);
    append_blob(&mut bytes, &state.application);
    bytes.extend_from_slice(&(state.entries.len() as u32).to_be_bytes());
    for entry in &state.entries {
        append_message(&mut bytes, entry);
    }
    bytes.extend_from_slice(&checksum(&bytes));
    Ok(bytes)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.bytes.len() - self.position {
            return Err(Error::Invalid("truncated image"));
        }
        let result = &self.bytes[self.position..self.position + count];
        self.position += count;
        Ok(result)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("exact four-byte slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("exact eight-byte slice"),
        ))
    }

    fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(
            self.take(16)?.try_into().expect("exact sixteen-byte slice"),
        ))
    }

    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn message<M: ProtobufMessage>(&mut self) -> Result<M, Error> {
        M::parse_from_bytes(self.blob()?).map_err(|error| Error::Decode(error.to_string()))
    }
}

fn decode(bytes: &[u8], limits: Limits) -> Result<State, Error> {
    if bytes.len() > limits.max_image_bytes || bytes.len() < 32 {
        return Err(Error::Invalid("image size outside bound"));
    }
    let split = bytes.len() - 32;
    if checksum(&bytes[..split]).as_slice() != &bytes[split..] {
        return Err(Error::Invalid("image checksum mismatch"));
    }
    let mut cursor = Cursor {
        bytes: &bytes[..split],
        position: 0,
    };
    if cursor.take(8)? != MAGIC {
        return Err(Error::Invalid("unknown image magic"));
    }
    if cursor.u32()? != VERSION {
        return Err(Error::Invalid("unknown image version"));
    }
    let identity = Identity {
        cluster_id: cursor.u128()?,
        cell_id: cursor.u128()?,
        cell_incarnation: cursor.u64()?,
        node_id: cursor.u64()?,
    };
    let applied = cursor.u64()?;
    let hard_state = cursor.message()?;
    let conf_state = cursor.message()?;
    let snapshot = cursor.message()?;
    let application = cursor.blob()?.to_vec();
    let count = cursor.u32()? as usize;
    if count > limits.max_entries || count > (cursor.bytes.len() - cursor.position) / 4 {
        return Err(Error::Invalid("invalid encoded entry count"));
    }
    let mut entries = Vec::new();
    for _ in 0..count {
        entries.push(cursor.message()?);
    }
    if cursor.position != cursor.bytes.len() {
        return Err(Error::Invalid("trailing image bytes"));
    }
    Ok(State {
        identity,
        hard_state,
        conf_state,
        applied,
        snapshot,
        entries,
        application,
    })
}

#[cfg(test)]
mod tests;
