//! A bounded, single-cell execution loop and authenticated peer mailboxes.
//!
//! Run the owner on a dedicated blocking thread. Network tasks only enqueue
//! authenticated input or report a delivery attempt; they never own RawNode or
//! execute synchronous storage. Proposal admission is not commit acceptance.
//! A read returns a durable application view after its own Safe ReadIndex.

mod driver;
mod workers;

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, SystemTimeError, UNIX_EPOCH};

use parking_lot::{Condvar, Mutex};
use protobuf::Message as ProtobufMessage;
use raft::eraftpb::MessageType;
use raft::SnapshotStatus;
use scap_raft_driver::{ReadBarrier, ReadTicket, Status};
use scap_raft_store::Identity;
use scap_raft_transport::{AdmissionError, Ingress};
use scap_raft_wire::{
    AuthorizedMessage, Binding, Envelope, Policy, Scope, CODEC, HEADER_BYTES, VERSION,
};

pub use driver::RaftDriver;
pub use workers::{NetworkSender, NetworkWorkers};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Closed,
    Full,
    Expired,
    Unknown,
    NotLeader,
    ReadNotReady,
    InputLimit,
    Clock,
    Driver(String),
    Wire(scap_raft_wire::Error),
    Network(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug)]
pub struct ClockReading {
    pub instant: Instant,
    pub unix_seconds: i64,
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Result<ClockReading, Error>;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<ClockReading, Error> {
        clock_reading(Instant::now(), SystemTime::now().duration_since(UNIX_EPOCH))
    }
}

fn clock_reading(
    instant: Instant,
    since_epoch: Result<Duration, SystemTimeError>,
) -> Result<ClockReading, Error> {
    let duration = since_epoch.map_err(|_| Error::Clock)?;
    let unix_seconds = unix_seconds(duration)?;
    Ok(ClockReading {
        instant,
        unix_seconds,
    })
}

fn unix_seconds(duration: Duration) -> Result<i64, Error> {
    i64::try_from(duration.as_secs()).map_err(|_| Error::Clock)
}

#[derive(Clone, Copy, Debug)]
pub struct QueueLimits {
    pub max_messages: usize,
    pub max_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig {
    pub inbox: QueueLimits,
    pub requests: QueueLimits,
    pub max_pending_deliveries: usize,
    pub max_pending_delivery_bytes: usize,
    pub max_pending_reads: usize,
    pub max_view_bytes: usize,
    pub max_poll_rounds: usize,
    pub tick_interval: Duration,
    pub delivery_timeout: Duration,
    pub max_inbound_age: Duration,
}

#[derive(Debug)]
pub enum Input {
    /// Local trusted admission only. The caller must later resolve business
    /// acceptance through the application state and a fresh read barrier.
    Propose {
        context: Vec<u8>,
        data: Vec<u8>,
    },
    Read,
    Status,
    Checkpoint,
}

#[derive(Clone, Debug)]
pub struct ReadView {
    pub identity: Identity,
    pub term: u64,
    pub index: u64,
    pub barrier: ReadBarrier,
    pub application: Vec<u8>,
}

#[derive(Debug)]
pub enum Answer {
    Admitted,
    Read(ReadView),
    Status(Status),
    Checkpointed,
}

struct Request {
    input: Input,
    reply: mpsc::SyncSender<Result<Answer, Error>>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    _reservation: Arc<RequestReservation>,
}

struct RequestBudget {
    limits: QueueLimits,
    count: usize,
    bytes: usize,
}

struct RequestReservation {
    budget: Arc<Mutex<RequestBudget>>,
    bytes: usize,
}

impl Drop for RequestReservation {
    fn drop(&mut self) {
        let mut budget = self.budget.lock();
        budget.count -= 1;
        budget.bytes -= self.bytes;
    }
}

fn reserve_request(
    budget: &Arc<Mutex<RequestBudget>>,
    bytes: usize,
) -> Result<Arc<RequestReservation>, Error> {
    let mut held = budget.lock();
    if !fits(held.limits, held.count, held.bytes, bytes) {
        return Err(Error::Full);
    }
    held.count += 1;
    held.bytes += bytes;
    Ok(Arc::new(RequestReservation {
        budget: Arc::clone(budget),
        bytes,
    }))
}

struct Inbound {
    authorized: AuthorizedMessage,
    expires: Instant,
    bytes: usize,
}

struct Shared {
    policy: Policy,
    inbound: VecDeque<Inbound>,
    inbound_bytes: usize,
    requests: VecDeque<Request>,
    feedback: BTreeMap<u64, DeliveryResult>,
    /// A completion can only refer to one live, bounded delivery reservation.
    live_deliveries: BTreeMap<u64, ()>,
    closed: bool,
}

struct Mailbox {
    state: Mutex<Shared>,
    wake: Condvar,
    config: RuntimeConfig,
    clock: Arc<dyn Clock>,
    requests: Arc<Mutex<RequestBudget>>,
}

#[derive(Clone)]
pub struct Handle {
    mailbox: Arc<Mailbox>,
}

/// Dropping a pending call marks it cancelled; a started proposal may still
/// commit. Neither timeout nor cancellation certifies non-commitment.
pub struct Pending {
    receiver: mpsc::Receiver<Result<Answer, Error>>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    mailbox: Arc<Mailbox>,
    _reservation: Arc<RequestReservation>,
}

impl Pending {
    pub fn wait(self) -> Result<Answer, Error> {
        self.wait_at(Instant::now())
    }

    fn wait_at(&self, now: Instant) -> Result<Answer, Error> {
        if now >= self.deadline {
            return Err(Error::Unknown);
        }
        self.receiver
            .recv_timeout(self.deadline.duration_since(now))
            .map_err(|_| Error::Unknown)?
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.mailbox.wake.notify_one();
    }
}

impl Handle {
    pub fn submit(&self, input: Input, deadline: Instant) -> Result<Pending, Error> {
        let now = self.mailbox.clock.now()?;
        if deadline <= now.instant {
            return Err(Error::Expired);
        }
        let bytes = match &input {
            Input::Propose { context, data } => context
                .len()
                .saturating_add(data.len())
                .saturating_mul(2)
                .saturating_add(256),
            Input::Read => self.mailbox.config.max_view_bytes.saturating_add(256),
            _ => 256,
        };
        let mut shared = self.mailbox.state.lock();
        if shared.closed {
            return Err(Error::Closed);
        }
        let reservation = reserve_request(&self.mailbox.requests, bytes)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        shared.requests.push_back(Request {
            input,
            reply,
            cancelled: Arc::clone(&cancelled),
            deadline,
            _reservation: Arc::clone(&reservation),
        });
        drop(shared);
        self.mailbox.wake.notify_one();
        Ok(Pending {
            receiver,
            cancelled,
            deadline,
            mailbox: Arc::clone(&self.mailbox),
            _reservation: reservation,
        })
    }

    /// Trusted local administration. Replacement and admission share one lock.
    /// Existing queued messages are revalidated at consumption, not grandfathered.
    pub fn replace_bindings(&self, bindings: Vec<Binding>) -> Result<u64, Error> {
        let mut shared = self.mailbox.state.lock();
        if shared.closed {
            return Err(Error::Closed);
        }
        shared
            .policy
            .replace_bindings(bindings)
            .map_err(Error::Wire)
    }

    /// A receipt only releases this delivery reservation. Duplicate, expired
    /// or unknown attempt IDs cannot change a later snapshot attempt.
    pub fn complete(&self, id: u64, result: DeliveryResult) -> bool {
        let mut shared = self.mailbox.state.lock();
        if shared.closed
            || !shared.live_deliveries.contains_key(&id)
            || shared.feedback.contains_key(&id)
        {
            return false;
        }
        shared.feedback.insert(id, result);
        drop(shared);
        self.mailbox.wake.notify_one();
        true
    }

    pub fn stop(&self) {
        let mut shared = self.mailbox.state.lock();
        shared.closed = true;
        for request in shared.requests.drain(..) {
            let _ = request.reply.try_send(Err(Error::Closed));
        }
        shared.inbound.clear();
        shared.inbound_bytes = 0;
        shared.feedback.clear();
        shared.live_deliveries.clear();
        drop(shared);
        self.mailbox.wake.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        self.mailbox.state.lock().closed
    }
}

impl Ingress for Handle {
    fn admit(&self, peer_leaf_der: &[u8], envelope: Envelope) -> Result<(), AdmissionError> {
        let now = self
            .mailbox
            .clock
            .now()
            .map_err(|_| AdmissionError::Unavailable)?;
        let mut shared = self.mailbox.state.lock();
        if shared.closed {
            return Err(AdmissionError::Unavailable);
        }
        let certificate = scap_raft_wire::certificate_identity(
            peer_leaf_der,
            shared.policy.limits().max_certificate_bytes,
        )
        .map_err(admission_error)?;
        // Overflow is larger than every validated queue budget, so the same
        // bounded admission check rejects it without wrapping the accounting.
        let bytes =
            inbound_cost(envelope.payload.len(), shared.policy.limits()).unwrap_or(usize::MAX);
        if !fits(
            self.mailbox.config.inbox,
            shared.inbound.len(),
            shared.inbound_bytes,
            bytes,
        ) {
            return Err(AdmissionError::Limit);
        }
        let authorized = shared
            .policy
            .authorize(certificate, now.unix_seconds, envelope)
            .map_err(admission_error)?;
        let expires = now
            .instant
            .checked_add(self.mailbox.config.max_inbound_age)
            .ok_or(AdmissionError::Limit)?;
        shared.inbound.push_back(Inbound {
            authorized,
            expires,
            bytes,
        });
        shared.inbound_bytes += bytes;
        drop(shared);
        self.mailbox.wake.notify_one();
        Ok(())
    }
}

fn admission_error(error: scap_raft_wire::Error) -> AdmissionError {
    match error {
        scap_raft_wire::Error::Unauthorized | scap_raft_wire::Error::PolicyChanged => {
            AdmissionError::PermissionDenied
        }
        scap_raft_wire::Error::CertificateTime => AdmissionError::Unauthenticated,
        scap_raft_wire::Error::Limit(_) => AdmissionError::Limit,
        _ => AdmissionError::Invalid,
    }
}

fn fits(limits: QueueLimits, count: usize, held: usize, incoming: usize) -> bool {
    count < limits.max_messages && incoming <= limits.max_bytes.saturating_sub(held)
}

/// Admission units conservatively include retained raw/decoded bytes plus
/// bounded protobuf field/entry overhead, instead of counting only wire bytes.
/// Allocator arenas and TLS buffers remain separately bounded native resources;
/// this is not a claim about exact process RSS.
fn inbound_cost(payload: usize, limits: scap_raft_wire::Limits) -> Option<usize> {
    let fields = limits.max_fields.min(payload).checked_mul(128)?;
    let entries = limits.max_entries.min(payload / 2).checked_mul(256)?;
    payload
        .checked_mul(2)?
        .checked_add(fields)?
        .checked_add(entries)?
        .checked_add(HEADER_BYTES + 512)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryResult {
    Received,
    Failed,
}

#[derive(Debug)]
pub struct Delivery {
    pub id: u64,
    pub peer: u64,
    pub snapshot: bool,
    pub envelope: Envelope,
    pub deadline: Instant,
}

pub trait Network {
    /// Must return immediately. Rejection drops this network attempt; Raft
    /// retains responsibility for retransmission and quorum progress.
    fn try_send(&mut self, delivery: Delivery) -> Result<(), Error>;
}

struct Outstanding {
    peer: u64,
    snapshot: bool,
    term: u64,
    bytes: usize,
    deadline: Instant,
}

struct ReadRequest {
    ticket: ReadTicket,
    request: Request,
}

pub struct Runtime<D: RaftDriver> {
    driver: D,
    handle: Handle,
    scope: Scope,
    config: RuntimeConfig,
    next_tick: Instant,
    next_delivery: u64,
    deliveries: BTreeMap<u64, Outstanding>,
    delivery_bytes: usize,
    latest_snapshot: BTreeMap<u64, (u64, u64)>,
    reads: BTreeMap<u64, ReadRequest>,
    prefer_request: bool,
    stopped: bool,
}

impl<D: RaftDriver> Runtime<D> {
    pub fn new(
        driver: D,
        policy: Policy,
        config: RuntimeConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, Handle), Error> {
        validate_config(config)?;
        let scope = policy.scope();
        let view = driver.view().map_err(driver_error)?;
        if view.identity
            != (Identity {
                cluster_id: scope.cluster_id,
                cell_id: scope.cell_id,
                cell_incarnation: scope.cell_incarnation,
                node_id: scope.node_id,
            })
        {
            return Err(Error::Invalid("runtime and durable identity differ"));
        }
        validate_members(&view.conf_state, &policy)?;
        let now = clock.now()?;
        let next_tick = now
            .instant
            .checked_add(config.tick_interval)
            .ok_or(Error::Invalid("tick interval overflow"))?;
        let mailbox = Arc::new(Mailbox {
            state: Mutex::new(Shared {
                policy,
                inbound: VecDeque::new(),
                inbound_bytes: 0,
                requests: VecDeque::new(),
                feedback: BTreeMap::new(),
                live_deliveries: BTreeMap::new(),
                closed: false,
            }),
            wake: Condvar::new(),
            config,
            clock,
            requests: Arc::new(Mutex::new(RequestBudget {
                limits: config.requests,
                count: 0,
                bytes: 0,
            })),
        });
        let handle = Handle { mailbox };
        Ok((
            Self {
                driver,
                handle: handle.clone(),
                scope,
                config,
                next_tick,
                next_delivery: 1,
                deliveries: BTreeMap::new(),
                delivery_bytes: 0,
                latest_snapshot: BTreeMap::new(),
                reads: BTreeMap::new(),
                prefer_request: false,
                stopped: false,
            },
            handle,
        ))
    }

    /// One bounded scheduling slice. Any fatal driver/clock error closes all
    /// ingress. Cancellation is checked before every local request and read.
    pub fn poll(&mut self, network: &mut impl Network) -> Result<usize, Error> {
        if self.stopped || self.handle.is_stopped() {
            self.handle.stop();
            self.close_reads();
            return Err(Error::Closed);
        }
        self.stopped = true;
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.poll_inner(network)
        })) {
            Ok(result) => result,
            Err(panic) => {
                self.handle.stop();
                self.close_reads();
                std::panic::resume_unwind(panic);
            }
        };
        if result.is_ok() {
            self.stopped = false;
        } else {
            self.handle.stop();
            self.close_reads();
        }
        result
    }

    fn poll_inner(&mut self, network: &mut impl Network) -> Result<usize, Error> {
        let mut work = 0;
        for _ in 0..self.config.max_poll_rounds {
            if self.handle.is_stopped() {
                return Err(Error::Closed);
            }
            let output = self.driver.drain().map_err(driver_error)?;
            let now = self.handle.mailbox.clock.now()?;
            for message in output.messages {
                self.emit(message, now.instant, network)?;
                work += 1;
            }
            for barrier in output.reads {
                if let Some(pending) = self.reads.remove(&barrier.ticket.sequence) {
                    let answer = self.read_answer(&pending, barrier, now.instant);
                    if self.driver.is_stopped() {
                        let error = answer.unwrap_err();
                        let _ = pending.request.reply.try_send(Err(error.clone()));
                        return Err(error);
                    }
                    let _ = pending.request.reply.try_send(answer);
                }
            }
            self.cancel_reads(now.instant)?;
            if output.more_ready {
                work += 1;
                continue;
            }
            if self.feedback(now.instant)? {
                work += 1;
                continue;
            }
            if now.instant >= self.next_tick {
                self.driver.tick().map_err(driver_error)?;
                // Do not replay a burst of old ticks after a storage stall.
                self.next_tick = now
                    .instant
                    .checked_add(self.config.tick_interval)
                    .ok_or(Error::Clock)?;
                work += 1;
                continue;
            }
            let request_first = self.prefer_request;
            self.prefer_request = !self.prefer_request;
            let handled = if request_first {
                self.request(now.instant)? || self.inbound(now)?
            } else {
                self.inbound(now)? || self.request(now.instant)?
            };
            if !handled {
                break;
            }
            work += 1;
        }
        Ok(work)
    }

    fn inbound(&mut self, now: ClockReading) -> Result<bool, Error> {
        let mut shared = self.handle.mailbox.state.lock();
        let Some(inbound) = shared.inbound.pop_front() else {
            return Ok(false);
        };
        shared.inbound_bytes -= inbound.bytes;
        if now.instant >= inbound.expires
            || shared
                .policy
                .revalidate(&inbound.authorized, now.unix_seconds)
                .is_err()
        {
            return Ok(true);
        }
        // Keep the policy lock through handoff. step() is bounded in-memory
        // work; all blocking persistence occurs later in drain(), without it.
        if let Err(error) = self.driver.step(inbound.authorized.into_message()) {
            if self.driver.is_stopped() {
                return Err(driver_error(error));
            }
        }
        Ok(true)
    }

    fn request(&mut self, now: Instant) -> Result<bool, Error> {
        let request = {
            let mut shared = self.handle.mailbox.state.lock();
            let Some(request) = shared.requests.pop_front() else {
                return Ok(false);
            };
            request
        };
        if request.cancelled.load(Ordering::Acquire) || now >= request.deadline {
            let _ = request.reply.try_send(Err(Error::Unknown));
            return Ok(true);
        }
        let result = match &request.input {
            Input::Propose { context, data } => self
                .driver
                .propose(context.clone(), data.clone())
                .map(|()| Answer::Admitted),
            Input::Status => self.driver.status().map(Answer::Status),
            Input::Checkpoint => self.driver.checkpoint().map(|()| Answer::Checkpointed),
            Input::Read => {
                if self.reads.len() >= self.config.max_pending_reads {
                    let _ = request.reply.try_send(Err(Error::Full));
                    return Ok(true);
                }
                match self.driver.read_index() {
                    Ok(ticket) => {
                        self.reads
                            .insert(ticket.sequence, ReadRequest { ticket, request });
                        return Ok(true);
                    }
                    Err(error) => Err(error),
                }
            }
        };
        let fatal = self.driver.is_stopped();
        let result = result.map_err(driver_error);
        if fatal {
            let error = result.unwrap_err();
            let _ = request.reply.try_send(Err(error.clone()));
            return Err(error);
        }
        let _ = request.reply.try_send(result);
        Ok(true)
    }

    fn read_answer(
        &self,
        pending: &ReadRequest,
        barrier: ReadBarrier,
        now: Instant,
    ) -> Result<Answer, Error> {
        if pending.request.cancelled.load(Ordering::Acquire) || now >= pending.request.deadline {
            return Err(Error::Unknown);
        }
        let state = self.driver.view().map_err(driver_error)?;
        if state.application.len() > self.config.max_view_bytes {
            return Err(Error::InputLimit);
        }
        let term = match state
            .entries
            .iter()
            .find(|entry| entry.index == state.applied)
        {
            Some(entry) => entry.term,
            None => state.snapshot.get_metadata().term,
        };
        Ok(Answer::Read(ReadView {
            identity: state.identity.clone(),
            term,
            index: state.applied,
            barrier,
            application: state.application.clone(),
        }))
    }

    fn cancel_reads(&mut self, now: Instant) -> Result<(), Error> {
        let expired: Vec<_> = self
            .reads
            .iter()
            .filter(|(_, r)| {
                r.request.cancelled.load(Ordering::Acquire) || now >= r.request.deadline
            })
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            let pending = self.reads.remove(&id).expect("collected live read");
            self.driver
                .cancel_read(pending.ticket)
                .map_err(driver_error)?;
            let _ = pending.request.reply.try_send(Err(Error::Unknown));
        }
        Ok(())
    }

    fn emit(
        &mut self,
        message: raft::eraftpb::Message,
        now: Instant,
        network: &mut impl Network,
    ) -> Result<(), Error> {
        let encoded = message.write_to_bytes().map_err(codec_error);
        self.emit_encoded(message, encoded, now, network)
    }

    fn emit_encoded(
        &mut self,
        message: raft::eraftpb::Message,
        encoded: Result<Vec<u8>, Error>,
        now: Instant,
        network: &mut impl Network,
    ) -> Result<(), Error> {
        let bytes = encoded?;
        let wire_bytes = HEADER_BYTES.saturating_add(bytes.len());
        let snapshot = message.get_msg_type() == MessageType::MsgSnapshot;
        let term = self.driver.status().map_err(driver_error)?.term;
        let id = self.next_delivery;
        self.next_delivery = id
            .checked_add(1)
            .ok_or(Error::Invalid("delivery identity exhausted"))?;
        let deadline = now
            .checked_add(self.config.delivery_timeout)
            .ok_or(Error::Clock)?;
        let envelope = Envelope {
            version: VERSION,
            codec: CODEC,
            cluster_id: self.scope.cluster_id,
            cell_id: self.scope.cell_id,
            cell_incarnation: self.scope.cell_incarnation,
            from_node: message.from,
            to_node: message.to,
            payload: bytes,
        };
        let delivery = Delivery {
            id,
            peer: message.to,
            snapshot,
            envelope,
            deadline,
        };
        let mut shared = self.handle.mailbox.state.lock();
        if shared.closed {
            return Ok(());
        }
        // Feedback has reserved capacity for each accepted attempt. Under
        // pressure, dropping an outgoing Raft message is safe; a subsequent
        // heartbeat retries replication. A dropped snapshot must be released.
        if self.deliveries.len() >= self.config.max_pending_deliveries
            || wire_bytes
                > self
                    .config
                    .max_pending_delivery_bytes
                    .saturating_sub(self.delivery_bytes)
        {
            if snapshot {
                self.latest_snapshot.insert(message.to, (0, term));
            }
            return Ok(());
        }
        self.deliveries.insert(
            id,
            Outstanding {
                peer: message.to,
                snapshot,
                term,
                bytes: wire_bytes,
                deadline,
            },
        );
        self.delivery_bytes += wire_bytes;
        if snapshot {
            self.latest_snapshot.insert(message.to, (id, term));
        }
        shared.live_deliveries.insert(id, ());
        drop(shared);
        if network.try_send(delivery).is_err() {
            self.handle.complete(id, DeliveryResult::Failed);
        }
        Ok(())
    }

    fn feedback(&mut self, now: Instant) -> Result<bool, Error> {
        // A snapshot dropped before reservation still needs explicit failure;
        // otherwise raft-rs can remain in Snapshot progress indefinitely.
        if let Some((&peer, &(_, term))) = self.latest_snapshot.iter().find(|(_, (id, _))| *id == 0)
        {
            self.latest_snapshot.remove(&peer);
            if term == self.driver.status().map_err(driver_error)?.term {
                self.driver
                    .report_snapshot(peer, SnapshotStatus::Failure)
                    .map_err(driver_error)?;
            }
            return Ok(true);
        }
        let Some((id, result)) = self.take_feedback(now) else {
            return Ok(false);
        };
        let Some(delivery) = self.deliveries.remove(&id) else {
            return Ok(true);
        };
        let result = if now >= delivery.deadline {
            DeliveryResult::Failed
        } else {
            result
        };
        self.delivery_bytes -= delivery.bytes;
        let status = self.driver.status().map_err(driver_error)?;
        if delivery.term != status.term || status.role != raft::StateRole::Leader {
            if self.latest_snapshot.get(&delivery.peer) == Some(&(id, delivery.term)) {
                self.latest_snapshot.remove(&delivery.peer);
            }
            return Ok(true);
        }
        if delivery.snapshot {
            if self.latest_snapshot.get(&delivery.peer) != Some(&(id, delivery.term)) {
                return Ok(true);
            }
            self.latest_snapshot.remove(&delivery.peer);
            let snapshot_status = match result {
                DeliveryResult::Received => SnapshotStatus::Finish,
                DeliveryResult::Failed => SnapshotStatus::Failure,
            };
            self.driver
                .report_snapshot(delivery.peer, snapshot_status)
                .map_err(driver_error)?;
        } else if result == DeliveryResult::Failed {
            self.driver
                .report_unreachable(delivery.peer)
                .map_err(driver_error)?;
        }
        Ok(true)
    }

    /// Select and revoke callback admission atomically, before driver work.
    fn take_feedback(&self, now: Instant) -> Option<(u64, DeliveryResult)> {
        let mut shared = self.handle.mailbox.state.lock();
        let next = shared.feedback.pop_first().or_else(|| {
            self.deliveries
                .iter()
                .find(|(_, delivery)| now >= delivery.deadline)
                .map(|(&id, _)| (id, DeliveryResult::Failed))
        });
        if let Some((id, _)) = next {
            // Neither a consumed receipt nor a timeout can be requeued.
            shared.live_deliveries.remove(&id);
        }
        next
    }

    /// The caller owns this dedicated thread and joins it after stop(). The
    /// maximum idle wait is one tick. No disk work executes under the mailbox.
    pub fn run(&mut self, network: &mut impl Network) -> Result<(), Error> {
        while !self.handle.is_stopped() {
            match self.poll(network) {
                Ok(0) => {
                    self.handle.mailbox.wait_for_work();
                }
                Ok(_) => {}
                Err(Error::Closed) => break,
                Err(error) => return Err(error),
            }
        }
        self.close_reads();
        Ok(())
    }

    fn close_reads(&mut self) {
        for (_, pending) in std::mem::take(&mut self.reads) {
            let _ = pending.request.reply.try_send(Err(Error::Closed));
        }
    }
}

impl<D: RaftDriver> Drop for Runtime<D> {
    fn drop(&mut self) {
        self.handle.stop();
        self.close_reads();
    }
}

fn driver_error(error: scap_raft_driver::Error) -> Error {
    match error {
        scap_raft_driver::Error::NotLeader => Error::NotLeader,
        scap_raft_driver::Error::ReadNotReady => Error::ReadNotReady,
        scap_raft_driver::Error::InputLimit | scap_raft_driver::Error::ReadLimit => {
            Error::InputLimit
        }
        other => Error::Driver(other.to_string()),
    }
}

fn codec_error(error: protobuf::ProtobufError) -> Error {
    Error::Driver(error.to_string())
}

fn validate_members(conf: &raft::eraftpb::ConfState, policy: &Policy) -> Result<(), Error> {
    if conf
        .voters
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != *policy.members()
        || !conf.learners.is_empty()
        || !conf.voters_outgoing.is_empty()
        || !conf.learners_next.is_empty()
        || conf.auto_leave
    {
        return Err(Error::Invalid(
            "runtime requires its fixed bootstrap voters",
        ));
    }
    Ok(())
}

impl Mailbox {
    fn wait_for_work(&self) {
        let mut shared = self.state.lock();
        if !shared.closed
            && shared.inbound.is_empty()
            && shared.requests.is_empty()
            && shared.feedback.is_empty()
        {
            self.wake.wait_for(&mut shared, self.config.tick_interval);
        }
    }
}

fn validate_config(config: RuntimeConfig) -> Result<(), Error> {
    for limit in [config.inbox, config.requests] {
        if !(1..=65_536).contains(&limit.max_messages)
            || !(HEADER_BYTES..=1_073_741_824).contains(&limit.max_bytes)
        {
            return Err(Error::Invalid("queue limits"));
        }
    }
    if !(1..=65_536).contains(&config.max_pending_deliveries)
        || !(HEADER_BYTES..=1_073_741_824).contains(&config.max_pending_delivery_bytes)
        || !(1..=65_536).contains(&config.max_pending_reads)
        || !(1..=67_108_864).contains(&config.max_view_bytes)
        || !(1..=65_536).contains(&config.max_poll_rounds)
    {
        return Err(Error::Invalid("runtime limits"));
    }
    if config.max_view_bytes.saturating_add(256) > config.requests.max_bytes {
        return Err(Error::Invalid("request budget cannot hold a read view"));
    }
    for interval in [
        config.tick_interval,
        config.delivery_timeout,
        config.max_inbound_age,
    ] {
        if interval.is_zero() || interval > Duration::from_secs(60) {
            return Err(Error::Invalid("runtime time budget"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
