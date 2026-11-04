//! Lazy, bounded, thread-confined execution by database. A slow recovery or
//! native call can occupy its own lane without blocking other databases. The
//! dispatcher never transfers an open SQLite connection between threads.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use scap_service::ServiceError;
use sha2::{Digest, Sha256};

use crate::config::DatabaseConfig;
use crate::failure;
use crate::mailbox::{Envelope, MAX_DATABASE_QUEUED};
use crate::worker::{ColdStorage, ControlPort, Reply, Request, Worker};

pub(crate) const MAX_LANES: usize = 32;
const RECEIVE_INTERVAL: Duration = Duration::from_millis(50);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

/// Operations are constructed and consumed inside the owning thread. The
/// executor itself is deliberately not Send: native SQLite remains confined.
pub(crate) trait Executor {
    fn tick(&mut self);
    fn request(&mut self, request: Request) -> Result<Reply, ServiceError>;
    fn dormant(&self) -> bool;
}

impl<P, F, C> Executor for Worker<P, F, C>
where
    P: ControlPort,
    F: scap_sql_worker::EngineFactory<P>,
    C: ColdStorage<P>,
{
    fn tick(&mut self) {
        let _ = Worker::tick(self);
    }
    fn request(&mut self, request: Request) -> Result<Reply, ServiceError> {
        Worker::request(self, request)
    }
    fn dormant(&self) -> bool {
        Worker::dormant(self)
    }
}

pub(crate) type Build = Box<dyn FnOnce() -> Result<Box<dyn Executor>, ServiceError> + Send>;
pub(crate) type Prepare = Box<dyn FnMut(DatabaseConfig, u128) -> Build>;
type Spawn = fn(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>;

struct State {
    accepting: bool,
    pending: VecDeque<Box<Envelope>>,
    active: Option<Arc<AtomicBool>>,
}

struct Queue {
    state: Mutex<State>,
    wake: Condvar,
}

enum Next {
    Request(Box<Envelope>),
    Poll,
    Stop,
}

impl Queue {
    fn new() -> Self {
        Self {
            state: Mutex::new(State {
                accepting: true,
                pending: VecDeque::new(),
                active: None,
            }),
            wake: Condvar::new(),
        }
    }

    fn send(&self, envelope: Envelope) -> Option<Envelope> {
        let mut state = self.state.lock();
        if !state.accepting {
            return Some(envelope);
        }
        if state.pending.len() >= MAX_DATABASE_QUEUED {
            let _ = envelope.reply.send(Err(failure("OVERLOADED")));
            return None;
        }
        state.pending.push_back(Box::new(envelope));
        self.wake.notify_one();
        None
    }

    fn next(&self, dormant: bool) -> Next {
        let mut state = self.state.lock();
        if !state.accepting {
            return Next::Stop;
        }
        if let Some(envelope) = state.pending.pop_front() {
            state.active = Some(envelope.request.context.cancelled.clone());
            return Next::Request(envelope);
        }
        // Dispatch and retirement use the same lock. There is no interval in
        // which a request can be accepted after the empty-queue decision.
        if dormant {
            state.accepting = false;
            return Next::Stop;
        }
        self.wake.wait_for(&mut state, RECEIVE_INTERVAL);
        Next::Poll
    }

    fn complete(&self) {
        self.state.lock().active = None;
    }

    fn stop(&self) {
        let mut state = self.state.lock();
        state.accepting = false;
        if let Some(active) = state.active.take() {
            active.store(true, Ordering::Release);
        }
        for envelope in state.pending.drain(..) {
            envelope
                .request
                .context
                .cancelled
                .store(true, Ordering::Release);
        }
        self.wake.notify_one();
    }
}

struct Close(Arc<Queue>);
impl Drop for Close {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Admitted requests that arrived after the old queue retired. Keep their
/// original reservation outside that queue's close guard until a joined,
/// successful owner can hand them to one fresh execution lane.
#[derive(Default)]
struct Deferred(VecDeque<Envelope>);

impl Deferred {
    fn send(&mut self, envelope: Envelope) {
        if self.0.len() >= MAX_DATABASE_QUEUED {
            let _ = envelope.reply.send(Err(failure("OVERLOADED")));
        } else {
            self.0.push_back(envelope);
        }
    }

    fn expire(&mut self, now: Instant) {
        for envelope in std::mem::take(&mut self.0) {
            let context = &envelope.request.context;
            if context.cancelled.load(Ordering::Acquire) || now >= context.deadline {
                let _ = envelope.reply.send(Err(failure("COMMIT_UNKNOWN")));
            } else {
                self.0.push_back(envelope);
            }
        }
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        for envelope in &self.0 {
            envelope
                .request
                .context
                .cancelled
                .store(true, Ordering::Release);
        }
    }
}

struct Lane {
    queue: Arc<Queue>,
    thread: JoinHandle<()>,
    result: mpsc::Receiver<Result<(), ServiceError>>,
    deferred: Deferred,
}

impl Lane {
    fn join(self) -> Result<Deferred, ServiceError> {
        self.thread
            .join()
            .map_err(|_| failure("SQL_LANE_PANICKED"))?;
        self.result
            .recv()
            .map_err(|_| failure("SQL_LANE_STOPPED"))??;
        Ok(self.deferred)
    }
}

fn native_spawn(task: Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("scap-sql-db".into())
        .spawn(task)
}

fn run(executor: &mut dyn Executor, queue: &Queue, stopped: &AtomicBool) {
    let mut maintenance = Instant::now();
    while !stopped.load(Ordering::Acquire) {
        if Instant::now() >= maintenance {
            executor.tick();
            maintenance = Instant::now() + MAINTENANCE_INTERVAL;
        }
        match queue.next(executor.dormant()) {
            Next::Request(envelope) => {
                let envelope = *envelope;
                let result = executor.request(envelope.request);
                queue.complete();
                let _ = envelope.reply.send(result);
            }
            Next::Poll => (),
            Next::Stop => break,
        }
    }
}

/// Every live or retiring thread remains owned until join completes. Retiring
/// work still occupies capacity; replacement cannot overlap its native writer.
/// A cold catalogue entry consumes no lane after its writer is suspended.
pub(crate) struct Lanes {
    boot: u128,
    sequence: u64,
    limit: usize,
    prepare: Prepare,
    spawn: Spawn,
    stopped: Arc<AtomicBool>,
    lanes: BTreeMap<u128, Lane>,
}

impl Lanes {
    pub(crate) fn new(
        boot: u128,
        stopped: Arc<AtomicBool>,
        prepare: Prepare,
    ) -> Result<Self, ServiceError> {
        Self::with_spawn(boot, stopped, prepare, MAX_LANES, native_spawn)
    }

    pub(crate) fn with_spawn(
        boot: u128,
        stopped: Arc<AtomicBool>,
        prepare: Prepare,
        limit: usize,
        spawn: Spawn,
    ) -> Result<Self, ServiceError> {
        if boot == 0 || limit == 0 || limit > MAX_LANES {
            return Err(failure("SQL_LANE_CONFIG"));
        }
        Ok(Self {
            boot,
            sequence: 0,
            limit,
            prepare,
            spawn,
            stopped,
            lanes: BTreeMap::new(),
        })
    }

    fn identity(&mut self, database: u128) -> Result<u128, ServiceError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure("IDENTITY_EXHAUSTED"))?;
        let mut hash = Sha256::new();
        hash.update(b"SCAP SQL lane v1");
        hash.update(self.boot.to_le_bytes());
        hash.update(database.to_le_bytes());
        hash.update(self.sequence.to_le_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        Ok(u128::from_le_bytes(digest[..16].try_into().unwrap()) | 1)
    }

    fn start(
        &mut self,
        database: DatabaseConfig,
        mut pending: Deferred,
    ) -> Result<(), ServiceError> {
        let id = database.identity.database_id;
        let boot = self.identity(id)?;
        let build = (self.prepare)(database, boot);
        let queue = Arc::new(Queue::new());
        for envelope in pending.0.drain(..) {
            // This new queue is not exposed to its thread until all handed-off
            // work has been installed in the original FIFO order.
            let _ = queue.send(envelope);
        }
        let (result, received) = mpsc::sync_channel(1);
        let owner = queue.clone();
        let stopped = self.stopped.clone();
        // The close guard is created before spawn: a failed spawn or skipped
        // task also cancels and releases every queued reservation.
        let close = Close(owner.clone());
        let thread = (self.spawn)(Box::new(move || {
            let _close = close;
            let outcome = build().map(|mut executor| run(&mut *executor, &owner, &stopped));
            let _ = result.send(outcome);
        }))
        .map_err(|_| failure("SQL_LANE_SPAWN"))?;
        self.lanes.insert(
            id,
            Lane {
                queue,
                thread,
                result: received,
                deferred: Deferred::default(),
            },
        );
        Ok(())
    }

    pub(crate) fn dispatch(&mut self, envelope: Envelope) -> Result<(), ServiceError> {
        let context = &envelope.request.context;
        if self.stopped.load(Ordering::Acquire)
            || context.cancelled.load(Ordering::Acquire)
            || Instant::now() >= context.deadline
        {
            let _ = envelope.reply.send(Err(failure("COMMIT_UNKNOWN")));
            return Ok(());
        }
        let id = envelope.request.database.identity.database_id;
        if let Some(lane) = self.lanes.get_mut(&id) {
            if let Some(envelope) = lane.queue.send(envelope) {
                lane.deferred.send(envelope);
            }
            return Ok(());
        }
        if self.lanes.len() >= self.limit {
            let _ = envelope.reply.send(Err(failure("OVERLOADED")));
            return Ok(());
        }
        self.start(
            envelope.request.database.clone(),
            Deferred(VecDeque::from([envelope])),
        )
    }

    /// Background recovery is best effort under the same lane capacity. It
    /// never queues behind an already running lane or wakes a suspended entry.
    pub(crate) fn recover(&mut self, database: DatabaseConfig) -> Result<(), ServiceError> {
        if self.stopped.load(Ordering::Acquire)
            || self.lanes.contains_key(&database.identity.database_id)
            || self.lanes.len() >= self.limit
        {
            return Ok(());
        }
        self.start(database, Deferred::default())
    }

    /// Join only completed threads on the dispatch path. A retiring lane keeps
    /// admitted work bounded and cancellable without stalling other databases.
    pub(crate) fn reap(&mut self) -> Result<(), ServiceError> {
        self.reap_at(Instant::now())
    }

    fn reap_at(&mut self, now: Instant) -> Result<(), ServiceError> {
        for lane in self.lanes.values_mut() {
            lane.deferred.expire(now);
        }
        let completed: Vec<_> = self
            .lanes
            .iter()
            .filter_map(|(id, lane)| lane.thread.is_finished().then_some(*id))
            .collect();
        for id in completed {
            let pending = self.lanes.remove(&id).unwrap().join()?;
            if let Some(first) = pending.0.front() {
                self.start(first.request.database.clone(), pending)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), ServiceError> {
        for lane in self.lanes.values_mut() {
            lane.queue.stop();
            // Cancel every lane's handoff before waiting for any native drop.
            drop(std::mem::take(&mut lane.deferred));
        }
        let mut failed = None;
        for lane in std::mem::take(&mut self.lanes).into_values() {
            if let Err(error) = lane.join() {
                failed = Some(error);
            }
        }
        failed.map_or(Ok(()), Err)
    }
}

impl Drop for Lanes {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests;
