//! Bounded background archival. SQL maintenance only enqueues and polls; it
//! never waits for object I/O. Foreground cold hydration retains its caller's
//! original budget. Every queued job keeps its exact owner/head and deadline.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{ArcMutexGuard, Mutex, RawMutex};
use scap_archive::{Controller, Objects};
use scap_cell::{DatabaseIdentity, DatabaseView};
use scap_cell_client::{Client, RequestContext};
use scap_raft_runtime::Clock;
use scap_service::ServiceError;
use tokio::sync::oneshot;

use crate::config::cell_limits;
use crate::failure;
use crate::worker::{ColdStorage, ControlPort};

const MAX_PENDING: usize = 8;
const RETRY_BACKOFF: Duration = Duration::from_secs(5);
const RECEIVE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
struct Job {
    database: DatabaseView,
    context: RequestContext,
    publish: u128,
    prune: u128,
}

struct QueuedJob {
    request: Job,
    gate: Arc<Mutex<()>>,
}

struct Completion {
    database: u128,
    prune: u128,
    completed: bool,
}

struct Entry {
    pending: Option<u128>,
    deadline: Instant,
    retry_after: Option<Instant>,
}

/// One entry per configured database, including failures in backoff. No object
/// bytes, SQL, or unbounded error strings enter either channel or this table.
struct Queue {
    sender: Option<SyncSender<QueuedJob>>,
    completions: Receiver<Completion>,
    entries: BTreeMap<u128, Entry>,
    gates: BTreeMap<u128, Arc<Mutex<()>>>,
    max_databases: usize,
    control: Arc<Control>,
}

impl Queue {
    /// Never evict a gate: replacing one while an old guard exists would split
    /// the exclusion boundary. Database IDs also serialize old incarnations.
    fn gate(&mut self, database: u128) -> Option<Arc<Mutex<()>>> {
        if let Some(gate) = self.gates.get(&database) {
            return Some(gate.clone());
        }
        if self.gates.len() >= self.max_databases {
            return None;
        }
        let gate = Arc::new(Mutex::new(()));
        self.gates.insert(database, gate.clone());
        Some(gate)
    }

    fn poll(&mut self) -> bool {
        let mut checkpoint = false;
        while let Ok(completion) = self.completions.try_recv() {
            if let Some(entry) = self.entries.get_mut(&completion.database) {
                if entry.pending == Some(completion.prune) {
                    entry.pending = None;
                    entry.retry_after = if completion.completed {
                        checkpoint = true;
                        None
                    } else {
                        Some(entry.deadline + RETRY_BACKOFF)
                    };
                }
            }
        }
        checkpoint
    }

    fn enqueue(&mut self, job: Job, now: Instant) -> Result<(), ServiceError> {
        if self.sender.is_none() {
            return Ok(());
        }
        if self.control.stopped.load(Ordering::Acquire) {
            return Err(failure("ARCHIVE_STOPPED"));
        }
        if job.context.cancelled.load(Ordering::Acquire) || now >= job.context.deadline {
            return Err(failure("COMMIT_UNKNOWN"));
        }
        let id = job.database.identity.database_id;
        if let Some(entry) = self.entries.get(&id) {
            if entry.pending.is_some() || entry.retry_after.is_some_and(|retry| now < retry) {
                return Ok(());
            }
        } else if self.entries.len() >= self.max_databases {
            return Ok(());
        }
        if self
            .entries
            .values()
            .filter(|entry| entry.pending.is_some())
            .count()
            >= MAX_PENDING
        {
            return Ok(());
        }
        let entry = Entry {
            pending: Some(job.prune),
            deadline: job.context.deadline,
            retry_after: None,
        };
        let Some(gate) = self.gate(id) else {
            return Ok(());
        };
        match self
            .sender
            .as_ref()
            .unwrap()
            .try_send(QueuedJob { request: job, gate })
        {
            Ok(()) => {
                self.entries.insert(id, entry);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Disconnected(_)) => Err(failure("ARCHIVE_STOPPED")),
        }
    }
}

fn live_gate(context: &RequestContext, clock: &dyn Clock) -> Result<(), ServiceError> {
    if context.cancelled.load(Ordering::Acquire)
        || clock.now().map_err(|_| failure("CLOCK"))?.instant >= context.deadline
    {
        return Err(failure("COMMIT_UNKNOWN"));
    }
    Ok(())
}

/// Cancellation is checked before and after the bounded mutex wait. It does
/// not interrupt the wait or renew the caller's original absolute deadline.
fn acquire_gate<G>(
    context: &RequestContext,
    clock: &dyn Clock,
    acquire: impl FnOnce(Instant) -> Option<G>,
) -> Result<G, ServiceError> {
    live_gate(context, clock)?;
    let guard = acquire(context.deadline).ok_or_else(|| failure("COMMIT_UNKNOWN"))?;
    live_gate(context, clock)?;
    Ok(guard)
}

#[derive(Default)]
struct Control {
    stopped: AtomicBool,
    active: Mutex<Option<Arc<AtomicBool>>>,
}

impl Control {
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(cancelled) = self.active.lock().as_ref() {
            cancelled.store(true, Ordering::Release);
        }
    }

    fn activate(&self, cancelled: &Arc<AtomicBool>) -> bool {
        *self.active.lock() = Some(cancelled.clone());
        !self.stopped.load(Ordering::Acquire)
    }

    fn clear(&self) {
        *self.active.lock() = None;
    }
}

trait Runner: Send {
    fn run(&mut self, job: &QueuedJob) -> Result<(), ServiceError>;
}

struct BoundRunner<P, S> {
    controller: Controller<P, S>,
    clock: Arc<dyn Clock>,
}
impl<P: ControlPort + Send, S: Objects + Send> Runner for BoundRunner<P, S> {
    fn run(&mut self, queued: &QueuedJob) -> Result<(), ServiceError> {
        let job = &queued.request;
        let _guard = acquire_gate(&job.context, self.clock.as_ref(), |deadline| {
            queued.gate.try_lock_until(deadline)
        })?;
        let archive = self
            .controller
            .publish_bound(&job.context, job.database.clone(), job.publish)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))?;
        self.controller
            .prune_bound(&job.context, job.database.clone(), archive, job.prune)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))
    }
}

/// Only the channel and timeout mechanism live behind this port; scheduling,
/// cancellation, source binding and checkpoint decisions stay in production.
trait Bus {
    fn receive(&mut self) -> Result<QueuedJob, RecvTimeoutError>;
    fn complete(&mut self, completion: Completion) -> bool;
}

struct NativeBus {
    jobs: Receiver<QueuedJob>,
    completions: SyncSender<Completion>,
}
impl Bus for NativeBus {
    fn receive(&mut self) -> Result<QueuedJob, RecvTimeoutError> {
        self.jobs.recv_timeout(RECEIVE_INTERVAL)
    }
    fn complete(&mut self, completion: Completion) -> bool {
        self.completions.try_send(completion).is_ok()
    }
}

fn run_worker(mut runner: Box<dyn Runner>, bus: &mut dyn Bus, control: &Control) {
    while !control.stopped.load(Ordering::Acquire) {
        let job = match bus.receive() {
            Ok(job) => job,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if !control.activate(&job.request.context.cancelled) {
            break;
        }
        let completed = runner.run(&job).is_ok();
        control.clear();
        if !bus.complete(Completion {
            database: job.request.database.identity.database_id,
            prune: job.request.prune,
            completed,
        }) {
            break;
        }
    }
    control.clear();
}

struct Exited(Option<oneshot::Sender<()>>);
impl Drop for Exited {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

type Spawn = fn(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>;
fn native_spawn(task: Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("scap-archive".into())
        .spawn(task)
}

/// Owns the background thread. Normal shutdown requests stop before joining on
/// a blocking supervisor thread. Drop is a final synchronous leak-prevention
/// guard. Production I/O retains the original (currently two-second) deadline;
/// shutdown does not renew it. Thread scheduling is not a hard time guarantee.
pub(crate) struct Supervisor {
    thread: Option<JoinHandle<()>>,
    control: Arc<Control>,
    done: Option<oneshot::Receiver<()>>,
}
impl Supervisor {
    pub(crate) fn request_stop(&self) {
        self.control.stop();
    }

    pub(crate) async fn completed(&mut self) {
        if let Some(done) = &mut self.done {
            let _ = done.await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    pub(crate) fn join(mut self) -> Result<(), ServiceError> {
        self.request_stop();
        self.thread
            .take()
            .map(|handle| handle.join())
            .transpose()
            .map_err(|_| failure("ARCHIVE_PANICKED"))?;
        Ok(())
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn start(
    runner: Option<Box<dyn Runner>>,
    max_databases: usize,
    spawn: Spawn,
) -> Result<(Queue, Supervisor), ServiceError> {
    if max_databases == 0 || max_databases > cell_limits().max_databases as usize {
        return Err(failure("ARCHIVE_CAPACITY"));
    }
    let (sender, jobs) = mpsc::sync_channel(MAX_PENDING);
    let (complete, completions) = mpsc::sync_channel(MAX_PENDING);
    let control = Arc::new(Control::default());
    let mut supervisor = Supervisor {
        thread: None,
        control: control.clone(),
        done: None,
    };
    let sender = if let Some(runner) = runner {
        let (finished, done) = oneshot::channel();
        let worker_control = control.clone();
        let handle = spawn(Box::new(move || {
            let _exit = Exited(Some(finished));
            run_worker(
                runner,
                &mut NativeBus {
                    jobs,
                    completions: complete,
                },
                &worker_control,
            );
        }))
        .map_err(|_| failure("ARCHIVE_SPAWN"))?;
        supervisor.thread = Some(handle);
        supervisor.done = Some(done);
        Some(sender)
    } else {
        None
    };
    Ok((
        Queue {
            sender,
            completions,
            entries: BTreeMap::new(),
            gates: BTreeMap::new(),
            max_databases,
            control,
        },
        supervisor,
    ))
}

#[derive(Clone)]
pub(crate) struct Jobs<P, S> {
    client: Client<P>,
    foreground: Option<S>,
    // Enqueue/poll hold this lock only for bounded in-memory bookkeeping. No
    // S3 or cell request runs while it is held. Every SQL lane therefore has
    // independent foreground hydration but shares one archival owner.
    queue: Arc<Mutex<Queue>>,
    clock: Arc<dyn Clock>,
}

/// Spawn at most one supervised archive thread. Disabling S3 creates none.
/// max_databases bounds retry metadata independently of the eight-job queue.
pub(crate) fn spawn<P, S>(
    client: Client<P>,
    objects: Option<S>,
    max_databases: usize,
    clock: Arc<dyn Clock>,
) -> Result<(Jobs<P, S>, Supervisor), ServiceError>
where
    P: ControlPort + Send,
    S: Objects + Clone + Send + 'static,
{
    let foreground = objects.clone();
    let runner = objects.map(|objects| {
        Box::new(BoundRunner {
            controller: Controller::new(client.clone(), objects),
            clock: clock.clone(),
        }) as Box<dyn Runner>
    });
    let (queue, supervisor) = start(runner, max_databases, native_spawn)?;
    Ok((
        Jobs {
            client,
            foreground,
            queue: Arc::new(Mutex::new(queue)),
            clock,
        },
        supervisor,
    ))
}

impl<P: ControlPort, S: Objects + Clone> ColdStorage<P> for Jobs<P, S> {
    type RecoveryGuard = Option<ArcMutexGuard<RawMutex, ()>>;

    fn recovery_guard(
        &mut self,
        database: DatabaseIdentity,
        context: &RequestContext,
    ) -> Result<Self::RecoveryGuard, ServiceError> {
        let gate = {
            let mut queue = self.queue.lock();
            if queue.sender.is_none() {
                return Ok(None);
            }
            if queue.control.stopped.load(Ordering::Acquire) {
                return Err(failure("ARCHIVE_STOPPED"));
            }
            queue
                .gate(database.database_id)
                .ok_or_else(|| failure("ARCHIVE_CAPACITY"))?
        };
        // The bookkeeping mutex is released before any wait. The owned guard
        // survives hydrate and the complete Claim/Activate sequence in Worker.
        acquire_gate(context, self.clock.as_ref(), |deadline| {
            gate.try_lock_arc_until(deadline)
        })
        .map(Some)
    }

    fn poll(&mut self) -> bool {
        self.queue.lock().poll()
    }
    fn hydrate(
        &mut self,
        _: &mut Client<P>,
        context: &RequestContext,
        database: &DatabaseView,
        operation: u128,
    ) -> Result<(), ServiceError> {
        let objects = self
            .foreground
            .clone()
            .ok_or_else(|| failure("ARCHIVE_UNAVAILABLE"))?;
        Controller::new(self.client.clone(), objects)
            .hydrate_bound(context, database.clone(), operation)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))
    }
    fn archive(
        &mut self,
        _: &mut Client<P>,
        context: &RequestContext,
        database: &DatabaseView,
        publish: u128,
        prune: u128,
    ) -> Result<bool, ServiceError> {
        let now = self.clock.now().map_err(|_| failure("CLOCK"))?.instant;
        self.queue.lock().enqueue(
            Job {
                database: database.clone(),
                context: context.clone(),
                publish,
                prune,
            },
            now,
        )?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests;
