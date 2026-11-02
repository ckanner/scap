//! Bounded background archival. SQL maintenance only enqueues and polls; it
//! never waits for object I/O. Foreground cold hydration retains its caller's
//! original budget. Every queued job keeps its exact owner/head and deadline.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use scap_archive::{Controller, Objects};
use scap_cell::DatabaseView;
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
    sender: Option<SyncSender<Job>>,
    completions: Receiver<Completion>,
    entries: BTreeMap<u128, Entry>,
    max_databases: usize,
    control: Arc<Control>,
}

impl Queue {
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
        let Some(sender) = &self.sender else {
            return Ok(());
        };
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
        match sender.try_send(job) {
            Ok(()) => {
                self.entries.insert(id, entry);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Disconnected(_)) => Err(failure("ARCHIVE_STOPPED")),
        }
    }
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
    fn run(&mut self, job: &Job) -> Result<(), ServiceError>;
}

struct BoundRunner<P, S>(Controller<P, S>);
impl<P: ControlPort + Send, S: Objects + Send> Runner for BoundRunner<P, S> {
    fn run(&mut self, job: &Job) -> Result<(), ServiceError> {
        let archive = self
            .0
            .publish_bound(&job.context, job.database.clone(), job.publish)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))?;
        self.0
            .prune_bound(&job.context, job.database.clone(), archive, job.prune)
            .map_err(|_| failure("ARCHIVE_UNAVAILABLE"))
    }
}

/// Only the channel and timeout mechanism live behind this port; scheduling,
/// cancellation, source binding and checkpoint decisions stay in production.
trait Bus {
    fn receive(&mut self) -> Result<Job, RecvTimeoutError>;
    fn complete(&mut self, completion: Completion) -> bool;
}

struct NativeBus {
    jobs: Receiver<Job>,
    completions: SyncSender<Completion>,
}
impl Bus for NativeBus {
    fn receive(&mut self) -> Result<Job, RecvTimeoutError> {
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
        if !control.activate(&job.context.cancelled) {
            break;
        }
        let completed = runner.run(&job).is_ok();
        control.clear();
        if !bus.complete(Completion {
            database: job.database.identity.database_id,
            prune: job.prune,
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
            max_databases,
            control,
        },
        supervisor,
    ))
}

pub(crate) struct Jobs<P, S> {
    foreground: Option<Controller<P, S>>,
    queue: Queue,
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
    let foreground = objects
        .clone()
        .map(|objects| Controller::new(client.clone(), objects));
    let runner = objects
        .map(|objects| Box::new(BoundRunner(Controller::new(client, objects))) as Box<dyn Runner>);
    let (queue, supervisor) = start(runner, max_databases, native_spawn)?;
    Ok((
        Jobs {
            foreground,
            queue,
            clock,
        },
        supervisor,
    ))
}

impl<P: ControlPort, S: Objects> ColdStorage<P> for Jobs<P, S> {
    fn poll(&mut self) -> bool {
        self.queue.poll()
    }
    fn hydrate(
        &mut self,
        _: &mut Client<P>,
        context: &RequestContext,
        database: &DatabaseView,
        operation: u128,
    ) -> Result<(), ServiceError> {
        self.foreground
            .as_mut()
            .ok_or_else(|| failure("ARCHIVE_UNAVAILABLE"))?
            .hydrate(context, database.identity, operation)
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
        self.queue.enqueue(
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
