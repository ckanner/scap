//! Bounded worker queues with tenant/database round-robin and control space.

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::{auth::Principal, wire::Call, Failure};

pub trait Worker {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure>;
}

impl Worker for crate::engine::Engine {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.execute(principal, call, deadline)
    }
}

pub type Factory = Arc<dyn Fn(usize) -> Result<Box<dyn Worker>, Failure> + Send + Sync>;

#[derive(Clone, Copy)]
pub struct Limits {
    pub workers: usize,
    pub control_workers: usize,
    pub queued_per_worker: usize,
    pub queued_per_tenant: usize,
    pub queued_per_database: usize,
    pub reserved_controls: usize,
}

struct Job {
    principal: Principal,
    call: Call,
    deadline: Instant,
    reply: oneshot::Sender<Result<Value, Failure>>,
}

struct DatabaseQueue {
    key: String,
    normal: VecDeque<Job>,
    controls: VecDeque<Job>,
    controls_taken: u8,
}

impl DatabaseQueue {
    fn len(&self) -> usize {
        self.normal.len() + self.controls.len()
    }
}

struct Group {
    tenant: (u64, u64),
    databases: VecDeque<DatabaseQueue>,
}

impl Group {
    fn len(&self) -> usize {
        self.databases.iter().map(DatabaseQueue::len).sum()
    }
    fn normal(&self) -> usize {
        self.databases
            .iter()
            .map(|database| database.normal.len())
            .sum()
    }
}

#[derive(Default)]
struct Queue {
    groups: VecDeque<Group>,
    closed: bool,
}

impl Queue {
    fn push(&mut self, job: Job, limits: Limits) -> Result<(), Failure> {
        if self.closed {
            return Err(Failure::new("UNAVAILABLE"));
        }
        let key = scap_object::format::head_key(&job.call.scope.native()?);
        let queued = self.groups.iter().map(Group::len).sum::<usize>();
        let normal = self.groups.iter().map(Group::normal).sum::<usize>();
        let priority = job.call.action.priority();
        if queued >= limits.queued_per_worker
            || (!priority && normal >= limits.queued_per_worker - limits.reserved_controls)
        {
            return Err(Failure::new("BACKPRESSURE"));
        }
        let tenant = (job.principal.deployment, job.principal.tenant);
        let position = match self.groups.iter().position(|group| group.tenant == tenant) {
            Some(position) => position,
            None => {
                self.groups.push_back(Group {
                    tenant,
                    databases: VecDeque::new(),
                });
                self.groups.len() - 1
            }
        };
        let group = &mut self.groups[position];
        if group.len() >= limits.queued_per_tenant
            || (!priority && group.normal() >= limits.queued_per_tenant - limits.reserved_controls)
        {
            return Err(Failure::new("BACKPRESSURE"));
        }
        let position = match group
            .databases
            .iter()
            .position(|database| database.key == key)
        {
            Some(position) => position,
            None => {
                group.databases.push_back(DatabaseQueue {
                    key,
                    normal: VecDeque::new(),
                    controls: VecDeque::new(),
                    controls_taken: 0,
                });
                group.databases.len() - 1
            }
        };
        let database = &mut group.databases[position];
        if database.len() >= limits.queued_per_database
            || (!priority
                && database.normal.len() >= limits.queued_per_database - limits.reserved_controls)
        {
            return Err(Failure::new("BACKPRESSURE"));
        }
        if priority {
            database.controls.push_back(job);
        } else {
            database.normal.push_back(job);
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<Job> {
        let mut group = self.groups.pop_front()?;
        let mut database = group.databases.pop_front().expect("nonempty tenant queue");
        let job = if !database.controls.is_empty()
            && (database.controls_taken < 3 || database.normal.is_empty())
        {
            database.controls_taken = database.controls_taken.saturating_add(1);
            database.controls.pop_front()
        } else {
            database.controls_taken = 0;
            database.normal.pop_front()
        };
        if database.len() != 0 {
            group.databases.push_back(database);
        }
        if !group.databases.is_empty() {
            self.groups.push_back(group);
        }
        job
    }
}

#[derive(Default)]
struct Lane {
    queue: Mutex<Queue>,
    changed: Condvar,
}

impl Lane {
    fn close(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        queue.closed = true;
        while let Some(job) = queue.pop() {
            let _ = job.reply.send(Err(Failure::new("UNAVAILABLE")));
        }
        self.changed.notify_all();
    }

    fn next(&self) -> Option<Job> {
        let mut queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        loop {
            if queue.closed {
                return None;
            }
            if let Some(job) = queue.pop() {
                return Some(job);
            }
            queue = self
                .changed
                .wait(queue)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

struct CloseOnExit(Arc<Lane>);
impl Drop for CloseOnExit {
    fn drop(&mut self) {
        self.0.close();
    }
}

pub struct Scheduler {
    lanes: Vec<Arc<Lane>>,
    threads: Vec<JoinHandle<()>>,
    limits: Limits,
}

type Task = Box<dyn FnOnce() + Send>;
type Spawn = fn(Task) -> std::io::Result<JoinHandle<()>>;

fn spawn(task: Task) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("scap-worker".to_owned())
        .spawn(task)
}

impl Scheduler {
    /// Factories execute inside dedicated threads, where !Send SQLite sessions
    /// can be created, used and dropped without entering a Tokio context.
    pub fn new(limits: Limits, factory: Factory) -> Result<Self, Failure> {
        Self::with_spawner(limits, factory, spawn)
    }

    fn with_spawner(limits: Limits, factory: Factory, spawn: Spawn) -> Result<Self, Failure> {
        if limits.workers == 0
            || limits.workers > 256
            || limits.control_workers == 0
            || limits.control_workers > 256 - limits.workers
            || limits.queued_per_worker == 0
            || limits.queued_per_tenant == 0
            || limits.queued_per_tenant > limits.queued_per_worker
            || limits.queued_per_database == 0
            || limits.queued_per_database > limits.queued_per_tenant
            || limits.reserved_controls == 0
            || limits.reserved_controls >= limits.queued_per_database
        {
            return Err(Failure::new("CONFIG"));
        }
        let mut scheduler = Self {
            lanes: Vec::new(),
            threads: Vec::new(),
            limits,
        };
        for index in 0..limits.workers + limits.control_workers {
            let lane = Arc::new(Lane::default());
            scheduler.lanes.push(lane.clone());
            let factory = factory.clone();
            let (started, ready) = mpsc::sync_channel(1);
            scheduler.threads.push(
                spawn(Box::new(move || {
                    let _close = CloseOnExit(lane.clone());
                    let mut worker = match factory(index) {
                        Ok(worker) => {
                            let _ = started.send(Ok(()));
                            worker
                        }
                        Err(error) => {
                            let _ = started.send(Err(error));
                            return;
                        }
                    };
                    while let Some(job) = lane.next() {
                        if job.reply.is_closed() {
                            continue;
                        }
                        let result = if Instant::now() >= job.deadline {
                            Err(Failure::new("DEADLINE"))
                        } else {
                            worker.execute(&job.principal, job.call, job.deadline)
                        };
                        let _ = job.reply.send(result);
                    }
                }))
                .map_err(|_| Failure::new("UNAVAILABLE"))?,
            );
            ready.recv().map_err(|_| Failure::new("UNAVAILABLE"))??;
        }
        Ok(scheduler)
    }

    pub fn submit(
        &self,
        principal: Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Result<Value, Failure>>, Failure> {
        let scope = call.scope.native()?;
        principal.authorize(&scope)?;
        let hash = Sha256::digest(scap_object::format::head_key(&scope).as_bytes());
        let hash = u64::from_le_bytes(hash[..8].try_into().expect("eight bytes")) as usize;
        // Lookup/cancel and metadata transitions never need a confined native
        // connection. Their separate lanes remain available during hydration.
        let index = if call.action.admission() == "control" {
            self.limits.workers + hash % self.limits.control_workers
        } else {
            hash % self.limits.workers
        };
        let lane = &self.lanes[index];
        let (reply, receiver) = oneshot::channel();
        lane.queue
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(
                Job {
                    principal,
                    call,
                    deadline,
                    reply,
                },
                self.limits,
            )?;
        lane.changed.notify_one();
        Ok(receiver)
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        for lane in &self.lanes {
            lane.close();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests;
