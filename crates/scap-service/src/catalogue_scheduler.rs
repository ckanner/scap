//! A separate, globally bounded catalogue queue. No SQL/control lane is borrowed.

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use serde_json::Value;
use tokio::sync::oneshot;

use crate::{auth::Principal, catalogue_wire::Call, Failure};

pub trait Worker {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure>;
}

impl Worker for crate::catalogue::Worker {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        crate::catalogue::Worker::execute(self, principal, call, deadline)
    }
}

pub type Factory = Arc<dyn Fn(usize) -> Result<Box<dyn Worker>, Failure> + Send + Sync>;

#[derive(Clone, Copy)]
pub struct Limits {
    pub workers: usize,
    pub queued_total: usize,
    pub queued_per_tenant: usize,
    pub queued_per_name: usize,
}

impl Limits {
    pub fn validate(self) -> Result<(), Failure> {
        if !(1..=32).contains(&self.workers)
            || !(1..=65536).contains(&self.queued_total)
            || !(1..=self.queued_total).contains(&self.queued_per_tenant)
            || !(1..=self.queued_per_tenant).contains(&self.queued_per_name)
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }
}

struct Job {
    principal: Principal,
    call: Call,
    deadline: Instant,
    reply: oneshot::Sender<Result<Value, Failure>>,
}

struct NameQueue {
    name: Option<String>,
    jobs: VecDeque<Job>,
}

struct TenantQueue {
    tenant: (u64, u64),
    names: VecDeque<NameQueue>,
}

impl TenantQueue {
    fn len(&self) -> usize {
        self.names.iter().map(|queue| queue.jobs.len()).sum()
    }

    fn name_cost(&self, name: Option<&str>) -> usize {
        let unknown = self
            .names
            .iter()
            .find(|queue| queue.name.is_none())
            .map_or(0, |queue| queue.jobs.len());
        let known = match name {
            Some(name) => self
                .names
                .iter()
                .find(|queue| queue.name.as_deref() == Some(name))
                .map_or(0, |queue| queue.jobs.len()),
            None => self
                .names
                .iter()
                .filter(|queue| queue.name.is_some())
                .map(|queue| queue.jobs.len())
                .max()
                .unwrap_or(0),
        };
        // An inspection has no authenticated name until its descriptor read.
        // Reserve its cost against every possible name in the tenant, so
        // changing operation IDs cannot evade the same-name queue limit.
        known + unknown
    }
}

#[derive(Default)]
struct Queue {
    tenants: VecDeque<TenantQueue>,
    closed: bool,
}

impl Queue {
    fn push(&mut self, job: Job, limits: Limits) -> Result<(), Failure> {
        if self.closed {
            return Err(Failure::new("UNAVAILABLE"));
        }
        if self.tenants.iter().map(TenantQueue::len).sum::<usize>() >= limits.queued_total {
            return Err(Failure::new("BACKPRESSURE"));
        }
        let tenant = (job.principal.deployment, job.principal.tenant);
        let name = job.call.action.name();
        let position = match self.tenants.iter().position(|queue| queue.tenant == tenant) {
            Some(position) => {
                let queue = &self.tenants[position];
                if queue.len() >= limits.queued_per_tenant
                    || queue.name_cost(name) >= limits.queued_per_name
                {
                    return Err(Failure::new("BACKPRESSURE"));
                }
                position
            }
            None => {
                self.tenants.push_back(TenantQueue {
                    tenant,
                    names: VecDeque::new(),
                });
                self.tenants.len() - 1
            }
        };
        let queue = &mut self.tenants[position];
        let position = match queue
            .names
            .iter()
            .position(|queue| queue.name.as_deref() == name)
        {
            Some(position) => position,
            None => {
                queue.names.push_back(NameQueue {
                    name: name.map(str::to_owned),
                    jobs: VecDeque::new(),
                });
                queue.names.len() - 1
            }
        };
        queue.names[position].jobs.push_back(job);
        Ok(())
    }

    fn pop(&mut self) -> Option<Job> {
        let mut tenant = self.tenants.pop_front()?;
        let mut name = tenant.names.pop_front().expect("nonempty tenant queue");
        let job = name.jobs.pop_front();
        if !name.jobs.is_empty() {
            tenant.names.push_back(name);
        }
        if !tenant.names.is_empty() {
            self.tenants.push_back(tenant);
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
    lane: Arc<Lane>,
    threads: Vec<JoinHandle<()>>,
    limits: Limits,
}

type Task = Box<dyn FnOnce() + Send>;
type Spawn = fn(Task) -> std::io::Result<JoinHandle<()>>;

fn spawn(task: Task) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("scap-catalogue".to_owned())
        .spawn(task)
}

impl Scheduler {
    pub fn new(limits: Limits, factory: Factory) -> Result<Self, Failure> {
        Self::with_spawner(limits, factory, spawn)
    }

    fn with_spawner(limits: Limits, factory: Factory, spawn: Spawn) -> Result<Self, Failure> {
        limits.validate()?;
        let mut scheduler = Self {
            lane: Arc::new(Lane::default()),
            threads: Vec::new(),
            limits,
        };
        for index in 0..limits.workers {
            let lane = scheduler.lane.clone();
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
        call.action.validate()?;
        call.action.authorize(&principal)?;
        let (reply, receiver) = oneshot::channel();
        self.lane
            .queue
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
        self.lane.changed.notify_one();
        Ok(receiver)
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.lane.close();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests;
