//! Bounded per-HEAD actors and an independent, fairly queued control pool.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

/// Invoked inside the owning thread. Neither a Worker nor its SQLite Session
/// must be Send. Actor indices occupy [0, active_database_actors); controls
/// have the remaining fixed indices. An actor index is reused only after exit.
pub type Factory = Arc<dyn Fn(usize) -> Result<Box<dyn Worker>, Failure> + Send + Sync>;

#[derive(Clone, Copy)]
pub struct Limits {
    pub active_database_actors: usize,
    pub active_database_actors_per_tenant: usize,
    pub actor_idle_timeout: Duration,
    pub control_workers: usize,
    pub queued_total: usize,
    pub queued_per_tenant: usize,
    pub queued_per_database: usize,
    pub reserved_controls: usize,
}

impl Limits {
    pub fn validate(self) -> Result<(), Failure> {
        if self.active_database_actors == 0
            || self.active_database_actors > 254
            || self.active_database_actors_per_tenant == 0
            || self.active_database_actors_per_tenant > self.active_database_actors
            || self.actor_idle_timeout < Duration::from_millis(1)
            || self.actor_idle_timeout > Duration::from_secs(86400)
            || self.control_workers == 0
            || self.control_workers > 255 - self.active_database_actors
            || self.queued_total == 0
            || self.queued_total > 65536
            || self.queued_per_tenant == 0
            || self.queued_per_tenant > self.queued_total
            || self.queued_per_database == 0
            || self.queued_per_database > self.queued_per_tenant
            || self.reserved_controls == 0
            || self.reserved_controls >= self.queued_per_database
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }
}

type Tenant = (u64, u64);

struct Job {
    principal: Principal,
    call: Call,
    key: String,
    deadline: Instant,
    reply: oneshot::Sender<Result<Value, Failure>>,
}

impl Job {
    fn tenant(&self) -> Tenant {
        (self.principal.deployment, self.principal.tenant)
    }

    fn control(&self) -> bool {
        self.call.action.admission() == "control"
    }
}

#[derive(Default)]
struct Count {
    total: usize,
    data: usize,
}

impl Count {
    fn full(&self, maximum: usize, reserve: usize, control: bool) -> bool {
        self.total >= maximum || (!control && self.data >= maximum - reserve)
    }

    fn add(&mut self, control: bool) {
        self.total += 1;
        self.data += usize::from(!control);
    }

    fn remove(&mut self, control: bool) {
        self.total -= 1;
        self.data -= usize::from(!control);
    }
}

/// All queues share these counters. Hashing control work to separate lanes
/// does not multiply tenant, database or global admission budgets.
#[derive(Default)]
struct Usage {
    all: Count,
    tenants: BTreeMap<Tenant, Count>,
    databases: BTreeMap<String, Count>,
}

impl Usage {
    fn check(&self, job: &Job, limits: Limits) -> Result<(), Failure> {
        let control = job.control();
        let empty = Count::default();
        let tenant = self.tenants.get(&job.tenant()).unwrap_or(&empty);
        let database = self.databases.get(&job.key).unwrap_or(&empty);
        if self
            .all
            .full(limits.queued_total, limits.reserved_controls, control)
            || tenant.full(limits.queued_per_tenant, limits.reserved_controls, control)
            || database.full(
                limits.queued_per_database,
                limits.reserved_controls,
                control,
            )
        {
            return Err(Failure::new("BACKPRESSURE"));
        }
        Ok(())
    }

    fn add(&mut self, job: &Job) {
        let control = job.control();
        self.all.add(control);
        self.tenants.entry(job.tenant()).or_default().add(control);
        self.databases
            .entry(job.key.clone())
            .or_default()
            .add(control);
    }

    fn remove(&mut self, job: &Job) {
        let control = job.control();
        self.all.remove(control);
        let tenant = self.tenants.get_mut(&job.tenant()).expect("queued tenant");
        tenant.remove(control);
        if tenant.total == 0 {
            self.tenants.remove(&job.tenant());
        }
        let database = self.databases.get_mut(&job.key).expect("queued database");
        database.remove(control);
        if database.total == 0 {
            self.databases.remove(&job.key);
        }
    }
}

#[derive(Default)]
struct DatabaseQueue {
    normal: VecDeque<Job>,
    priority: VecDeque<Job>,
    priority_taken: u8,
}

impl DatabaseQueue {
    fn empty(&self) -> bool {
        self.normal.is_empty() && self.priority.is_empty()
    }

    fn push(&mut self, job: Job) {
        if job.call.action.priority() {
            self.priority.push_back(job);
        } else {
            self.normal.push_back(job);
        }
    }

    fn pop(&mut self) -> Option<Job> {
        if !self.priority.is_empty() && (self.priority_taken < 3 || self.normal.is_empty()) {
            self.priority_taken = self.priority_taken.saturating_add(1);
            self.priority.pop_front()
        } else {
            self.priority_taken = 0;
            self.normal.pop_front()
        }
    }
}

struct Group {
    tenant: Tenant,
    databases: VecDeque<(String, DatabaseQueue)>,
}

#[derive(Default)]
struct Queue {
    groups: VecDeque<Group>,
}

impl Queue {
    fn push(&mut self, job: Job) {
        let tenant = job.tenant();
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
        let databases = &mut self.groups[position].databases;
        let position = match databases.iter().position(|(key, _)| *key == job.key) {
            Some(position) => position,
            None => {
                databases.push_back((job.key.clone(), DatabaseQueue::default()));
                databases.len() - 1
            }
        };
        databases[position].1.push(job);
    }

    fn pop(&mut self) -> Option<Job> {
        let mut group = self.groups.pop_front()?;
        let (key, mut database) = group.databases.pop_front().expect("nonempty tenant queue");
        let job = database.pop();
        if !database.empty() {
            group.databases.push_back((key, database));
        }
        if !group.databases.is_empty() {
            self.groups.push_back(group);
        }
        job
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Starting,
    Running,
    Draining,
}

struct Actor {
    slot: usize,
    tenant: Tenant,
    phase: Phase,
    jobs: DatabaseQueue,
    changed: Arc<Condvar>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Control {
    queue: Queue,
    closed: bool,
    changed: Arc<Condvar>,
}

struct State {
    closed: bool,
    actors: BTreeMap<String, Actor>,
    controls: Vec<Control>,
    usage: Usage,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Shared {
    state: Mutex<State>,
    reaping: Condvar,
}

impl Shared {
    fn next_actor(&self, key: &str, changed: &Condvar, idle: Duration) -> Option<Job> {
        let idle_until = Instant::now() + idle;
        let mut state = lock(&self.state);
        loop {
            if state.closed {
                return None;
            }
            let actor = state.actors.get_mut(key).expect("live actor reservation");
            if let Some(job) = actor.jobs.pop() {
                state.usage.remove(&job);
                return Some(job);
            }
            if Instant::now() >= idle_until {
                // Retain this slot until the worker and its !Send connection
                // have dropped and an out-of-lock join proves full exit.
                actor.phase = Phase::Draining;
                return None;
            }
            state = changed
                .wait_timeout(state, idle_until.saturating_duration_since(Instant::now()))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn next_control(&self, index: usize, changed: &Condvar) -> Option<Job> {
        let mut state = lock(&self.state);
        loop {
            let control = &mut state.controls[index];
            if control.closed {
                return None;
            }
            if let Some(job) = control.queue.pop() {
                state.usage.remove(&job);
                return Some(job);
            }
            state = changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn close_actor(&self, key: &str) {
        let mut state = lock(&self.state);
        state.actors.get_mut(key).expect("actor reservation").phase = Phase::Draining;
        while let Some(job) = state
            .actors
            .get_mut(key)
            .expect("actor reservation")
            .jobs
            .pop()
        {
            state.usage.remove(&job);
            let _ = job.reply.send(Err(Failure::new("UNAVAILABLE")));
        }
        self.reaping.notify_all();
    }

    fn close_control(&self, index: usize) {
        let mut state = lock(&self.state);
        state.controls[index].closed = true;
        while let Some(job) = state.controls[index].queue.pop() {
            state.usage.remove(&job);
            let _ = job.reply.send(Err(Failure::new("UNAVAILABLE")));
        }
        state.controls[index].changed.notify_all();
    }

    fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        let mut jobs = Vec::new();
        for actor in state.actors.values_mut() {
            actor.phase = Phase::Draining;
            jobs.extend(std::iter::from_fn(|| actor.jobs.pop()));
            actor.changed.notify_all();
        }
        for control in &mut state.controls {
            control.closed = true;
            jobs.extend(std::iter::from_fn(|| control.queue.pop()));
            control.changed.notify_all();
        }
        for job in jobs {
            state.usage.remove(&job);
            let _ = job.reply.send(Err(Failure::new("UNAVAILABLE")));
        }
        self.reaping.notify_all();
    }

    /// A dedicated, budgeted thread owns retirement. Request threads never
    /// join: even a finished main function may have a slow TLS destructor.
    fn reap(&self) {
        loop {
            let (key, thread) = {
                let mut state = lock(&self.state);
                loop {
                    let key = state
                        .actors
                        .iter()
                        .find(|(_, actor)| actor.phase == Phase::Draining && actor.thread.is_some())
                        .map(|(key, _)| key.clone());
                    if let Some(key) = key {
                        let thread = state
                            .actors
                            .get_mut(&key)
                            .expect("draining actor")
                            .thread
                            .take()
                            .expect("draining thread");
                        break (key, thread);
                    }
                    if state.closed {
                        return;
                    }
                    state = self
                        .reaping
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            };
            // Keep the tombstone and both capacity reservations while native
            // or thread-local cleanup runs. Only this reaper owns the handle.
            let _ = thread.join();
            lock(&self.state).actors.remove(&key);
            self.reaping.notify_all();
        }
    }
}

enum Exit {
    Actor(Arc<Shared>, String),
    Control(Arc<Shared>, usize),
    Reaper(Arc<Shared>),
}

impl Drop for Exit {
    fn drop(&mut self) {
        match self {
            Self::Actor(shared, key) => shared.close_actor(key),
            Self::Control(shared, index) => shared.close_control(*index),
            Self::Reaper(shared) => shared.close(),
        }
    }
}

fn execute(worker: &mut dyn Worker, job: Job) {
    if job.reply.is_closed() {
        return;
    }
    let result = if Instant::now() >= job.deadline {
        Err(Failure::new("DEADLINE"))
    } else {
        worker.execute(&job.principal, job.call, job.deadline)
    };
    let _ = job.reply.send(result);
}

pub struct Scheduler {
    shared: Arc<Shared>,
    controls: Vec<JoinHandle<()>>,
    reaper: Option<JoinHandle<()>>,
    limits: Limits,
    factory: Factory,
    spawn: Spawn,
}

type Task = Box<dyn FnOnce() + Send>;
type Spawn = fn(&str, Task) -> std::io::Result<JoinHandle<()>>;

fn spawn(name: &str, task: Task) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(task)
}

impl Scheduler {
    pub fn new(limits: Limits, factory: Factory) -> Result<Self, Failure> {
        Self::with_spawner(limits, factory, spawn)
    }

    fn with_spawner(limits: Limits, factory: Factory, spawn: Spawn) -> Result<Self, Failure> {
        limits.validate()?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                closed: false,
                actors: BTreeMap::new(),
                controls: (0..limits.control_workers)
                    .map(|_| Control::default())
                    .collect(),
                usage: Usage::default(),
            }),
            reaping: Condvar::new(),
        });
        let mut scheduler = Self {
            shared,
            controls: Vec::new(),
            reaper: None,
            limits,
            factory,
            spawn,
        };
        for index in 0..limits.control_workers {
            let shared = scheduler.shared.clone();
            let changed = lock(&shared.state).controls[index].changed.clone();
            let factory = scheduler.factory.clone();
            let (started, ready) = mpsc::sync_channel(1);
            scheduler.controls.push(
                spawn(
                    "scap-control",
                    Box::new(move || {
                        let _exit = Exit::Control(shared.clone(), index);
                        let mut worker = match factory(limits.active_database_actors + index) {
                            Ok(worker) => {
                                let _ = started.send(Ok(()));
                                worker
                            }
                            Err(error) => {
                                let _ = started.send(Err(error));
                                return;
                            }
                        };
                        while let Some(job) = shared.next_control(index, &changed) {
                            execute(worker.as_mut(), job);
                        }
                    }),
                )
                .map_err(|_| Failure::new("UNAVAILABLE"))?,
            );
            ready.recv().map_err(|_| Failure::new("UNAVAILABLE"))??;
        }
        let shared = scheduler.shared.clone();
        scheduler.reaper = Some(
            spawn(
                "scap-reaper",
                Box::new(move || {
                    let _exit = Exit::Reaper(shared.clone());
                    shared.reap();
                }),
            )
            .map_err(|_| Failure::new("UNAVAILABLE"))?,
        );
        Ok(scheduler)
    }

    fn start_actor(&self, key: String, slot: usize, changed: Arc<Condvar>) -> Result<(), Failure> {
        let shared = self.shared.clone();
        let factory = self.factory.clone();
        let worker_key = key.clone();
        let idle = self.limits.actor_idle_timeout;
        let task = Box::new(move || {
            let _exit = Exit::Actor(shared.clone(), worker_key.clone());
            let mut worker = match factory(slot) {
                Ok(worker) => worker,
                Err(_) => return,
            };
            lock(&shared.state)
                .actors
                .get_mut(&worker_key)
                .expect("starting actor")
                .phase = Phase::Running;
            while let Some(job) = shared.next_actor(&worker_key, &changed, idle) {
                execute(worker.as_mut(), job);
            }
        });
        match (self.spawn)("scap-database", task) {
            Ok(thread) => {
                lock(&self.shared.state)
                    .actors
                    .get_mut(&key)
                    .expect("starting reservation")
                    .thread = Some(thread);
                self.shared.reaping.notify_all();
                Ok(())
            }
            Err(_) => {
                // Other submitters may already have queued behind Starting.
                self.shared.close_actor(&key);
                lock(&self.shared.state).actors.remove(&key);
                self.shared.reaping.notify_all();
                Err(Failure::new("UNAVAILABLE"))
            }
        }
    }

    pub fn submit(
        &self,
        principal: Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Result<Value, Failure>>, Failure> {
        let scope = call.scope.native()?;
        principal.authorize(&scope)?;
        let key = scap_object::format::head_key(&scope);
        let (reply, receiver) = oneshot::channel();
        let job = Job {
            principal,
            call,
            key: key.clone(),
            deadline,
            reply,
        };
        let mut state = lock(&self.shared.state);
        if state.closed {
            return Err(Failure::new("UNAVAILABLE"));
        }
        state.usage.check(&job, self.limits)?;
        if job.control() {
            let hash = Sha256::digest(key.as_bytes());
            let hash = u64::from_le_bytes(hash[..8].try_into().expect("eight bytes")) as usize;
            let index = hash % self.limits.control_workers;
            if state.controls[index].closed {
                return Err(Failure::new("UNAVAILABLE"));
            }
            state.usage.add(&job);
            state.controls[index].queue.push(job);
            state.controls[index].changed.notify_one();
            return Ok(receiver);
        }
        if let Some(actor) = state.actors.get(&key) {
            if actor.phase == Phase::Draining {
                return Err(Failure::new("BACKPRESSURE"));
            }
            state.usage.add(&job);
            let actor = state.actors.get_mut(&key).expect("existing actor");
            actor.jobs.push(job);
            actor.changed.notify_one();
            return Ok(receiver);
        }
        let tenant = job.tenant();
        if state.actors.len() >= self.limits.active_database_actors
            || state
                .actors
                .values()
                .filter(|actor| actor.tenant == tenant)
                .count()
                >= self.limits.active_database_actors_per_tenant
        {
            return Err(Failure::new("BACKPRESSURE"));
        }
        let slot = (0..self.limits.active_database_actors)
            .find(|slot| state.actors.values().all(|actor| actor.slot != *slot))
            .expect("available actor slot");
        let changed = Arc::new(Condvar::new());
        let mut jobs = DatabaseQueue::default();
        state.usage.add(&job);
        jobs.push(job);
        state.actors.insert(
            key.clone(),
            Actor {
                slot,
                tenant,
                phase: Phase::Starting,
                jobs,
                changed: changed.clone(),
                thread: None,
            },
        );
        drop(state);
        self.start_actor(key, slot, changed)?;
        Ok(receiver)
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.shared.close();
        // Reservations remain visible to exit guards until every owning
        // thread has finished. Taking a handle does not remove its actor.
        let actors: Vec<_> = lock(&self.shared.state)
            .actors
            .values_mut()
            .filter_map(|actor| actor.thread.take())
            .collect();
        for thread in actors.into_iter().chain(self.controls.drain(..)) {
            let _ = thread.join();
        }
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
    }
}

#[cfg(test)]
mod tests;
