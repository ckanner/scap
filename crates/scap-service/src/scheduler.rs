//! Bounded per-HEAD actors and an independent, fairly queued control pool.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::{auth::Principal, wire::Call, Failure};

mod group;
use group::{ActorWorker, Work};

pub trait Worker {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure>;

    /// Opt in explicitly before serving budgeted HTTP work. A custom worker
    /// must forward/obey the context; the default never runs an unmetered call.
    fn execute_budgeted(
        &mut self,
        _principal: &Principal,
        _call: Call,
        _deadline: Instant,
        _output: &mut crate::output::OutputContext,
    ) -> Result<Value, Failure> {
        Err(Failure::new("UNAVAILABLE"))
    }

    /// Declining guarantees that no member SQL has started. Legacy workers
    /// retain their original single-request behavior and budgeted boundary.
    fn execute_group(
        &mut self,
        _members: &mut [crate::group::Member<'_>],
        _limits: scap_object::GroupLimits,
    ) -> crate::group::Outcome {
        crate::group::Outcome::Declined
    }
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

    fn execute_budgeted(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        output: &mut crate::output::OutputContext,
    ) -> Result<Value, Failure> {
        self.execute_budgeted(principal, call, deadline, output)
    }

    fn execute_group(
        &mut self,
        members: &mut [crate::group::Member<'_>],
        limits: scap_object::GroupLimits,
    ) -> crate::group::Outcome {
        self.execute_group(members, limits)
    }
}

/// Invoked inside the owning thread. Neither a Worker nor its SQLite Session
/// must be Send. Actor indices occupy [0, active_database_actors); controls
/// follow them, then optional query workers. An actor index is reused only
/// after exit. Every worker owns its private native connections and files.
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

/// Enabling the separate read pool is explicit. Existing deployments keep
/// their actor-only execution path when no profile is provided. Query workers
/// use independent complete private images, never a shared native WAL.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadPool {
    pub workers: usize,
    pub active_per_tenant: usize,
    pub active_per_database: usize,
}

impl ReadPool {
    pub fn validate(self, limits: Limits) -> Result<(), Failure> {
        limits.validate()?;
        if self.workers == 0
            || self.workers > 255 - limits.active_database_actors - limits.control_workers
            || self.active_per_tenant == 0
            || self.active_per_tenant > self.workers
            || self.active_per_database == 0
            || self.active_per_database > self.active_per_tenant
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
    reply: Reply,
    _reservation: Option<Arc<crate::intake::Lease>>,
    output: Option<crate::output::OutputContext>,
    _output_hold: Option<crate::output::WorkHold>,
}

enum Reply {
    Value(oneshot::Sender<Result<Value, Failure>>),
    Encoded(oneshot::Sender<crate::output::Reply>),
}

impl Reply {
    fn is_closed(&self) -> bool {
        match self {
            Self::Value(sender) => sender.is_closed(),
            Self::Encoded(sender) => sender.is_closed(),
        }
    }
}

impl Job {
    fn tenant(&self) -> Tenant {
        (self.principal.deployment, self.principal.tenant)
    }

    fn control(&self) -> bool {
        self.call.action.admission() == "control"
    }

    fn fail(mut self, error: Failure) {
        match self.reply {
            Reply::Value(sender) => {
                let _ = sender.send(Err(error));
            }
            Reply::Encoded(sender) => {
                let output = self.output.take().expect("encoded job output context");
                finish_encoded(
                    sender,
                    crate::output::OwnedValue::new(Err(error), output),
                    self.deadline,
                );
            }
        }
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

    /// Round-robin both tenants and databases, skipping only currently full
    /// active reservations. A blocked hot database cannot stop another tenant.
    fn pop_eligible(&mut self, eligible: impl Fn(Tenant, &str) -> bool) -> Option<Job> {
        for _ in 0..self.groups.len() {
            let mut group = self.groups.pop_front().expect("counted tenant queue");
            for _ in 0..group.databases.len() {
                let (key, mut database) = group.databases.pop_front().expect("counted database");
                if eligible(group.tenant, &key) {
                    let job = database.pop();
                    if !database.empty() {
                        group.databases.push_back((key, database));
                    }
                    if !group.databases.is_empty() {
                        self.groups.push_back(group);
                    }
                    return job;
                }
                group.databases.push_back((key, database));
            }
            self.groups.push_back(group);
        }
        None
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

#[derive(Default)]
struct Readers {
    queue: Queue,
    tenants: BTreeMap<Tenant, usize>,
    databases: BTreeMap<String, usize>,
    live: usize,
    closed: bool,
    changed: Arc<Condvar>,
}

impl Readers {
    fn pop(&mut self, limits: ReadPool) -> Option<Job> {
        let job = self.queue.pop_eligible(|tenant, key| {
            self.tenants.get(&tenant).copied().unwrap_or(0) < limits.active_per_tenant
                && self.databases.get(key).copied().unwrap_or(0) < limits.active_per_database
        })?;
        *self.tenants.entry(job.tenant()).or_default() += 1;
        *self.databases.entry(job.key.clone()).or_default() += 1;
        Some(job)
    }

    fn release(&mut self, tenant: Tenant, key: &str) {
        let count = self.tenants.get_mut(&tenant).expect("active read tenant");
        *count -= 1;
        if *count == 0 {
            self.tenants.remove(&tenant);
        }
        let count = self.databases.get_mut(key).expect("active read database");
        *count -= 1;
        if *count == 0 {
            self.databases.remove(key);
        }
        self.changed.notify_all();
    }
}

struct State {
    closed: bool,
    actors: BTreeMap<String, Actor>,
    controls: Vec<Control>,
    readers: Readers,
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
    fn next_actor(
        self: &Arc<Self>,
        key: &str,
        changed: &Condvar,
        idle: Duration,
        profile: Option<crate::group::Profile>,
    ) -> Option<Work> {
        let idle_until = Instant::now() + idle;
        let mut state = lock(&self.state);
        loop {
            if state.closed {
                return None;
            }
            let actor = state.actors.get_mut(key).expect("live actor reservation");
            if let Some(job) = actor.jobs.pop() {
                let work = Work::collect(self.clone(), &mut actor.jobs, job, profile);
                if let Work::Single(job) = &work {
                    state.usage.remove(job);
                }
                return Some(work);
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

    fn next_read(&self, limits: ReadPool, changed: &Condvar) -> Option<Job> {
        let mut state = lock(&self.state);
        loop {
            if state.readers.closed {
                return None;
            }
            if let Some(job) = state.readers.pop(limits) {
                state.usage.remove(&job);
                return Some(job);
            }
            state = changed.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn close_reader(&self) {
        let mut state = lock(&self.state);
        state.readers.live -= 1;
        if state.readers.live == 0 {
            state.readers.closed = true;
            while let Some(job) = state.readers.queue.pop() {
                state.usage.remove(&job);
                job.fail(Failure::new("UNAVAILABLE"));
            }
        }
        state.readers.changed.notify_all();
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
            job.fail(Failure::new("UNAVAILABLE"));
        }
        self.reaping.notify_all();
    }

    fn close_control(&self, index: usize) {
        let mut state = lock(&self.state);
        state.controls[index].closed = true;
        while let Some(job) = state.controls[index].queue.pop() {
            state.usage.remove(&job);
            job.fail(Failure::new("UNAVAILABLE"));
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
        state.readers.closed = true;
        jobs.extend(std::iter::from_fn(|| state.readers.queue.pop()));
        state.readers.changed.notify_all();
        for job in jobs {
            state.usage.remove(&job);
            job.fail(Failure::new("UNAVAILABLE"));
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
    Reader(Arc<Shared>),
}

impl Drop for Exit {
    fn drop(&mut self) {
        match self {
            Self::Actor(shared, key) => shared.close_actor(key),
            Self::Control(shared, index) => shared.close_control(*index),
            Self::Reaper(shared) => shared.close(),
            Self::Reader(shared) => shared.close_reader(),
        }
    }
}

/// Held across execution, encoded output transfer and job cleanup. Expiration,
/// a dropped HTTP receiver, or panic does not release a running native call.
struct ReadActivity {
    shared: Arc<Shared>,
    tenant: Tenant,
    key: String,
}

impl Drop for ReadActivity {
    fn drop(&mut self) {
        lock(&self.shared.state)
            .readers
            .release(self.tenant, &self.key);
    }
}

// On unwind Rust drops fields in declaration order: finish native worker/cache
// destruction before releasing its in-flight read reservation. On success the
// activity is cleared only after execute() has dropped the job and its holds.
struct ReadWorker {
    worker: Box<dyn Worker>,
    activity: Option<ReadActivity>,
}

fn perform(worker: &mut dyn Worker, job: &mut Job) -> Option<Result<Value, Failure>> {
    if job.reply.is_closed() {
        return None;
    }
    if Instant::now() >= job.deadline {
        return Some(Err(Failure::new("DEADLINE")));
    }
    // Keep the original Job's leases alive in its owner while the worker
    // borrows them, including unwind. Only the action's payload is moved.
    let call = Call {
        version: job.call.version,
        scope: job.call.scope.clone(),
        action: std::mem::replace(
            &mut job.call.action,
            crate::wire::Action::Query {
                statements: Vec::new(),
            },
        ),
    };
    Some(match job.output.as_mut() {
        Some(output) => worker.execute_budgeted(&job.principal, call, job.deadline, output),
        None => worker.execute(&job.principal, call, job.deadline),
    })
}

fn deliver(mut job: Job, result: Option<Result<Value, Failure>>) {
    let Some(result) = result else {
        return;
    };
    match job.reply {
        Reply::Value(reply) => {
            let _ = reply.send(result);
        }
        Reply::Encoded(sender) => {
            let output = job.output.take().expect("encoded job output context");
            finish_encoded(
                sender,
                crate::output::OwnedValue::new(result, output),
                job.deadline,
            );
        }
    }
}

fn execute(worker: &mut dyn Worker, mut job: Job) {
    let result = perform(worker, &mut job);
    deliver(job, result);
}

fn finish_encoded(
    sender: oneshot::Sender<crate::output::Reply>,
    value: crate::output::OwnedValue,
    deadline: Instant,
) {
    if let Some(reply) = value.finish(deadline) {
        // The same deadline includes final serialization. The job's
        // independent hold survives even a successful send/wakeup.
        send_before(sender, reply, deadline, Instant::now());
    }
}

fn send_before(
    sender: oneshot::Sender<crate::output::Reply>,
    reply: crate::output::Reply,
    deadline: Instant,
    now: Instant,
) {
    if now < deadline {
        let _ = sender.send(reply);
    }
}

pub struct Scheduler {
    shared: Arc<Shared>,
    controls: Vec<JoinHandle<()>>,
    readers: Vec<JoinHandle<()>>,
    read_pool: Option<ReadPool>,
    group_commit: Option<crate::group::Profile>,
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

    pub fn with_read_pool(
        limits: Limits,
        read_pool: Option<ReadPool>,
        factory: Factory,
    ) -> Result<Self, Failure> {
        Self::with_read_spawner(limits, read_pool, factory, spawn)
    }

    pub fn with_execution(
        limits: Limits,
        read_pool: Option<ReadPool>,
        group_commit: Option<crate::group::Profile>,
        factory: Factory,
    ) -> Result<Self, Failure> {
        Self::with_execution_spawner(limits, read_pool, group_commit, factory, spawn)
    }

    fn with_spawner(limits: Limits, factory: Factory, spawn: Spawn) -> Result<Self, Failure> {
        Self::with_read_spawner(limits, None, factory, spawn)
    }

    fn with_read_spawner(
        limits: Limits,
        read_pool: Option<ReadPool>,
        factory: Factory,
        spawn: Spawn,
    ) -> Result<Self, Failure> {
        Self::with_execution_spawner(limits, read_pool, None, factory, spawn)
    }

    fn with_execution_spawner(
        limits: Limits,
        read_pool: Option<ReadPool>,
        group_commit: Option<crate::group::Profile>,
        factory: Factory,
        spawn: Spawn,
    ) -> Result<Self, Failure> {
        limits.validate()?;
        if let Some(read_pool) = read_pool {
            read_pool.validate(limits)?;
        }
        if let Some(group_commit) = group_commit {
            group_commit.validate(limits)?;
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                closed: false,
                actors: BTreeMap::new(),
                controls: (0..limits.control_workers)
                    .map(|_| Control::default())
                    .collect(),
                readers: Readers {
                    live: read_pool.map_or(0, |profile| profile.workers),
                    ..Readers::default()
                },
                usage: Usage::default(),
            }),
            reaping: Condvar::new(),
        });
        let mut scheduler = Self {
            shared,
            controls: Vec::new(),
            readers: Vec::new(),
            read_pool,
            group_commit,
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
        if let Some(profile) = read_pool {
            for index in 0..profile.workers {
                let shared = scheduler.shared.clone();
                let changed = lock(&shared.state).readers.changed.clone();
                let factory = scheduler.factory.clone();
                let (started, ready) = mpsc::sync_channel(1);
                scheduler.readers.push(
                    spawn(
                        "scap-query",
                        Box::new(move || {
                            let _exit = Exit::Reader(shared.clone());
                            let worker = match factory(
                                limits.active_database_actors + limits.control_workers + index,
                            ) {
                                Ok(worker) => {
                                    let _ = started.send(Ok(()));
                                    worker
                                }
                                Err(error) => {
                                    let _ = started.send(Err(error));
                                    return;
                                }
                            };
                            let mut owned = ReadWorker {
                                worker,
                                activity: None,
                            };
                            while let Some(job) = shared.next_read(profile, &changed) {
                                owned.activity = Some(ReadActivity {
                                    shared: shared.clone(),
                                    tenant: job.tenant(),
                                    key: job.key.clone(),
                                });
                                execute(owned.worker.as_mut(), job);
                                owned.activity = None;
                            }
                        }),
                    )
                    .map_err(|_| Failure::new("UNAVAILABLE"))?,
                );
                ready.recv().map_err(|_| Failure::new("UNAVAILABLE"))??;
            }
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
        let profile = self.group_commit;
        let task = Box::new(move || {
            let _exit = Exit::Actor(shared.clone(), worker_key.clone());
            let worker = match factory(slot) {
                Ok(worker) => worker,
                Err(_) => return,
            };
            // The field order keeps counted work and its leases reserved if
            // a failed worker has native/TLS cleanup to finish during unwind.
            let mut owned = ActorWorker {
                worker,
                active: None,
            };
            lock(&shared.state)
                .actors
                .get_mut(&worker_key)
                .expect("starting actor")
                .phase = Phase::Running;
            while let Some(work) = shared.next_actor(&worker_key, &changed, idle, profile) {
                match work {
                    Work::Single(job) => execute(owned.worker.as_mut(), job),
                    Work::Group(batch) => {
                        owned.active = Some(batch);
                        owned
                            .active
                            .as_mut()
                            .expect("active group")
                            .run(owned.worker.as_mut());
                        owned.active = None;
                    }
                }
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
        let (reply, receiver) = oneshot::channel();
        self.enqueue(principal, call, deadline, None, Reply::Value(reply), None)?;
        Ok(receiver)
    }

    pub(crate) fn submit_encoded(
        &self,
        principal: Principal,
        call: Call,
        deadline: Instant,
        reservation: Arc<crate::intake::Lease>,
        output: crate::output::OutputContext,
    ) -> Result<oneshot::Receiver<crate::output::Reply>, Failure> {
        reservation.claim(&principal, call.action.admission())?;
        output.claim(&principal, call.action.admission() != "data")?;
        let (sender, receiver) = oneshot::channel();
        self.enqueue(
            principal,
            call,
            deadline,
            Some(reservation),
            Reply::Encoded(sender),
            Some(output),
        )?;
        Ok(receiver)
    }

    fn enqueue(
        &self,
        principal: Principal,
        call: Call,
        deadline: Instant,
        reservation: Option<Arc<crate::intake::Lease>>,
        reply: Reply,
        output: Option<crate::output::OutputContext>,
    ) -> Result<(), Failure> {
        let scope = call.scope.native()?;
        principal.authorize(&scope)?;
        let key = scap_object::format::head_key(&scope);
        let hold = output.as_ref().map(crate::output::OutputContext::work_hold);
        let job = Job {
            principal,
            call,
            key: key.clone(),
            deadline,
            reply,
            _reservation: reservation,
            _output_hold: hold,
            output,
        };
        let mut state = lock(&self.shared.state);
        if state.closed {
            return Err(Failure::new("UNAVAILABLE"));
        }
        // Parsing and this mutex wait spend the original request budget too.
        // Expired work must not reserve an actor or run its factory: an idle
        // actor would otherwise hold capacity after SQL was already forbidden.
        if Instant::now() >= deadline {
            return Err(Failure::new("DEADLINE"));
        }
        state.usage.check(&job, self.limits)?;
        if self.read_pool.is_some() && matches!(job.call.action, crate::wire::Action::Query { .. })
        {
            if state.readers.closed {
                return Err(Failure::new("UNAVAILABLE"));
            }
            state.usage.add(&job);
            state.readers.queue.push(job);
            state.readers.changed.notify_one();
            return Ok(());
        }
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
            return Ok(());
        }
        if let Some(actor) = state.actors.get(&key) {
            if actor.phase == Phase::Draining {
                return Err(Failure::new("BACKPRESSURE"));
            }
            state.usage.add(&job);
            let actor = state.actors.get_mut(&key).expect("existing actor");
            actor.jobs.push(job);
            actor.changed.notify_one();
            return Ok(());
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
        Ok(())
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
        for thread in actors
            .into_iter()
            .chain(self.controls.drain(..))
            .chain(self.readers.drain(..))
        {
            let _ = thread.join();
        }
        if let Some(reaper) = self.reaper.take() {
            let _ = reaper.join();
        }
    }
}

#[cfg(test)]
mod tests;
