//! Separate bounded discovery admission. Checkpoints never grant permission.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use scap_object::{catalogue as core, Options};
use scap_object_store::{Listings, Objects};
use serde_json::{json, Value};

use crate::{
    auth::Principal,
    discovery_cursor::CursorCodec,
    discovery_wire::{self as wire, Call, Operation},
    Failure,
};

pub const TIMEOUT: Duration = Duration::from_secs(5);
const FINALIZATION_RESERVE: Duration = Duration::from_secs(1);
pub const MAX_BODY_BYTES: usize = 65536;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
type Tenant = (u64, u64);

#[derive(Default)]
pub struct Admission {
    active: Arc<Mutex<BTreeSet<Tenant>>>,
}

/// Retained by the blocking operation AND its response body/bytes. A timeout
/// or disconnected client cannot free a slot while object I/O still runs.
pub struct Reservation {
    active: Arc<Mutex<BTreeSet<Tenant>>>,
    tenant: Tenant,
    submitted: AtomicBool,
}

impl Admission {
    pub fn acquire(&self, principal: &Principal) -> Result<Arc<Reservation>, Failure> {
        let tenant = (principal.deployment, principal.tenant);
        let mut active = self
            .active
            .lock()
            .map_err(|_| Failure::new("UNAVAILABLE"))?;
        if active.len() >= 2 || active.contains(&tenant) {
            return Err(Failure::new("BACKPRESSURE"));
        }
        active.insert(tenant);
        Ok(Arc::new(Reservation {
            active: self.active.clone(),
            tenant,
            submitted: AtomicBool::new(false),
        }))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.tenant);
    }
}

struct Reader {
    objects: Arc<dyn Objects>,
    listings: Arc<dyn Listings>,
    worker: u64,
    codec: Arc<CursorCodec>,
}

type Task = Box<dyn FnOnce() + Send>;
type Spawn = fn(Task) -> std::io::Result<JoinHandle<()>>;
type Reply = tokio::sync::oneshot::Receiver<Result<Vec<u8>, Failure>>;

pub struct Discovery {
    reader: Arc<Reader>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    pub admission: Admission,
}

impl Discovery {
    pub fn new(
        objects: Arc<dyn Objects>,
        listings: Arc<dyn Listings>,
        worker: u64,
        codec: Arc<CursorCodec>,
    ) -> Result<Self, Failure> {
        if worker == 0 {
            return Err(Failure::new("CONFIG"));
        }
        Ok(Self {
            reader: Arc::new(Reader {
                objects,
                listings,
                worker,
                codec,
            }),
            workers: Mutex::new(Vec::new()),
            admission: Admission::default(),
        })
    }

    pub fn submit(
        &self,
        principal: Principal,
        call: Call,
        reservation: Arc<Reservation>,
        deadline: Instant,
    ) -> Result<Reply, Failure> {
        self.submit_with(principal, call, reservation, deadline, spawn)
    }

    fn submit_with(
        &self,
        principal: Principal,
        call: Call,
        reservation: Arc<Reservation>,
        deadline: Instant,
        spawn: Spawn,
    ) -> Result<Reply, Failure> {
        if !Arc::ptr_eq(&reservation.active, &self.admission.active)
            || reservation.tenant != (principal.deployment, principal.tenant)
            || reservation.submitted.swap(true, Ordering::AcqRel)
        {
            return Err(Failure::new("INVALID"));
        }
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| Failure::new("UNAVAILABLE"))?;
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let _ = workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        // A completed operation can have released its lease while its OS
        // thread is still exiting. Bound these handles too, without waiting.
        if workers.len() >= 2 {
            return Err(Failure::new("BACKPRESSURE"));
        }
        let reader = self.reader.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let worker = spawn(Box::new(move || {
            let _reservation = reservation;
            let value = reader.execute(&principal, call, deadline);
            let _ = sender.send(value);
        }))
        .map_err(|_| Failure::new("UNAVAILABLE"))?;
        workers.push(worker);
        Ok(receiver)
    }
}

fn spawn(task: Task) -> std::io::Result<JoinHandle<()>> {
    // Tokio blocking tasks retain a current Handle, which the synchronous S3
    // adapter correctly rejects. These are bounded plain OS worker threads.
    std::thread::Builder::new()
        .name("scap-discovery".into())
        .spawn(task)
}

impl Drop for Discovery {
    fn drop(&mut self) {
        for worker in self
            .workers
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner())
            .drain(..)
        {
            let _ = worker.join();
        }
    }
}

impl Reader {
    fn execute(
        &self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Vec<u8>, Failure> {
        let started = Instant::now();
        if started >= deadline {
            return Err(Failure::new("DEADLINE"));
        }
        // I/O must stop before the outer HTTP deadline so a bounded partial
        // page can still be encoded and sealed. Using the same deadline for
        // both discarded every continuation under sustained slow storage.
        let read_deadline = read_deadline(started, deadline);
        // Recheck current trusted capability before decrypting any cursor or
        // touching the bucket. Provision/ADMIN never grants this capability.
        if call.operation == Operation::Inventory && !principal.deployment_inventory {
            return Err(Failure::new("DENIED"));
        }
        let checkpoint = call
            .cursor
            .as_ref()
            .map(|token| self.codec.open(principal, call.operation.view(), token))
            .transpose()?;
        let value = match call.operation {
            Operation::Names => {
                let catalogue = core::Catalogue::new(
                    self.objects.clone(),
                    principal.deployment,
                    principal.tenant,
                    self.worker,
                    Options::default(),
                )?;
                let names = core::VisibleNames::new(catalogue, self.listings.clone());
                let caller = core::Caller {
                    principal: principal.principal,
                    provision: principal.provision,
                };
                let cursor = match checkpoint {
                    Some(bytes) => names.resume_authenticated(caller, &bytes),
                    None => names.begin(caller),
                }
                .map_err(wire::error)?;
                let page = names
                    .page(caller, cursor, core::DiscoveryBudget::default(), read_deadline)
                    .expect("same coordinator, validated caller and fixed valid budget; I/O stops stay in page");
                let token = if page.traversal_exhausted {
                    None
                } else {
                    Some(
                        self.codec.seal(
                            principal,
                            call.operation.view(),
                            &names
                                .checkpoint(&page.cursor)
                                .expect("page retains its own coordinator"),
                        )?,
                    )
                };
                wire::names(&page, token)
            }
            Operation::Inventory => {
                let capability =
                    core::RecoveryCapability::trusted_deployment(principal.deployment, self.worker)
                        .map_err(wire::error)?;
                let inventory = core::RecoveryInventory::new(
                    self.objects.clone(),
                    self.listings.clone(),
                    capability,
                    Options::default(),
                )
                .expect("default runtime options are valid");
                let cursor = match checkpoint {
                    Some(bytes) => inventory
                        .resume_authenticated(&bytes)
                        .map_err(wire::error)?,
                    None => inventory.begin(),
                };
                let page = inventory
                    .page(cursor, core::DiscoveryBudget::default(), read_deadline)
                    .expect("same coordinator and fixed valid budget; I/O stops stay in page");
                let token = if page.completion.traversal_exhausted {
                    None
                } else {
                    Some(
                        self.codec.seal(
                            principal,
                            call.operation.view(),
                            &inventory
                                .checkpoint(&page.cursor)
                                .expect("page retains its own coordinator"),
                        )?,
                    )
                };
                wire::inventory(&page, token)
            }
        };
        bounded(value, deadline)
    }
}

fn read_deadline(started: Instant, deadline: Instant) -> Instant {
    started
        + deadline
            .saturating_duration_since(started)
            .saturating_sub(FINALIZATION_RESERVE)
}

fn bounded(value: Value, deadline: Instant) -> Result<Vec<u8>, Failure> {
    let bytes =
        serde_json::to_vec(&json!({"ok":true,"value":value})).expect("JSON value serialization");
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Failure::new("LIMIT"));
    }
    if Instant::now() >= deadline {
        return Err(Failure::new("DEADLINE"));
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests;
