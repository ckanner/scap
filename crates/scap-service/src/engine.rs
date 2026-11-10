//! Thread-confined sessions, explicit ownership controls and bounded cache.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use scap_object::format::{head_key, DatabaseQuota};
use scap_object::{Database, Options, Session};
use scap_object_store::{Garbage, Listings, Objects};
use serde_json::{Map, Value};
use tokio::sync::Semaphore;

use crate::auth::Principal;
use crate::wire::{self, Action, Call};
use crate::Failure;

struct Cached {
    database: Database,
    session: Option<Session>,
    touched: u64,
}

#[derive(Clone)]
pub(crate) struct Collector {
    pub deployment: u64,
    pub listings: Arc<dyn Listings>,
    pub garbage: Arc<dyn Garbage>,
}

pub struct Engine {
    objects: Arc<dyn Objects>,
    worker: u64,
    options: Options,
    cache: BTreeMap<String, Cached>,
    // Drop sessions before their parent directory.
    directory: tempfile::TempDir,
    maximum: usize,
    max_pages: u64,
    serial: u64,
    recovery: Arc<Semaphore>,
    collector: Option<Collector>,
}

/// Keep storage admission and its ordering identical when testing a directory
/// creation failure. Only the actual creation effect can vary.
fn create_cache(
    parent: &Path,
    create: impl FnOnce(&Path) -> std::io::Result<tempfile::TempDir>,
) -> Result<tempfile::TempDir, Failure> {
    scap_object_sqlite::validate_cache_directory(parent).map_err(|_| Failure::new("CACHE_IO"))?;
    create(parent).map_err(|_| Failure::new("CACHE_IO"))
}

impl Engine {
    pub fn new(
        objects: Arc<dyn Objects>,
        worker: u64,
        options: Options,
        cache_parent: &Path,
        maximum: usize,
        max_pages: u64,
        recovery: Arc<Semaphore>,
    ) -> Result<Self, Failure> {
        if worker == 0 || maximum == 0 || max_pages == 0 {
            return Err(Failure::new("CONFIG"));
        }
        options.validate().map_err(Failure::from)?;
        // Engine is also a public trusted Rust boundary; callers can construct
        // it without Config::prepare. Validate before creating worker files.
        let directory = create_cache(cache_parent, |parent| {
            tempfile::Builder::new()
                .prefix("scap-worker-")
                .tempdir_in(parent)
        })?;
        Ok(Self {
            objects,
            worker,
            options,
            cache: BTreeMap::new(),
            directory,
            maximum,
            max_pages,
            serial: 0,
            recovery,
            collector: None,
        })
    }

    pub(crate) fn with_collector(mut self, collector: Option<Collector>) -> Self {
        self.collector = collector;
        self
    }

    fn next_path(&mut self) -> Result<PathBuf, Failure> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or_else(|| Failure::new("LIMIT"))?;
        Ok(self
            .directory
            .path()
            .join(format!("session-{}", self.serial)))
    }

    fn trim(&mut self) {
        while self.cache.len() > self.maximum
            || self
                .cache
                .values()
                .map(|entry| {
                    entry
                        .session
                        .as_ref()
                        .map_or(0, |session| u64::from(session.page_count()))
                })
                .sum::<u64>()
                > self.max_pages
        {
            // Positive budgets mean an empty cache cannot exceed either cap.
            let key = self
                .cache
                .iter()
                .min_by_key(|(_, entry)| entry.touched)
                .expect("nonempty over-budget cache")
                .0
                .clone();
            self.cache.remove(&key);
        }
    }

    /// One call only: errors never trigger SQL or administrative CAS replay.
    pub fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        self.execute_using(principal, call, deadline, None)
    }

    /// HTTP workers must explicitly forward the original context and deadline.
    /// This does not cover core/native buffers allocated before service output.
    pub fn execute_budgeted(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        output: &mut crate::output::OutputContext,
    ) -> Result<Value, Failure> {
        self.execute_using(principal, call, deadline, Some(output))
    }

    fn execute_using(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
        output: Option<&mut crate::output::OutputContext>,
    ) -> Result<Value, Failure> {
        if call.version != 1 {
            return Err(Failure::new("VERSION"));
        }
        if Instant::now() >= deadline {
            return Err(Failure::new("DEADLINE"));
        }
        let scope = call.scope.native()?;
        call.action.validate()?;
        principal.authorize(&scope)?;
        if call
            .action
            .expected_worker()
            .is_some_and(|worker| worker != self.worker)
        {
            return Err(Failure::new("TARGET_MISMATCH"));
        }
        if matches!(call.action, Action::Create { .. }) && !principal.provision {
            return Err(Failure::new("DENIED"));
        }
        let path = self.next_path()?;
        // HEAD keys intentionally exclude incarnation/generation to fence old
        // identities. Local cache identities must include both: an alias may
        // never turn an old identity into access to a different database.
        let key = format!(
            "{}/inc/{}/gen/{}",
            head_key(&scope),
            scope.incarnation,
            scope.generation
        );
        let mut entry = match self.cache.remove(&key) {
            Some(entry) => entry,
            None => Cached {
                database: Database::with_options(
                    self.objects.clone(),
                    scope,
                    self.worker,
                    self.options.clone(),
                )
                .map_err(Failure::from)?,
                session: None,
                touched: 0,
            },
        };
        entry.touched = self.serial;
        let result = self.dispatch(principal, &mut entry, call.action, &path, deadline, output);
        // A failed native operation may have invalidated the private connection.
        // Quarantined Database handles survive while resident; no failed cache
        // is reused, and a future recreation verifies S3 before serving.
        if result.is_err() {
            entry.session = None;
        }
        self.cache.insert(key, entry);
        self.trim();
        result
    }

    fn session<'a>(
        &self,
        principal: u64,
        entry: &'a mut Cached,
        path: &Path,
        deadline: Instant,
    ) -> Result<&'a mut Session, Failure> {
        if entry.session.is_none() {
            let _slot = self
                .recovery
                .try_acquire()
                .map_err(|_| Failure::new("RECOVERY_BUSY"))?;
            entry.session = Some(
                entry
                    .database
                    .session(principal, path, deadline)
                    .map_err(Failure::from)?,
            );
        }
        Ok(entry.session.as_mut().expect("session initialized"))
    }

    fn dispatch(
        &self,
        principal: &Principal,
        entry: &mut Cached,
        action: Action,
        path: &Path,
        deadline: Instant,
        output: Option<&mut crate::output::OutputContext>,
    ) -> Result<Value, Failure> {
        let deployment = principal.deployment;
        let principal = principal.principal;
        let database = entry.database.clone();
        let head =
            match action {
                Action::Create { nonce } => database.create(principal, nonce.0, deadline)?,
                Action::Status { .. } => database.status(principal, deadline)?,
                Action::StorageStatus {} => {
                    entry.session = None;
                    database.storage_status(principal, deadline)?
                }
                Action::RetireStorage {
                    expected_head_serial,
                } => {
                    // This publishes a permanent metadata barrier. It neither
                    // needs delete credentials nor replays any application SQL.
                    entry.session = None;
                    database.retire_storage(principal, expected_head_serial.0, deadline)?
                }
                Action::Open {} => {
                    // An explicit recovery call has its own HTTP deadline and
                    // refreshes a cached stale root without ever replaying SQL.
                    entry.session = None;
                    self.session(principal, entry, path, deadline)?;
                    database.status(principal, deadline)?
                }
                Action::Query { statements } => {
                    let statements = wire::statements(&statements)?;
                    let value = self.session(principal, entry, path, deadline)?.query(
                        principal,
                        &statements,
                        deadline,
                    )?;
                    return match output {
                        Some(output) => queried_budgeted(value, output),
                        None => queried(value),
                    };
                }
                Action::Execute {
                    request,
                    statements,
                } => {
                    let identity = request.native(principal)?;
                    let statements = wire::statements(&statements)?;
                    let expected =
                        scap_object::request(identity.epoch, identity.id, principal, &statements)?;
                    if expected != identity {
                        return Err(Failure::new("REQUEST_CONFLICT"));
                    }
                    let (receipt, result) = self
                        .session(principal, entry, path, deadline)?
                        .execute(principal, &identity, &statements, deadline)?;
                    return match output {
                        Some(output) => committed_budgeted(receipt, result, output),
                        None => committed(receipt, result),
                    };
                }
                Action::Lookup { request } => {
                    let resolution =
                        database.lookup(principal, &request.native(principal)?, deadline)?;
                    return resolved(resolution, output);
                }
                Action::Cancel { request } => {
                    let resolution =
                        database.cancel(principal, &request.native(principal)?, deadline)?;
                    return resolved(resolution, output);
                }
                Action::Activate {
                    expected_revision,
                    nonce,
                    ..
                } => {
                    let _slot = self
                        .recovery
                        .try_acquire()
                        .map_err(|_| Failure::new("RECOVERY_BUSY"))?;
                    entry.session = None;
                    let (head, session) = database.activate_session(
                        principal,
                        expected_revision.0,
                        nonce.0,
                        path,
                        deadline,
                    )?;
                    entry.session = Some(session);
                    head
                }
                Action::Takeover {
                    expected_revision,
                    nonce,
                    ..
                } => {
                    entry.session = None;
                    database.takeover(principal, expected_revision.0, nonce.0, deadline)?
                }
                Action::CloseFull {
                    expected_revision,
                    nonce,
                } => database.close_full(principal, expected_revision.0, nonce.0, deadline)?,
                Action::Policy {
                    expected_revision,
                    nonce,
                    permissions,
                } => database.set_policy(
                    principal,
                    expected_revision.0,
                    nonce.0,
                    permissions
                        .iter()
                        .map(wire::WirePermission::native)
                        .collect(),
                    deadline,
                )?,
                Action::Quota {
                    expected_revision,
                    nonce,
                    max_bytes,
                } => {
                    entry.session = None;
                    database.set_quota(
                        principal,
                        expected_revision.0,
                        nonce.0,
                        DatabaseQuota {
                            max_bytes: max_bytes.map(|value| value.0),
                        },
                        deadline,
                    )?
                }
                Action::Lifecycle {
                    expected_revision,
                    nonce,
                    lifecycle,
                } => {
                    entry.session = None;
                    database.set_lifecycle(
                        principal,
                        expected_revision.0,
                        nonce.0,
                        lifecycle,
                        deadline,
                    )?
                }
                Action::CompactBegin {
                    expected_head_serial,
                } => {
                    entry.session = None;
                    database.compact_begin(principal, expected_head_serial.0, deadline)?
                }
                Action::CompactCopy { plan_serial } => {
                    let _slot = self
                        .recovery
                        .try_acquire()
                        .map_err(|_| Failure::new("RECOVERY_BUSY"))?;
                    database.compact_copy(principal, plan_serial.0, deadline)?
                }
                Action::CompactPromote { plan_serial } => {
                    // Promotion leaves ownership inactive. Never retain the
                    // retired image or silently activate/replay application SQL.
                    entry.session = None;
                    database.compact_promote(principal, plan_serial.0, deadline)?
                }
                Action::CompactAbort { plan_serial } => {
                    database.compact_abort(principal, plan_serial.0, deadline)?
                }
                Action::GcPrepare {
                    expected_head_serial,
                    generation,
                    after,
                } => {
                    let collector = self.collector(deployment)?;
                    let _slot = self
                        .recovery
                        .try_acquire()
                        .map_err(|_| Failure::new("RECOVERY_BUSY"))?;
                    let report = database.gc_prepare(
                        principal,
                        expected_head_serial.0,
                        generation.0,
                        after.as_deref(),
                        collector.listings.as_ref(),
                        collector.garbage.as_ref(),
                        deadline,
                    )?;
                    if let Some(output) = output {
                        output.head_result();
                    }
                    return Ok(wire::sweep(&report));
                }
                Action::GcResume { batch_serial } => {
                    let collector = self.collector(deployment)?;
                    let _slot = self
                        .recovery
                        .try_acquire()
                        .map_err(|_| Failure::new("RECOVERY_BUSY"))?;
                    let report = database.gc_resume(
                        principal,
                        batch_serial.0,
                        collector.garbage.as_ref(),
                        deadline,
                    )?;
                    if let Some(output) = output {
                        output.head_result();
                    }
                    return Ok(wire::sweep(&report));
                }
            };
        if let Some(output) = output {
            output.head_result();
        }
        Ok(wire::status(&head))
    }

    fn collector(&self, deployment: u64) -> Result<&Collector, Failure> {
        let collector = self
            .collector
            .as_ref()
            .ok_or_else(|| Failure::new("GC_DISABLED"))?;
        if deployment != collector.deployment {
            return Err(Failure::new("DENIED"));
        }
        Ok(collector)
    }
}

fn committed(
    receipt: scap_object::Receipt,
    result: scap_sql::TransactionResult,
) -> Result<Value, Failure> {
    let encoded = match wire::result(&result) {
        Ok(encoded) => encoded,
        Err(_) => {
            return Err(Failure {
                code: "COMMITTED_BUT_UNAVAILABLE",
                receipt: Some(Box::new(receipt)),
            })
        }
    };
    Ok(wire::committed(&receipt, encoded))
}

fn committed_budgeted(
    receipt: scap_object::Receipt,
    result: scap_sql::TransactionResult,
    output: &mut crate::output::OutputContext,
) -> Result<Value, Failure> {
    output.committed(receipt);
    let encoded =
        wire::budgeted_result(&result, output).map_err(|_| output.committed_unavailable())?;
    Ok(wire::committed(output.receipt(), encoded))
}

fn resolved(
    resolution: scap_object::Resolution,
    output: Option<&mut crate::output::OutputContext>,
) -> Result<Value, Failure> {
    match output {
        Some(output) => wire::budgeted_resolved(resolution, output),
        None => Ok(wire::resolved(resolution)),
    }
}

fn queried_budgeted(
    result: scap_sql::TransactionResult,
    output: &mut crate::output::OutputContext,
) -> Result<Value, Failure> {
    Ok(Value::Object(Map::from_iter([(
        "result".into(),
        Value::String(wire::budgeted_result(&result, output)?),
    )])))
}

fn queried(result: scap_sql::TransactionResult) -> Result<Value, Failure> {
    Ok(Value::Object(Map::from_iter([(
        "result".into(),
        Value::String(wire::result(&result)?),
    )])))
}

#[cfg(test)]
mod tests;
