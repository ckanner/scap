use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_cell::{AdminResult, Admission, CommandKind, DatabaseView, Grant, Lookup, Outcome};
use scap_cell_client::{CellPort, Client, RequestContext};
use scap_engine::EngineIdentity;
use scap_raft_runtime::Clock;
use scap_service::{Mode, Outcome as ServiceOutcome, ServiceError};
use scap_sql::{Statement, TransactionResult};
use scap_sql_worker::{Engine, EngineFactory, OwnerRequest, Writer};
use sha2::{Digest, Sha256};

use crate::config::{cell_limits, worker_limits, Config, DatabaseConfig};
use crate::failure;
pub(crate) use crate::local::LocalPort;

pub(crate) trait ControlPort: CellPort + Clone + 'static {
    fn leadership(&self, deadline: Instant) -> Result<(bool, u64), ServiceError>;
    fn maintain(&self, deadline: Instant, force: bool) -> Result<(), ServiceError>;
}

pub(crate) enum Operation {
    Status,
    Execute {
        mode: Mode,
        statements: Vec<Statement>,
    },
    Outcome {
        resolve: bool,
        statements: Vec<Statement>,
    },
}

pub(crate) struct Request {
    pub database: DatabaseConfig,
    pub context: RequestContext,
    pub request_id: u128,
    pub operation: Operation,
}

pub(crate) enum Reply {
    Status(scap_service::DatabaseStatus),
    Sql(TransactionResult),
    Outcome(ServiceOutcome),
}

/// Object I/O is outside the ordered state machine. An implementation must use
/// the currently published exact archive and preserve this original context.
pub(crate) trait ColdStorage<P: ControlPort> {
    /// Collect completed background work without waiting for object I/O.
    fn poll(&mut self) -> bool {
        false
    }
    fn hydrate(
        &mut self,
        client: &mut Client<P>,
        context: &RequestContext,
        database: &DatabaseView,
        operation: u128,
    ) -> Result<(), ServiceError>;
    fn archive(
        &mut self,
        client: &mut Client<P>,
        context: &RequestContext,
        database: &DatabaseView,
        publish: u128,
        prune: u128,
    ) -> Result<bool, ServiceError>;
}

struct BorrowFactory<'a, F>(&'a mut F);
impl<P: CellPort + 'static, F: EngineFactory<P>> EngineFactory<P> for BorrowFactory<'_, F> {
    type Engine = F::Engine;
    fn create(
        &mut self,
        directory: &Path,
        image: scap_engine::Image,
        limits: scap_sqlite::WriterLimits,
        gate: scap_cell_client::Gate<P>,
    ) -> Result<Self::Engine, scap_sqlite::Error> {
        self.0.create(directory, image, limits, gate)
    }
}

struct Slot<P: CellPort + 'static, E: Engine> {
    writer: Writer<P, E>,
    // Field declaration order closes the engine before removing its directory.
    _cache: crate::cache::Cache,
    last_use: Instant,
}

fn current_owner(owner: scap_cell::OwnerToken, revision: u64, view: &DatabaseView) -> bool {
    owner == view.owner && view.active && revision == view.revision
}

/// Thread-confined SQL ownership and catalogue maintenance. The dispatcher uses
/// `scan` without opening an engine; each lazy database lane uses `tick` and
/// `request`. Only the Raft leader recovers owners. A change of term retires the
/// local writers; ReadIndex and ordered acceptance remain the authority.
pub(crate) struct Worker<P: ControlPort, F: EngineFactory<P>, C: ColdStorage<P>> {
    config: Config,
    port: P,
    client: Client<P>,
    factory: F,
    cold: C,
    clock: Arc<dyn Clock>,
    ready: Arc<AtomicBool>,
    boot: u128,
    sequence: u64,
    term: u64,
    cursor: usize,
    writers: BTreeMap<u128, Slot<P, F::Engine>>,
    cache_failed: Arc<AtomicBool>,
    checkpoint_needed: bool,
    maintenance_round: u8,
}

impl<P: ControlPort, F: EngineFactory<P>, C: ColdStorage<P>> Worker<P, F, C> {
    pub(crate) fn new(
        config: Config,
        port: P,
        factory: F,
        cold: C,
        clock: Arc<dyn Clock>,
        ready: Arc<AtomicBool>,
        boot: u128,
    ) -> Result<Self, ServiceError> {
        if boot == 0 {
            return Err(failure("BOOT_ID"));
        }
        let client = Client::new(
            config.cluster_id,
            config.cell,
            cell_limits(),
            port.clone(),
            clock.clone(),
        )
        .map_err(|_| failure("CELL_SCOPE"))?;
        Ok(Self {
            config,
            port,
            client,
            factory,
            cold,
            clock,
            ready,
            boot,
            sequence: 0,
            term: 0,
            cursor: 0,
            writers: BTreeMap::new(),
            cache_failed: Arc::new(AtomicBool::new(false)),
            checkpoint_needed: false,
            maintenance_round: 0,
        })
    }

    fn id(&mut self) -> Result<u128, ServiceError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure("IDENTITY_EXHAUSTED"))?;
        let mut hash = Sha256::new();
        hash.update(b"SCAP service operation v1");
        hash.update(self.boot.to_le_bytes());
        hash.update(self.sequence.to_le_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        Ok(u128::from_le_bytes(digest[..16].try_into().unwrap()) | 1)
    }

    fn admin(
        &mut self,
        auth_epoch: u64,
        deadline: Instant,
    ) -> Result<RequestContext, ServiceError> {
        Ok(RequestContext {
            admission: Admission {
                principal_id: self.config.administrator_id,
                credential_id: self.config.service_credential_id,
                admission_id: self.id()?,
                auth_epoch,
            },
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    fn leader(&mut self, deadline: Instant) -> Result<(), ServiceError> {
        let (leader, term) = self.port.leadership(deadline).inspect_err(|_| {
            self.writers.clear();
            self.ready.store(false, Ordering::Release);
        })?;
        if !leader || term != self.term {
            self.writers.clear();
            self.ready.store(false, Ordering::Release);
            self.term = term;
        }
        if !leader {
            return Err(failure("NOT_LEADER"));
        }
        Ok(())
    }

    fn state(&mut self, deadline: Instant) -> Result<scap_cell::CellState, ServiceError> {
        let context = self.admin(1, deadline)?;
        let result = self.client.read(&context);
        self.ready.store(result.is_ok(), Ordering::Release);
        result.map_err(|_| failure("COMMIT_UNKNOWN"))
    }

    fn database(
        &mut self,
        config: &DatabaseConfig,
        deadline: Instant,
    ) -> Result<DatabaseView, ServiceError> {
        let mut state = self.state(deadline)?;
        if state.database(config.identity.database_id).is_none() {
            let mut grants = BTreeMap::new();
            grants.insert(
                self.config.administrator_id,
                scap_cell::ADMIN | scap_cell::READ | scap_cell::WRITE,
            );
            for token in &config.tokens {
                *grants.entry(token.principal_id).or_insert(0) |= token.permissions;
            }
            let context = self.admin(1, deadline)?;
            let operation_id = self.id()?;
            let applied = self
                .client
                .submit(
                    &context,
                    config.identity,
                    CommandKind::Create {
                        operation_id,
                        policy: grants
                            .into_iter()
                            .map(|(principal_id, permissions)| Grant {
                                principal_id,
                                permissions,
                            })
                            .collect(),
                    },
                )
                .map_err(|_| failure("COMMIT_UNKNOWN"))?;
            if !matches!(
                applied.outcome,
                Outcome::Administrative(AdminResult::Created)
                    | Outcome::AlreadyApplied(AdminResult::Created)
            ) {
                return Err(failure("DATABASE_CREATE_REJECTED"));
            }
            state = self.state(deadline)?;
        }
        let view = state
            .database(config.identity.database_id)
            .ok_or_else(|| failure("DATABASE_MISSING"))?;
        if view.identity != config.identity {
            return Err(failure("DATABASE_FENCED"));
        }
        Ok(view)
    }

    fn recover(
        &mut self,
        database: &DatabaseConfig,
        view: DatabaseView,
        deadline: Instant,
    ) -> Result<(), ServiceError> {
        self.recover_after_prune(database, view, deadline, true)
    }

    fn recover_after_prune(
        &mut self,
        database: &DatabaseConfig,
        mut view: DatabaseView,
        deadline: Instant,
        may_refresh: bool,
    ) -> Result<(), ServiceError> {
        let context = self.admin(view.auth_epoch, deadline)?;
        if view.cold {
            let hydrate = self.id()?;
            self.cold
                .hydrate(&mut self.client, &context, &view, hydrate)?;
            view = self.database(database, deadline)?;
        }
        let instance = self.id()?;
        let request = OwnerRequest {
            identity: EngineIdentity {
                cell: self.config.cell,
                database: database.identity,
            },
            expected_owner_epoch: view.owner.epoch,
            worker_instance_id: instance,
            claim_operation_id: self.id()?,
            activate_operation_id: self.id()?,
        };
        let directory = self
            .config
            .data_dir
            .join("writers")
            .join(format!("{instance:032x}"));
        let cache = crate::cache::Cache::reserve(directory.clone(), self.cache_failed.clone())?;
        let writer = match Writer::recover_with(
            self.client.clone(),
            &context,
            request,
            &directory,
            worker_limits(),
            self.clock.clone(),
            BorrowFactory(&mut self.factory),
        ) {
            Ok(writer) => writer,
            Err(scap_sql_worker::Error::Rejected(scap_cell::Reject::Cold)) if may_refresh => {
                // An already queued archive can prune between the initial view
                // and ClaimOwner. This explicit rejection proves no owner was
                // acquired and SQL has not run. Refresh once with the original
                // deadline; no unknown write or administrative attempt retries.
                drop(cache);
                let fresh = self.database(database, deadline)?;
                return self.recover_after_prune(database, fresh, deadline, false);
            }
            Err(_) => return Err(failure("RECOVERY_UNAVAILABLE")),
        };
        self.writers.insert(
            database.identity.database_id,
            Slot {
                writer,
                _cache: cache,
                last_use: self.clock.now().map_err(|_| failure("CLOCK"))?.instant,
            },
        );
        Ok(())
    }

    fn check_cache(&self) -> Result<(), ServiceError> {
        if self.cache_failed.load(Ordering::Acquire) {
            self.ready.store(false, Ordering::Release);
            return Err(failure("CACHE_CLEANUP_REQUIRED"));
        }
        Ok(())
    }

    fn begin_tick(&mut self) -> Result<(Instant, Instant), ServiceError> {
        self.check_cache()?;
        let now = self
            .clock
            .now()
            .map_err(|_| {
                self.ready.store(false, Ordering::Release);
                failure("CLOCK")
            })?
            .instant;
        let deadline = now + Duration::from_secs(2);
        self.checkpoint_needed |= self.cold.poll();
        self.maintenance_round = (self.maintenance_round + 1) % 30;
        self.port
            .maintain(
                deadline,
                self.checkpoint_needed || self.maintenance_round == 0,
            )
            .inspect_err(|_| self.ready.store(false, Ordering::Release))?;
        self.checkpoint_needed = false;
        self.leader(deadline)?;
        Ok((now, deadline))
    }

    fn next_database(
        &mut self,
        deadline: Instant,
    ) -> Result<(DatabaseConfig, DatabaseView), ServiceError> {
        let database = self.config.databases[self.cursor].clone();
        self.cursor = (self.cursor + 1) % self.config.databases.len();
        let view = self.database(&database, deadline)?;
        Ok((database, view))
    }

    /// Inspect one catalogue entry without creating a SQLite connection or
    /// performing foreground object I/O. Suspended entries can enqueue bounded
    /// background archival; only unsuspended entries ask for a recovery lane.
    /// Requests can independently schedule their own database between scans.
    pub(crate) fn scan(&mut self) -> Result<Option<DatabaseConfig>, ServiceError> {
        let (_, deadline) = self.begin_tick()?;
        let (database, view) = self.next_database(deadline)?;
        if !view.suspended {
            return Ok(Some(database));
        }
        if !view.cold {
            let context = self.admin(view.auth_epoch, deadline)?;
            let publish = self.id()?;
            let prune = self.id()?;
            self.checkpoint_needed |=
                self.cold
                    .archive(&mut self.client, &context, &view, publish, prune)?;
        }
        Ok(None)
    }

    /// A lane can retire only after native writers have closed. Failed cleanup
    /// remains attached to this lane so a restart cannot hide that failure.
    pub(crate) fn dormant(&self) -> bool {
        self.writers.is_empty() && !self.cache_failed.load(Ordering::Acquire)
    }

    /// A single bounded maintenance action per tick prevents a cold catalogue
    /// from creating one unbounded startup/recovery queue. Suspended databases
    /// stay asleep until an authenticated request explicitly needs them.
    pub(crate) fn tick(&mut self) -> Result<(), ServiceError> {
        let (now, deadline) = self.begin_tick()?;
        let (database, view) = self.next_database(deadline)?;
        let id = database.identity.database_id;
        if self.writers.get(&id).is_some_and(|slot| {
            !current_owner(slot.writer.owner(), slot.writer.head().revision, &view)
        }) {
            // A stale local idle timer never authorizes suspending a new owner.
            self.writers.remove(&id);
            return self.check_cache();
        }
        let expired = self.writers.get(&id).is_some_and(|slot| {
            now.saturating_duration_since(slot.last_use) >= self.config.idle_timeout
        });
        if expired {
            let context = self.admin(view.auth_epoch, deadline)?;
            let operation_id = self.id()?;
            let outcome = self
                .client
                .submit(
                    &context,
                    database.identity,
                    CommandKind::SuspendDb {
                        operation_id,
                        token: view.owner,
                        expected_revision: view.revision,
                    },
                )
                .map_err(|_| failure("COMMIT_UNKNOWN"))?
                .outcome;
            if !matches!(
                outcome,
                Outcome::Administrative(AdminResult::Suspended(_))
                    | Outcome::AlreadyApplied(AdminResult::Suspended(_))
            ) {
                return Err(failure("SUSPEND_REJECTED"));
            }
            self.writers.remove(&id);
            let view = self.database(&database, deadline)?;
            let publish = self.id()?;
            let prune = self.id()?;
            self.checkpoint_needed |=
                self.cold
                    .archive(&mut self.client, &context, &view, publish, prune)?;
        } else if !view.suspended && !self.writers.contains_key(&id) {
            self.recover(&database, view, deadline)?;
        } else if view.suspended && !view.cold {
            let context = self.admin(view.auth_epoch, deadline)?;
            let publish = self.id()?;
            let prune = self.id()?;
            self.checkpoint_needed |=
                self.cold
                    .archive(&mut self.client, &context, &view, publish, prune)?;
        }
        self.check_cache()
    }

    pub(crate) fn request(&mut self, request: Request) -> Result<Reply, ServiceError> {
        self.check_cache()?;
        let context = &request.context;
        if context.cancelled.load(Ordering::Acquire)
            || self.clock.now().map_err(|_| failure("CLOCK"))?.instant >= context.deadline
        {
            return Err(failure("COMMIT_UNKNOWN"));
        }
        self.leader(context.deadline)?;
        match request.operation {
            Operation::Status => {
                let state = self
                    .client
                    .read(context)
                    .map_err(|_| failure("COMMIT_UNKNOWN"))?;
                let view = state
                    .metadata(request.database.identity, context.admission)
                    .map_err(|_| failure("OUTCOME_FORBIDDEN"))?;
                Ok(Reply::Status(scap_service::DatabaseStatus {
                    revision: view.revision,
                    suspended: view.suspended,
                    cold: view.cold,
                    owner_active: view.active,
                    archived_revision: view.archive.map(|archive| archive.revision),
                }))
            }
            Operation::Outcome {
                resolve,
                statements,
            } => self
                .outcome(
                    &request.database,
                    context,
                    request.request_id,
                    resolve,
                    &statements,
                )
                .map(Reply::Outcome),
            Operation::Execute { mode, statements } => {
                let id = request.database.identity.database_id;
                if !self.writers.contains_key(&id) {
                    let view = self.database(&request.database, context.deadline)?;
                    // A cold wake has administrative side effects. Authenticate
                    // current policy before doing those on behalf of a caller.
                    // An already active Writer performs its own fresh barrier
                    // and authorization; it does not need duplicate barriers.
                    let fingerprint =
                        scap_sql::request_fingerprint(&statements, worker_limits().sqlite.sql)
                            .map_err(|_| failure("INVALID_REQUEST"))?;
                    self.client
                        .read(context)
                        .map_err(|_| failure("COMMIT_UNKNOWN"))?
                        .lookup(
                            request.database.identity,
                            context.admission,
                            request.request_id,
                            fingerprint,
                        )
                        .map_err(|_| failure("OUTCOME_FORBIDDEN"))?;
                    self.recover(&request.database, view, context.deadline)?;
                }
                let slot = self.writers.get_mut(&id).unwrap();
                if slot.writer.head().identity.database != request.database.identity {
                    return Err(failure("DATABASE_FENCED"));
                }
                let result = match mode {
                    Mode::Read => slot
                        .writer
                        .query(context.clone(), &statements)
                        .map(|read| read.result),
                    Mode::Write => slot
                        .writer
                        .execute(context.clone(), request.request_id, &statements)
                        .map(|write| write.result),
                };
                let stopped = slot.writer.is_stopped();
                let observed = self.clock.now();
                if let Ok(now) = &observed {
                    slot.last_use = now.instant;
                }
                if result.is_err() || stopped || observed.is_err() {
                    self.writers.remove(&id);
                }
                observed.map_err(|_| failure("CLOCK"))?;
                result.map(Reply::Sql).map_err(|error| match error {
                    scap_sql_worker::Error::Native(
                        scap_sqlite::Error::CommittedButUnavailable { .. },
                    ) => failure("COMMITTED_RESULT_UNAVAILABLE"),
                    _ if mode == Mode::Read => failure("QUERY_FAILED"),
                    _ => failure("COMMIT_UNKNOWN"),
                })
            }
        }
    }

    fn outcome(
        &mut self,
        database: &DatabaseConfig,
        context: &RequestContext,
        request_id: u128,
        resolve: bool,
        statements: &[Statement],
    ) -> Result<ServiceOutcome, ServiceError> {
        let fingerprint = scap_sql::request_fingerprint(statements, worker_limits().sqlite.sql)
            .map_err(|_| failure("INVALID_REQUEST"))?;
        if resolve {
            let applied = self
                .client
                .submit(
                    context,
                    database.identity,
                    CommandKind::ResolveOrCancel {
                        request_id,
                        request_fingerprint: fingerprint,
                    },
                )
                .map_err(|_| failure("COMMIT_UNKNOWN"))?;
            match applied.outcome {
                Outcome::Cancelled | Outcome::AlreadyCancelled | Outcome::AlreadyCommitted(_) => (),
                _ => return Err(failure("RESOLVE_REJECTED")),
            }
        }
        let state = self
            .client
            .read(context)
            .map_err(|_| failure("COMMIT_UNKNOWN"))?;
        match state
            .lookup(
                database.identity,
                context.admission,
                request_id,
                fingerprint,
            )
            .map_err(|_| failure("OUTCOME_FORBIDDEN"))?
        {
            Lookup::Unknown => Ok(ServiceOutcome::Unknown),
            Lookup::Cancelled { .. } => Ok(ServiceOutcome::Cancelled),
            Lookup::Committed { commit, result } => Ok(ServiceOutcome::Committed {
                result: scap_sql::decode_result(&result, worker_limits().sqlite.sql)
                    .map_err(|_| failure("RESULT_CORRUPT"))?,
                sequence: commit.receipt.sequence,
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
