use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use parking_lot::Mutex;
use scap_cell_client::RequestContext as CellContext;
use scap_service::{
    Backend, BackendFuture, Call, DatabaseStatus, Mode, Outcome, OutcomeAction, OutcomeCall,
    RequestContext, RotateCall, ServiceError,
};
use scap_sql::{Statement, TransactionResult, Value};
use tokio::sync::oneshot;

use crate::auth::Verifier;
use crate::config::{worker_limits, DatabaseConfig, TokenConfig};
use crate::failure;
use crate::worker::{Operation, Reply, Request};

const MAX_QUEUED: usize = 32;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_DATABASE_QUEUED: usize = 8;
const MAX_DATABASE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Default)]
struct Usage {
    count: usize,
    bytes: usize,
    databases: BTreeMap<u128, (usize, usize)>,
}

struct Reservation {
    usage: Arc<Mutex<Usage>>,
    database: u128,
    bytes: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut usage = self.usage.lock();
        usage.count -= 1;
        usage.bytes -= self.bytes;
        let database = usage.databases.get_mut(&self.database).unwrap();
        database.0 -= 1;
        database.1 -= self.bytes;
        if database.0 == 0 {
            usage.databases.remove(&self.database);
        }
    }
}

struct Cancellation(Arc<AtomicBool>);
impl Drop for Cancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

type PendingResponse = (
    oneshot::Receiver<Result<Reply, ServiceError>>,
    std::time::Instant,
    Cancellation,
);

pub(crate) struct Envelope {
    pub request: Request,
    pub reply: oneshot::Sender<Result<Reply, ServiceError>>,
    _reservation: Reservation,
}

struct Inner {
    verifier: Verifier,
    sender: mpsc::SyncSender<Envelope>,
    usage: Arc<Mutex<Usage>>,
    stopped: Arc<AtomicBool>,
}

#[derive(Clone)]
pub(crate) struct Mailbox(Arc<Inner>);

impl Mailbox {
    pub(crate) fn new(
        databases: &[DatabaseConfig],
        stopped: Arc<AtomicBool>,
    ) -> (Self, mpsc::Receiver<Envelope>) {
        let (sender, receiver) = mpsc::sync_channel(MAX_QUEUED);
        (
            Self(Arc::new(Inner {
                verifier: Verifier::new(databases),
                sender,
                usage: Arc::new(Mutex::new(Usage::default())),
                stopped,
            })),
            receiver,
        )
    }

    fn enqueue(
        &self,
        context: RequestContext,
        mode: Mode,
        operation: Operation,
    ) -> Result<PendingResponse, ServiceError> {
        if self.0.stopped.load(Ordering::Acquire) {
            return Err(failure("UNAVAILABLE"));
        }
        let deadline = context.deadline;
        if context.cancelled.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
            return Err(failure("COMMIT_UNKNOWN"));
        }
        let (database, admission) = if matches!(operation, Operation::Rotate { .. }) {
            self.0.verifier.verify_administrator(&context)?
        } else {
            self.0.verifier.verify(&context, mode)?
        };
        let statements: &[Statement] = match &operation {
            Operation::Execute { statements, .. } | Operation::Outcome { statements, .. } => {
                scap_sql::validate_statements(statements, worker_limits().sqlite.sql)
                    .map_err(|_| failure("INVALID_REQUEST"))?;
                statements
            }
            Operation::Status | Operation::Rotate { .. } => &[][..],
        };
        let bytes = request_bytes(statements, &database);
        let mut usage = self.0.usage.lock();
        if bytes > MAX_REQUEST_BYTES || usage.count >= MAX_QUEUED || bytes > MAX_BYTES - usage.bytes
        {
            return Err(failure("OVERLOADED"));
        }
        let id = database.identity.database_id;
        let &(count, used) = usage.databases.get(&id).unwrap_or(&(0, 0));
        if count >= MAX_DATABASE_QUEUED || bytes > MAX_DATABASE_BYTES - used {
            return Err(failure("OVERLOADED"));
        }
        usage.count += 1;
        usage.bytes += bytes;
        usage.databases.insert(id, (count + 1, used + bytes));
        drop(usage);
        let reservation = Reservation {
            usage: self.0.usage.clone(),
            database: id,
            bytes,
        };
        let cancellation = Cancellation(context.cancelled.clone());
        let (reply, receiver) = oneshot::channel();
        let envelope = Envelope {
            request: Request {
                database,
                context: CellContext {
                    admission,
                    deadline,
                    cancelled: context.cancelled,
                },
                request_id: context.request_id,
                operation,
            },
            reply,
            _reservation: reservation,
        };
        self.0
            .sender
            .try_send(envelope)
            .map_err(|_| failure("UNAVAILABLE"))?;
        Ok((receiver, deadline, cancellation))
    }

    async fn receive(
        pending: Result<PendingResponse, ServiceError>,
    ) -> Result<Reply, ServiceError> {
        let (receiver, deadline, cancellation) = pending?;
        let result = tokio::time::timeout_at(deadline.into(), receiver)
            .await
            .map_err(|_| failure("COMMIT_UNKNOWN"))?
            .map_err(|_| failure("COMMIT_UNKNOWN"))?;
        // Tokio may poll a ready response before observing an elapsed timer.
        // Preserve the original absolute deadline and cancellation at delivery.
        if cancellation.0.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
            return Err(failure("COMMIT_UNKNOWN"));
        }
        result
    }
}

impl Backend for Mailbox {
    fn execute(&self, call: Call) -> BackendFuture<TransactionResult> {
        let pending = self.enqueue(
            call.context,
            call.mode,
            Operation::Execute {
                mode: call.mode,
                statements: call.statements,
            },
        );
        Box::pin(async move {
            match Self::receive(pending).await? {
                Reply::Sql(result) => Ok(result),
                _ => Err(failure("INVALID_BACKEND_REPLY")),
            }
        })
    }

    fn outcome(&self, call: OutcomeCall) -> BackendFuture<Outcome> {
        let mode = match call.action {
            OutcomeAction::Lookup => Mode::Read,
            OutcomeAction::ResolveOrCancel | OutcomeAction::Acknowledge { .. } => Mode::Write,
        };
        let pending = self.enqueue(
            call.context,
            mode,
            Operation::Outcome {
                action: call.action,
                statements: call.statements,
            },
        );
        Box::pin(async move {
            match Self::receive(pending).await? {
                Reply::Outcome(outcome) => Ok(outcome),
                _ => Err(failure("INVALID_BACKEND_REPLY")),
            }
        })
    }

    fn status(&self, context: RequestContext) -> BackendFuture<DatabaseStatus> {
        let pending = self.enqueue(context, Mode::Read, Operation::Status);
        Box::pin(async move {
            match Self::receive(pending).await? {
                Reply::Status(status) => Ok(status),
                _ => Err(failure("INVALID_BACKEND_REPLY")),
            }
        })
    }

    fn rotate(&self, call: RotateCall) -> BackendFuture<u64> {
        let pending = self.enqueue(
            call.context,
            Mode::Read,
            Operation::Rotate {
                expected_epoch: call.expected_epoch,
            },
        );
        Box::pin(async move {
            match Self::receive(pending).await? {
                Reply::Rotated(epoch) => Ok(epoch),
                _ => Err(failure("INVALID_BACKEND_REPLY")),
            }
        })
    }
}

fn request_bytes(statements: &[Statement], database: &DatabaseConfig) -> usize {
    // The envelope owns a clone of the complete immutable database policy,
    // so count that allocation as well as bounded SQL/parameter allocations.
    let mut bytes = 1024_usize
        .saturating_add(database.name.len())
        .saturating_add(
            database
                .tokens
                .len()
                .saturating_mul(std::mem::size_of::<TokenConfig>()),
        );
    for statement in statements {
        bytes = bytes.saturating_add(statement.sql.len()).saturating_add(64);
        for value in &statement.parameters {
            bytes = bytes.saturating_add(32);
            if let Value::Text(value) = value {
                bytes = bytes.saturating_add(value.len());
            }
            if let Value::Blob(value) = value {
                bytes = bytes.saturating_add(value.len());
            }
        }
    }
    bytes
}

#[cfg(test)]
mod tests;
