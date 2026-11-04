//! Bounded, self-contained Hrana HTTP v2 requests and explicit outcome lookup.
//!
//! This adapter never authenticates a client-provided scope or retries SQL.
//! Backends must verify credentials, authorize the immutable database identity,
//! and preserve the original deadline/cancellation through durable completion.
//! Only a closed, self-contained execute or standard atomic batch is supported;
//! interactive streams, arbitrary conditional programs and cursors fail closed.

mod http;
mod protocol;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use scap_sql::{SqlLimits, Statement, TransactionResult};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

pub use http::router;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceError {
    pub code: String,
    pub message: String,
}

impl ServiceError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Read,
    Write,
}

/// Credentials are intentionally absent from Debug implementations and output.
pub struct RequestContext {
    pub database: String,
    pub credential: String,
    pub request_id: u128,
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}

pub struct Call {
    pub context: RequestContext,
    pub mode: Mode,
    pub statements: Vec<Statement>,
}

pub struct OutcomeCall {
    pub context: RequestContext,
    /// Exact business statements after Hrana atomic-program translation.
    pub statements: Vec<Statement>,
    pub resolve_or_cancel: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Committed {
        result: TransactionResult,
        sequence: u64,
    },
    Cancelled,
    /// A point-in-time absence; never proof that a late write cannot commit.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseStatus {
    pub revision: u64,
    pub base_revision: u64,
    pub tail_entries: u64,
    pub tail_bytes: u64,
    pub suspended: bool,
    pub cold: bool,
    pub owner_active: bool,
    pub archived_revision: Option<u64>,
}

pub type BackendFuture<T> = Pin<Box<dyn Future<Output = Result<T, ServiceError>> + Send>>;

pub trait Backend: Send + Sync + 'static {
    fn execute(&self, call: Call) -> BackendFuture<TransactionResult>;
    fn outcome(&self, call: OutcomeCall) -> BackendFuture<Outcome>;
    fn status(&self, context: RequestContext) -> BackendFuture<DatabaseStatus>;
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub max_pipeline_requests: usize,
    pub max_cached_statements: usize,
    pub max_cached_sql_bytes: usize,
    pub max_inflight: usize,
    pub max_token_bytes: usize,
    pub max_timeout: Duration,
    pub sql: SqlLimits,
}

impl Limits {
    fn validate(self) -> Result<(), ServiceError> {
        self.sql
            .validate()
            .map_err(|_| invalid("invalid SQL limits"))?;
        if self.max_body_bytes == 0
            || self.max_body_bytes > 16 * 1024 * 1024
            || self.max_response_bytes < 1024
            || self.max_response_bytes > 128 * 1024 * 1024
            || self.max_pipeline_requests < 2
            || self.max_pipeline_requests > 1024
            || self.max_cached_statements == 0
            || self.max_cached_statements > 1024
            || self.max_cached_sql_bytes == 0
            || self.max_cached_sql_bytes > self.max_body_bytes
            || self.max_inflight == 0
            || self.max_inflight > 1024
            || self.max_token_bytes == 0
            || self.max_token_bytes > 8192
            || self.max_timeout.is_zero()
            || self.max_timeout > Duration::from_secs(3600)
        {
            return Err(invalid("invalid HTTP limits"));
        }
        Ok(())
    }
}

/// Wall-clock translation happens once at HTTP admission; all subsequent work
/// uses the resulting monotonic deadline. A client may shorten, never extend,
/// the configured maximum request budget.
pub trait Environment: Send + Sync + 'static {
    fn now(&self) -> Instant;
    fn unix_millis(&self) -> Result<u64, ServiceError>;
}

pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn unix_millis(&self) -> Result<u64, ServiceError> {
        unix_millis(SystemTime::now())
    }
}

fn unix_millis(time: SystemTime) -> Result<u64, ServiceError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("invalid service clock"))?;
    u64::try_from(duration.as_millis()).map_err(|_| invalid("service clock overflow"))
}

pub struct Service<B: Backend> {
    backend: B,
    default_database: String,
    boot_id: u128,
    next_id: AtomicU64,
    limits: Limits,
    permits: Semaphore,
    environment: Arc<dyn Environment>,
}

impl<B: Backend> Service<B> {
    /// `boot_id` must be freshly generated for each service process start.
    pub fn new(
        backend: B,
        default_database: String,
        boot_id: u128,
        limits: Limits,
    ) -> Result<Self, ServiceError> {
        Self::with_environment(
            backend,
            default_database,
            boot_id,
            limits,
            Arc::new(SystemEnvironment),
        )
    }

    pub fn with_environment(
        backend: B,
        default_database: String,
        boot_id: u128,
        limits: Limits,
        environment: Arc<dyn Environment>,
    ) -> Result<Self, ServiceError> {
        limits.validate()?;
        validate_database(&default_database)?;
        if boot_id == 0 {
            return Err(invalid("zero service boot identity"));
        }
        Ok(Self {
            backend,
            default_database,
            boot_id,
            next_id: AtomicU64::new(1),
            limits,
            permits: Semaphore::new(limits.max_inflight),
            environment,
        })
    }

    fn generate_request_id(&self) -> Result<u128, ServiceError> {
        let sequence = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
            .map_err(|_| ServiceError::new("OVERLOADED", "service identity sequence exhausted"))?;
        let mut hash = Sha256::new();
        hash.update(b"SCAP HTTP request v1");
        hash.update(self.boot_id.to_le_bytes());
        hash.update(sequence.to_le_bytes());
        let bytes: [u8; 32] = hash.finalize().into();
        // Reserve zero without making request identity depend on SQL content.
        Ok(u128::from_le_bytes(bytes[..16].try_into().unwrap()) | 1)
    }
}

fn invalid(message: &str) -> ServiceError {
    ServiceError::new("INVALID_REQUEST", message)
}
fn unsupported() -> ServiceError {
    ServiceError::new(
        "UNSUPPORTED_FEATURE",
        "unsupported Hrana program or statement feature",
    )
}

fn validate_database(database: &str) -> Result<(), ServiceError> {
    if database.is_empty()
        || database.len() > 64
        || !database
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || x == b'-' || x == b'_')
    {
        return Err(invalid("invalid database route"));
    }
    Ok(())
}

fn parse_request_id(value: &str) -> Result<u128, ServiceError> {
    if value.len() != 32 || !value.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err(invalid("request ID must be 32 hexadecimal digits"));
    }
    let id = u128::from_str_radix(value, 16).unwrap();
    if id == 0 {
        return Err(invalid("zero request ID"));
    }
    Ok(id)
}

struct CancelGuard(Arc<AtomicBool>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
