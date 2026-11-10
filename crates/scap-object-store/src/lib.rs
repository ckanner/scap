//! Bounded exact-key access and candidate discovery for object-authoritative databases.

mod gc;
mod gc_xml;
mod listing;
mod listing_guard;
mod listing_xml;

pub use gc::{
    DeleteOutcome, Garbage, GcBatch, GcCandidate, GcError, GcS3, MAX_DELETE_BATCH,
    MAX_GC_RESPONSE_BYTES,
};

pub use listing::{
    ListEnd, ListEntry, ListError, ListKind, ListMode, ListPage, ListRequest, Listings,
    MAX_LIST_ENTRIES, MAX_LIST_RESPONSE_BYTES,
};

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut};
use object_store::path::Path;
use object_store::{
    ClientOptions, GetResult, ObjectStore, ObjectStoreExt, PutMode, PutOptions, RetryConfig,
    UpdateVersion,
};
use tokio::runtime::{Handle, Runtime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub bytes: Vec<u8>,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Missing,
    Conflict,
    Unknown,
    Invalid,
    /// Local configured or aggregate allowance was exhausted. No physical
    /// response corruption or missing durable object is implied.
    Budget,
    /// The actual response exceeds the caller's format bound.
    Limit,
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition<'a> {
    Absent,
    Match(&'a str),
}

pub trait Objects: Send + Sync {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError>;

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError>;
}

/// Explicit configuration: ambient credentials and metadata discovery are not used.
/// Credentials deliberately do not implement `Debug`.
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub timeout: Duration,
    pub max_object_bytes: usize,
    pub allow_http: bool,
}

/// Synchronous, bounded adapter for dedicated database worker threads.
///
/// Construct, call and drop this adapter outside an asynchronous runtime. Clones
/// share one I/O runtime and connection pool. Every write has a condition; the
/// adapter never refreshes an ETag, follows redirects, retries a request, or
/// performs an implicit listing.
#[derive(Clone)]
pub struct S3 {
    store: Arc<AmazonS3>,
    runtime: Arc<Runtime>,
    max_object_bytes: usize,
    bucket: String,
}

impl S3 {
    pub fn new(config: S3Config) -> Result<Self, StoreError> {
        Self::build(config, AmazonS3Builder::build, runtime)
    }

    fn build(
        config: S3Config,
        construct: fn(AmazonS3Builder) -> object_store::Result<AmazonS3>,
        make_runtime: fn() -> std::io::Result<Runtime>,
    ) -> Result<Self, StoreError> {
        let endpoint = reqwest::Url::parse(&config.endpoint).map_err(|_| StoreError::Invalid)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || (endpoint.scheme() == "http" && !config.allow_http)
            || config.region.is_empty()
            || config.bucket.is_empty()
            || config.access_key.is_empty()
            || config.secret_key.is_empty()
            || config.session_token.as_deref() == Some("")
            || config.max_object_bytes == 0
            || config.timeout.is_zero()
            || Handle::try_current().is_ok()
        {
            return Err(StoreError::Invalid);
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let bucket = config.bucket.clone();
        let mut builder = AmazonS3Builder::new()
            .with_endpoint(config.endpoint)
            .with_region(config.region)
            .with_bucket_name(config.bucket)
            .with_access_key_id(config.access_key)
            .with_secret_access_key(config.secret_key)
            .with_virtual_hosted_style_request(false)
            .with_allow_http(config.allow_http)
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .with_http_connector(listing_guard::Connector(listing_guard::Direct {
                timeout: config.timeout,
                allow_http: config.allow_http,
            }))
            .with_retry(RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            })
            .with_client_options(
                ClientOptions::new()
                    .with_allow_http(config.allow_http)
                    .with_timeout(config.timeout)
                    .with_connect_timeout(config.timeout)
                    .with_pool_max_idle_per_host(2),
            );
        if let Some(token) = config.session_token {
            builder = builder.with_token(token);
        }
        let store = construct(builder).map_err(|_| StoreError::Invalid)?;
        let runtime = make_runtime().map_err(|_| StoreError::Invalid)?;
        Ok(Self {
            store: Arc::new(store),
            runtime: Arc::new(runtime),
            max_object_bytes: config.max_object_bytes,
            bucket,
        })
    }

    fn check(&self, key: &str, size: usize, deadline: Instant) -> Result<Path, StoreError> {
        if Handle::try_current().is_ok() {
            return Err(StoreError::Invalid);
        }
        if size > self.max_object_bytes {
            return Err(StoreError::Budget);
        }
        budget(deadline)?;
        if key.is_empty() || key.len() > 1024 {
            return Err(StoreError::Invalid);
        }
        let path = Path::parse(key).map_err(|_| StoreError::Invalid)?;
        if path.as_ref() != key {
            return Err(StoreError::Invalid);
        }
        Ok(path)
    }

    fn execute<T>(
        &self,
        deadline: Instant,
        future: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        let outcome = self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), future)
                .await
                .map_err(|_| StoreError::Unknown)?
        });
        budget(deadline)?;
        outcome
    }
}

impl Objects for S3 {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let path = self.check(key, max_bytes, deadline)?;
        self.execute(deadline, async {
            // This one GET supplies both the body and its ETag. A separate HEAD
            // could observe a different version and would invalidate CAS safety.
            let object = self.store.get(&path).await.map_err(read_error)?;
            read_object(object, max_bytes).await
        })
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        let path = self.check(key, bytes.len(), deadline)?;
        let mode = match condition {
            Condition::Absent => PutMode::Create,
            Condition::Match(etag) => {
                if !valid_etag(etag) {
                    return Err(StoreError::Invalid);
                }
                PutMode::Update(UpdateVersion {
                    e_tag: Some(etag.to_owned()),
                    version: None,
                })
            }
        };
        self.execute(deadline, async {
            let result = self
                .store
                .put_opts(
                    &path,
                    bytes.to_vec().into(),
                    PutOptions {
                        mode,
                        ..PutOptions::default()
                    },
                )
                .await
                .map_err(write_error)?;
            result
                .e_tag
                .filter(|etag| valid_etag(etag))
                .ok_or(StoreError::Unknown)
        })
    }
}

fn runtime() -> std::io::Result<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
}

fn budget(deadline: Instant) -> Result<(), StoreError> {
    if Instant::now() >= deadline {
        return Err(StoreError::Unknown);
    }
    Ok(())
}

fn valid_etag(etag: &str) -> bool {
    etag.len() >= 2
        && etag.len() <= 1024
        && etag.starts_with('"')
        && etag.ends_with('"')
        && etag.as_bytes()[1..etag.len() - 1]
            .iter()
            .all(|byte| *byte != b'"' && (0x21..=0x7e).contains(byte))
}

async fn read_object(object: GetResult, max_bytes: usize) -> Result<Stored, StoreError> {
    if object.meta.size > max_bytes as u64 {
        return Err(StoreError::Limit);
    }
    if object.range != (0..object.meta.size) {
        return Err(StoreError::Corrupt);
    }
    let expected = object.meta.size;
    let etag = object
        .meta
        .e_tag
        .as_ref()
        .filter(|etag| valid_etag(etag))
        .ok_or(StoreError::Corrupt)?
        .clone();
    let mut stream = object.into_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StoreError::Unknown)?;
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(StoreError::Limit);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() as u64 != expected {
        return Err(StoreError::Corrupt);
    }
    Ok(Stored { bytes, etag })
}

fn read_error(error: object_store::Error) -> StoreError {
    match error {
        object_store::Error::NotFound { .. } => StoreError::Missing,
        _ => StoreError::Unknown,
    }
}

fn write_error(error: object_store::Error) -> StoreError {
    match error {
        object_store::Error::Precondition { .. } => StoreError::Conflict,
        // object_store 0.14.2 wraps Create's 412 in AlreadyExists, whose source
        // is a typed Precondition. A raw 409 also becomes AlreadyExists but its
        // source is RetryError. Only the former proves condition failure.
        object_store::Error::AlreadyExists { source, .. } => {
            match source.downcast_ref::<object_store::Error>() {
                Some(object_store::Error::Precondition { .. }) => StoreError::Conflict,
                _ => StoreError::Unknown,
            }
        }
        _ => StoreError::Unknown,
    }
}

#[cfg(test)]
mod tests;
