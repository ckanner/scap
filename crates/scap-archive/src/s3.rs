use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut};
use object_store::path::Path;
use object_store::{ClientOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions, RetryConfig};
use scap_cell_client::RequestContext;
use tokio::runtime::Handle;

use crate::{Error, Objects};

/// Explicit credentials; no ambient discovery or metadata-service fallback.
/// TLS is mandatory unless the operator explicitly enables local HTTP testing.
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub allow_http: bool,
    pub max_object_bytes: u32,
    pub request_timeout: Duration,
}

#[derive(Clone)]
pub struct S3 {
    store: AmazonS3,
    runtime: Handle,
    max_object_bytes: u32,
}

impl S3 {
    /// The supplied runtime must keep running while a dedicated blocking caller
    /// invokes Objects. Do not invoke these synchronous methods on its async
    /// executor threads. No service threads or unbounded queues are created.
    pub fn new(config: S3Config, runtime: Handle) -> Result<Self, Error> {
        Self::build(config, runtime, AmazonS3Builder::build)
    }

    fn build(
        config: S3Config,
        runtime: Handle,
        construct: fn(AmazonS3Builder) -> object_store::Result<AmazonS3>,
    ) -> Result<Self, Error> {
        let url = reqwest::Url::parse(&config.endpoint).map_err(|_| Error::Invalid)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || (url.scheme() == "http" && !config.allow_http)
            || config.region.is_empty()
            || config.bucket.is_empty()
            || config.access_key.is_empty()
            || config.secret_key.is_empty()
            || config.max_object_bytes == 0
            || config.request_timeout.is_zero()
        {
            return Err(Error::Invalid);
        }
        // reqwest's no-provider TLS feature requires an explicit runtime default.
        // Keep an already configured application provider; otherwise install ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = AmazonS3Builder::new()
            .with_endpoint(config.endpoint)
            .with_region(config.region)
            .with_bucket_name(config.bucket)
            .with_access_key_id(config.access_key)
            .with_secret_access_key(config.secret_key)
            .with_allow_http(config.allow_http)
            .with_virtual_hosted_style_request(false)
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .with_retry(RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            })
            .with_client_options(
                ClientOptions::new()
                    .with_allow_http(config.allow_http)
                    .with_timeout(config.request_timeout)
                    .with_connect_timeout(config.request_timeout)
                    .with_pool_max_idle_per_host(2),
            );
        if let Some(token) = config.session_token {
            builder = builder.with_token(token);
        }
        let store = construct(builder).map_err(object_error)?;
        Ok(Self {
            store,
            runtime,
            max_object_bytes: config.max_object_bytes,
        })
    }

    fn check(&self, size: usize, context: &RequestContext) -> Result<(), Error> {
        if size > self.max_object_bytes as usize {
            return Err(Error::TooLarge);
        }
        if context.cancelled.load(Ordering::Acquire) || Instant::now() >= context.deadline {
            return Err(Error::Unknown);
        }
        Ok(())
    }
}

impl Objects for S3 {
    fn put(&mut self, key: &str, bytes: &[u8], context: &RequestContext) -> Result<(), Error> {
        self.check(bytes.len(), context)?;
        let path = Path::parse(key).map_err(|_| Error::Invalid)?;
        let future = self.store.put_opts(
            &path,
            bytes.to_vec().into(),
            PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            },
        );
        let result = self
            .runtime
            .block_on(async { tokio::time::timeout_at(context.deadline.into(), future).await })
            .map_err(|_| Error::Unknown)?;
        match result {
            Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(_) => return Err(Error::Object),
        }
        self.check(bytes.len(), context)
    }

    fn get(
        &mut self,
        key: &str,
        max_bytes: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Error> {
        self.check(max_bytes as usize, context)?;
        let path = Path::parse(key).map_err(|_| Error::Invalid)?;
        let future = async {
            let head = self.store.head(&path).await.map_err(object_error)?;
            if head.size > u64::from(max_bytes) {
                return Err(Error::TooLarge);
            }
            let object = self.store.get(&path).await.map_err(object_error)?;
            if object.meta.size > u64::from(max_bytes) {
                return Err(Error::TooLarge);
            }
            collect(object.into_stream(), max_bytes).await
        };
        let bytes = self
            .runtime
            .block_on(async { tokio::time::timeout_at(context.deadline.into(), future).await })
            .map_err(|_| Error::Unknown)??;
        self.check(bytes.len(), context)?;
        Ok(bytes)
    }
}

async fn collect(
    mut stream: futures_util::stream::BoxStream<'_, object_store::Result<bytes::Bytes>>,
    max_bytes: u32,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(object_error)?;
        let chunk = chunk.as_ref();
        if bytes.len().saturating_add(chunk.len()) > max_bytes as usize {
            return Err(Error::TooLarge);
        }
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn object_error(_: object_store::Error) -> Error {
    Error::Object
}

#[cfg(test)]
mod tests;
