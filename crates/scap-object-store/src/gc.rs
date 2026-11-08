//! A separate, bounded deletion capability. This transport does not prove that
//! a generation is retired: the authority must persist that proof before use.

use std::future::Future;
use std::time::Instant;

use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Method, Request};
use object_store::aws::AwsAuthorizer;
use object_store::client::{HttpClient, HttpConnector, HttpRequest, HttpRequestBody};
use object_store::ClientOptions;
use tokio::runtime::Handle;

use crate::{listing_guard, S3Config, S3};

pub const MAX_DELETE_BATCH: usize = 32;
pub const MAX_GC_RESPONSE_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcError {
    Invalid,
    Limit,
    Denied,
    Unsupported,
    Corrupt,
    /// A DELETE might already have taken effect. Never reinterpret this as
    /// Missing, Conflict, or a reason to refresh the original candidate ETag.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    /// The backend acknowledged this conditional deletion. This does not
    /// certify a permanently empty prefix or the absence of historical versions.
    Applied,
    /// This exact response reports NoSuchKey; it is not NoSuchBucket.
    Missing,
    Conflict,
}

/// Construct separately with the dedicated GC credentials. Ordinary `S3` and
/// `Objects` have no conversion or DELETE method. No ambient credentials,
/// automatic retries, redirects, governance bypass, or version deletion.
pub struct GcS3 {
    inner: S3,
    client: HttpClient,
    endpoint: reqwest::Url,
    region: String,
    deployment: u64,
}

/// One checked physical prefix, original deadline and at most 32 DELETE calls.
/// Not Clone: an uncertain call closes the batch. Creating another batch
/// rechecks backend settings; it does not resolve any previous unknown call.
pub struct GcBatch<'a> {
    store: &'a GcS3,
    prefix: String,
    deadline: Instant,
    remaining: usize,
}

impl GcS3 {
    pub fn new(config: S3Config, deployment: u64) -> Result<Self, GcError> {
        Self::build(config, deployment, connect)
    }

    fn build(
        config: S3Config,
        deployment: u64,
        connector: fn(&listing_guard::Direct) -> Result<HttpClient, GcError>,
    ) -> Result<Self, GcError> {
        // These values enter the SDK's signature header. Its authorizer assumes
        // valid header values; reject invalid configuration before construction.
        if deployment == 0
            || !(3..=63).contains(&config.bucket.len())
            || !config
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            || config.bucket.ends_with("--x-s3")
            || HeaderValue::from_str(&config.access_key).is_err()
            || HeaderValue::from_str(&config.region).is_err()
            || config
                .session_token
                .as_ref()
                .is_some_and(|token| HeaderValue::from_str(token).is_err())
        {
            return Err(GcError::Invalid);
        }
        let endpoint = reqwest::Url::parse(&config.endpoint).map_err(|_| GcError::Invalid)?;
        let region = config.region.clone();
        let direct = listing_guard::Direct {
            timeout: config.timeout,
            allow_http: config.allow_http,
        };
        let inner = S3::new(config).map_err(|_| GcError::Invalid)?;
        let client = connector(&direct)?;
        Ok(Self {
            inner,
            client,
            endpoint,
            region,
            deployment,
        })
    }

    /// The caller must independently prove retirement, pin drain and its
    /// durable deletion plan. Configuration must remain fixed for the deployment:
    /// two GETs cannot lock out a concurrent administrator changing versioning.
    pub fn begin_batch(&self, prefix: &str, deadline: Instant) -> Result<GcBatch<'_>, GcError> {
        if Handle::try_current().is_ok() || !valid_prefix(prefix, self.deployment) {
            return Err(GcError::Invalid);
        }
        self.execute(deadline, async {
            let versioning = self
                .request(Method::GET, "", Some("versioning"), None)
                .await?;
            status_ok(versioning.status, 200)?;
            crate::gc_xml::unversioned(&versioning.bytes)?;
            let lock = self
                .request(Method::GET, "", Some("object-lock"), None)
                .await?;
            match lock.status {
                404 => {
                    if crate::gc_xml::error_code(&lock.bytes)?
                        != "ObjectLockConfigurationNotFoundError"
                    {
                        return Err(GcError::Unsupported);
                    }
                }
                200 => return Err(GcError::Unsupported),
                _ => status_ok(lock.status, 404)?,
            }
            Ok(())
        })?;
        Ok(GcBatch {
            store: self,
            prefix: prefix.into(),
            deadline,
            remaining: MAX_DELETE_BATCH,
        })
    }

    fn execute<T>(
        &self,
        deadline: Instant,
        future: impl Future<Output = Result<T, GcError>>,
    ) -> Result<T, GcError> {
        remaining(deadline)?;
        let result = self.inner.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), future)
                .await
                .map_err(|_| GcError::Unknown)?
        });
        remaining(deadline)?;
        result
    }

    async fn request(
        &self,
        method: Method,
        key: &str,
        query: Option<&str>,
        etag: Option<&str>,
    ) -> Result<Response, GcError> {
        let mut url = self.endpoint.clone();
        url.set_path(&format!(
            "/{}{}{}",
            self.inner.bucket,
            if key.is_empty() { "" } else { "/" },
            key
        ));
        url.set_query(query);
        let mut request = Request::builder().method(method).uri(url.as_str());
        if let Some(etag) = etag {
            request = request.header(http::header::IF_MATCH, etag);
        }
        let mut request = request
            .body(HttpRequestBody::empty())
            .map_err(|_| GcError::Invalid)?;
        let credential = self
            .inner
            .store
            .credentials()
            .get_credential()
            .await
            .map_err(|_| GcError::Unknown)?;
        authorize(&mut request, &credential, &self.region)?;
        let response = self
            .client
            .execute(request)
            .await
            .map_err(|_| GcError::Unknown)?;
        let status = response.status().as_u16();
        let (parts, body) = response.into_parts();
        let mut stream = body.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| GcError::Unknown)?;
            if chunk.len() > MAX_GC_RESPONSE_BYTES - bytes.len() {
                return Err(GcError::Unknown);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers: parts.headers,
            bytes,
        })
    }
}

impl GcBatch<'_> {
    /// Only a lowercase content hash can be appended to the fixed prefix. The
    /// ETag comes from an exact candidate GET, never from a LIST authority guess.
    pub fn delete(&mut self, hash: &str, etag: &str) -> Result<DeleteOutcome, GcError> {
        if Handle::try_current().is_ok()
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !crate::valid_etag(etag)
        {
            return Err(GcError::Invalid);
        }
        if self.remaining == 0 {
            return Err(GcError::Limit);
        }
        self.remaining -= 1;
        let key = format!("{}{hash}", self.prefix);
        let result = self.store.execute(self.deadline, async {
            let response = self
                .store
                .request(Method::DELETE, &key, None, Some(etag))
                .await?;
            deletion(response)
        });
        if result.is_err() {
            self.remaining = 0;
        }
        result
    }
}

struct Response {
    status: u16,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

fn connect(direct: &listing_guard::Direct) -> Result<HttpClient, GcError> {
    direct
        .connect(&ClientOptions::new())
        .map_err(|_| GcError::Invalid)
}

fn authorize(
    request: &mut HttpRequest,
    credential: &object_store::aws::AwsCredential,
    region: &str,
) -> Result<(), GcError> {
    AwsAuthorizer::new(credential, "s3", region)
        .try_authorize(request, None)
        .map_err(|_| GcError::Unknown)
}

fn remaining(deadline: Instant) -> Result<(), GcError> {
    if Instant::now() >= deadline {
        return Err(GcError::Unknown);
    }
    Ok(())
}

fn status_ok(actual: u16, expected: u16) -> Result<(), GcError> {
    if actual == expected {
        return Ok(());
    }
    Err(if actual == 403 {
        GcError::Denied
    } else {
        GcError::Unknown
    })
}

fn deletion(response: Response) -> Result<DeleteOutcome, GcError> {
    if response.headers.contains_key("x-amz-version-id")
        || response.headers.contains_key("x-amz-delete-marker")
    {
        return Err(GcError::Unknown);
    }
    match response.status {
        204 if response.bytes.is_empty()
            && response
                .headers
                .get(http::header::CONTENT_LENGTH)
                .is_none_or(|value| value == "0") =>
        {
            Ok(DeleteOutcome::Applied)
        }
        412 => Ok(DeleteOutcome::Conflict),
        404 => match crate::gc_xml::error_code(&response.bytes) {
            Ok(code) if code == "NoSuchKey" => Ok(DeleteOutcome::Missing),
            _ => Err(GcError::Unknown),
        },
        403 => Err(GcError::Denied),
        _ => Err(GcError::Unknown),
    }
}

fn valid_prefix(prefix: &str, deployment: u64) -> bool {
    if prefix.len() > 960 {
        return false;
    }
    let parts: Vec<_> = prefix.split('/').collect();
    if parts.len() != 13
        || parts[0] != "scap-object"
        || parts[1] != "v1"
        || parts[5] != "inc"
        || parts[7] != "gen"
        || parts[9] != "storage"
        || parts[11] != "objects"
        || !parts[12].is_empty()
    {
        return false;
    }
    for i in [2, 3, 4, 6, 8, 10] {
        let Ok(value) = parts[i].parse::<u64>() else {
            return false;
        };
        if value == 0 || value.to_string() != parts[i] || (i == 2 && value != deployment) {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "gc_tests.rs"]
mod tests;
