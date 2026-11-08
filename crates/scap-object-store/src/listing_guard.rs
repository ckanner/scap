//! Bound raw LIST bodies before the SDK's unbounded XML collector.

use std::time::Duration;

use futures_util::StreamExt;
use object_store::client::{
    HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest, HttpResponse, HttpService,
};
use object_store::ClientOptions;

use crate::listing::{Context, ListError, MAX_LIST_RESPONSE_BYTES};

/// The SDK's default reqwest connector follows redirects and permits protocol
/// retries independently of RetryConfig. Configure the shared GET/PUT/LIST
/// transport explicitly; SDK signing and request serialization remain intact.
#[derive(Debug)]
pub(super) struct Direct {
    pub timeout: Duration,
    pub allow_http: bool,
}

impl HttpConnector for Direct {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        self.build(reqwest::ClientBuilder::build)
    }
}

impl Direct {
    fn build(
        &self,
        construct: fn(reqwest::ClientBuilder) -> reqwest::Result<reqwest::Client>,
    ) -> object_store::Result<HttpClient> {
        let builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .https_only(!self.allow_http)
            .timeout(self.timeout)
            .connect_timeout(self.timeout)
            .pool_max_idle_per_host(2);
        let client = construct(builder).map_err(|error| object_store::Error::Generic {
            store: "scap explicit HTTP client",
            source: Box::new(error),
        })?;
        Ok(HttpClient::new(client))
    }
}

#[derive(Debug)]
pub(super) struct Connector<C>(pub C);

impl<C: HttpConnector> HttpConnector for Connector<C> {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        client(self.0.connect(options))
    }
}

fn client(inner: object_store::Result<HttpClient>) -> object_store::Result<HttpClient> {
    Ok(HttpClient::new(Service(inner?)))
}

#[derive(Debug)]
struct Service(HttpClient);

#[async_trait::async_trait]
impl HttpService for Service {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        guarded(&self.0, request).await
    }
}

// Keep the executable guard outside async_trait expansion so its own branches
// remain visible in the first-party unit coverage map.
async fn guarded(client: &HttpClient, request: HttpRequest) -> Result<HttpResponse, HttpError> {
    let context = request.extensions().get::<Context>().cloned();
    let response = client.execute(request).await?;
    let Some(context) = context else {
        // Exact GET/PUT retain their existing streaming and error behavior.
        return Ok(response);
    };
    let status = response.status().as_u16();
    if status != 200 {
        // Do not let the SDK collect an unbounded error body, or reinterpret
        // a missing bucket/forbidden listing as an empty prefix.
        return Err(failure(if status == 403 {
            ListError::Denied
        } else {
            ListError::Unknown
        }));
    }
    let (mut parts, body) = response.into_parts();
    let mut stream = body.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > MAX_LIST_RESPONSE_BYTES - bytes.len() {
            return Err(failure(ListError::Limit));
        }
        bytes.extend_from_slice(&chunk);
    }
    let proof = crate::listing_xml::validate(&bytes, &context).map_err(failure)?;
    parts.extensions.insert(proof);
    Ok(HttpResponse::from_parts(parts, bytes.into()))
}

fn failure(error: ListError) -> HttpError {
    HttpError::new(HttpErrorKind::Decode, error)
}

#[cfg(test)]
#[path = "listing_guard_tests.rs"]
mod tests;
