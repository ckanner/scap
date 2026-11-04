//! Explicit local management client. The secret is read from the environment,
//! never an argument, and neither redirects nor ambient proxies are followed.

use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;

use scap_service::ServiceError;
use serde_json::Value;

use crate::config::ManagementConfig;
use crate::{failure, management, Config};

pub(crate) fn command(args: &[OsString]) -> Result<(), ServiceError> {
    let (config, body) = read_command(args)?;
    execute(
        config,
        body,
        std::env::var("SCAP_MANAGEMENT_TOKEN").ok(),
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        &mut std::io::stdout().lock(),
    )
}

fn read_command(args: &[OsString]) -> Result<(ManagementConfig, Option<Vec<u8>>), ServiceError> {
    let (path, body_path) = match args {
        [config] => (config, None),
        [config, body] => (config, Some(body)),
        _ => {
            return Err(failure(
                "USAGE: scap-server --membership CONFIG [REQUEST_JSON_FILE]",
            ))
        }
    };
    let config = Config::decode(&crate::node::read_file(Path::new(path), 1024 * 1024)?)?;
    let management = config
        .management
        .ok_or_else(|| failure("MANAGEMENT_DISABLED"))?;
    let body = body_path
        .map(|path| crate::node::read_file(Path::new(path), management::MAX_BODY as u64))
        .transpose()?;
    Ok((management, body))
}

fn execute(
    config: ManagementConfig,
    body: Option<Vec<u8>>,
    token: Option<String>,
    runtime: std::io::Result<tokio::runtime::Runtime>,
    output: &mut dyn Write,
) -> Result<(), ServiceError> {
    let token = token
        .filter(|token| !token.is_empty() && token.len() <= 4096)
        .ok_or_else(|| failure("MANAGEMENT_TOKEN"))?;
    let changing = body.is_some();
    let (_, timeout) = management::parse_request(changing, body.as_deref().unwrap_or(&[]))?;
    let runtime = runtime.map_err(|_| failure("EXECUTOR"))?;
    let deadline = Instant::now() + timeout;
    let report = runtime.block_on(request(config.listen, body, token, deadline));
    runtime.shutdown_timeout(std::time::Duration::from_millis(100));
    let (status, value) = report?;
    writeln!(output, "{value}").map_err(|_| failure("MANAGEMENT_OUTPUT"))?;
    if !(200..300).contains(&status) {
        return Err(failure(
            value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("MANAGEMENT_HTTP"),
        ));
    }
    if changing && value.get("outcome").and_then(Value::as_str) != Some("applied") {
        return Err(failure("MEMBERSHIP_UNKNOWN"));
    }
    if !value.get("membership").is_some_and(Value::is_object) {
        return Err(failure("MANAGEMENT_RESPONSE"));
    }
    Ok(())
}

pub(crate) async fn request(
    address: SocketAddr,
    body: Option<Vec<u8>>,
    token: String,
    deadline: Instant,
) -> Result<(u16, Value), ServiceError> {
    request_with(
        client(reqwest::ClientBuilder::build),
        address,
        body,
        token,
        deadline,
    )
    .await
}

fn client(
    construct: impl FnOnce(reqwest::ClientBuilder) -> Result<reqwest::Client, reqwest::Error>,
) -> Result<reqwest::Client, ServiceError> {
    // reqwest's already pinned no-provider TLS feature requires an explicit
    // provider even for this HTTP-only loopback client. Preserve an existing one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    construct(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only(),
    )
    .map_err(|_| failure("MANAGEMENT_HTTP"))
}

async fn request_with(
    client: Result<reqwest::Client, ServiceError>,
    address: SocketAddr,
    body: Option<Vec<u8>>,
    token: String,
    deadline: Instant,
) -> Result<(u16, Value), ServiceError> {
    let client = client?;
    let url = format!("http://{address}{}", management::PATH);
    let request = match body {
        Some(body) => client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body),
        None => client.get(url),
    }
    .bearer_auth(token)
    .header("Connection", "close");
    tokio::time::timeout_at(deadline.into(), async {
        let mut response = request
            .send()
            .await
            .map_err(|_| failure("MEMBERSHIP_UNKNOWN"))?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > management::MAX_RESPONSE as u64)
        {
            return Err(failure("MANAGEMENT_RESPONSE_LIMIT"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("MEMBERSHIP_UNKNOWN"))?
        {
            if chunk.len() > management::MAX_RESPONSE.saturating_sub(bytes.len()) {
                return Err(failure("MANAGEMENT_RESPONSE_LIMIT"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| failure("MANAGEMENT_RESPONSE"))?;
        Ok((status, value))
    })
    .await
    .map_err(|_| failure("MEMBERSHIP_UNKNOWN"))?
}

#[cfg(test)]
mod tests;
