use scap_archive::{S3Config, S3};
use scap_service::ServiceError;

use crate::config::{cell_limits, ArchiveConfig};
use crate::failure;

pub(crate) fn connect(
    config: Option<&ArchiveConfig>,
    runtime: tokio::runtime::Handle,
    environment: impl Fn(&str) -> Option<String>,
) -> Result<Option<S3>, ServiceError> {
    config
        .map(|config| {
            let access_key =
                environment(&config.access_key_env).ok_or_else(|| failure("ARCHIVE_CREDENTIAL"))?;
            let secret_key =
                environment(&config.secret_key_env).ok_or_else(|| failure("ARCHIVE_CREDENTIAL"))?;
            S3::new(
                S3Config {
                    endpoint: config.endpoint.clone(),
                    region: config.region.clone(),
                    bucket: config.bucket.clone(),
                    access_key,
                    secret_key,
                    session_token: None,
                    allow_http: config.allow_http,
                    max_object_bytes: cell_limits().max_command_bytes - 192,
                    request_timeout: std::time::Duration::from_secs(2),
                },
                runtime.clone(),
            )
            .map_err(|_| failure("ARCHIVE_CONFIG"))
        })
        .transpose()
}

#[cfg(test)]
mod tests;
