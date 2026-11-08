//! Strict deployment configuration. No ambient AWS identity or client identity.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use scap_object::format::MAX_OBJECT_BYTES;
use scap_object_store::S3Config;
use serde::Deserialize;

use crate::{
    auth::{Authenticator, Credential},
    scheduler::Limits,
    wire::Decimal,
    Failure,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    pub listen: SocketAddr,
    pub worker_instance: Decimal,
    pub cache_directory: PathBuf,
    pub s3: ObjectConfig,
    pub admission: Admission,
    pub catalogue: Option<CatalogueAdmission>,
    pub cache: Cache,
    pub credentials: Vec<Credential>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_env: String,
    pub secret_key_env: String,
    pub session_token_env: Option<String>,
    pub allow_http: bool,
    pub timeout_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub workers: usize,
    pub control_workers: usize,
    pub queued_per_worker: usize,
    pub queued_per_tenant: usize,
    pub queued_per_database: usize,
    pub reserved_controls: usize,
    pub data_intake: usize,
    pub control_intake: usize,
    pub recovery_intake: usize,
    pub max_body_bytes: usize,
    pub timeout_ms: u64,
    pub recovery_timeout_ms: u64,
}

impl Admission {
    pub fn limits(&self) -> Limits {
        Limits {
            workers: self.workers,
            control_workers: self.control_workers,
            queued_per_worker: self.queued_per_worker,
            queued_per_tenant: self.queued_per_tenant,
            queued_per_database: self.queued_per_database,
            reserved_controls: self.reserved_controls,
        }
    }
}

/// Missing configuration disables name operations. Every enabled capacity is
/// explicit and independent of the existing database admission pools.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueAdmission {
    pub workers: usize,
    pub queued_total: usize,
    pub queued_per_tenant: usize,
    pub queued_per_name: usize,
    pub intake: usize,
    pub max_body_bytes: usize,
    pub timeout_ms: u64,
}

impl CatalogueAdmission {
    pub fn limits(&self) -> crate::catalogue_scheduler::Limits {
        crate::catalogue_scheduler::Limits {
            workers: self.workers,
            queued_total: self.queued_total,
            queued_per_tenant: self.queued_per_tenant,
            queued_per_name: self.queued_per_name,
        }
    }

    pub fn validate(&self) -> Result<(), Failure> {
        self.limits().validate()?;
        self.validate_transport()
    }

    pub(crate) fn validate_transport(&self) -> Result<(), Failure> {
        if !(1..=4096).contains(&self.intake)
            || !(1..=65536).contains(&self.max_body_bytes)
            || !(1..=86400000).contains(&self.timeout_ms)
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub sessions_per_worker: usize,
    pub pages_per_worker: u64,
    pub parallel_recoveries: usize,
}

pub struct Prepared {
    pub service: ServiceConfig,
    pub s3: S3Config,
}

pub struct ServiceConfig {
    pub listen: SocketAddr,
    pub worker_instance: u64,
    pub cache_directory: PathBuf,
    pub admission: Admission,
    pub catalogue: Option<CatalogueAdmission>,
    pub cache: Cache,
    pub auth: Authenticator,
}

fn secret(name: &str, environment: &dyn Fn(&str) -> Option<OsString>) -> Result<String, Failure> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Failure::new("CONFIG"));
    }
    environment(name)
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Failure::new("CONFIG"))
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Failure::new("CONFIG"));
        }
        serde_json::from_slice(bytes).map_err(|_| Failure::new("CONFIG"))
    }

    pub fn prepare(self) -> Result<Prepared, Failure> {
        self.prepare_with(&|name| std::env::var_os(name))
    }

    fn prepare_with(
        self,
        environment: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Prepared, Failure> {
        let admission = &self.admission;
        // This listener has no TLS termination. It can only be exposed through
        // a separately configured authenticated TLS reverse proxy.
        if self.version != 1
            || !self.listen.ip().is_loopback()
            || self.worker_instance.0 == 0
            || !self.cache_directory.is_absolute()
            || !self.cache_directory.is_dir()
            || self.cache.sessions_per_worker == 0
            || self.cache.sessions_per_worker > 4096
            || self.cache.pages_per_worker == 0
            || self.cache.parallel_recoveries == 0
            || self.cache.parallel_recoveries > 256
            || admission.max_body_bytes == 0
            || admission.max_body_bytes > 128 * 1024 * 1024
            || admission.queued_per_worker > 65536
            || !(1..=4096).contains(&admission.data_intake)
            || !(1..=4096).contains(&admission.control_intake)
            || !(1..=4096).contains(&admission.recovery_intake)
            || !(1..=86400000).contains(&admission.timeout_ms)
            || !(admission.timeout_ms..=604800000).contains(&admission.recovery_timeout_ms)
            || !(1..=86400000).contains(&self.s3.timeout_ms)
        {
            return Err(Failure::new("CONFIG"));
        }
        if let Some(catalogue) = &self.catalogue {
            catalogue.validate()?;
        }
        // Even a disposable execution image requires SQLite-compatible local
        // I/O. Reject unsupported mounts before credentials or workers are used.
        scap_object_sqlite::validate_cache_directory(&self.cache_directory)
            .map_err(|_| Failure::new("CACHE_IO"))?;
        let access_key = secret(&self.s3.access_key_env, environment)?;
        let secret_key = secret(&self.s3.secret_key_env, environment)?;
        let session_token = self
            .s3
            .session_token_env
            .as_ref()
            .map(|name| secret(name, environment))
            .transpose()?;
        Ok(Prepared {
            s3: S3Config {
                endpoint: self.s3.endpoint,
                region: self.s3.region,
                bucket: self.s3.bucket,
                access_key,
                secret_key,
                session_token,
                timeout: Duration::from_millis(self.s3.timeout_ms),
                max_object_bytes: MAX_OBJECT_BYTES,
                allow_http: self.s3.allow_http,
            },
            service: ServiceConfig {
                listen: self.listen,
                worker_instance: self.worker_instance.0,
                cache_directory: self.cache_directory,
                admission: self.admission,
                catalogue: self.catalogue,
                cache: self.cache,
                auth: Authenticator::new(self.credentials)?,
            },
        })
    }
}

#[cfg(test)]
mod tests;
