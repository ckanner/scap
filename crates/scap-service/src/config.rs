//! Strict deployment configuration. No ambient AWS identity or client identity.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use scap_object::format::MAX_OBJECT_BYTES;
use scap_object_store::S3Config;
use serde::{Deserialize, Deserializer};

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
    #[serde(default)]
    pub transport: crate::transport::Profile,
    /// Ordinary /v1 encoding backings only; not other routes or process RSS.
    #[serde(default)]
    pub output: crate::output::Profile,
    pub worker_instance: WorkerInstance,
    pub cache_directory: PathBuf,
    pub s3: ObjectConfig,
    /// Missing GC credentials leave physical deletion unavailable.
    pub gc: Option<GarbageConfig>,
    pub admission: Admission,
    pub catalogue: Option<CatalogueAdmission>,
    pub discovery: Option<DiscoveryConfig>,
    pub cache: Cache,
    pub execution: Option<ExecutionConfig>,
    /// Per owner-resume payload reads; independent of output, quota and RSS.
    pub owner_recovery: Option<OwnerRecoveryConfig>,
    pub credentials: Vec<Credential>,
}

/// JSON keeps the existing canonical decimal strings and adds exactly "auto".
/// The direct Rust API distinguishes selection from the final assigned number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerInstance {
    Explicit(u64),
    Auto,
}

impl<'de> Deserialize<'de> for WorkerInstance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == "auto" {
            return Ok(Self::Auto);
        }
        let number = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if number.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical worker identity"));
        }
        Ok(Self::Explicit(number))
    }
}

/// An automatic identity is resolved before deriving its startup-specific
/// cursor codec. Key material is validated during configuration, never logged.
pub enum PreparedDiscovery {
    Ready(std::sync::Arc<crate::discovery_cursor::CursorCodec>),
    Automatic {
        master: [u8; 32],
        namespace: [u8; 32],
    },
}

impl PreparedDiscovery {
    pub(crate) fn accepts(&self, worker: WorkerInstance) -> bool {
        matches!(
            (self, worker),
            (Self::Ready(_), WorkerInstance::Explicit(_))
                | (Self::Automatic { .. }, WorkerInstance::Auto)
        )
    }

    pub(crate) fn bind(
        self,
        worker: u64,
    ) -> Result<std::sync::Arc<crate::discovery_cursor::CursorCodec>, Failure> {
        match self {
            Self::Ready(codec) => Ok(codec),
            Self::Automatic { master, namespace } => {
                crate::discovery_cursor::CursorCodec::new(master, namespace, worker)
                    .map(std::sync::Arc::new)
            }
        }
    }
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

/// Dedicated credentials for the same fixed object namespace. The API cannot
/// select a backend, bucket, deployment or credential for physical deletion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GarbageConfig {
    pub deployment: Decimal,
    pub access_key_env: String,
    pub secret_key_env: String,
    pub session_token_env: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub data_profile: Option<crate::intake::Profile>,
    pub control_profile: Option<crate::intake::Profile>,
    pub recovery_profile: Option<crate::intake::Profile>,
    pub active_database_actors: usize,
    pub active_database_actors_per_tenant: usize,
    pub actor_idle_timeout_ms: u64,
    pub control_workers: usize,
    pub queued_total: usize,
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
            active_database_actors: self.active_database_actors,
            active_database_actors_per_tenant: self.active_database_actors_per_tenant,
            actor_idle_timeout: Duration::from_millis(self.actor_idle_timeout_ms),
            control_workers: self.control_workers,
            queued_total: self.queued_total,
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
    pub intake_profile: Option<crate::intake::Profile>,
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
        self.build_intake().map(|_| ())
    }

    /// The same checked construction is used by parsed configuration and the
    /// direct ServiceConfig entry point, before starting catalogue workers.
    pub(crate) fn build_intake(&self) -> Result<crate::intake::Intake, Failure> {
        if !(1..=65536).contains(&self.max_body_bytes) || !(1..=86400000).contains(&self.timeout_ms)
        {
            return Err(Failure::new("CONFIG"));
        }
        crate::intake::Intake::new(
            crate::intake::Class::Catalogue,
            self.intake,
            self.max_body_bytes,
            self.intake_profile,
        )
    }
}

/// Local execution limits do not change persisted result bytes or database quota.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    pub result_memory_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecoveryConfig {
    pub payload_gets: u64,
    pub payload_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub pages_per_actor: u64,
    pub parallel_recoveries: usize,
}

/// Discovery uses the fixed v1 resource profile and a separate admission pool.
/// The environment variable contains a 32-byte lowercase hex master key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    pub cursor_key_env: String,
}

pub struct Prepared {
    pub service: ServiceConfig,
    pub s3: S3Config,
    pub gc: Option<PreparedGarbage>,
}

pub struct PreparedGarbage {
    pub deployment: u64,
    pub s3: S3Config,
}

pub struct ServiceConfig {
    pub options: scap_object::Options,
    pub listen: SocketAddr,
    pub transport: crate::transport::Profile,
    pub output: crate::output::Profile,
    pub worker_instance: WorkerInstance,
    pub cache_directory: PathBuf,
    pub admission: Admission,
    pub catalogue: Option<CatalogueAdmission>,
    pub discovery: Option<PreparedDiscovery>,
    pub gc_deployment: Option<u64>,
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
        self.prepare_using(environment, crate::discovery_cursor::CursorCodec::new)
    }

    fn prepare_using(
        self,
        environment: &dyn Fn(&str) -> Option<OsString>,
        create_cursor: fn(
            [u8; 32],
            [u8; 32],
            u64,
        ) -> Result<crate::discovery_cursor::CursorCodec, Failure>,
    ) -> Result<Prepared, Failure> {
        self.transport.checked()?;
        self.output.checked()?;
        let mut options = scap_object::Options::default();
        if let Some(execution) = self.execution {
            options.result_memory_bytes = execution.result_memory_bytes;
        }
        if let Some(recovery) = self.owner_recovery {
            options.owner_recovery_gets = recovery.payload_gets;
            options.owner_recovery_bytes = recovery.payload_bytes;
        }
        options.validate().map_err(|_| Failure::new("CONFIG"))?;
        let admission = &self.admission;
        admission.limits().validate()?;
        // This listener has no TLS termination. It can only be exposed through
        // a separately configured authenticated TLS reverse proxy.
        if self.version != 1
            || !self.listen.ip().is_loopback()
            || self.worker_instance == WorkerInstance::Explicit(0)
            || !self.cache_directory.is_absolute()
            || !self.cache_directory.is_dir()
            || self.cache.pages_per_actor == 0
            || self.cache.parallel_recoveries == 0
            || self.cache.parallel_recoveries > 256
            || admission.max_body_bytes == 0
            || admission.max_body_bytes > 128 * 1024 * 1024
            || !(1..=4096).contains(&admission.data_intake)
            || !(1..=4096).contains(&admission.control_intake)
            || !(1..=4096).contains(&admission.recovery_intake)
            || !(1..=86400000).contains(&admission.timeout_ms)
            || !(admission.timeout_ms..=604800000).contains(&admission.recovery_timeout_ms)
            || !(1..=86400000).contains(&self.s3.timeout_ms)
        {
            return Err(Failure::new("CONFIG"));
        }
        for (total, profile) in [
            (admission.data_intake, admission.data_profile),
            (admission.control_intake, admission.control_profile),
            (admission.recovery_intake, admission.recovery_profile),
        ] {
            crate::intake::Profile::resolve(total, admission.max_body_bytes, profile)?;
        }
        if let Some(catalogue) = &self.catalogue {
            catalogue.validate()?;
        }
        if let Some(gc) = &self.gc {
            let ordinary = [
                Some(self.s3.access_key_env.as_str()),
                Some(self.s3.secret_key_env.as_str()),
                self.s3.session_token_env.as_deref(),
            ];
            let dedicated = [
                Some(gc.access_key_env.as_str()),
                Some(gc.secret_key_env.as_str()),
                gc.session_token_env.as_deref(),
            ];
            if gc.deployment.0 == 0
                || self
                    .credentials
                    .iter()
                    .any(|credential| credential.deployment.0 != gc.deployment.0)
                || dedicated
                    .into_iter()
                    .flatten()
                    .any(|name| ordinary.contains(&Some(name)))
            {
                return Err(Failure::new("CONFIG"));
            }
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
        let gc_deployment = self.gc.as_ref().map(|gc| gc.deployment.0);
        let gc = match self.gc {
            Some(gc) => {
                let gc_access_key = secret(&gc.access_key_env, environment)?;
                if gc_access_key == access_key {
                    return Err(Failure::new("CONFIG"));
                }
                Some(PreparedGarbage {
                    deployment: gc.deployment.0,
                    s3: S3Config {
                        endpoint: self.s3.endpoint.clone(),
                        region: self.s3.region.clone(),
                        bucket: self.s3.bucket.clone(),
                        access_key: gc_access_key,
                        secret_key: secret(&gc.secret_key_env, environment)?,
                        session_token: gc
                            .session_token_env
                            .as_ref()
                            .map(|name| secret(name, environment))
                            .transpose()?,
                        timeout: Duration::from_millis(self.s3.timeout_ms),
                        max_object_bytes: MAX_OBJECT_BYTES,
                        allow_http: self.s3.allow_http,
                    },
                })
            }
            None => None,
        };
        let discovery = match self.discovery {
            Some(config) => {
                let key = crate::auth::decode_hash(&secret(&config.cursor_key_env, environment)?)?;
                let namespace = crate::discovery_cursor::namespace(
                    &self.s3.endpoint,
                    &self.s3.region,
                    &self.s3.bucket,
                );
                Some(match self.worker_instance {
                    WorkerInstance::Explicit(worker) => PreparedDiscovery::Ready(
                        std::sync::Arc::new(create_cursor(key, namespace, worker)?),
                    ),
                    WorkerInstance::Auto => PreparedDiscovery::Automatic {
                        master: key,
                        namespace,
                    },
                })
            }
            None => None,
        };
        Ok(Prepared {
            gc,
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
                options,
                listen: self.listen,
                transport: self.transport,
                output: self.output,
                worker_instance: self.worker_instance,
                cache_directory: self.cache_directory,
                admission: self.admission,
                catalogue: self.catalogue,
                discovery,
                gc_deployment,
                cache: self.cache,
                auth: Authenticator::new(self.credentials)?,
            },
        })
    }
}

#[cfg(test)]
mod tests;
