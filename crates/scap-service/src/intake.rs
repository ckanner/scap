//! Authenticated request and raw-body reservations, shared until the final owner.
//!
//! These counters cover request count and raw body extent. They are not a
//! response, typed-JSON, SQLite allocator, socket-buffer or process RSS budget.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Deserialize;

use crate::{
    auth::Principal,
    lifecycle::{Lane, Registry, Trace},
    rejection::Budget,
    Failure,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Data,
    Control,
    Recovery,
    Catalogue,
}

impl Class {
    pub(crate) fn admission(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Control => "control",
            Self::Recovery => "recovery",
            Self::Catalogue => "catalogue",
        }
    }

    fn budgets(self) -> [Budget; 4] {
        use Budget::*;
        match self {
            Self::Data => [
                IntakeDataRequestsGlobal,
                IntakeDataRequestsTenant,
                IntakeDataBodyGlobal,
                IntakeDataBodyTenant,
            ],
            Self::Control => [
                IntakeControlRequestsGlobal,
                IntakeControlRequestsTenant,
                IntakeControlBodyGlobal,
                IntakeControlBodyTenant,
            ],
            Self::Recovery => [
                IntakeRecoveryRequestsGlobal,
                IntakeRecoveryRequestsTenant,
                IntakeRecoveryBodyGlobal,
                IntakeRecoveryBodyTenant,
            ],
            Self::Catalogue => [
                IntakeCatalogueRequestsGlobal,
                IntakeCatalogueRequestsTenant,
                IntakeCatalogueBodyGlobal,
                IntakeCatalogueBodyTenant,
            ],
        }
    }
}

/// Explicit overrides for the version-1 compatibility profile. Global request
/// count and maximum single body remain the existing configuration fields.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub requests_per_tenant: usize,
    pub body_bytes: usize,
    pub body_bytes_per_tenant: usize,
}

impl Profile {
    pub fn resolve(
        total: usize,
        max_body_bytes: usize,
        configured: Option<Self>,
    ) -> Result<Self, Failure> {
        if !(1..=4096).contains(&total) || !(1..=128 * 1024 * 1024).contains(&max_body_bytes) {
            return Err(Failure::new("CONFIG"));
        }
        let profile = configured.unwrap_or(Self {
            version: 1,
            requests_per_tenant: (total / 2).max(1),
            body_bytes: total.saturating_mul(max_body_bytes).min(256 * 1024 * 1024),
            body_bytes_per_tenant: total.saturating_mul(max_body_bytes).min(128 * 1024 * 1024),
        });
        if profile.version != 1
            || !(1..=total).contains(&profile.requests_per_tenant)
            || profile.body_bytes < max_body_bytes
            || profile.body_bytes_per_tenant < max_body_bytes
            || profile.body_bytes_per_tenant > profile.body_bytes
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(profile)
    }
}

type Tenant = (u64, u64);

#[derive(Default)]
struct Count {
    requests: usize,
    bytes: usize,
}

#[derive(Default)]
struct Usage {
    all: Count,
    tenants: BTreeMap<Tenant, Count>,
}

pub struct Intake {
    class: Class,
    total: usize,
    max_body_bytes: usize,
    profile: Profile,
    usage: Mutex<Usage>,
    lifecycle: Option<(Arc<Registry>, Lane)>,
}

/// The original authenticated identity and admission class travel with the
/// queued/running job and with every emitted response-byte clone.
pub struct Lease {
    pool: Arc<Intake>,
    principal: Principal,
    bytes: AtomicUsize,
    submitted: AtomicBool,
    trace: Option<Trace>,
}

impl Intake {
    pub fn new(
        class: Class,
        total: usize,
        max_body_bytes: usize,
        profile: Option<Profile>,
    ) -> Result<Self, Failure> {
        Ok(Self {
            class,
            total,
            max_body_bytes,
            profile: Profile::resolve(total, max_body_bytes, profile)?,
            usage: Mutex::new(Usage::default()),
            lifecycle: None,
        })
    }

    /// Attach the daemon's optional, fixed-cardinality observer before sharing
    /// this pool. Restore uses the existing recovery admission class, but its
    /// separate pool is observed under its own lane.
    pub fn with_lifecycle(mut self, registry: Arc<Registry>, lane: Lane) -> Result<Self, Failure> {
        if !matches!(
            (self.class, lane),
            (Class::Data, Lane::Data)
                | (Class::Control, Lane::Control)
                | (Class::Recovery, Lane::Recovery | Lane::Restore)
                | (Class::Catalogue, Lane::Catalogue)
        ) {
            return Err(Failure::new("CONFIG"));
        }
        self.lifecycle = Some((registry, lane));
        Ok(self)
    }

    pub(crate) fn validate(&self, class: Class, max_body_bytes: usize) -> Result<(), Failure> {
        if self.class != class || self.max_body_bytes != max_body_bytes {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }

    /// No waiting and no partial reservation: both resource dimensions and
    /// both scopes are checked under one short lock, before inserting a key.
    pub fn acquire(self: &Arc<Self>, principal: &Principal) -> Result<Arc<Lease>, Failure> {
        let tenant = (principal.deployment, principal.tenant);
        let mut usage = self.usage.lock().map_err(|_| Failure::new("UNAVAILABLE"))?;
        let empty = Count::default();
        let current = usage.tenants.get(&tenant).unwrap_or(&empty);
        let [requests_global, requests_tenant, body_global, body_tenant] = self.class.budgets();
        // Preserve the original short-circuit order and copy the deciding
        // counters under this same lock; later releases cannot rewrite them.
        if usage.all.requests >= self.total {
            return Err(Failure::budget(
                requests_global,
                usage.all.requests as u64,
                self.total as u64,
                1,
            ));
        }
        if current.requests >= self.profile.requests_per_tenant {
            return Err(Failure::budget(
                requests_tenant,
                current.requests as u64,
                self.profile.requests_per_tenant as u64,
                1,
            ));
        }
        if usage
            .all
            .bytes
            .checked_add(self.max_body_bytes)
            .is_none_or(|bytes| bytes > self.profile.body_bytes)
        {
            return Err(Failure::budget(
                body_global,
                usage.all.bytes as u64,
                self.profile.body_bytes as u64,
                self.max_body_bytes as u64,
            ));
        }
        if current
            .bytes
            .checked_add(self.max_body_bytes)
            .is_none_or(|bytes| bytes > self.profile.body_bytes_per_tenant)
        {
            return Err(Failure::budget(
                body_tenant,
                current.bytes as u64,
                self.profile.body_bytes_per_tenant as u64,
                self.max_body_bytes as u64,
            ));
        }
        usage.all.requests += 1;
        usage.all.bytes += self.max_body_bytes;
        let current = usage.tenants.entry(tenant).or_default();
        current.requests += 1;
        current.bytes += self.max_body_bytes;
        let trace = if let Some((registry, lane)) = &self.lifecycle {
            let acquired = Instant::now();
            drop(usage);
            Some(registry.acquire(*lane, acquired))
        } else {
            drop(usage);
            None
        };
        Ok(Arc::new(Lease {
            pool: self.clone(),
            principal: principal.clone(),
            bytes: AtomicUsize::new(self.max_body_bytes),
            submitted: AtomicBool::new(false),
            trace,
        }))
    }

    pub fn available_permits(&self) -> usize {
        self.total
            - self
                .usage
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .all
                .requests
    }
}

impl Lease {
    /// Called only after the bounded body read has finished. The remaining
    /// extent stays conservatively charged through work and response lifetime.
    pub(crate) fn shrink_body(&self, actual: usize) -> Result<(), Failure> {
        let mut usage = self
            .pool
            .usage
            .lock()
            .map_err(|_| Failure::new("UNAVAILABLE"))?;
        let previous = self.bytes.load(Ordering::Relaxed);
        if actual > previous {
            return Err(Failure::new("LIMIT"));
        }
        let refund = previous - actual;
        usage.all.bytes -= refund;
        usage
            .tenants
            .get_mut(&(self.principal.deployment, self.principal.tenant))
            .expect("live intake tenant")
            .bytes -= refund;
        self.bytes.store(actual, Ordering::Relaxed);
        drop(usage);
        if let Some(trace) = &self.trace {
            trace.body_ready();
        }
        Ok(())
    }

    pub(crate) fn trace(&self) -> Option<&Trace> {
        self.trace.as_ref()
    }

    /// This boundary may precede worker return when the HTTP deadline wins.
    pub(crate) fn http_response_ready(&self) {
        if let Some(trace) = &self.trace {
            trace.http_response_ready();
        }
    }

    pub(crate) fn claim(&self, principal: &Principal, admission: &str) -> Result<(), Failure> {
        if self.principal != *principal || self.pool.class.admission() != admission {
            return Err(Failure::new("DENIED"));
        }
        if self.submitted.swap(true, Ordering::AcqRel) {
            return Err(Failure::new("INVALID"));
        }
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut usage = self
            .pool
            .usage
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let bytes = self.bytes.load(Ordering::Relaxed);
        usage.all.requests -= 1;
        usage.all.bytes -= bytes;
        let tenant = (self.principal.deployment, self.principal.tenant);
        let current = usage.tenants.get_mut(&tenant).expect("live intake tenant");
        current.requests -= 1;
        current.bytes -= bytes;
        if current.requests == 0 {
            usage.tenants.remove(&tenant);
        }
        if let Some(trace) = &self.trace {
            let released = Instant::now();
            drop(usage);
            trace.finish(released);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
