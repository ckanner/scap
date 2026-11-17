//! Independent, bounded recovery work for cross-Scope snapshot restores.
//!
//! The byte reservation covers one logical image plus a fixed sidecar allowance.
//! It is not a filesystem quota or a process RSS limit. Jobs retain reservations
//! until native handles and their private directory have actually been dropped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use scap_object::{catalogue as core, Options};
use scap_object_store::Objects;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::{
    auth::Principal,
    catalogue_wire::{Call, NativeAction},
    Failure,
};

const SIDECAR_ALLOWANCE: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub admission: crate::config::CatalogueAdmission,
    pub recovery_timeout_ms: u64,
    pub max_staging_bytes: u64,
    pub max_staging_bytes_per_tenant: u64,
    pub budget: Budget,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub source_gets: u64,
    pub source_bytes: u64,
    pub target_puts: u64,
    pub target_put_bytes: u64,
    pub target_gets: u64,
    pub target_get_bytes: u64,
    pub max_image_bytes: u64,
}

impl Budget {
    pub fn native(self) -> Result<core::RestoreBudget, Failure> {
        let budget = core::RestoreBudget {
            source_gets: self.source_gets,
            source_bytes: self.source_bytes,
            target_puts: self.target_puts,
            target_put_bytes: self.target_put_bytes,
            target_gets: self.target_gets,
            target_get_bytes: self.target_get_bytes,
            max_image_bytes: self.max_image_bytes,
        };
        budget.validate().map_err(|_| Failure::new("CONFIG"))?;
        Ok(budget)
    }
}

impl Profile {
    pub fn validate(&self) -> Result<(), Failure> {
        self.admission.limits().validate()?;
        self.admission
            .build_for_class(crate::intake::Class::Recovery)?;
        self.budget.native()?;
        if !(self.admission.timeout_ms..=604800000).contains(&self.recovery_timeout_ms) {
            return Err(Failure::new("CONFIG"));
        }
        Pool::new(self.max_staging_bytes, self.max_staging_bytes_per_tenant).map(|_| ())
    }
}

#[derive(Default)]
struct Usage {
    total: u64,
    tenants: BTreeMap<(u64, u64), u64>,
}

pub struct Pool {
    maximum: u64,
    per_tenant: u64,
    usage: Mutex<Usage>,
}

impl Pool {
    pub fn new(maximum: u64, per_tenant: u64) -> Result<Self, Failure> {
        if per_tenant == 0 || per_tenant > maximum {
            return Err(Failure::new("CONFIG"));
        }
        Ok(Self {
            maximum,
            per_tenant,
            usage: Mutex::new(Usage::default()),
        })
    }

    fn acquire(
        self: &Arc<Self>,
        principal: &Principal,
        image_bytes: u64,
    ) -> Result<Lease, Failure> {
        let bytes = image_bytes
            .checked_add(SIDECAR_ALLOWANCE)
            .ok_or_else(|| Failure::new("LIMIT"))?;
        let key = (principal.deployment, principal.tenant);
        let mut usage = self.usage.lock().map_err(|_| Failure::new("UNAVAILABLE"))?;
        let tenant = usage.tenants.get(&key).copied().unwrap_or(0);
        if bytes > self.maximum.saturating_sub(usage.total)
            || bytes > self.per_tenant.saturating_sub(tenant)
        {
            return Err(Failure::new("RECOVERY_BUSY"));
        }
        usage.total += bytes;
        usage.tenants.insert(key, tenant + bytes);
        Ok(Lease {
            pool: self.clone(),
            key,
            bytes,
        })
    }
}

struct Lease {
    pool: Arc<Pool>,
    key: (u64, u64),
    bytes: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut usage = self
            .pool
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        usage.total -= self.bytes;
        let tenant = usage
            .tenants
            .get_mut(&self.key)
            .expect("live restore reservation");
        *tenant -= self.bytes;
        if *tenant == 0 {
            usage.tenants.remove(&self.key);
        }
    }
}

pub struct Worker {
    objects: Arc<dyn Objects>,
    worker: u64,
    options: Options,
    directory: PathBuf,
    recovery: Arc<Semaphore>,
    staging: Arc<Pool>,
    budget: core::RestoreBudget,
}

impl Worker {
    pub fn new(
        objects: Arc<dyn Objects>,
        worker: u64,
        options: Options,
        directory: &Path,
        recovery: Arc<Semaphore>,
        staging: Arc<Pool>,
        budget: core::RestoreBudget,
    ) -> Result<Self, Failure> {
        options.validate().map_err(|_| Failure::new("CONFIG"))?;
        budget.validate().map_err(|_| Failure::new("CONFIG"))?;
        scap_object_sqlite::validate_cache_directory(directory)
            .map_err(|_| Failure::new("CACHE_IO"))?;
        Ok(Self {
            objects,
            worker,
            options,
            directory: directory.to_owned(),
            recovery,
            staging,
            budget,
        })
    }

    fn resume(
        &self,
        principal: &Principal,
        reference: &core::RestoreRef,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        let catalogue = core::Catalogue::new(
            self.objects.clone(),
            principal.deployment,
            principal.tenant,
            self.worker,
            self.options.clone(),
        )?;
        let caller = core::Caller {
            principal: principal.principal,
            provision: principal.provision,
        };
        let observed = catalogue.inspect_restore(
            caller,
            reference.creation.creator,
            reference.creation.operation,
            deadline,
        )?;
        if &observed.prepared.reference != reference {
            return Err(Failure::new("IDENTITY_CONFLICT"));
        }
        if observed.phase != core::RestorePhase::Copying {
            // A concurrent caller can advance Reserved to Copying after this
            // observation. Zero every copy direction, including completion
            // reads, so that race fails before opening an unreserved image.
            let budget = core::RestoreBudget {
                source_gets: 0,
                target_gets: 0,
                target_puts: 0,
                ..self.budget
            };
            return Ok(crate::restore_wire::progress(&catalogue.resume_restore(
                caller,
                reference,
                &self.directory,
                budget,
                deadline,
            )?));
        }
        if observed.prepared.image_bytes() > self.budget.max_image_bytes {
            return Err(Failure::new("LIMIT"));
        }
        let _recovery = self
            .recovery
            .try_acquire()
            .map_err(|_| Failure::new("RECOVERY_BUSY"))?;
        let _staging = self
            .staging
            .acquire(principal, observed.prepared.image_bytes())?;
        // Drop the directory before either reservation. Never reopen files from
        // a previous attempt, including after a timed-out HTTP response.
        let directory = tempfile::Builder::new()
            .prefix("scap-restore-")
            .tempdir_in(&self.directory)
            .map_err(|_| Failure::new("CACHE_IO"))?;
        let progress = catalogue.resume_restore(
            caller,
            reference,
            &directory.path().join("image"),
            self.budget,
            deadline,
        )?;
        Ok(crate::restore_wire::progress(&progress))
    }
}

impl crate::catalogue_scheduler::Worker for Worker {
    fn execute(
        &mut self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        call.action.authorize(principal)?;
        match call.action.native()? {
            NativeAction::ResumeRestore(reference) => self.resume(principal, &reference, deadline),
            _ => Err(Failure::new("INVALID")),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
