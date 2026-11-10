//! One request's accounting also covers every nested catalogue exact GET.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError, Stored};

use super::discovery::{DiscoveryBudget, DiscoveryError, DiscoveryUsage};

pub(super) struct Meter {
    inner: Arc<dyn Objects>,
    limit: DiscoveryBudget,
    used: Mutex<DiscoveryUsage>,
    blocked: AtomicBool,
    now: fn() -> Instant,
}

impl Meter {
    pub fn remaining(&self, deadline: Instant) -> Result<(), DiscoveryError> {
        if (self.now)() >= deadline {
            Err(DiscoveryError::Unknown)
        } else {
            Ok(())
        }
    }
    pub fn new(inner: Arc<dyn Objects>, limit: DiscoveryBudget, now: fn() -> Instant) -> Arc<Self> {
        Arc::new(Self {
            inner,
            limit,
            used: Mutex::new(DiscoveryUsage::default()),
            blocked: AtomicBool::new(false),
            now,
        })
    }

    pub fn usage(&self) -> DiscoveryUsage {
        *self.used.lock().expect("private discovery accounting")
    }

    pub fn failure(&self, error: DiscoveryError) -> DiscoveryError {
        if self.blocked.load(Ordering::Relaxed) {
            DiscoveryError::Limit
        } else {
            error
        }
    }

    pub fn page(&self, deadline: Instant) -> Result<(), DiscoveryError> {
        self.remaining(deadline)?;
        let mut used = self.used.lock().expect("private discovery accounting");
        if used.list_pages == self.limit.list_pages
            || self.limit.list_bytes - used.list_bytes < scap_object_store::MAX_LIST_RESPONSE_BYTES
        {
            return Err(DiscoveryError::Limit);
        }
        used.list_pages += 1;
        used.list_bytes += scap_object_store::MAX_LIST_RESPONSE_BYTES;
        Ok(())
    }

    pub fn listed(&self, bytes: usize) -> Result<(), DiscoveryError> {
        if bytes > scap_object_store::MAX_LIST_RESPONSE_BYTES {
            return Err(DiscoveryError::Corrupt);
        }
        self.used
            .lock()
            .expect("private discovery accounting")
            .list_bytes -= scap_object_store::MAX_LIST_RESPONSE_BYTES - bytes;
        Ok(())
    }

    pub fn candidate(&self, deadline: Instant) -> Result<(), DiscoveryError> {
        self.remaining(deadline)?;
        let mut used = self.used.lock().expect("private discovery accounting");
        if used.candidates == self.limit.candidates {
            return Err(DiscoveryError::Limit);
        }
        used.candidates += 1;
        Ok(())
    }
}

impl Objects for Meter {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError> {
        if (self.now)() >= deadline {
            return Err(StoreError::Unknown);
        }
        let allowance = {
            let mut used = self.used.lock().expect("private discovery accounting");
            if used.exact_gets == self.limit.exact_gets
                || used.metadata_bytes == self.limit.metadata_bytes
            {
                self.blocked.store(true, Ordering::Relaxed);
                return Err(StoreError::Budget);
            }
            used.exact_gets += 1;
            let allowance = max_bytes.min(self.limit.metadata_bytes - used.metadata_bytes);
            // Reserve before I/O; even a future concurrent nested read cannot
            // spend this request's remaining byte budget twice.
            used.metadata_bytes += allowance;
            allowance
        };
        let mut result = self.inner.get(key, allowance, deadline);
        if matches!(result, Err(StoreError::Limit)) && allowance < max_bytes {
            self.blocked.store(true, Ordering::Relaxed);
            result = Err(StoreError::Budget);
        }
        // An error has no trustworthy consumed-byte count. Keep the full
        // reservation; only a successful bounded body earns a refund.
        let actual = result
            .as_ref()
            .map_or(allowance, |stored| stored.bytes.len());
        if actual > allowance {
            return Err(StoreError::Corrupt);
        }
        self.used
            .lock()
            .expect("private discovery accounting")
            .metadata_bytes -= allowance - actual;
        if (self.now)() >= deadline {
            return Err(StoreError::Unknown);
        }
        result
    }

    fn put(
        &self,
        _key: &str,
        _bytes: &[u8],
        _condition: Condition<'_>,
        _deadline: Instant,
    ) -> Result<String, StoreError> {
        // Discovery can never turn a classification into a protocol action.
        Err(StoreError::Invalid)
    }
}
