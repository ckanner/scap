//! Stateful whole-job admission. Errors retain conservative byte reservations.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use scap_object_store::{
    Condition, ListError, ListPage, ListRequest, Listings, Objects, StoreError, Stored,
    MAX_LIST_RESPONSE_BYTES,
};

use super::{DiscoveryBudget, RecoveryStop};

/// Hard totals for one stateful job. Each value may be lowered, never raised.
/// The separate absolute job deadline is capped at one hour; concurrency is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryBudget {
    pub list_pages: u64,
    pub candidates: u64,
    pub exact_gets: u64,
    pub list_bytes: u64,
    pub metadata_bytes: u64,
    pub data_bytes: u64,
}

impl Default for RecoveryBudget {
    fn default() -> Self {
        Self {
            list_pages: 4096,
            candidates: 65536,
            exact_gets: 1_048_576,
            list_bytes: 4 * 1024 * 1024 * 1024,
            metadata_bytes: 512 * 1024 * 1024,
            data_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}

impl RecoveryBudget {
    pub(super) fn validate(self) -> Result<Self, RecoveryStop> {
        let cap = Self::default();
        if self.list_pages > cap.list_pages
            || self.candidates > cap.candidates
            || self.exact_gets > cap.exact_gets
            || self.list_bytes > cap.list_bytes
            || self.metadata_bytes > cap.metadata_bytes
            || self.data_bytes > cap.data_bytes
        {
            Err(RecoveryStop::Invalid)
        } else {
            Ok(self)
        }
    }
}

/// Cumulative conservative consumption, including failed/repeated attempts.
/// Metadata is HEAD/catalogue body bytes. Data includes every other exact GET,
/// including data-tree, request-index and Result envelopes. Failed requests keep
/// their full requested cap; these counters are not measured HTTP wire traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryUsage {
    pub list_pages: u64,
    pub candidates: u64,
    pub exact_gets: u64,
    pub list_bytes: u64,
    pub metadata_bytes: u64,
    pub data_bytes: u64,
}

pub(super) struct RecoveryMeter {
    objects: Arc<dyn Objects>,
    listings: Arc<dyn Listings>,
    limit: RecoveryBudget,
    used: Mutex<RecoveryUsage>,
    blocked: AtomicBool,
    pub deadline: Instant,
    pub now: fn() -> Instant,
}

impl RecoveryMeter {
    pub fn new(
        objects: Arc<dyn Objects>,
        listings: Arc<dyn Listings>,
        limit: RecoveryBudget,
        deadline: Instant,
        now: fn() -> Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            objects,
            listings,
            limit,
            used: Mutex::new(RecoveryUsage::default()),
            blocked: AtomicBool::new(false),
            deadline,
            now,
        })
    }

    pub fn usage(&self) -> RecoveryUsage {
        *self.used.lock().expect("private recovery accounting")
    }

    pub fn check(&self, deadline: Instant) -> Result<(), RecoveryStop> {
        if (self.now)() >= deadline.min(self.deadline) {
            Err(RecoveryStop::Unknown)
        } else if self.blocked.load(Ordering::Relaxed) {
            Err(RecoveryStop::Limit)
        } else {
            Ok(())
        }
    }

    pub fn failure(&self, error: RecoveryStop) -> RecoveryStop {
        if self.blocked.load(Ordering::Relaxed) {
            RecoveryStop::Limit
        } else {
            error
        }
    }

    pub fn discovery_budget(&self) -> DiscoveryBudget {
        DiscoveryBudget {
            candidates: usize::from(self.usage().candidates < self.limit.candidates),
            ..DiscoveryBudget::default()
        }
    }

    pub fn counted_candidates(&self, count: usize) {
        // Discovery received at most the single remaining candidate allowance.
        self.used
            .lock()
            .expect("private recovery accounting")
            .candidates += count as u64;
    }

    pub fn retry_candidate(&self) -> Result<(), RecoveryStop> {
        let mut used = self.used.lock().expect("private recovery accounting");
        if used.candidates == self.limit.candidates {
            self.blocked.store(true, Ordering::Relaxed);
            Err(RecoveryStop::Limit)
        } else {
            used.candidates += 1;
            Ok(())
        }
    }
}

impl Objects for RecoveryMeter {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let deadline = deadline.min(self.deadline);
        self.check(deadline).map_err(|error| {
            if error == RecoveryStop::Limit {
                StoreError::Limit
            } else {
                StoreError::Unknown
            }
        })?;
        let metadata = key.ends_with("/head") || key.contains("/catalogue/");
        let allowance = {
            let mut used = self.used.lock().expect("private recovery accounting");
            let remaining = if metadata {
                self.limit.metadata_bytes - used.metadata_bytes
            } else {
                self.limit.data_bytes - used.data_bytes
            };
            if used.exact_gets == self.limit.exact_gets || remaining == 0 {
                self.blocked.store(true, Ordering::Relaxed);
                return Err(StoreError::Limit);
            }
            used.exact_gets += 1;
            let allowance = (max_bytes as u64).min(remaining) as usize;
            if metadata {
                used.metadata_bytes += allowance as u64;
            } else {
                used.data_bytes += allowance as u64;
            }
            allowance
        };
        let result = self.objects.get(key, allowance, deadline);
        if matches!(result, Err(StoreError::Limit)) && allowance < max_bytes {
            self.blocked.store(true, Ordering::Relaxed);
        }
        let actual = result.as_ref().map_or(allowance, |value| value.bytes.len());
        if actual > allowance {
            return Err(StoreError::Corrupt);
        }
        let mut used = self.used.lock().expect("private recovery accounting");
        let refund = (allowance - actual) as u64;
        if metadata {
            used.metadata_bytes -= refund;
        } else {
            used.data_bytes -= refund;
        }
        drop(used);
        if (self.now)() >= deadline {
            return Err(StoreError::Unknown);
        }
        result
    }

    fn put(&self, _: &str, _: &[u8], _: Condition<'_>, _: Instant) -> Result<String, StoreError> {
        Err(StoreError::Invalid)
    }
}

impl Listings for RecoveryMeter {
    fn list_page(
        &self,
        request: &ListRequest<'_>,
        deadline: Instant,
    ) -> Result<ListPage, ListError> {
        let deadline = deadline.min(self.deadline);
        self.check(deadline).map_err(|error| {
            if error == RecoveryStop::Limit {
                ListError::Limit
            } else {
                ListError::Unknown
            }
        })?;
        {
            let mut used = self.used.lock().expect("private recovery accounting");
            if used.list_pages == self.limit.list_pages
                || self.limit.list_bytes - used.list_bytes < MAX_LIST_RESPONSE_BYTES as u64
            {
                self.blocked.store(true, Ordering::Relaxed);
                return Err(ListError::Limit);
            }
            used.list_pages += 1;
            used.list_bytes += MAX_LIST_RESPONSE_BYTES as u64;
        }
        let result = self.listings.list_page(request, deadline);
        if let Ok(page) = &result {
            if page.response_bytes > MAX_LIST_RESPONSE_BYTES {
                return Err(ListError::Corrupt);
            }
            self.used
                .lock()
                .expect("private recovery accounting")
                .list_bytes -= (MAX_LIST_RESPONSE_BYTES - page.response_bytes) as u64;
        }
        if (self.now)() >= deadline {
            return Err(ListError::Unknown);
        }
        result
    }
}

#[cfg(test)]
#[path = "recovery_budget_tests.rs"]
mod tests;
