//! Independent source/target copy accounting. Failed I/O keeps its reservation;
//! a shortened local GET cap is Budget, never source corruption or retirement.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError, Stored};

use super::RestoreBudget;

#[cfg(test)]
#[path = "restore_budget_tests.rs"]
mod tests;

#[derive(Default)]
struct Used {
    gets: u64,
    get_bytes: u64,
    puts: u64,
    put_bytes: u64,
}

pub(super) struct Meter {
    objects: Arc<dyn Objects>,
    gets: u64,
    get_bytes: u64,
    puts: u64,
    put_bytes: u64,
    deadline: Instant,
    used: Mutex<Used>,
    now: fn() -> Instant,
}

impl Meter {
    pub fn source(
        objects: Arc<dyn Objects>,
        budget: RestoreBudget,
        deadline: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            objects,
            gets: budget.source_gets,
            get_bytes: budget.source_bytes,
            puts: 0,
            put_bytes: 0,
            deadline,
            used: Mutex::new(Used::default()),
            now: Instant::now,
        })
    }

    pub fn target(
        objects: Arc<dyn Objects>,
        budget: RestoreBudget,
        deadline: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            objects,
            gets: budget.target_gets,
            get_bytes: budget.target_get_bytes,
            puts: budget.target_puts,
            put_bytes: budget.target_put_bytes,
            deadline,
            used: Mutex::new(Used::default()),
            now: Instant::now,
        })
    }

    fn check(&self, deadline: Instant) -> Result<Instant, StoreError> {
        let deadline = deadline.min(self.deadline);
        if (self.now)() >= deadline {
            Err(StoreError::Unknown)
        } else {
            Ok(deadline)
        }
    }
}

impl Objects for Meter {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let deadline = self.check(deadline)?;
        let allowance = {
            let mut used = self.used.lock().expect("private restore budget");
            let remaining = self.get_bytes - used.get_bytes;
            if used.gets == self.gets || remaining == 0 {
                return Err(StoreError::Budget);
            }
            let allowance = (maximum as u64).min(remaining) as usize;
            used.gets += 1;
            used.get_bytes += allowance as u64;
            allowance
        };
        let result = self.objects.get(key, allowance, deadline);
        self.check(deadline)?;
        match result {
            Ok(stored) => {
                if stored.bytes.len() > allowance {
                    return Err(StoreError::Corrupt);
                }
                self.used.lock().expect("private restore budget").get_bytes -=
                    (allowance - stored.bytes.len()) as u64;
                Ok(stored)
            }
            Err(StoreError::Limit) if allowance < maximum => Err(StoreError::Budget),
            Err(error) => Err(error),
        }
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        let deadline = self.check(deadline)?;
        {
            let mut used = self.used.lock().expect("private restore budget");
            if used.puts == self.puts || bytes.len() as u64 > self.put_bytes - used.put_bytes {
                return Err(StoreError::Budget);
            }
            used.puts += 1;
            used.put_bytes += bytes.len() as u64;
        }
        let result = self.objects.put(key, bytes, condition, deadline);
        self.check(deadline)?;
        result
    }
}
