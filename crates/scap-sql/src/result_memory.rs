//! Per-materialization accounting for the owned Rust result graph.
//!
//! Encoding limits count wire bytes, while a NULL still occupies a full Value
//! slot and each short row owns a vector allocation. Keep these bounds separate.

use std::mem::size_of;

use crate::{SqlError, TransactionResult};

/// A budget for one typed result, independent of its retained wire format.
///
/// Every vector passed to `reserve` must start empty and grow only through this
/// budget. Capacity is charged, including a complete replacement allocation
/// while the old allocation is still alive. Inline members are charged through
/// their containing vector; the root TransactionResult header is charged once.
/// Dropping an intermediate value does not refund its charge, so early drops
/// are conservative. This is not a shared lease or a global process RSS bound:
/// allocator metadata, SQLite allocations, encoded buffers and callers retaining
/// results from several operations require their own resource controls.
#[derive(Debug)]
pub struct ResultMemoryBudget {
    maximum: u64,
    used: u64,
}

impl ResultMemoryBudget {
    pub fn new(maximum: u64) -> Result<Self, SqlError> {
        let budget = Self {
            maximum,
            used: size_of::<TransactionResult>() as u64,
        };
        budget.check_additional(0)?;
        Ok(budget)
    }

    /// Reserve `additional` slots before pushing any values into `values`.
    ///
    /// Known sizes can be reserved in one call. Incremental collection grows
    /// geometrically, but the unused slots and growth overlap remain charged.
    /// The allocation request is checked first; allocator-reported capacity is
    /// reconciled before accepting the replacement. Hidden allocator overhead
    /// is outside this typed-graph budget.
    pub fn reserve<T>(&mut self, values: &mut Vec<T>, additional: usize) -> Result<(), SqlError> {
        self.reserve_with(values, additional, |replacement, capacity| {
            replacement
                .try_reserve_exact(capacity)
                .map_err(|_| SqlError::ResourceExhausted)
        })
    }

    pub fn text(&mut self, value: &str) -> Result<String, SqlError> {
        // The bytes came from &str and copying cannot change them. Converting
        // this already charged Vec into String reuses the same allocation.
        Ok(String::from_utf8(self.blob(value.as_bytes())?).expect("copied UTF-8 remains valid"))
    }

    pub fn blob(&mut self, value: &[u8]) -> Result<Vec<u8>, SqlError> {
        let mut copied = Vec::new();
        self.reserve(&mut copied, value.len())?;
        copied.extend_from_slice(value);
        Ok(copied)
    }

    fn check_additional(&self, bytes: u64) -> Result<(), SqlError> {
        let peak = self
            .used
            .checked_add(bytes)
            .ok_or(SqlError::ResourceExhausted)?;
        if peak > self.maximum {
            return Err(SqlError::ResourceExhausted);
        }
        Ok(())
    }

    fn reserve_with<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
        allocate: impl FnOnce(&mut Vec<T>, usize) -> Result<(), SqlError>,
    ) -> Result<(), SqlError> {
        let required = values
            .len()
            .checked_add(additional)
            .ok_or(SqlError::ResourceExhausted)?;
        // Vec's ZST capacity is usize::MAX, so ZSTs allocate nothing. The
        // checked length addition still rejects overflow before this branch.
        if required <= values.capacity() {
            return Ok(());
        }
        let capacity = growth_capacity(values.capacity(), required)?;
        let old_bytes = allocation_bytes::<T>(values.capacity())?;
        let retained = self
            .used
            .checked_sub(old_bytes)
            .ok_or(SqlError::ResourceExhausted)?;
        self.check_additional(allocation_bytes::<T>(capacity)?)?;
        let mut replacement = Vec::new();
        allocate(&mut replacement, capacity)?;
        let actual = allocation_bytes::<T>(replacement.capacity())?;
        self.check_additional(actual)?;
        // try_reserve_exact guarantees at least the requested capacity. Moving
        // elements therefore cannot allocate. Keep the old allocation alive
        // until the entire replacement is admitted and initialized.
        replacement.append(values);
        *values = replacement;
        self.used = retained + actual; // bounded by the checked overlap above
        Ok(())
    }
}

fn growth_capacity(current: usize, required: usize) -> Result<usize, SqlError> {
    Ok(required.max(current.checked_mul(2).ok_or(SqlError::ResourceExhausted)?))
}

fn allocation_bytes<T>(capacity: usize) -> Result<u64, SqlError> {
    (capacity as u64)
        .checked_mul(size_of::<T>() as u64)
        .ok_or(SqlError::ResourceExhausted)
}

#[cfg(test)]
#[path = "result_memory_tests.rs"]
mod tests;
