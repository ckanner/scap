//! Bounded SQL request identities and retained transaction results.
//!
//! Version 1 uses exact SQL bytes and typed positional parameters for request
//! identity. It does not normalize SQL or infer semantic equivalence. Results
//! are buffered until commit completion; encoding them does not authorize ACK.
//! NaN and infinities are outside this initial, finite-number SQL contract.

use sha2::{Digest, Sha256};

mod result_validation;
pub use result_validation::validate_result;
mod result_memory;
pub use result_memory::ResultMemoryBudget;

/// Local typed-result allocation budget. It is independent of the durable
/// SCAPRES1 byte limit and is not a process-wide allocator/RSS limit.
pub const DEFAULT_RESULT_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

const REQUEST_MAGIC: &[u8; 8] = b"SCAPSQL1";
const RESULT_MAGIC: &[u8; 8] = b"SCAPRES1";

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Statement {
    pub sql: String,
    pub parameters: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StatementResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub affected_rows: u64,
    pub last_insert_rowid: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionResult {
    pub statements: Vec<StatementResult>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlLimits {
    pub max_statements: u32,
    /// Sum of SQL UTF-8 bytes in a transaction.
    pub max_sql_bytes: u32,
    /// Positional parameter count per statement.
    pub max_parameters: u32,
    pub max_columns: u32,
    /// Sum of rows over the complete transaction.
    pub max_rows: u32,
    pub max_result_bytes: u32,
    /// Per text, blob or column name; lengths are bytes, not characters.
    pub max_value_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlError {
    Invalid,
    Limit,
    Malformed,
    /// A valid result cannot be materialized within the local allocation
    /// budget, or a fallible allocation was refused. This is not corruption.
    ResourceExhausted,
}

impl SqlLimits {
    pub fn validate(self) -> Result<(), SqlError> {
        if self.max_statements == 0
            || self.max_sql_bytes == 0
            || self.max_parameters == 0
            || self.max_columns == 0
            || self.max_rows == 0
            || self.max_result_bytes < 12
            || self.max_value_bytes == 0
        {
            return Err(SqlError::Invalid);
        }
        Ok(())
    }
}

pub fn validate_statements(statements: &[Statement], limits: SqlLimits) -> Result<(), SqlError> {
    limits.validate()?;
    if statements.is_empty() || statements.len() > limits.max_statements as usize {
        return Err(SqlError::Limit);
    }
    let mut remaining_sql = limits.max_sql_bytes as usize;
    for statement in statements {
        if statement.sql.is_empty() || statement.sql.as_bytes().contains(&0) {
            return Err(SqlError::Invalid);
        }
        if statement.sql.len() > remaining_sql
            || statement.parameters.len() > limits.max_parameters as usize
        {
            return Err(SqlError::Limit);
        }
        remaining_sql -= statement.sql.len();
        for value in &statement.parameters {
            validate_value(value, limits)?;
        }
    }
    Ok(())
}

fn validate_value(value: &Value, limits: SqlLimits) -> Result<(), SqlError> {
    match value {
        Value::Text(value) => validate_length(value.len(), limits),
        Value::Blob(value) => validate_length(value.len(), limits),
        Value::Real(value) if !value.is_finite() => Err(SqlError::Invalid),
        _ => Ok(()),
    }
}

fn validate_length(length: usize, limits: SqlLimits) -> Result<(), SqlError> {
    if length > limits.max_value_bytes as usize {
        return Err(SqlError::Limit);
    }
    Ok(())
}

/// Stable exact-request fingerprint, independent of generated physical pages.
/// This streams into SHA-256 so large permitted input does not gain a second
/// unbounded encoded copy. Authorization and request ID are separate bindings.
pub fn request_fingerprint(
    statements: &[Statement],
    limits: SqlLimits,
) -> Result<[u8; 32], SqlError> {
    validate_statements(statements, limits)?;
    let mut digest = Sha256::new();
    digest.update(REQUEST_MAGIC);
    digest.update((statements.len() as u32).to_le_bytes());
    for statement in statements {
        digest.update((statement.sql.len() as u32).to_le_bytes());
        digest.update(statement.sql.as_bytes());
        digest.update((statement.parameters.len() as u32).to_le_bytes());
        for value in &statement.parameters {
            write_value(value, |bytes| digest.update(bytes));
        }
    }
    Ok(digest.finalize().into())
}

fn write_value(value: &Value, mut write: impl FnMut(&[u8])) {
    match value {
        Value::Null => write(&[0]),
        Value::Integer(value) => {
            write(&[1]);
            write(&value.to_le_bytes())
        }
        Value::Real(value) => {
            write(&[2]);
            write(&value.to_bits().to_le_bytes())
        }
        Value::Text(value) => {
            write(&[3]);
            write(&(value.len() as u32).to_le_bytes());
            write(value.as_bytes())
        }
        Value::Blob(value) => {
            write(&[4]);
            write(&(value.len() as u32).to_le_bytes());
            write(value)
        }
    }
}

struct Encoder<F> {
    write: F,
    written: usize,
    limit: usize,
}

impl<F: FnMut(&[u8])> Encoder<F> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), SqlError> {
        if bytes.len() > self.limit - self.written {
            return Err(SqlError::Limit);
        }
        (self.write)(bytes);
        self.written += bytes.len();
        Ok(())
    }

    fn count(&mut self, count: usize) -> Result<(), SqlError> {
        // Every count is bounded by a validated u32 limit before reaching here.
        self.put(&(count as u32).to_le_bytes())
    }
}

/// A validated, allocation-free plan for one canonical SCAPRES1 result.
///
/// The immutable borrow keeps the counted graph unchanged until the caller
/// writes it. This lets an output owner reserve its exact wire-byte credit
/// before allocating a destination; it is not itself a memory reservation.
pub struct ResultEncoding<'a> {
    result: &'a TransactionResult,
    limits: SqlLimits,
    encoded_len: usize,
}

impl ResultEncoding<'_> {
    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Write the original result into a destination of exactly `encoded_len`.
    /// A wrong-sized destination is INVALID and remains entirely unchanged.
    /// This never allocates or grows the caller's backing storage.
    pub fn write_exact(&self, destination: &mut [u8]) -> Result<(), SqlError> {
        if destination.len() != self.encoded_len {
            return Err(SqlError::Invalid);
        }
        let mut offset = 0;
        write_result(self.result, self.limits, |bytes| {
            let end = offset + bytes.len();
            destination[offset..end].copy_from_slice(bytes);
            offset = end;
        })?;
        Ok(())
    }
}

/// Validate and count using the same ordered emitter as `encode_result`.
/// No result-sized scratch allocation is needed for validation alone.
pub fn plan_result(
    result: &TransactionResult,
    limits: SqlLimits,
) -> Result<ResultEncoding<'_>, SqlError> {
    let encoded_len = write_result(result, limits, |_| {})?;
    Ok(ResultEncoding {
        result,
        limits,
        encoded_len,
    })
}

pub fn encode_result(result: &TransactionResult, limits: SqlLimits) -> Result<Vec<u8>, SqlError> {
    encode_result_with(result, limits, &mut Vec::try_reserve_exact)
}

type ResultAllocator<'a> =
    dyn FnMut(&mut Vec<u8>, usize) -> Result<(), std::collections::TryReserveError> + 'a;

fn encode_result_with(
    result: &TransactionResult,
    limits: SqlLimits,
    allocate: &mut ResultAllocator<'_>,
) -> Result<Vec<u8>, SqlError> {
    let plan = plan_result(result, limits)?;
    let mut bytes = Vec::new();
    // The local seam has Vec::try_reserve_exact's contract: success reserves
    // at least the requested capacity. Initializing/writing cannot grow it.
    allocate(&mut bytes, plan.encoded_len()).map_err(|_| SqlError::ResourceExhausted)?;
    bytes.resize(plan.encoded_len(), 0);
    plan.write_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_result(
    result: &TransactionResult,
    limits: SqlLimits,
    mut write: impl FnMut(&[u8]),
) -> Result<usize, SqlError> {
    limits.validate()?;
    if result.statements.len() > limits.max_statements as usize {
        return Err(SqlError::Limit);
    }
    // The validated minimum includes this fixed 12-byte header.
    write(RESULT_MAGIC);
    write(&(result.statements.len() as u32).to_le_bytes());
    let mut encoder = Encoder {
        write,
        written: 12,
        limit: limits.max_result_bytes as usize,
    };
    let mut remaining_rows = limits.max_rows as usize;
    for statement in &result.statements {
        if statement.columns.len() > limits.max_columns as usize
            || statement.rows.len() > remaining_rows
        {
            return Err(SqlError::Limit);
        }
        remaining_rows -= statement.rows.len();
        if statement.columns.is_empty() && !statement.rows.is_empty() {
            return Err(SqlError::Invalid);
        }
        encoder.count(statement.columns.len())?;
        for column in &statement.columns {
            validate_length(column.len(), limits)?;
            encoder.count(column.len())?;
            encoder.put(column.as_bytes())?;
        }
        encoder.count(statement.rows.len())?;
        for row in &statement.rows {
            if row.len() != statement.columns.len() {
                return Err(SqlError::Invalid);
            }
            for value in row {
                validate_value(value, limits)?;
                let mut status = Ok(());
                write_value(value, |bytes| {
                    if status.is_ok() {
                        status = encoder.put(bytes);
                    }
                });
                status?;
            }
        }
        encoder.put(&statement.affected_rows.to_le_bytes())?;
        encoder.put(&statement.last_insert_rowid.to_le_bytes())?;
    }
    Ok(encoder.written)
}

struct Decoder<'a> {
    bytes: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], SqlError> {
        if length > self.bytes.len() {
            return Err(SqlError::Malformed);
        }
        let (value, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(value)
    }

    fn number<const N: usize>(&mut self) -> Result<[u8; N], SqlError> {
        // take(N) guarantees the exact array length.
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn count(&mut self, limit: u32) -> Result<usize, SqlError> {
        let count = u32::from_le_bytes(self.number()?);
        if count > limit {
            return Err(SqlError::Limit);
        }
        Ok(count as usize)
    }

    fn bytes(&mut self, limits: SqlLimits) -> Result<&'a [u8], SqlError> {
        let count = self.count(limits.max_value_bytes)?;
        self.take(count)
    }

    fn text(
        &mut self,
        limits: SqlLimits,
        memory: &mut ResultMemoryBudget,
    ) -> Result<String, SqlError> {
        // Materialization only runs after the allocation-free wire validator.
        // The input slice is immutable during both passes.
        let text = std::str::from_utf8(self.bytes(limits).expect("validated text extent"))
            .expect("validated UTF-8");
        memory.text(text)
    }

    fn value(
        &mut self,
        limits: SqlLimits,
        memory: &mut ResultMemoryBudget,
    ) -> Result<Value, SqlError> {
        let value = match self.take(1).expect("validated value tag")[0] {
            0 => Value::Null,
            1 => Value::Integer(i64::from_le_bytes(
                self.number().expect("validated integer"),
            )),
            2 => Value::Real(f64::from_bits(u64::from_le_bytes(
                self.number().expect("validated finite real"),
            ))),
            3 => Value::Text(self.text(limits, memory)?),
            // The validator rejects every other tag, leaving only Blob (4).
            _ => Value::Blob(memory.blob(self.bytes(limits).expect("validated blob extent"))?),
        };
        Ok(value)
    }
}

/// Decode a retained result only after the caller has rechecked current
/// authorization and semantic request identity in the current authoritative object snapshot.
pub fn decode_result(bytes: &[u8], limits: SqlLimits) -> Result<TransactionResult, SqlError> {
    decode_result_with_memory_limit(bytes, limits, DEFAULT_RESULT_MEMORY_BYTES)
}

/// Decode with a separate local typed-graph budget. Counts from the input do
/// not trigger bulk row allocation: each value is parsed and each container
/// growth is charged before its allocation. A resource error must never be
/// interpreted as an invalid durable result or authorization to repeat SQL.
pub fn decode_result_with_memory_limit(
    bytes: &[u8],
    limits: SqlLimits,
    maximum_memory_bytes: u64,
) -> Result<TransactionResult, SqlError> {
    // Preserve format error precedence and reject forged counts before any
    // result allocation. A valid graph may still need more memory than its
    // compact encoding; only that second pass can return ResourceExhausted.
    validate_result(bytes, limits)?;
    let mut decoder = Decoder { bytes };
    decoder.take(8).expect("validated result magic");
    let count = decoder
        .count(limits.max_statements)
        .expect("validated statement count");
    let mut memory = ResultMemoryBudget::new(maximum_memory_bytes)?;
    let mut statements = Vec::new();
    memory.reserve(&mut statements, count)?;
    let mut remaining_rows = limits.max_rows;
    for _ in 0..count {
        let columns_count = decoder
            .count(limits.max_columns)
            .expect("validated column count");
        let mut columns = Vec::new();
        memory.reserve(&mut columns, columns_count)?;
        for _ in 0..columns_count {
            columns.push(decoder.text(limits, &mut memory)?);
        }
        let rows_count = decoder.count(remaining_rows).expect("validated row count");
        remaining_rows -= rows_count as u32;
        let mut rows = Vec::new();
        for _ in 0..rows_count {
            memory.reserve(&mut rows, 1)?;
            let mut row = Vec::new();
            memory.reserve(&mut row, columns_count)?;
            for _ in 0..columns_count {
                row.push(decoder.value(limits, &mut memory)?);
            }
            rows.push(row);
        }
        statements.push(StatementResult {
            columns,
            rows,
            affected_rows: u64::from_le_bytes(decoder.number().expect("validated affected rows")),
            last_insert_rowid: i64::from_le_bytes(
                decoder.number().expect("validated insert rowid"),
            ),
        });
    }
    Ok(TransactionResult { statements })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod result_validation_tests;

#[cfg(test)]
mod result_memory_decode_tests;
