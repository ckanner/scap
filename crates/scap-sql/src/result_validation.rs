//! Allocation-free validation of retained SCAPRES1 bytes.
//!
//! Recovery needs to establish that every retained result is decodable, but
//! must not materialize all its rows merely to check the recovery closure.
//! This walks the existing decoder's bounded cursor and keeps no result data.

use super::{Decoder, SqlError, SqlLimits, RESULT_MAGIC};

/// Check the same wire contract as `decode_result`, without constructing a
/// TransactionResult or copying any text/blob bytes. The caller supplies the
/// persisted format limits, not a newly tightened SQL admission budget.
///
/// The original bytes are never normalized; signed zero and all integer bits
/// remain untouched. This is a structural check, not authorization or an ACK.
pub fn validate_result(bytes: &[u8], limits: SqlLimits) -> Result<(), SqlError> {
    limits.validate()?;
    if bytes.len() > limits.max_result_bytes as usize {
        return Err(SqlError::Limit);
    }
    let mut decoder = Decoder { bytes };
    if decoder.take(8)? != RESULT_MAGIC {
        return Err(SqlError::Malformed);
    }
    let statements = decoder.count(limits.max_statements)?;
    let mut remaining_rows = limits.max_rows;
    for _ in 0..statements {
        let columns = decoder.count(limits.max_columns)?;
        for _ in 0..columns {
            std::str::from_utf8(decoder.bytes(limits)?).map_err(|_| SqlError::Malformed)?;
        }
        let rows = decoder.count(remaining_rows)?;
        if columns == 0 && rows != 0 {
            return Err(SqlError::Malformed);
        }
        remaining_rows -= rows as u32;
        for _ in 0..rows {
            for _ in 0..columns {
                skip_value(&mut decoder, limits)?;
            }
        }
        // affected_rows: u64; last_insert_rowid: i64. Every bit pattern is
        // valid. take(16) checks both complete little-endian fields exist.
        decoder.take(16)?;
    }
    if !decoder.bytes.is_empty() {
        return Err(SqlError::Malformed);
    }
    Ok(())
}

fn skip_value(decoder: &mut Decoder<'_>, limits: SqlLimits) -> Result<(), SqlError> {
    match decoder.take(1)?[0] {
        0 => {}
        1 => {
            decoder.take(8)?;
        }
        2 => {
            let number = f64::from_le_bytes(decoder.number()?);
            if !number.is_finite() {
                return Err(SqlError::Invalid);
            }
        }
        3 => {
            std::str::from_utf8(decoder.bytes(limits)?).map_err(|_| SqlError::Malformed)?;
        }
        4 => {
            decoder.bytes(limits)?;
        }
        _ => return Err(SqlError::Malformed),
    }
    Ok(())
}
