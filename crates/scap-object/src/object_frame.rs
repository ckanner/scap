//! Validate the original immutable frame before copying its raw payload.
//! This is local frame validation, not a proof of any referenced objects.

use super::{
    budget, check, digest, Envelope, FormatError, Metadata, Payload, Scope, StoredResult,
    FRAME_BYTES, MAGIC, MAX_OBJECT_BYTES, MAX_RESULT_BYTES, SMALL_METADATA_BYTES,
};

/// Owns bounded JSON metadata and borrows the exact hash-checked frame. Raw
/// Chunk/Result bytes remain in the input until conversion to an Envelope.
pub(crate) struct ValidatedFrame<'a> {
    bytes: &'a [u8],
    raw_offset: usize,
    envelope: Envelope,
}

impl<'a> ValidatedFrame<'a> {
    pub(crate) fn parse(
        bytes: &'a [u8],
        scope: &Scope,
        expected_hash: &str,
    ) -> Result<Self, FormatError> {
        // Preserve the public decoder's limit/error precedence. The metadata
        // and raw bounds also make the later offset sum and usize cast safe.
        budget(bytes.len(), MAX_OBJECT_BYTES)?;
        check(digest(bytes) == expected_hash).map_err(|_| FormatError::Corrupt)?;
        check(bytes.len() >= FRAME_BYTES).map_err(|_| FormatError::Corrupt)?;
        check(&bytes[..8] == MAGIC).map_err(|_| FormatError::Corrupt)?;
        let metadata_len =
            u32::from_le_bytes(bytes[8..12].try_into().expect("fixed frame field")) as usize;
        let raw_len = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed frame field"));
        check(metadata_len <= SMALL_METADATA_BYTES).map_err(|_| FormatError::Corrupt)?;
        check(raw_len <= MAX_RESULT_BYTES as u64).map_err(|_| FormatError::Corrupt)?;
        let raw_offset = FRAME_BYTES + metadata_len;
        check(bytes.len() == raw_offset + raw_len as usize).map_err(|_| FormatError::Corrupt)?;
        let metadata: Metadata = serde_json::from_slice(&bytes[FRAME_BYTES..raw_offset])
            .map_err(|_| FormatError::Corrupt)?;
        match &metadata.payload {
            Payload::Chunk { bytes, .. } | Payload::Result(StoredResult { bytes, .. }) => {
                check(bytes.is_empty()).map_err(|_| FormatError::Corrupt)?;
            }
            _ => check(raw_len == 0).map_err(|_| FormatError::Corrupt)?,
        }
        let envelope = Envelope {
            format: metadata.format,
            scope: metadata.scope,
            payload: metadata.payload,
        };
        envelope
            .validate_with_raw_len(raw_len as usize)
            .map_err(|_| FormatError::Corrupt)?;
        check(envelope.scope == *scope).map_err(|_| FormatError::Corrupt)?;
        Ok(Self {
            bytes,
            raw_offset,
            envelope,
        })
    }

    /// Return the original bytes, including noncanonical but valid JSON.
    /// Re-encoding the metadata need not reproduce this frame or its hash.
    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) fn into_envelope(self) -> Envelope {
        let raw = &self.as_bytes()[self.raw_offset..];
        let mut envelope = self.envelope;
        match &mut envelope.payload {
            Payload::Chunk { bytes, .. } | Payload::Result(StoredResult { bytes, .. }) => {
                bytes.extend_from_slice(raw);
            }
            _ => {}
        }
        envelope
    }
}

#[cfg(test)]
#[path = "object_frame_tests.rs"]
mod tests;
