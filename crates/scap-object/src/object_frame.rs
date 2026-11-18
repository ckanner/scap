//! Validate the original immutable frame before copying its raw payload.
//! This is local frame validation, not a proof of any referenced objects.

use super::{
    digest, Envelope, FormatError, Metadata, Payload, Scope, StoredResult, FRAME_BYTES, MAGIC,
    MAX_OBJECT_BYTES, MAX_RESULT_BYTES, SMALL_METADATA_BYTES,
};

/// Owns bounded JSON metadata and borrows the exact hash-checked frame. Raw
/// Chunk/Result bytes remain in the input until conversion to an Envelope.
pub(crate) struct ValidatedFrame<'a> {
    bytes: &'a [u8],
    raw_offset: usize,
    envelope: Envelope,
}

/// Internal traversal parts, not an owned decoded Envelope. Chunk/Result
/// metadata has empty embedded bytes; its validated payload is `raw`.
pub(crate) struct FrameParts<'a> {
    pub(crate) metadata: Payload,
    pub(crate) frame: &'a [u8],
    pub(crate) raw: &'a [u8],
}

impl<'a> ValidatedFrame<'a> {
    pub(crate) fn parse(
        bytes: &'a [u8],
        scope: &Scope,
        expected_hash: &str,
    ) -> Result<Self, FormatError> {
        // Preserve the public decoder's limit/error precedence. The metadata
        // and raw bounds also make the later offset sum and usize cast safe.
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(FormatError::Limit);
        }
        if digest(bytes) != expected_hash {
            return Err(FormatError::Corrupt);
        }
        if bytes.len() < FRAME_BYTES {
            return Err(FormatError::Corrupt);
        }
        if &bytes[..8] != MAGIC {
            return Err(FormatError::Corrupt);
        }
        let metadata_len =
            u32::from_le_bytes(bytes[8..12].try_into().expect("fixed frame field")) as usize;
        let raw_len = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed frame field"));
        if metadata_len > SMALL_METADATA_BYTES {
            return Err(FormatError::Corrupt);
        }
        if raw_len > MAX_RESULT_BYTES as u64 {
            return Err(FormatError::Corrupt);
        }
        let raw_offset = FRAME_BYTES + metadata_len;
        if bytes.len() != raw_offset + raw_len as usize {
            return Err(FormatError::Corrupt);
        }
        let metadata = serde_json::from_slice::<Metadata>(&bytes[FRAME_BYTES..raw_offset]);
        let Ok(metadata) = metadata else {
            return Err(FormatError::Corrupt);
        };
        if let Payload::Chunk { bytes, .. } = &metadata.payload {
            if !bytes.is_empty() {
                return Err(FormatError::Corrupt);
            }
        } else if let Payload::Result(StoredResult { bytes, .. }) = &metadata.payload {
            if !bytes.is_empty() {
                return Err(FormatError::Corrupt);
            }
        } else if raw_len != 0 {
            return Err(FormatError::Corrupt);
        }
        let envelope = Envelope {
            format: metadata.format,
            scope: metadata.scope,
            payload: metadata.payload,
        };
        if envelope.validate_with_raw_len(raw_len as usize).is_err() {
            return Err(FormatError::Corrupt);
        }
        if envelope.scope != *scope {
            return Err(FormatError::Corrupt);
        }
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

    pub(crate) fn raw_payload(&self) -> &'a [u8] {
        &self.as_bytes()[self.raw_offset..]
    }

    pub(crate) fn into_parts(self) -> FrameParts<'a> {
        FrameParts {
            frame: self.as_bytes(),
            raw: self.raw_payload(),
            metadata: self.envelope.payload,
        }
    }

    pub(crate) fn into_envelope(self) -> Envelope {
        let raw = self.raw_payload();
        let mut envelope = self.envelope;
        if let Payload::Chunk { bytes, .. } = &mut envelope.payload {
            bytes.extend_from_slice(raw);
        } else if let Payload::Result(StoredResult { bytes, .. }) = &mut envelope.payload {
            bytes.extend_from_slice(raw);
        }
        envelope
    }
}

#[cfg(test)]
#[path = "object_frame_tests.rs"]
mod tests;
