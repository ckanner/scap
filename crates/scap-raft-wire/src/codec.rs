use crate::{Envelope, Error, Limits};

const MAGIC: &[u8; 8] = b"SCAPRPC1";
pub const HEADER_BYTES: usize = 80;

pub fn encode_envelope(envelope: &Envelope, max_wire_bytes: usize) -> Result<Vec<u8>, Error> {
    if max_wire_bytes < HEADER_BYTES || envelope.payload.len() > max_wire_bytes - HEADER_BYTES {
        return Err(Error::Limit("peer envelope"));
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + envelope.payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&envelope.version.to_le_bytes());
    bytes.extend_from_slice(&envelope.codec.to_le_bytes());
    bytes.extend_from_slice(&envelope.cluster_id.to_le_bytes());
    bytes.extend_from_slice(&envelope.cell_id.to_le_bytes());
    bytes.extend_from_slice(&envelope.cell_incarnation.to_le_bytes());
    bytes.extend_from_slice(&envelope.from_node.to_le_bytes());
    bytes.extend_from_slice(&envelope.to_node.to_le_bytes());
    bytes.extend_from_slice(&(envelope.payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&envelope.payload);
    Ok(bytes)
}

pub fn decode_envelope(bytes: &[u8], max_wire_bytes: usize) -> Result<Envelope, Error> {
    if bytes.len() > max_wire_bytes {
        return Err(Error::Limit("peer envelope"));
    }
    if bytes.len() < HEADER_BYTES || &bytes[..8] != MAGIC {
        return Err(Error::Malformed("peer envelope header"));
    }
    let mut header = &bytes[8..HEADER_BYTES];
    let version = u32::from_le_bytes(take(&mut header));
    let codec = u32::from_le_bytes(take(&mut header));
    let cluster_id = u128::from_le_bytes(take(&mut header));
    let cell_id = u128::from_le_bytes(take(&mut header));
    let cell_incarnation = u64::from_le_bytes(take(&mut header));
    let from_node = u64::from_le_bytes(take(&mut header));
    let to_node = u64::from_le_bytes(take(&mut header));
    let payload_len = u64::from_le_bytes(take(&mut header));
    if payload_len != (bytes.len() - HEADER_BYTES) as u64 {
        return Err(Error::Malformed("peer envelope length"));
    }
    Ok(Envelope {
        version,
        codec,
        cluster_id,
        cell_id,
        cell_incarnation,
        from_node,
        to_node,
        payload: bytes[HEADER_BYTES..].to_vec(),
    })
}

fn take<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
    // Only called after the complete fixed header length is validated.
    let (head, rest) = bytes.split_at(N);
    *bytes = rest;
    head.try_into().expect("fixed header slice")
}

#[derive(Clone, Copy)]
enum Kind {
    Message,
    Entry,
    Snapshot,
    Metadata,
    Configuration,
}

/// A zero-allocation framing pass before generated protobuf decoding. Bytes
/// and application payloads stay opaque; only known nested message structures
/// are traversed. Unknown groups are outside the pinned proto3 codec contract.
pub(crate) fn preflight_raft(bytes: &[u8], limits: Limits) -> Result<(), Error> {
    let mut fields = limits.max_fields;
    let mut entries = limits.max_entries;
    scan(bytes, Kind::Message, &mut fields, &mut entries)
}

fn scan(
    mut bytes: &[u8],
    kind: Kind,
    fields: &mut usize,
    entries: &mut usize,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        spend(fields, "Raft fields")?;
        let tag = varint(&mut bytes)?;
        let field = tag >> 3;
        if field == 0 || field > 0x1fff_ffff {
            return Err(Error::Malformed("Raft field tag"));
        }
        match tag & 7 {
            0 => {
                let value = varint(&mut bytes)?;
                match (kind, field) {
                    (Kind::Message, 1) if value > 18 => {
                        return Err(Error::Unsupported("Raft message enum"));
                    }
                    (Kind::Entry, 1) if value > 2 => {
                        return Err(Error::Unsupported("Raft entry enum"));
                    }
                    _ => {}
                }
            }
            1 => {
                slice(&mut bytes, 8)?;
            }
            2 => {
                let length = varint(&mut bytes)?;
                let nested = slice(&mut bytes, length)?;
                match (kind, field) {
                    (Kind::Message, 7) => {
                        spend(entries, "Raft entries")?;
                        scan(nested, Kind::Entry, fields, entries)?;
                    }
                    (Kind::Message, 9) => scan(nested, Kind::Snapshot, fields, entries)?,
                    (Kind::Snapshot, 2) => scan(nested, Kind::Metadata, fields, entries)?,
                    (Kind::Metadata, 1) => scan(nested, Kind::Configuration, fields, entries)?,
                    (Kind::Configuration, 1..=4) => {
                        let mut packed = nested;
                        while !packed.is_empty() {
                            spend(fields, "Raft fields")?;
                            varint(&mut packed)?;
                        }
                    }
                    _ => {}
                }
            }
            5 => {
                slice(&mut bytes, 4)?;
            }
            _ => return Err(Error::Malformed("Raft wire type")),
        }
    }
    Ok(())
}

fn spend(remaining: &mut usize, name: &'static str) -> Result<(), Error> {
    if *remaining == 0 {
        return Err(Error::Limit(name));
    }
    *remaining -= 1;
    Ok(())
}

fn slice<'a>(bytes: &mut &'a [u8], length: u64) -> Result<&'a [u8], Error> {
    if length > bytes.len() as u64 {
        return Err(Error::Malformed("Raft field length"));
    }
    let (head, rest) = bytes.split_at(length as usize);
    *bytes = rest;
    Ok(head)
}

fn varint(bytes: &mut &[u8]) -> Result<u64, Error> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        let (byte, rest) = bytes
            .split_first()
            .ok_or(Error::Malformed("Raft truncated varint"))?;
        *bytes = rest;
        if shift == 63 && *byte > 1 {
            return Err(Error::Malformed("Raft overflowing varint"));
        }
        result |= ((*byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}
