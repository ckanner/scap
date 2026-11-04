//! Versioned content-addressed physical layout for one atomic logical image.
//!
//! Boundaries depend on nearby content, so insertion into a serialized log does
//! not force every following block to be rewritten. Hashes authenticate bytes
//! against accidental corruption, not a hostile disk or rollback. The manifest,
//! new blocks, and deletion of superseded blocks are one synchronous WriteBatch.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::Error;

pub(crate) const MANIFEST_KEY: &[u8] = b"scap/g1/0-manifest";
pub(crate) const CHUNK_PREFIX: &[u8] = b"scap/g1/1-chunk/";
const MAGIC: &[u8; 8] = b"SCAPBLK!";
const VERSION: u32 = 1;
pub(crate) const MIN_CHUNK: usize = 4096;
pub(crate) const MAX_CHUNK: usize = 32768;
const BOUNDARY_MASK: u64 = 8191;
const HEADER: usize = 56;
const TRAILER: usize = 32;
const RECORD: usize = 36;

pub(crate) type Hash = [u8; 32];

// Fixed splitmix64-derived gear values are part of physical layout version 1.
// This rolling boundary hash is not used as an integrity or identity digest.
const fn gear_table() -> [u64; 256] {
    let mut values = [0; 256];
    let mut index = 0;
    while index < values.len() {
        let mut value = (index as u64).wrapping_add(0x9e3779b97f4a7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        values[index] = value ^ (value >> 31);
        index += 1;
    }
    values
}
const GEAR: [u64; 256] = gear_table();

pub(crate) fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub(crate) fn chunk_key(digest: &Hash) -> Vec<u8> {
    [CHUNK_PREFIX, digest].concat()
}

pub(crate) struct Plan<'a> {
    pub manifest: Vec<u8>,
    pub chunks: BTreeMap<Hash, &'a [u8]>,
}

pub(crate) fn plan(image: &[u8]) -> Plan<'_> {
    let mut chunks = BTreeMap::new();
    let mut records = Vec::new();
    let mut start = 0;
    let mut rolling = 0u64;
    for (index, byte) in image.iter().enumerate() {
        rolling = rolling.wrapping_shl(1).wrapping_add(GEAR[*byte as usize]);
        let length = index + 1 - start;
        if length >= MIN_CHUNK && (rolling & BOUNDARY_MASK == 0 || length == MAX_CHUNK) {
            record(&image[start..=index], &mut chunks, &mut records);
            start = index + 1;
            rolling = 0;
        }
    }
    if start < image.len() {
        record(&image[start..], &mut chunks, &mut records);
    }
    let mut manifest = Vec::with_capacity(HEADER + records.len() + TRAILER);
    manifest.extend_from_slice(MAGIC);
    manifest.extend_from_slice(&VERSION.to_be_bytes());
    manifest.extend_from_slice(&(image.len() as u64).to_be_bytes());
    manifest.extend_from_slice(&((records.len() / RECORD) as u32).to_be_bytes());
    manifest.extend_from_slice(&hash(image));
    manifest.extend_from_slice(&records);
    manifest.extend_from_slice(&hash(&manifest));
    Plan { manifest, chunks }
}

fn record<'a>(bytes: &'a [u8], chunks: &mut BTreeMap<Hash, &'a [u8]>, records: &mut Vec<u8>) {
    let digest = hash(bytes);
    chunks.insert(digest, bytes);
    records.extend_from_slice(&digest);
    records.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
}

pub(crate) struct Chunk {
    pub length: usize,
    pub offsets: Vec<usize>,
}

pub(crate) struct Manifest {
    pub length: usize,
    pub digest: Hash,
    pub chunks: BTreeMap<Hash, Chunk>,
}

pub(crate) fn decode(bytes: &[u8], max_image_bytes: usize) -> Result<Manifest, Error> {
    if bytes.len() < HEADER + TRAILER {
        return Err(Error::Invalid("truncated block manifest"));
    }
    if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_be_bytes() {
        return Err(Error::Invalid("unknown block manifest format"));
    }
    let length = u64::from_be_bytes(bytes[12..20].try_into().expect("eight bytes"));
    if length > max_image_bytes as u64 {
        return Err(Error::Invalid(
            "image exceeds the configured owned-copy bound",
        ));
    }
    let length = length as usize;
    let count = u32::from_be_bytes(bytes[20..24].try_into().expect("four bytes")) as usize;
    if count > length / MIN_CHUNK + 1
        || bytes.len() != HEADER + count.saturating_mul(RECORD) + TRAILER
    {
        return Err(Error::Invalid("invalid block manifest count"));
    }
    let end = bytes.len() - TRAILER;
    if hash(&bytes[..end]) != bytes[end..] {
        return Err(Error::Invalid("block manifest checksum mismatch"));
    }
    let digest = bytes[24..56].try_into().expect("digest bytes");
    let mut chunks: BTreeMap<Hash, Chunk> = BTreeMap::new();
    let mut offset = 0usize;
    for (index, record) in bytes[HEADER..end].chunks_exact(RECORD).enumerate() {
        let digest = record[..32].try_into().expect("digest bytes");
        let size = u32::from_be_bytes(record[32..].try_into().expect("four bytes")) as usize;
        if size == 0
            || size > MAX_CHUNK
            || (index + 1 < count && size < MIN_CHUNK)
            || size > length.saturating_sub(offset)
        {
            return Err(Error::Invalid("invalid block length"));
        }
        let chunk = chunks.entry(digest).or_insert_with(|| Chunk {
            length: size,
            offsets: Vec::new(),
        });
        if chunk.length != size {
            return Err(Error::Invalid("conflicting block lengths"));
        }
        chunk.offsets.push(offset);
        offset += size;
    }
    if offset != length {
        return Err(Error::Invalid("block manifest does not cover image"));
    }
    Ok(Manifest {
        length,
        digest,
        chunks,
    })
}

#[cfg(test)]
mod tests;
