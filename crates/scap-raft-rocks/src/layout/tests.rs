use super::*;

fn resign(bytes: &mut [u8]) {
    let end = bytes.len() - TRAILER;
    let digest = hash(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
}

fn noisy(length: usize) -> Vec<u8> {
    let mut seed = 0x123456789abcdef0u64;
    (0..length)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

fn restore(plan: &Plan<'_>, bound: usize) -> Vec<u8> {
    let manifest = decode(&plan.manifest, bound).unwrap();
    let mut image = vec![0; manifest.length];
    for (digest, chunk) in &manifest.chunks {
        let bytes = plan.chunks[digest];
        assert_eq!(hash(bytes), *digest);
        assert_eq!(bytes.len(), chunk.length);
        for offset in &chunk.offsets {
            image[*offset..*offset + chunk.length].copy_from_slice(bytes);
        }
    }
    assert_eq!(hash(&image), manifest.digest);
    image
}

#[test]
fn partitions_preserve_empty_short_repeated_and_boundary_sized_images() {
    assert_eq!(gear_table(), GEAR);
    for bytes in [
        vec![],
        b"native payload".to_vec(),
        vec![0; MIN_CHUNK - 1],
        vec![0; MAX_CHUNK],
        vec![0; MAX_CHUNK * 3 + 7],
        noisy(MAX_CHUNK * 20),
    ] {
        let p = plan(&bytes);
        assert_eq!(restore(&p, bytes.len()), bytes);
        assert!(p.chunks.values().all(|chunk| chunk.len() <= MAX_CHUNK));
        assert_eq!(plan(&bytes).manifest, p.manifest);
    }
    let bytes = vec![0; MAX_CHUNK * 3];
    let p = plan(&bytes);
    assert_eq!(p.chunks.len(), 1);
    let decoded = decode(&p.manifest, bytes.len()).unwrap();
    assert_eq!(
        decoded.chunks.values().next().unwrap().offsets,
        [0, MAX_CHUNK, MAX_CHUNK * 2]
    );
    let digest = hash(b"key");
    assert_eq!(chunk_key(&digest), [CHUNK_PREFIX, &digest].concat());
}

#[test]
fn an_insert_does_not_rewrite_the_unchanged_history_suffix() {
    let original = noisy(1024 * 1024);
    let before = plan(&original);
    let mut changed = original.clone();
    changed.splice(91..91, b"new raft metadata".iter().copied());
    let after = plan(&changed);
    let changed_bytes: usize = after
        .chunks
        .iter()
        .filter(|(digest, _)| !before.chunks.contains_key(*digest))
        .map(|(_, bytes)| bytes.len())
        .sum();
    assert!(
        changed_bytes < MAX_CHUNK * 3,
        "only local boundary blocks change: {changed_bytes}"
    );
    assert_eq!(restore(&after, changed.len()), changed);
}

#[test]
fn manifest_enforces_format_checksum_and_allocation_bound_before_copy() {
    let bytes = noisy(MIN_CHUNK * 4);
    let valid = plan(&bytes).manifest;
    for n in [0, HEADER, HEADER + TRAILER - 1] {
        assert!(decode(&valid[..n], bytes.len()).is_err());
    }
    for index in [0, 11] {
        let mut bad = valid.clone();
        bad[index] ^= 1;
        resign(&mut bad);
        assert!(matches!(
            decode(&bad, bytes.len()),
            Err(Error::Invalid("unknown block manifest format"))
        ));
    }
    assert!(matches!(
        decode(&valid, bytes.len() - 1),
        Err(Error::Invalid(
            "image exceeds the configured owned-copy bound"
        ))
    ));
    let mut bad = valid.clone();
    bad[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        decode(&bad, bytes.len()),
        Err(Error::Invalid("invalid block manifest count"))
    ));
    let mut bad = valid.clone();
    bad.push(0);
    assert!(matches!(
        decode(&bad, bytes.len()),
        Err(Error::Invalid("invalid block manifest count"))
    ));
    let mut bad = valid;
    bad[24] ^= 1;
    assert!(matches!(
        decode(&bad, bytes.len()),
        Err(Error::Invalid("block manifest checksum mismatch"))
    ));
}

#[test]
fn manifest_requires_exact_coverage_and_consistent_deduplicated_lengths() {
    let bytes = vec![0; MAX_CHUNK * 2];
    let valid = plan(&bytes).manifest;
    for size in [0u32, MAX_CHUNK as u32 + 1, MIN_CHUNK as u32 - 1] {
        let mut bad = valid.clone();
        bad[HEADER + 32..HEADER + RECORD].copy_from_slice(&size.to_be_bytes());
        resign(&mut bad);
        assert!(matches!(
            decode(&bad, bytes.len()),
            Err(Error::Invalid("invalid block length"))
        ));
    }
    let mut bad = valid.clone();
    bad[12..20].copy_from_slice(&(MAX_CHUNK as u64 - 1).to_be_bytes());
    resign(&mut bad);
    assert!(matches!(
        decode(&bad, bytes.len()),
        Err(Error::Invalid("invalid block length"))
    ));
    let mut bad = valid.clone();
    bad[HEADER + RECORD + 32..HEADER + 2 * RECORD]
        .copy_from_slice(&(MAX_CHUNK as u32 - 1).to_be_bytes());
    resign(&mut bad);
    assert!(matches!(
        decode(&bad, bytes.len()),
        Err(Error::Invalid("conflicting block lengths"))
    ));
    let mut bad = plan(b"small").manifest;
    bad[12..20].copy_from_slice(&6u64.to_be_bytes());
    resign(&mut bad);
    assert!(matches!(
        decode(&bad, 6),
        Err(Error::Invalid("block manifest does not cover image"))
    ));
    let mut bad = plan(&[]).manifest;
    bad[12..20].copy_from_slice(&1u64.to_be_bytes());
    resign(&mut bad);
    assert!(matches!(
        decode(&bad, 1),
        Err(Error::Invalid("block manifest does not cover image"))
    ));
}
