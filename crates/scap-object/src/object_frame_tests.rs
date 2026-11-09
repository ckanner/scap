use super::super::*;
use super::ValidatedFrame;

fn scope() -> Scope {
    Scope {
        deployment: 1,
        tenant: 2,
        database: 3,
        incarnation: 4,
        generation: 5,
    }
}

fn envelope(payload: Payload) -> Envelope {
    Envelope {
        format: 2,
        scope: scope(),
        payload,
    }
}

fn result(bytes: Vec<u8>) -> Payload {
    Payload::Result(StoredResult {
        request: Request {
            epoch: 1,
            id: 2,
            principal: 3,
            fingerprint: digest(b"original request"),
        },
        sequence: 1,
        transition: Transition {
            revision: 2,
            nonce: 3,
        },
        data_root: digest(b"unfetched data root"),
        bytes,
    })
}

fn metadata(payload: Payload) -> Metadata {
    Metadata {
        format: 2,
        scope: scope(),
        payload,
    }
}

fn frame(metadata: &[u8], raw: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    bytes.extend_from_slice(metadata);
    bytes.extend_from_slice(raw);
    bytes
}

fn reject(bytes: &[u8], scope: &Scope, hash: &str) {
    assert_eq!(
        ValidatedFrame::parse(bytes, scope, hash).err(),
        Some(FormatError::Corrupt)
    );
    assert_eq!(decode_object(bytes, scope, hash), Err(FormatError::Corrupt));
}

#[test]
fn validated_frames_keep_raw_payload_borrowed_until_owned_conversion() {
    for payload in [
        Payload::Chunk {
            first_page: 33,
            bytes: vec![0xa5; CHUNK_BYTES],
        },
        Payload::Node {
            level: 0,
            first_chunk: 0,
            children: vec![digest(b"unfetched child")],
        },
        Payload::Manifest(Manifest {
            page_count: 1,
            root: Some(digest(b"unfetched node")),
        }),
        Payload::Manifest(Manifest {
            page_count: 0,
            root: None,
        }),
        result(vec![0, 255, 128, 1]),
        result(Vec::new()),
        Payload::Index(RequestIndex::Leaf {
            epoch: 1,
            entries: Vec::new(),
        }),
    ] {
        let original = envelope(payload);
        let bytes = encode_object(&original).unwrap();
        let hash = digest(&bytes);
        let parsed = ValidatedFrame::parse(&bytes, &scope(), &hash).unwrap();
        assert_eq!(parsed.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(parsed.as_bytes(), bytes);
        match &parsed.envelope.payload {
            Payload::Chunk { bytes, .. } | Payload::Result(StoredResult { bytes, .. }) => {
                assert!(bytes.is_empty());
            }
            payload => assert_eq!(payload, &original.payload),
        }
        assert_eq!(parsed.into_envelope(), original);
        assert_eq!(decode_object(&bytes, &scope(), &hash), Ok(original));
    }
}

#[test]
fn noncanonical_json_preserves_the_original_frame_and_content_hash() {
    for (payload, raw, kind, escaped_kind) in [
        (
            Payload::Chunk {
                first_page: 1,
                bytes: Vec::new(),
            },
            vec![0x5a; PAGE_SIZE],
            "chunk",
            r"ch\u0075nk",
        ),
        (
            result(Vec::new()),
            vec![0, 255, 1, 128],
            "result",
            r"res\u0075lt",
        ),
    ] {
        // Value reorders object fields; whitespace and a valid JSON escape
        // create another valid representation of exactly the same metadata.
        let value = serde_json::to_value(metadata(payload)).unwrap();
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        let changed = pretty.replace(kind, escaped_kind);
        assert_ne!(pretty, changed);
        let noncanonical = frame(format!("\n{changed}\t ").as_bytes(), &raw);
        let hash = digest(&noncanonical);
        let parsed = ValidatedFrame::parse(&noncanonical, &scope(), &hash).unwrap();
        assert_eq!(parsed.as_bytes().as_ptr(), noncanonical.as_ptr());
        assert_eq!(parsed.as_bytes(), noncanonical);
        assert_eq!(digest(parsed.as_bytes()), hash);
        let original = parsed.into_envelope();
        let canonical = encode_object(&original).unwrap();
        assert_ne!(canonical, noncanonical);
        assert_ne!(digest(&canonical), hash);
        assert_eq!(
            decode_object(&noncanonical, &scope(), &hash),
            Ok(original.clone())
        );
        assert_eq!(
            decode_object(&canonical, &scope(), &digest(&canonical)),
            Ok(original)
        );
        reject(&noncanonical, &scope(), &digest(&canonical));
    }
}

#[test]
fn conversion_keeps_the_existing_owned_lifetime_and_raw_bytes() {
    let expected = envelope(result(vec![0, 255, 128, 1]));
    let converted = {
        let input = encode_object(&expected).unwrap();
        ValidatedFrame::parse(&input, &scope(), &digest(&input))
            .unwrap()
            .into_envelope()
    };
    assert_eq!(converted, expected);
    let public = {
        let input = encode_object(&expected).unwrap();
        decode_object(&input, &scope(), &digest(&input)).unwrap()
    };
    assert_eq!(public, expected);
}

#[test]
fn embedded_bytes_must_be_empty_and_payload_types_cannot_hide_raw_data() {
    for (payload, raw) in [
        (
            Payload::Chunk {
                first_page: 1,
                bytes: Vec::new(),
            },
            vec![1; PAGE_SIZE],
        ),
        (result(Vec::new()), vec![1, 2, 3]),
    ] {
        let original = serde_json::to_value(metadata(payload)).unwrap();
        for bytes in [serde_json::json!([7]), serde_json::Value::Null] {
            let mut value = original.clone();
            value["payload"]["value"]["bytes"] = bytes;
            let wire = frame(&serde_json::to_vec(&value).unwrap(), &raw);
            reject(&wire, &scope(), &digest(&wire));
        }
        let mut missing = original.clone();
        missing["payload"]["value"]
            .as_object_mut()
            .unwrap()
            .remove("bytes");
        let wire = frame(&serde_json::to_vec(&missing).unwrap(), &raw);
        reject(&wire, &scope(), &digest(&wire));
        let mut wrong_type = original;
        wrong_type["payload"]["kind"] = serde_json::json!("manifest");
        let wire = frame(&serde_json::to_vec(&wrong_type).unwrap(), &raw);
        reject(&wire, &scope(), &digest(&wire));
    }
    for payload in [
        Payload::Node {
            level: 0,
            first_chunk: 0,
            children: vec![digest(b"child")],
        },
        Payload::Manifest(Manifest {
            page_count: 0,
            root: None,
        }),
        Payload::Index(RequestIndex::Leaf {
            epoch: 1,
            entries: Vec::new(),
        }),
    ] {
        let wire = frame(&serde_json::to_vec(&metadata(payload)).unwrap(), b"extra");
        reject(&wire, &scope(), &digest(&wire));
    }
}

#[test]
fn the_complete_logical_scope_is_checked_without_materializing_the_payload() {
    let input = encode_object(&envelope(Payload::Chunk {
        first_page: 1,
        bytes: vec![0x5a; CHUNK_BYTES],
    }))
    .unwrap();
    let hash = digest(&input);
    for field in [
        "deployment",
        "tenant",
        "database",
        "incarnation",
        "generation",
    ] {
        let mut value = serde_json::to_value(scope()).unwrap();
        value[field] = serde_json::json!(99);
        let foreign: Scope = serde_json::from_value(value).unwrap();
        reject(&input, &foreign, &hash);
        let mut invalid = serde_json::to_value(metadata(result(Vec::new()))).unwrap();
        invalid["scope"][field] = serde_json::json!(0);
        let expected = serde_json::from_value(invalid["scope"].clone()).unwrap();
        let wire = frame(&serde_json::to_vec(&invalid).unwrap(), b"raw");
        reject(&wire, &expected, &digest(&wire));
    }
}

#[test]
fn borrowed_semantic_validation_uses_external_raw_length_and_existing_rules() {
    let chunk = metadata(Payload::Chunk {
        first_page: 1,
        bytes: Vec::new(),
    });
    for length in [0, PAGE_SIZE - 1, CHUNK_BYTES + PAGE_SIZE] {
        let wire = frame(&serde_json::to_vec(&chunk).unwrap(), &vec![0; length]);
        reject(&wire, &scope(), &digest(&wire));
    }
    let tail = metadata(Payload::Chunk {
        first_page: (MAX_PAGES - 1) / CHUNK_PAGES * CHUNK_PAGES + 1,
        bytes: Vec::new(),
    });
    let wire = frame(
        &serde_json::to_vec(&tail).unwrap(),
        &vec![0; 31 * PAGE_SIZE],
    );
    reject(&wire, &scope(), &digest(&wire));
    let Payload::Result(mut invalid_result) = result(Vec::new()) else {
        panic!()
    };
    invalid_result.request.id = 0;
    for (payload, raw) in [
        (
            Payload::Node {
                level: 0,
                first_chunk: 0,
                children: vec!["invalid hash".into()],
            },
            &[][..],
        ),
        (
            Payload::Manifest(Manifest {
                page_count: 1,
                root: None,
            }),
            &[][..],
        ),
        (Payload::Result(invalid_result), b"raw"),
        (
            Payload::Index(RequestIndex::Leaf {
                epoch: 0,
                entries: Vec::new(),
            }),
            &[][..],
        ),
    ] {
        let wire = frame(&serde_json::to_vec(&metadata(payload)).unwrap(), raw);
        reject(&wire, &scope(), &digest(&wire));
    }
}
