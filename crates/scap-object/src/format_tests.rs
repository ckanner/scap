use super::*;

fn scope() -> Scope {
    Scope {
        deployment: 1,
        tenant: 2,
        database: 3,
        incarnation: 4,
        generation: 5,
    }
}

fn request() -> Request {
    Request {
        epoch: 1,
        id: 2,
        principal: 3,
        fingerprint: digest(b"sql with typed parameters"),
    }
}

fn transition() -> Transition {
    Transition {
        revision: 1,
        nonce: 2,
    }
}

fn head() -> Head {
    Head {
        format: 1,
        scope: scope(),
        revision: 1,
        transition: transition(),
        sequence: 0,
        owner_epoch: 1,
        owner_instance: 1,
        active: false,
        auth_epoch: 1,
        policy: vec![Permission {
            principal: 1,
            read: true,
            write: true,
            admin: true,
        }],
        lifecycle: Lifecycle::Ready,
        data_root: digest(b"data"),
        request_epoch: 1,
        windows: vec![Window {
            epoch: 1,
            root: digest(b"requests"),
            count: 0,
        }],
    }
}

fn envelope(payload: Payload) -> Envelope {
    Envelope {
        format: 1,
        scope: scope(),
        payload,
    }
}

fn manifest() -> Manifest {
    Manifest {
        pages: vec![digest(b"page")],
        image_hash: digest(b"image"),
    }
}

fn result() -> StoredResult {
    StoredResult {
        request: request(),
        sequence: 1,
        transition: transition(),
        data_root: digest(b"data"),
        bytes: b"bounded original result".to_vec(),
    }
}

fn committed() -> Entry {
    Entry {
        request: request(),
        outcome: OutcomeRef::Committed {
            result: digest(b"original result"),
        },
    }
}

fn cancelled() -> Entry {
    Entry {
        request: Request { id: 4, ..request() },
        outcome: OutcomeRef::Cancelled {
            transition: transition(),
        },
    }
}

fn object_round_trip(object: Envelope) {
    let bytes = encode_object(&object).unwrap();
    assert_eq!(
        decode_object(&bytes, &scope(), &digest(&bytes)),
        Ok(object.clone())
    );
    assert_eq!(encode_object(&object), Ok(bytes));
    assert!(!format!("{object:?}").is_empty());
}

fn reject_head(change: impl FnOnce(&mut Head), error: FormatError) {
    let mut value = head();
    change(&mut value);
    assert_eq!(encode_head(&value), Err(error));
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(decode_head(&bytes, &scope()), Err(FormatError::Corrupt));
}

fn reject_object(object: Envelope, error: FormatError) {
    assert_eq!(encode_object(&object), Err(error));
    let bytes = serde_json::to_vec(&object).unwrap();
    assert_eq!(
        decode_object(&bytes, &scope(), &digest(&bytes)),
        Err(FormatError::Corrupt)
    );
}

#[test]
fn exact_keys_hashes_and_nonzero_scope_are_stable() {
    assert_eq!(
        digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let value = scope();
    assert_eq!(value.validate(), Ok(()));
    assert_eq!(head_key(&value), "scap-object/v1/1/2/3/head");
    let hash = digest(b"object");
    assert_eq!(
        object_key(&value, &hash),
        format!("scap-object/v1/1/2/3/inc/4/gen/5/objects/{hash}")
    );
    let mut replacement = value.clone();
    replacement.incarnation += 1;
    replacement.generation += 1;
    assert_eq!(head_key(&value), head_key(&replacement));
    assert_ne!(object_key(&value, &hash), object_key(&replacement, &hash));
    for field in [
        "deployment",
        "tenant",
        "database",
        "incarnation",
        "generation",
    ] {
        let mut json = serde_json::to_value(&value).unwrap();
        json[field] = 0.into();
        assert_eq!(
            serde_json::from_value::<Scope>(json).unwrap().validate(),
            Err(FormatError::Invalid)
        );
    }
}

#[test]
fn request_identity_and_digest_encoding_are_strict() {
    assert_eq!(request().validate(), Ok(()));
    for field in ["epoch", "id", "principal"] {
        let mut json = serde_json::to_value(request()).unwrap();
        json[field] = 0.into();
        assert_eq!(
            serde_json::from_value::<Request>(json).unwrap().validate(),
            Err(FormatError::Invalid)
        );
    }
    for fingerprint in [
        String::new(),
        "0".repeat(63),
        "f".repeat(65),
        "F".repeat(64),
        "g".repeat(64),
        "é".repeat(32),
    ] {
        assert_eq!(
            Request {
                fingerprint,
                ..request()
            }
            .validate(),
            Err(FormatError::Invalid)
        );
    }
    for fingerprint in [
        "0".repeat(64),
        "9".repeat(64),
        "a".repeat(64),
        "f".repeat(64),
    ] {
        assert_eq!(
            Request {
                fingerprint,
                ..request()
            }
            .validate(),
            Ok(())
        );
    }
}

#[test]
fn all_head_lifecycles_and_three_full_retention_windows_round_trip() {
    for lifecycle in [Lifecycle::Ready, Lifecycle::Maintenance, Lifecycle::Deleted] {
        for current in [1, 2, 3, 4, u64::MAX] {
            let mut value = head();
            value.lifecycle = lifecycle.clone();
            value.request_epoch = current;
            value.windows = (0..current.min(3))
                .map(|offset| Window {
                    epoch: current - offset,
                    root: digest(&offset.to_le_bytes()),
                    count: MAX_REQUESTS as u32,
                })
                .collect();
            value.sequence = u64::MAX;
            value.active = true;
            let bytes = encode_head(&value).unwrap();
            assert_eq!(decode_head(&bytes, &scope()), Ok(value.clone()));
            assert_eq!(encode_head(&value), Ok(bytes));
            assert!(!format!("{value:?}").is_empty());
        }
    }
    let value = head();
    assert_eq!(
        decode_head(&encode_head(&value).unwrap(), &scope()),
        Ok(value)
    );
}

#[test]
fn invalid_head_identity_version_owner_and_roots_are_rejected() {
    reject_head(|v| v.format = 2, FormatError::Invalid);
    reject_head(|v| v.scope.tenant = 0, FormatError::Invalid);
    reject_head(|v| v.revision = 0, FormatError::Invalid);
    reject_head(|v| v.owner_epoch = 0, FormatError::Invalid);
    reject_head(|v| v.owner_instance = 0, FormatError::Invalid);
    reject_head(|v| v.auth_epoch = 0, FormatError::Invalid);
    reject_head(|v| v.request_epoch = 0, FormatError::Invalid);
    reject_head(|v| v.transition.revision = 0, FormatError::Invalid);
    reject_head(|v| v.transition.nonce = 0, FormatError::Invalid);
    reject_head(|v| v.transition.revision = 2, FormatError::Invalid);
    reject_head(|v| v.data_root = "bad".into(), FormatError::Invalid);
}

#[test]
fn policies_require_unique_nonzero_principals_and_a_remaining_admin() {
    reject_head(|v| v.policy.clear(), FormatError::Invalid);
    reject_head(|v| v.policy[0].principal = 0, FormatError::Invalid);
    reject_head(|v| v.policy[0].admin = false, FormatError::Invalid);
    reject_head(|v| v.policy.push(v.policy[0].clone()), FormatError::Invalid);
    reject_head(
        |v| {
            v.policy = (1..=MAX_PRINCIPALS as u64 + 1)
                .map(|principal| Permission {
                    principal,
                    ..v.policy[0].clone()
                })
                .collect()
        },
        FormatError::Limit,
    );
    let mut value = head();
    value.policy = (1..=MAX_PRINCIPALS as u64)
        .rev()
        .map(|principal| Permission {
            principal,
            read: false,
            write: false,
            admin: principal == 1,
        })
        .collect();
    assert!(encode_head(&value).unwrap().len() < MAX_HEAD_BYTES);
}

#[test]
fn retention_windows_cannot_skip_drop_or_close_partial_epochs() {
    reject_head(|v| v.windows.clear(), FormatError::Invalid);
    reject_head(
        |v| v.windows = vec![v.windows[0].clone(); 4],
        FormatError::Limit,
    );
    reject_head(|v| v.windows[0].epoch = 0, FormatError::Invalid);
    reject_head(|v| v.windows[0].epoch = 2, FormatError::Invalid);
    reject_head(|v| v.windows[0].root.clear(), FormatError::Invalid);
    reject_head(
        |v| v.windows[0].count = MAX_REQUESTS as u32 + 1,
        FormatError::Limit,
    );
    reject_head(|v| v.request_epoch = 2, FormatError::Invalid);
    reject_head(
        |v| {
            v.request_epoch = 2;
            v.windows.insert(
                0,
                Window {
                    epoch: 2,
                    ..v.windows[0].clone()
                },
            );
        },
        FormatError::Invalid,
    );
}

#[test]
fn all_object_variants_round_trip_with_original_byte_results() {
    object_round_trip(envelope(Payload::Page(vec![0; PAGE_SIZE])));
    object_round_trip(envelope(Payload::Manifest(manifest())));
    object_round_trip(envelope(Payload::Manifest(Manifest {
        pages: Vec::new(),
        image_hash: digest(&[]),
    })));
    object_round_trip(envelope(Payload::Result(result())));
    object_round_trip(envelope(Payload::Index(Vec::new())));
    object_round_trip(envelope(Payload::Index(vec![committed(), cancelled()])));
}

#[test]
fn object_semantics_reject_invalid_versions_scopes_and_pages() {
    let mut object = envelope(Payload::Page(vec![0; PAGE_SIZE]));
    object.format = 0;
    reject_object(object.clone(), FormatError::Invalid);
    object.format = 1;
    object.scope.generation = 0;
    reject_object(object, FormatError::Invalid);
    for length in [0, PAGE_SIZE - 1, PAGE_SIZE + 1] {
        reject_object(
            envelope(Payload::Page(vec![0; length])),
            FormatError::Invalid,
        );
    }
}

#[test]
fn manifest_count_and_all_hashes_are_validated() {
    reject_object(
        envelope(Payload::Manifest(Manifest {
            pages: vec![digest(b"page"); MAX_PAGES + 1],
            ..manifest()
        })),
        FormatError::Limit,
    );
    reject_object(
        envelope(Payload::Manifest(Manifest {
            image_hash: "bad".into(),
            ..manifest()
        })),
        FormatError::Invalid,
    );
    reject_object(
        envelope(Payload::Manifest(Manifest {
            pages: vec!["bad".into()],
            ..manifest()
        })),
        FormatError::Invalid,
    );
    object_round_trip(envelope(Payload::Manifest(Manifest {
        pages: vec![digest(b"page"); MAX_PAGES],
        ..manifest()
    })));
}

#[test]
fn stored_results_are_bound_to_nonzero_original_identity_and_bounded_bytes() {
    let mut value = result();
    value.request.id = 0;
    reject_object(envelope(Payload::Result(value)), FormatError::Invalid);
    let mut value = result();
    value.sequence = 0;
    reject_object(envelope(Payload::Result(value)), FormatError::Invalid);
    let mut value = result();
    value.transition.nonce = 0;
    reject_object(envelope(Payload::Result(value)), FormatError::Invalid);
    let mut value = result();
    value.data_root = String::new();
    reject_object(envelope(Payload::Result(value)), FormatError::Invalid);
    let mut value = result();
    value.bytes = vec![255; MAX_RESULT_BYTES + 1];
    reject_object(envelope(Payload::Result(value)), FormatError::Limit);
    let mut value = result();
    value.bytes = vec![255; MAX_RESULT_BYTES];
    let object = envelope(Payload::Result(value));
    let wire = encode_object(&object).unwrap();
    assert!(wire.len() > MAX_RESULT_BYTES * 4);
    assert!(wire.len() < MAX_OBJECT_BYTES);
    object_round_trip(object);
}

#[test]
fn index_budget_identity_epoch_and_both_outcome_variants_are_checked() {
    let entries: Vec<_> = (1..=MAX_REQUESTS as u64 + 1)
        .map(|id| Entry {
            request: Request { id, ..request() },
            ..committed()
        })
        .collect();
    reject_object(
        envelope(Payload::Index(entries.clone())),
        FormatError::Limit,
    );
    object_round_trip(envelope(Payload::Index(entries[..MAX_REQUESTS].to_vec())));
    reject_object(
        envelope(Payload::Index(vec![committed(), committed()])),
        FormatError::Invalid,
    );
    let mut entry = committed();
    entry.request.fingerprint.clear();
    reject_object(envelope(Payload::Index(vec![entry])), FormatError::Invalid);
    let mut entry = cancelled();
    entry.request.epoch = 2;
    reject_object(
        envelope(Payload::Index(vec![committed(), entry])),
        FormatError::Invalid,
    );
    let mut entry = committed();
    entry.outcome = OutcomeRef::Committed {
        result: "bad".into(),
    };
    reject_object(envelope(Payload::Index(vec![entry])), FormatError::Invalid);
    let mut entry = cancelled();
    entry.outcome = OutcomeRef::Cancelled {
        transition: Transition {
            nonce: 0,
            ..transition()
        },
    };
    reject_object(envelope(Payload::Index(vec![entry])), FormatError::Invalid);
}

#[test]
fn wire_boundaries_and_byte_hashes_fail_closed() {
    assert_eq!(
        decode_head(&vec![0; MAX_HEAD_BYTES + 1], &scope()),
        Err(FormatError::Limit)
    );
    assert_eq!(
        decode_object(&vec![0; MAX_OBJECT_BYTES + 1], &scope(), "unused"),
        Err(FormatError::Limit)
    );
    assert_eq!(encode(&"abcd", 5), Err(FormatError::Limit));
    assert_eq!(encode(&"abcd", 6), Ok(b"\"abcd\"".to_vec()));
    let bytes = encode_object(&envelope(Payload::Index(Vec::new()))).unwrap();
    assert_eq!(
        decode_object(&bytes, &scope(), "wrong"),
        Err(FormatError::Corrupt)
    );
    let other = Scope {
        incarnation: 6,
        ..scope()
    };
    assert_eq!(
        decode_object(&bytes, &other, &digest(&bytes)),
        Err(FormatError::Corrupt)
    );
    assert_eq!(
        decode_head(&encode_head(&head()).unwrap(), &other),
        Err(FormatError::Corrupt)
    );
    for bytes in [b"{".as_slice(), b"null", b"[]", b"{} trailing"] {
        assert_eq!(decode_head(bytes, &scope()), Err(FormatError::Corrupt));
        assert_eq!(
            decode_object(bytes, &scope(), &digest(bytes)),
            Err(FormatError::Corrupt)
        );
    }
}

#[test]
fn strict_serde_rejects_unknown_duplicate_and_out_of_range_fields() {
    let original = serde_json::to_value(head()).unwrap();
    for (path, value) in [
        ("extra", serde_json::json!(1)),
        ("format", serde_json::json!(1.5)),
        ("owner_instance", serde_json::json!(-1)),
        ("lifecycle", serde_json::json!("surprise")),
    ] {
        let mut json = original.clone();
        json[path] = value;
        assert_eq!(
            decode_head(&serde_json::to_vec(&json).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    for path in ["scope", "transition", "policy/0", "windows/0"] {
        let mut json = original.clone();
        json.pointer_mut(&format!("/{path}")).unwrap()["extra"] = 1.into();
        assert_eq!(
            decode_head(&serde_json::to_vec(&json).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    let wire = String::from_utf8(encode_head(&head()).unwrap()).unwrap();
    let duplicate = wire.replacen("\"format\":1", "\"format\":1,\"format\":1", 1);
    assert_eq!(
        decode_head(duplicate.as_bytes(), &scope()),
        Err(FormatError::Corrupt)
    );
    let overflow = wire.replacen("\"revision\":1", "\"revision\":18446744073709551616", 1);
    assert_eq!(
        decode_head(overflow.as_bytes(), &scope()),
        Err(FormatError::Corrupt)
    );

    let objects = [
        (envelope(Payload::Manifest(manifest())), "/payload/value"),
        (envelope(Payload::Result(result())), "/payload/value"),
        (
            envelope(Payload::Result(result())),
            "/payload/value/request",
        ),
        (
            envelope(Payload::Index(vec![committed()])),
            "/payload/value/0",
        ),
        (
            envelope(Payload::Index(vec![committed()])),
            "/payload/value/0/outcome",
        ),
        (
            envelope(Payload::Index(vec![cancelled()])),
            "/payload/value/0/outcome",
        ),
        (envelope(Payload::Index(Vec::new())), "/payload"),
        (envelope(Payload::Index(Vec::new())), ""),
    ];
    for (object, path) in objects {
        let mut json = serde_json::to_value(object).unwrap();
        json.pointer_mut(path).unwrap()["extra"] = 1.into();
        let bytes = serde_json::to_vec(&json).unwrap();
        assert_eq!(
            decode_object(&bytes, &scope(), &digest(&bytes)),
            Err(FormatError::Corrupt)
        );
    }
}
