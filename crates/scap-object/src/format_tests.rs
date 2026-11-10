use super::*;

fn index(entries: Vec<Entry>) -> Payload {
    Payload::Index(RequestIndex::Leaf { epoch: 1, entries })
}

fn reference(first: u64, count: u32) -> IndexChild {
    IndexChild {
        hash: digest(&first.to_le_bytes()),
        summary: IndexSummary {
            first,
            last: first + (count as u64 - 1),
            count,
            result_bytes: 0,
        },
    }
}

fn index_branch() -> RequestIndex {
    RequestIndex::Branch {
        epoch: 1,
        level: 1,
        children: vec![reference(1, 64), reference(100, 64)],
    }
}

#[test]
fn segmented_node_codec_bounds_ranges_occupancy_and_aggregates() {
    object_round_trip(envelope(Payload::Index(index_branch())));
    for epoch in [0, 2] {
        reject_object(
            envelope(Payload::Index(RequestIndex::Leaf {
                epoch,
                entries: vec![committed()],
            })),
            FormatError::Invalid,
        );
    }
    let mut large = committed();
    large.result_bytes = MAX_RESULT_BYTES as u64 + 1;
    reject_object(envelope(index(vec![large])), FormatError::Invalid);
    let mut cancelled_bytes = cancelled();
    cancelled_bytes.result_bytes = 1;
    reject_object(envelope(index(vec![cancelled_bytes])), FormatError::Invalid);
    reject_object(
        envelope(index(vec![cancelled(), committed()])),
        FormatError::Invalid,
    );
    for level in [0, MAX_REQUEST_INDEX_LEVEL + 1] {
        let RequestIndex::Branch {
            epoch, children, ..
        } = index_branch()
        else {
            panic!()
        };
        reject_object(
            envelope(Payload::Index(RequestIndex::Branch {
                epoch,
                level,
                children,
            })),
            FormatError::Invalid,
        );
    }
    for count in [0, 1, 33] {
        let children = (0..count).map(|i| reference(i * 64 + 1, 64)).collect();
        reject_object(
            envelope(Payload::Index(RequestIndex::Branch {
                epoch: 1,
                level: 1,
                children,
            })),
            if count == 33 {
                FormatError::Limit
            } else {
                FormatError::Invalid
            },
        );
    }
    let mutations: Vec<Mutation<IndexChild>> = vec![
        Box::new(|child| child.hash.clear()),
        Box::new(|child| child.summary.first = 0),
        Box::new(|child| child.summary.last = 0),
        Box::new(|child| child.summary.last = 63),
        Box::new(|child| child.summary.count = 63),
        Box::new(|child| child.summary.count = 129),
        Box::new(|child| child.summary.result_bytes = 64 * MAX_RESULT_BYTES as u64 + 1),
    ];
    for mutate in mutations {
        let RequestIndex::Branch {
            epoch,
            level,
            mut children,
        } = index_branch()
        else {
            panic!()
        };
        mutate(&mut children[0]);
        reject_object(
            envelope(Payload::Index(RequestIndex::Branch {
                epoch,
                level,
                children,
            })),
            FormatError::Invalid,
        );
    }
    let children = vec![reference(1, 64), reference(64, 64)];
    reject_object(
        envelope(Payload::Index(RequestIndex::Branch {
            epoch: 1,
            level: 1,
            children,
        })),
        FormatError::Invalid,
    );
    let children = (0..5).map(|i| reference(i * 16384 + 1, 16384)).collect();
    reject_object(
        envelope(Payload::Index(RequestIndex::Branch {
            epoch: 1,
            level: 3,
            children,
        })),
        FormatError::Limit,
    );
}

#[test]
fn worst_case_index_nodes_fit_the_original_small_metadata_limit() {
    let entries = (0..REQUEST_LEAF_CAPACITY)
        .map(|offset| Entry {
            request: Request {
                epoch: u64::MAX,
                id: u64::MAX - REQUEST_LEAF_CAPACITY as u64 + 1 + offset as u64,
                principal: u64::MAX,
                fingerprint: "f".repeat(64),
            },
            outcome: OutcomeRef::Committed {
                result: "f".repeat(64),
            },
            result_bytes: MAX_RESULT_BYTES as u64,
        })
        .collect();
    let scope = Scope {
        deployment: u64::MAX,
        tenant: u64::MAX,
        database: u64::MAX,
        incarnation: u64::MAX,
        generation: u64::MAX,
    };
    let leaf = Envelope {
        format: 2,
        scope: scope.clone(),
        payload: Payload::Index(RequestIndex::Leaf {
            epoch: u64::MAX,
            entries,
        }),
    };
    let leaf_bytes = encode_object(&leaf).unwrap();
    assert!(leaf_bytes.len() < 43 * 1024);
    assert_eq!(
        decode_object(&leaf_bytes, &scope, &digest(&leaf_bytes)),
        Ok(leaf)
    );
    let children = (0..REQUEST_BRANCH_CAPACITY)
        .map(|offset| {
            let mut child = reference(u64::MAX - 4096 + 1 + offset as u64 * 128, 128);
            child.summary.result_bytes = 128 * MAX_RESULT_BYTES as u64;
            child
        })
        .collect();
    let branch = Envelope {
        format: 2,
        scope: scope.clone(),
        payload: Payload::Index(RequestIndex::Branch {
            epoch: u64::MAX,
            level: 1,
            children,
        }),
    };
    let bytes = encode_object(&branch).unwrap();
    assert!(bytes.len() < 8 * 1024);
    assert_eq!(decode_object(&bytes, &scope, &digest(&bytes)), Ok(branch));
}

#[test]
fn discovery_decodes_only_the_actual_slot_and_legacy_head_is_rejected() {
    let mut value = head();
    value.scope.incarnation += 1;
    value.scope.generation += 1;
    let bytes = encode_head(&value).unwrap();
    let slot = DatabaseSlot {
        deployment: value.scope.deployment,
        tenant: value.scope.tenant,
        database: value.scope.database,
    };
    assert_eq!(decode_head_at_slot(&bytes, &slot), Ok(value.clone()));
    assert_eq!(decode_head(&bytes, &scope()), Err(FormatError::Corrupt));
    value.format = 3;
    assert_eq!(encode_head(&value), Err(FormatError::Invalid));
    assert_eq!(
        decode_head_at_slot(&serde_json::to_vec(&value).unwrap(), &slot),
        Err(FormatError::Corrupt)
    );
}

type Mutation<T> = Box<dyn Fn(&mut T)>;

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
        format: 6,
        scope: scope(),
        head_serial: 1,
        storage: Storage {
            active_generation: 1,
            allocated_through: 1,
            plan: None,
            sweep: None,
            terminal: None,
        },
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
        creation: None,
        deletion: None,
        data_root: digest(b"data"),
        quota: DatabaseQuota {
            max_bytes: Some(10 * 1024 * 1024 * 1024),
        },
        retention: Retention {
            max_entries: 128,
            max_result_bytes: 256 * 1024 * 1024,
        },
        request_epoch: 1,
        windows: vec![Window {
            epoch: 1,
            root: digest(b"requests"),
            count: 0,
            result_bytes: 0,
        }],
    }
}

#[test]
fn terminal_wire_versions_preserve_field_presence_and_reject_cross_version_aliases() {
    let live = head();
    let live_json = serde_json::to_value(&live).unwrap();
    assert!(live_json["storage"].get("terminal").is_none());
    let mut terminal = live.clone();
    terminal.format = 7;
    terminal.lifecycle = Lifecycle::Deleted;
    terminal.head_serial = 2;
    terminal.storage.terminal = Some(TerminalSeal { serial: 2 });
    let bytes = encode_head(&terminal).unwrap();
    assert_eq!(decode_head(&bytes, &scope()).unwrap(), terminal);
    assert!(terminal.storage.retired(1));
    assert!(!terminal.storage.retired(0));
    assert!(!terminal.storage.retired(2));
    let terminal_json = serde_json::to_value(&terminal).unwrap();
    for value in [serde_json::Value::Null, serde_json::json!({"serial": 2})] {
        let mut invalid = live_json.clone();
        invalid["storage"]["terminal"] = value;
        assert_eq!(
            decode_head(&serde_json::to_vec(&invalid).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    for value in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!({"serial": 2, "extra": 1}),
        serde_json::json!({"serial": "2"}),
    ] {
        let mut invalid = terminal_json.clone();
        invalid["storage"]["terminal"] = value;
        assert_eq!(
            decode_head(&serde_json::to_vec(&invalid).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    let mut missing = terminal_json.clone();
    missing["storage"]
        .as_object_mut()
        .unwrap()
        .remove("terminal");
    assert_eq!(
        decode_head(&serde_json::to_vec(&missing).unwrap(), &scope()),
        Err(FormatError::Corrupt)
    );
    let wire = String::from_utf8(bytes).unwrap();
    for duplicate in [
        wire.replace(
            "\"terminal\":{\"serial\":2}",
            "\"terminal\":{\"serial\":2},\"terminal\":{\"serial\":2}",
        ),
        wire.replace(
            "\"terminal\":{\"serial\":2}",
            "\"terminal\":{\"serial\":2,\"serial\":2}",
        ),
    ] {
        assert_ne!(duplicate, wire);
        assert_eq!(
            decode_head(duplicate.as_bytes(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    for change in 0..8 {
        let mut invalid = terminal.clone();
        match change {
            0 => invalid.active = true,
            1 => invalid.lifecycle = Lifecycle::Ready,
            2 => invalid.storage.terminal.as_mut().unwrap().serial = 0,
            3 => invalid.storage.terminal.as_mut().unwrap().serial = 1,
            4 => invalid.storage.terminal.as_mut().unwrap().serial = 3,
            5 => invalid.format = 6,
            6 => {
                invalid.storage.plan = Some(CopyPlan {
                    serial: 1,
                    source: 1,
                    target: 2,
                    phase: CopyPhase::Copying,
                    basis: CopyBasis::capture(&terminal),
                })
            }
            _ => {
                // M < seal <= HEAD still holds; only R < seal is violated.
                invalid.revision = 2;
                invalid.transition.revision = 2;
            }
        }
        assert_eq!(encode_head(&invalid), Err(FormatError::Invalid));
        assert_eq!(
            decode_head(&serde_json::to_vec(&invalid).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    terminal.head_serial = 3;
    terminal.storage.sweep = Some(SweepCheckpoint {
        serial: 3,
        generation: 1,
        next_after: None,
        exhausted: true,
        entries: vec![SweepEntry {
            key: object_key(&scope(), 1, &terminal.data_root),
            hash: terminal.data_root.clone(),
            etag: "\"original\"".into(),
            disposition: SweepDisposition::Pending,
        }],
    });
    assert_eq!(
        decode_head(&encode_head(&terminal).unwrap(), &scope()).unwrap(),
        terminal
    );
    for serial in [1, 2, 4] {
        let mut invalid = terminal.clone();
        invalid.storage.sweep.as_mut().unwrap().serial = serial;
        assert_eq!(encode_head(&invalid), Err(FormatError::Invalid));
    }
}

fn named_head(lifecycle: Lifecycle) -> Head {
    let mut head = head();
    head.lifecycle = lifecycle;
    head.creation = Some(NamedCreation {
        creator: 1,
        operation: 2,
        name_hash: digest(b"named database"),
        descriptor_hash: digest(b"fixed create descriptor"),
    });
    head
}

fn named_deleted(kind: NamedDeletionKind) -> Head {
    let mut head = named_head(Lifecycle::Deleted);
    let expected_head_revision = if kind == NamedDeletionKind::Delete {
        head.revision = 2;
        head.head_serial = 2;
        head.transition.revision = 2;
        Some(1)
    } else {
        None
    };
    head.deletion = Some(NamedDeletion {
        kind,
        principal: 1,
        operation: 3,
        expected_name_revision: 1,
        expected_head_revision,
        nonce: head.transition.nonce,
        descriptor_hash: digest(b"fixed control descriptor"),
    });
    head
}

#[test]
fn head_v5_mandatory_nullable_origins_do_not_change_immutable_v2_frames() {
    for candidate in [
        head(),
        named_head(Lifecycle::Provisioning),
        named_head(Lifecycle::Ready),
        named_head(Lifecycle::Maintenance),
        named_deleted(NamedDeletionKind::Abort),
        named_deleted(NamedDeletionKind::Delete),
    ] {
        let encoded = encode_head(&candidate).unwrap();
        assert_eq!(decode_head(&encoded, &scope()).unwrap(), candidate);
        for field in ["creation", "deletion"] {
            let mut value = serde_json::to_value(&candidate).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert_eq!(
                decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
                Err(FormatError::Corrupt)
            );
        }
    }
    let mut old = head();
    old.format = 2;
    assert_eq!(
        decode_head(&serde_json::to_vec(&old).unwrap(), &scope()),
        Err(FormatError::Corrupt)
    );
    let object = envelope(index(Vec::new()));
    let bytes = encode_object(&object).unwrap();
    assert_eq!(&bytes[..8], b"SCAPOBJ2");
    assert_eq!(
        decode_object(&bytes, &scope(), &digest(&bytes))
            .unwrap()
            .format,
        2
    );
}

#[test]
fn head5_requires_serial_and_exact_foundation_storage_without_future_states() {
    let original = serde_json::to_value(head()).unwrap();
    for field in ["head_serial", "storage"] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            decode_head(&serde_json::to_vec(&missing).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
        let mut null = original.clone();
        null[field] = serde_json::Value::Null;
        assert_eq!(
            decode_head(&serde_json::to_vec(&null).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    for field in ["active_generation", "allocated_through"] {
        let mut missing = original.clone();
        missing["storage"].as_object_mut().unwrap().remove(field);
        assert_eq!(
            decode_head(&serde_json::to_vec(&missing).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
        for bad in [
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!("1"),
            serde_json::json!(0),
            serde_json::json!(2),
            serde_json::json!(u64::MAX),
        ] {
            let mut value = original.clone();
            value["storage"][field] = bad;
            assert_eq!(
                decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
                Err(FormatError::Corrupt)
            );
        }
    }
    for field in ["pins", "staging", "freeze", "future"] {
        for nested in [false, true] {
            let mut value = original.clone();
            let target = if nested {
                &mut value["storage"]
            } else {
                &mut value
            };
            target[field] = serde_json::Value::Null;
            assert_eq!(
                decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
                Err(FormatError::Corrupt)
            );
        }
    }
    for old in [1, 2, 3, 4, 5] {
        let mut value = original.clone();
        value["format"] = old.into();
        assert_eq!(
            decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    for bad in [
        serde_json::json!(null),
        serde_json::json!(false),
        serde_json::json!("1"),
        serde_json::json!(-1),
        serde_json::json!(1.0),
        serde_json::json!(0),
    ] {
        let mut value = original.clone();
        value["head_serial"] = bad;
        assert_eq!(
            decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    let wire = serde_json::to_string(&original).unwrap();
    for changed in [
        wire.replace("\"head_serial\":1", "\"head_serial\":18446744073709551616"),
        wire.replace("\"head_serial\":1", "\"head_serial\":1,\"head_serial\":1"),
        wire.replace(
            "\"active_generation\":1",
            "\"active_generation\":1,\"active_generation\":1",
        ),
    ] {
        assert_eq!(
            decode_head(changed.as_bytes(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    reject_head(|value| value.head_serial = 0, FormatError::Invalid);
    reject_head(
        |value| value.storage.active_generation = 2,
        FormatError::Invalid,
    );
    reject_head(
        |value| value.storage.allocated_through = 2,
        FormatError::Invalid,
    );
    reject_head(
        |value| {
            value.revision = 2;
            value.transition.revision = 2;
        },
        FormatError::Invalid,
    );
    for mut value in [
        head(),
        named_deleted(NamedDeletionKind::Abort),
        named_deleted(NamedDeletionKind::Delete),
    ] {
        value.head_serial = u64::MAX;
        assert_eq!(
            decode_head(&encode_head(&value).unwrap(), &scope()).unwrap(),
            value
        );
    }
}

#[test]
fn largest_foundation_head_keeps_the_existing_head_and_acl_bounds() {
    let mut value = named_deleted(NamedDeletionKind::Delete);
    value.scope = Scope {
        deployment: u64::MAX,
        tenant: u64::MAX,
        database: u64::MAX,
        incarnation: u64::MAX,
        generation: u64::MAX,
    };
    value.head_serial = u64::MAX;
    value.revision = u64::MAX;
    value.transition = Transition {
        revision: u64::MAX,
        nonce: u64::MAX,
    };
    value.sequence = u64::MAX;
    value.owner_epoch = u64::MAX;
    value.owner_instance = u64::MAX;
    value.auth_epoch = u64::MAX;
    value.request_epoch = u64::MAX;
    value.policy = (0..MAX_PRINCIPALS as u64)
        .map(|offset| Permission {
            principal: u64::MAX - offset,
            read: false,
            write: false,
            admin: offset == 0,
        })
        .collect();
    value.creation = Some(NamedCreation {
        creator: u64::MAX,
        operation: u64::MAX,
        name_hash: "f".repeat(64),
        descriptor_hash: "f".repeat(64),
    });
    value.deletion = Some(NamedDeletion {
        kind: NamedDeletionKind::Delete,
        principal: u64::MAX,
        operation: u64::MAX,
        expected_name_revision: u64::MAX,
        expected_head_revision: Some(u64::MAX - 1),
        nonce: u64::MAX,
        descriptor_hash: "f".repeat(64),
    });
    value.quota.max_bytes = Some(u64::from(MAX_PAGES) * PAGE_SIZE as u64);
    value.retention = Retention {
        max_entries: MAX_REQUESTS,
        max_result_bytes: u64::MAX,
    };
    value.windows = (0..3)
        .map(|offset| Window {
            epoch: u64::MAX - offset,
            root: "f".repeat(64),
            count: MAX_REQUESTS,
            result_bytes: u64::from(MAX_REQUESTS) * MAX_RESULT_BYTES as u64,
        })
        .collect();
    let bytes = encode_head(&value).unwrap();
    // Independently derived canonical serialized size; this is a format-valid
    // maximum-width witness, not a claimed reachable workload history.
    assert_eq!(bytes.len(), 79_646);
    assert_eq!(MAX_HEAD_BYTES - bytes.len(), 182_498);
    assert_eq!(decode_head(&bytes, &value.scope).unwrap(), value);
    assert_eq!(head_key(&value.scope).len(), 82);
    assert_eq!(object_key(&value.scope, 1, &"f".repeat(64)).len(), 210);
}

#[test]
fn physical_head_slots_require_prefix_identity_but_allow_distinct_immutable_origins() {
    let mut foreign = head();
    foreign.scope.incarnation += 1;
    let encoded = encode_head(&foreign).unwrap();
    assert_eq!(decode_head(&encoded, &scope()), Err(FormatError::Corrupt));
    assert_eq!(decode_head_slot(&encoded, &scope()).unwrap(), foreign);
    foreign.scope.generation += 1;
    assert_eq!(
        decode_head_slot(&encode_head(&foreign).unwrap(), &scope()).unwrap(),
        foreign
    );
    for change in [0, 1, 2] {
        let mut bad = foreign.clone();
        match change {
            0 => bad.scope.deployment += 1,
            1 => bad.scope.tenant += 1,
            _ => bad.scope.database += 1,
        }
        assert_eq!(
            decode_head_slot(&encode_head(&bad).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
}

#[test]
fn named_head_and_deletion_proofs_are_strictly_validated() {
    let mutations: Vec<Mutation<Head>> = vec![
        Box::new(|h| h.creation.as_mut().unwrap().creator = 0),
        Box::new(|h| h.creation.as_mut().unwrap().operation = 0),
        Box::new(|h| h.creation.as_mut().unwrap().name_hash = "bad".into()),
        Box::new(|h| h.creation.as_mut().unwrap().descriptor_hash = "bad".into()),
        Box::new(|h| h.creation = None),
        Box::new(|h| h.active = true),
        Box::new(|h| h.sequence = 1),
        Box::new(|h| h.request_epoch = 2),
        Box::new(|h| h.windows[0].count = 1),
        Box::new(|h| h.windows[0].result_bytes = 1),
    ];
    for mutate in mutations {
        let mut invalid = named_head(Lifecycle::Provisioning);
        mutate(&mut invalid);
        assert!(invalid.validate_named().is_err());
        assert!(invalid.validate().is_err());
        assert_eq!(
            decode_head(&serde_json::to_vec(&invalid).unwrap(), &invalid.scope),
            Err(FormatError::Corrupt)
        );
    }
    let mutations: Vec<Mutation<Head>> = vec![
        Box::new(|h| h.deletion.as_mut().unwrap().principal = 0),
        Box::new(|h| h.deletion.as_mut().unwrap().operation = 0),
        Box::new(|h| h.deletion.as_mut().unwrap().expected_name_revision = 0),
        Box::new(|h| h.deletion.as_mut().unwrap().nonce = 0),
        Box::new(|h| h.deletion.as_mut().unwrap().descriptor_hash = "bad".into()),
        Box::new(|h| h.deletion.as_mut().unwrap().expected_head_revision = Some(1)),
        Box::new(|h| h.active = true),
        Box::new(|h| h.transition.nonce += 1),
        Box::new(|h| h.policy[0].principal = 2),
        Box::new(|h| h.policy[0].admin = false),
        Box::new(|h| h.creation.as_mut().unwrap().creator += 1),
        Box::new(|h| h.revision = 3),
        Box::new(|h| h.sequence = 1),
        Box::new(|h| h.request_epoch = 2),
        Box::new(|h| h.windows[0].count = 1),
        Box::new(|h| h.windows[0].result_bytes = 1),
        Box::new(|h| h.deletion = None),
        Box::new(|h| h.creation = None),
        Box::new(|h| h.lifecycle = Lifecycle::Ready),
    ];
    for mutate in mutations {
        let mut invalid = named_deleted(NamedDeletionKind::Abort);
        mutate(&mut invalid);
        assert!(invalid.validate_named().is_err());
    }
    for expected in [None, Some(0), Some(2), Some(u64::MAX)] {
        let mut invalid = named_deleted(NamedDeletionKind::Delete);
        invalid.deletion.as_mut().unwrap().expected_head_revision = expected;
        assert!(invalid.validate_named().is_err());
    }
    let mut valid = named_deleted(NamedDeletionKind::Delete);
    valid.deletion.as_mut().unwrap().principal = 2;
    valid.policy.push(Permission {
        principal: 2,
        read: false,
        write: false,
        admin: true,
    });
    assert!(valid.validate().is_ok());
    let wire = serde_json::to_value(&valid).unwrap();
    for path in ["/creation", "/deletion"] {
        let mut value = wire.clone();
        value.pointer_mut(path).unwrap()["extra"] = 1.into();
        assert_eq!(
            decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    let mut value = wire;
    value["deletion"]
        .as_object_mut()
        .unwrap()
        .remove("expected_head_revision");
    assert_eq!(
        decode_head(&serde_json::to_vec(&value).unwrap(), &scope()),
        Err(FormatError::Corrupt)
    );
}

fn envelope(payload: Payload) -> Envelope {
    Envelope {
        format: 2,
        scope: scope(),
        payload,
    }
}

fn manifest() -> Manifest {
    Manifest {
        page_count: 1,
        root: Some(digest(b"root node")),
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
        result_bytes: 0,
        request: request(),
        outcome: OutcomeRef::Committed {
            result: digest(b"original result"),
        },
    }
}

fn cancelled() -> Entry {
    Entry {
        result_bytes: 0,
        request: Request { id: 4, ..request() },
        outcome: OutcomeRef::Cancelled {
            transition: transition(),
        },
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

// Deliberately bypass semantic validation, so decode rejection tests reach the
// v2 metadata/semantic checks instead of merely failing the frame magic.
fn unchecked(object: &Envelope) -> Vec<u8> {
    let (payload, raw) = match &object.payload {
        Payload::Chunk { first_page, bytes } => (
            Payload::Chunk {
                first_page: *first_page,
                bytes: Vec::new(),
            },
            bytes.as_slice(),
        ),
        Payload::Result(value) => (
            Payload::Result(StoredResult {
                request: value.request.clone(),
                sequence: value.sequence,
                transition: value.transition.clone(),
                data_root: value.data_root.clone(),
                bytes: Vec::new(),
            }),
            value.bytes.as_slice(),
        ),
        payload => (payload.clone(), &[][..]),
    };
    frame(
        &serde_json::to_vec(&Envelope {
            format: object.format,
            scope: object.scope.clone(),
            payload,
        })
        .unwrap(),
        raw,
    )
}

fn object_round_trip(object: Envelope) {
    let bytes = encode_object(&object).unwrap();
    assert_eq!(
        decode_object(&bytes, &scope(), &digest(&bytes)),
        Ok(object.clone())
    );
    assert_eq!(encode_object(&object), Ok(bytes));
}

fn reject_head(change: impl FnOnce(&mut Head), error: FormatError) {
    let mut value = head();
    change(&mut value);
    assert_eq!(encode_head(&value), Err(error));
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(decode_head(&bytes, &scope()), Err(FormatError::Corrupt));
}

fn reject_wire(bytes: &[u8]) {
    assert_eq!(
        decode_object(bytes, &scope(), &digest(bytes)),
        Err(FormatError::Corrupt)
    );
}

fn reject_object(object: Envelope, error: FormatError) {
    assert_eq!(encode_object(&object), Err(error));
    reject_wire(&unchecked(&object));
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
        object_key(&value, 1, &hash),
        format!("scap-object/v1/1/2/3/inc/4/gen/5/storage/1/objects/{hash}")
    );
    let mut replacement = value.clone();
    replacement.incarnation += 1;
    replacement.generation += 1;
    assert_eq!(head_key(&value), head_key(&replacement));
    assert_ne!(
        object_key(&value, 1, &hash),
        object_key(&replacement, 1, &hash)
    );
    assert_ne!(object_key(&value, 1, &hash), object_key(&value, 2, &hash));
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
fn quota_is_durable_explicit_and_separate_from_native_geometry() {
    assert_eq!(head().quota.max_pages(), Ok(2_621_440));
    assert_eq!(DatabaseQuota { max_bytes: None }.max_pages(), Ok(MAX_PAGES));
    for bytes in [
        0,
        1,
        PAGE_SIZE as u64 + 1,
        (MAX_PAGES as u64 + 1) * PAGE_SIZE as u64,
        u64::MAX,
    ] {
        let quota = DatabaseQuota {
            max_bytes: Some(bytes),
        };
        assert_eq!(quota.validate(), Err(FormatError::Invalid));
        assert_eq!(quota.max_pages(), Err(FormatError::Invalid));
        reject_head(|h| h.quota = quota, FormatError::Invalid);
    }
    assert_eq!(
        DatabaseQuota {
            max_bytes: Some(MAX_PAGES as u64 * PAGE_SIZE as u64)
        }
        .max_pages(),
        Ok(MAX_PAGES)
    );
    let mut value = head();
    value.quota.max_bytes = None;
    assert_eq!(
        decode_head(&encode_head(&value).unwrap(), &scope()),
        Ok(value)
    );
    for json in ["{}", "{\"max_bytes\":null,\"extra\":1}"] {
        assert!(serde_json::from_str::<DatabaseQuota>(json).is_err());
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
                    count: value.retention.max_entries,
                    result_bytes: 0,
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
    reject_head(|v| v.format = 1, FormatError::Invalid);
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
fn retention_validates_count_bytes_and_the_exact_full_boundary() {
    for entries in [0, MAX_REQUESTS + 1] {
        reject_head(|v| v.retention.max_entries = entries, FormatError::Invalid);
    }
    reject_head(
        |v| v.retention.max_result_bytes = MAX_RESULT_BYTES as u64 - 1,
        FormatError::Invalid,
    );
    assert_eq!(
        Retention {
            max_entries: MAX_REQUESTS,
            max_result_bytes: u64::MAX
        }
        .validate(),
        Ok(())
    );
    let mut value = head();
    value.retention.max_entries = 8;
    value.retention.max_result_bytes = 2 * MAX_RESULT_BYTES as u64;
    value.windows[0].count = 1;
    value.windows[0].result_bytes = MAX_RESULT_BYTES as u64;
    assert!(!value.windows[0].full(&value.retention));
    value.windows[0].count = 2;
    value.windows[0].result_bytes += 1;
    assert!(value.windows[0].full(&value.retention));
    value.request_epoch = 2;
    value.windows.insert(
        0,
        Window {
            epoch: 2,
            root: digest(b"new"),
            count: 0,
            result_bytes: 0,
        },
    );
    assert_eq!(
        decode_head(&encode_head(&value).unwrap(), &scope()),
        Ok(value)
    );
    reject_head(|v| v.windows[0].result_bytes = 1, FormatError::Invalid);
    reject_head(
        |v| {
            v.windows[0].count = 1;
            v.windows[0].result_bytes = MAX_RESULT_BYTES as u64 + 1;
        },
        FormatError::Invalid,
    );
    reject_head(
        |v| {
            v.windows[0].count = 5;
            v.windows[0].result_bytes = v.retention.max_result_bytes + 1;
        },
        FormatError::Invalid,
    );
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
        |v| v.windows[0].count = v.retention.max_entries + 1,
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
fn all_object_variants_round_trip_without_json_byte_expansion() {
    object_round_trip(envelope(Payload::Chunk {
        first_page: 1,
        bytes: vec![0; PAGE_SIZE],
    }));
    object_round_trip(envelope(Payload::Chunk {
        first_page: 33,
        bytes: vec![255; CHUNK_BYTES],
    }));
    object_round_trip(envelope(Payload::Node {
        level: MAX_TREE_LEVEL,
        first_chunk: 0,
        children: vec![digest(b"child"); TREE_FANOUT],
    }));
    object_round_trip(envelope(Payload::Manifest(manifest())));
    object_round_trip(envelope(Payload::Manifest(Manifest {
        page_count: 0,
        root: None,
    })));
    object_round_trip(envelope(Payload::Result(result())));
    object_round_trip(envelope(index(Vec::new())));
    object_round_trip(envelope(index(vec![committed(), cancelled()])));
    assert!(!format!("{:?}", envelope(Payload::Manifest(manifest()))).is_empty());
}

#[test]
fn object_versions_scopes_chunk_geometry_and_node_budgets_are_checked() {
    let mut object = envelope(Payload::Chunk {
        first_page: 1,
        bytes: vec![0; PAGE_SIZE],
    });
    object.format = 1;
    reject_object(object.clone(), FormatError::Invalid);
    object.format = 2;
    object.scope.generation = 0;
    reject_object(object, FormatError::Invalid);
    for first_page in [0, 2, MAX_PAGES] {
        reject_object(
            envelope(Payload::Chunk {
                first_page,
                bytes: vec![0; PAGE_SIZE],
            }),
            FormatError::Invalid,
        );
    }
    for length in [0, PAGE_SIZE - 1, PAGE_SIZE + 1] {
        reject_object(
            envelope(Payload::Chunk {
                first_page: 1,
                bytes: vec![0; length],
            }),
            FormatError::Invalid,
        );
    }
    reject_object(
        envelope(Payload::Chunk {
            first_page: 1,
            bytes: vec![0; CHUNK_BYTES + PAGE_SIZE],
        }),
        FormatError::Limit,
    );
    let first_page = (MAX_PAGES - 1) / CHUNK_PAGES * CHUNK_PAGES + 1;
    object_round_trip(envelope(Payload::Chunk {
        first_page,
        bytes: vec![0; 30 * PAGE_SIZE],
    }));
    reject_object(
        envelope(Payload::Chunk {
            first_page,
            bytes: vec![0; 31 * PAGE_SIZE],
        }),
        FormatError::Invalid,
    );
    for (level, first_chunk, children, error) in [
        (
            MAX_TREE_LEVEL + 1,
            0,
            vec![digest(b"c")],
            FormatError::Invalid,
        ),
        (
            0,
            MAX_PAGES.div_ceil(CHUNK_PAGES),
            vec![digest(b"c")],
            FormatError::Invalid,
        ),
        (0, 0, vec![], FormatError::Invalid),
        (
            0,
            0,
            vec![digest(b"c"); TREE_FANOUT + 1],
            FormatError::Limit,
        ),
        (0, 0, vec!["bad".into()], FormatError::Invalid),
    ] {
        reject_object(
            envelope(Payload::Node {
                level,
                first_chunk,
                children,
            }),
            error,
        );
    }
}

#[test]
fn manifest_count_root_presence_and_hash_are_validated() {
    for (value, error) in [
        (
            Manifest {
                page_count: u32::MAX,
                ..manifest()
            },
            FormatError::Limit,
        ),
        (
            Manifest {
                page_count: 0,
                ..manifest()
            },
            FormatError::Invalid,
        ),
        (
            Manifest {
                root: None,
                ..manifest()
            },
            FormatError::Invalid,
        ),
        (
            Manifest {
                root: Some("bad".into()),
                ..manifest()
            },
            FormatError::Invalid,
        ),
    ] {
        reject_object(envelope(Payload::Manifest(value)), error);
    }
    object_round_trip(envelope(Payload::Manifest(Manifest {
        page_count: MAX_PAGES,
        ..manifest()
    })));
    assert!(serde_json::from_str::<Manifest>("{\"page_count\":0}").is_err());
}

#[test]
fn stored_results_keep_identity_and_exact_maximum_raw_byte_capacity() {
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
    value.data_root.clear();
    reject_object(envelope(Payload::Result(value)), FormatError::Invalid);
    let mut value = result();
    value.bytes = vec![255; MAX_RESULT_BYTES + 1];
    reject_object(envelope(Payload::Result(value)), FormatError::Limit);
    let object = envelope(Payload::Result(StoredResult {
        bytes: vec![255; MAX_RESULT_BYTES],
        ..result()
    }));
    let wire = encode_object(&object).unwrap();
    assert!(wire.len() > MAX_RESULT_BYTES && wire.len() < MAX_RESULT_BYTES + 1024);
    assert!(wire.len() <= MAX_OBJECT_BYTES);
    assert_eq!(&wire[wire.len() - 16..], &[255; 16]);
    assert_eq!(decode_object(&wire, &scope(), &digest(&wire)), Ok(object));
}

#[test]
fn index_budget_identity_epoch_and_both_outcome_variants_are_checked() {
    let entries: Vec<_> = (1..=REQUEST_LEAF_CAPACITY as u64 + 1)
        .map(|id| Entry {
            result_bytes: 0,
            request: Request { id, ..request() },
            ..committed()
        })
        .collect();
    reject_object(envelope(index(entries.clone())), FormatError::Limit);
    object_round_trip(envelope(index(entries[..REQUEST_LEAF_CAPACITY].to_vec())));
    reject_object(
        envelope(index(vec![committed(), committed()])),
        FormatError::Invalid,
    );
    let mut entry = committed();
    entry.request.fingerprint.clear();
    reject_object(envelope(index(vec![entry])), FormatError::Invalid);
    let mut entry = cancelled();
    entry.request.epoch = 2;
    reject_object(
        envelope(index(vec![committed(), entry])),
        FormatError::Invalid,
    );
    let mut entry = committed();
    entry.outcome = OutcomeRef::Committed {
        result: "bad".into(),
    };
    reject_object(envelope(index(vec![entry])), FormatError::Invalid);
    let mut entry = cancelled();
    entry.outcome = OutcomeRef::Cancelled {
        transition: Transition {
            nonce: 0,
            ..transition()
        },
    };
    reject_object(envelope(index(vec![entry])), FormatError::Invalid);
}

#[test]
fn wire_budgets_exact_framing_and_object_scope_fail_closed() {
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
    assert_eq!(encode_frame(&"abcd", &[], 5), Err(FormatError::Limit));
    assert_eq!(
        encode_frame(&"abcd", &vec![0; MAX_OBJECT_BYTES - FRAME_BYTES - 5], 6),
        Err(FormatError::Limit)
    );
    assert_eq!(
        encode_frame(&"abcd", b"raw", 6).unwrap(),
        frame(b"\"abcd\"", b"raw")
    );
    let bytes = encode_object(&envelope(index(Vec::new()))).unwrap();
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
    for value in [b"{".as_slice(), b"null", b"[]", b"{} trailing"] {
        assert_eq!(decode_head(value, &scope()), Err(FormatError::Corrupt));
        reject_wire(value);
    }
    let mut invalid = bytes.clone();
    invalid[0] ^= 1;
    reject_wire(&invalid);
    let mut invalid = bytes.clone();
    invalid[8..12].copy_from_slice(&((SMALL_METADATA_BYTES + 1) as u32).to_le_bytes());
    reject_wire(&invalid);
    let mut invalid = bytes.clone();
    invalid[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    reject_wire(&invalid);
    let mut invalid = bytes.clone();
    invalid.push(0);
    reject_wire(&invalid);
    reject_wire(&bytes[..bytes.len() - 1]);
    reject_wire(&frame(b"{", &[]));
    reject_wire(&frame(
        &serde_json::to_vec(&envelope(index(vec![]))).unwrap(),
        b"unexpected raw",
    ));
    let mut metadata = serde_json::to_vec(&envelope(Payload::Manifest(manifest()))).unwrap();
    metadata.resize(SMALL_METADATA_BYTES, b' ');
    let boundary = frame(&metadata, &[]);
    assert!(decode_object(&boundary, &scope(), &digest(&boundary)).is_ok());
    metadata.push(b' ');
    reject_wire(&frame(&metadata, &[]));
    for payload in [
        Payload::Chunk {
            first_page: 1,
            bytes: vec![1],
        },
        Payload::Result(result()),
    ] {
        reject_wire(&frame(
            &serde_json::to_vec(&envelope(payload)).unwrap(),
            b"raw",
        ));
    }
}

#[test]
fn strict_serde_rejects_unknown_duplicate_out_of_range_and_missing_fields() {
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
    for path in [
        "scope",
        "transition",
        "policy/0",
        "windows/0",
        "quota",
        "retention",
    ] {
        let mut json = original.clone();
        json.pointer_mut(&format!("/{path}")).unwrap()["extra"] = 1.into();
        assert_eq!(
            decode_head(&serde_json::to_vec(&json).unwrap(), &scope()),
            Err(FormatError::Corrupt)
        );
    }
    let wire = String::from_utf8(encode_head(&head()).unwrap()).unwrap();
    let duplicate = wire.replacen("\"format\":6", "\"format\":6,\"format\":6", 1);
    assert_ne!(duplicate, wire);
    assert_eq!(
        decode_head(duplicate.as_bytes(), &scope()),
        Err(FormatError::Corrupt)
    );
    let overflow = wire.replacen("\"revision\":1", "\"revision\":18446744073709551616", 1);
    assert_eq!(
        decode_head(overflow.as_bytes(), &scope()),
        Err(FormatError::Corrupt)
    );
    for (object, path) in [
        (envelope(Payload::Manifest(manifest())), "/payload/value"),
        (
            envelope(Payload::Chunk {
                first_page: 1,
                bytes: vec![],
            }),
            "/payload/value",
        ),
        (
            envelope(Payload::Node {
                level: 0,
                first_chunk: 0,
                children: vec![],
            }),
            "/payload/value",
        ),
        (envelope(Payload::Result(result())), "/payload/value"),
        (
            envelope(Payload::Result(result())),
            "/payload/value/request",
        ),
        (
            envelope(index(vec![committed()])),
            "/payload/value/entries/0",
        ),
        (
            envelope(index(vec![committed()])),
            "/payload/value/entries/0/outcome",
        ),
        (
            envelope(index(vec![cancelled()])),
            "/payload/value/entries/0/outcome",
        ),
        (envelope(index(vec![])), "/payload"),
        (envelope(index(vec![])), ""),
    ] {
        let mut json = serde_json::to_value(object).unwrap();
        json.pointer_mut(path).unwrap()["extra"] = 1.into();
        reject_wire(&frame(&serde_json::to_vec(&json).unwrap(), &[]));
    }
    let metadata = serde_json::to_string(&envelope(index(vec![]))).unwrap();
    reject_wire(&frame(
        metadata
            .replacen("\"format\":2", "\"format\":2,\"format\":2", 1)
            .as_bytes(),
        &[],
    ));
}
