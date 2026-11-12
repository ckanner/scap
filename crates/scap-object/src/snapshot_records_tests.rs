use super::*;
use crate::tests::{deadline, fixture};

fn descriptor() -> (Snapshot, SnapshotDescriptor) {
    let (_, database) = fixture();
    let mut base = database.read_head(deadline()).unwrap();
    base.etag = format!("\"{}\"", base.etag);
    let input = PrepareSnapshotInput {
        creator: 7,
        operation: 101,
        expected_revision: base.head.revision,
        expected_head_serial: base.head.head_serial,
        label: "saved".to_string(),
    };
    let descriptor = SnapshotDescriptor::new(&base, &input, 0, SnapshotLimits::default()).unwrap();
    (base, descriptor)
}

#[test]
fn exact_records_bind_scope_original_head_point_and_first_limits() {
    let (base, descriptor) = descriptor();
    assert_eq!(
        SnapshotDescriptor::decode(&descriptor.bytes().unwrap()).unwrap(),
        descriptor
    );
    assert!(descriptor.matches(&base));
    assert_eq!(
        descriptor.reference().capture_serial,
        base.head.head_serial + 1
    );
    assert_eq!(descriptor.entry().point.page_count, 0);
    let proof = SnapshotProof {
        version: 1,
        scope: descriptor.scope.clone(),
        entry: descriptor.entry(),
    };
    assert_eq!(
        SnapshotProof::decode(&proof.bytes().unwrap()).unwrap(),
        proof
    );
    let identity = descriptor.input.identity();
    assert!(key(&descriptor.scope, &identity, false).contains("/snapshot/v1/descriptor/7/101"));
    assert!(key(&descriptor.scope, &identity, true).contains("/snapshot/v1/proof/7/101"));
    assert!(key(&descriptor.scope, &identity, true).len() < 512);
}

#[test]
fn public_inputs_reject_invalid_identity_revision_and_labels() {
    let (_, descriptor) = descriptor();
    for cut in 0..7 {
        let mut input = descriptor.input.clone();
        match cut {
            0 => input.creator = 0,
            1 => input.operation = 0,
            2 => input.expected_revision = 0,
            3 => input.expected_head_serial = 0,
            4 => input.label.clear(),
            5 => input.label = "x".repeat(129),
            _ => input.label.push('\n'),
        }
        assert!(input.validate().is_err(), "input {cut}");
    }
    let mut input = descriptor.input.clone();
    input.label = "中".repeat(42);
    input.validate().unwrap();
    input.label.push('中');
    assert!(input.validate().is_err());
    input.label = "\"".repeat(128);
    input.validate().unwrap();
}

#[test]
fn every_descriptor_field_is_required_and_unknown_or_duplicate_fields_reject() {
    let (_, descriptor) = descriptor();
    let json = serde_json::to_value(&descriptor).unwrap();
    for field in [
        "version",
        "scope",
        "input",
        "base",
        "point",
        "limits",
        "input_digest",
    ] {
        let mut absent = json.clone();
        absent.as_object_mut().unwrap().remove(field);
        assert!(
            SnapshotDescriptor::decode(&serde_json::to_vec(&absent).unwrap()).is_err(),
            "{field}"
        );
        let mut null = json.clone();
        null[field] = serde_json::Value::Null;
        assert!(
            SnapshotDescriptor::decode(&serde_json::to_vec(&null).unwrap()).is_err(),
            "{field}"
        );
    }
    let text = String::from_utf8(descriptor.bytes().unwrap()).unwrap();
    for text in [
        format!("{{\"version\":1,{}", &text[1..]),
        format!("{{\"extra\":null,{}", &text[1..]),
        format!("{text}x"),
        "{}".to_string(),
    ] {
        assert!(SnapshotDescriptor::decode(text.as_bytes()).is_err());
    }
    for path in ["scope", "input", "base", "point", "limits"] {
        let mut unknown = json.clone();
        unknown[path]["extra"] = serde_json::Value::Bool(true);
        assert!(SnapshotDescriptor::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}

#[test]
fn descriptor_semantics_reject_rebound_or_impossible_record_fields() {
    let (base, original) = descriptor();
    for cut in 0..14 {
        let mut bad = original.clone();
        match cut {
            0 => bad.version = 2,
            1 => bad.scope.database = 0,
            2 => bad.input.creator = 0,
            3 => bad.point.data_root = "bad".to_string(),
            4 => bad.point.source_revision = 0,
            5 => bad.limits.max_points = 65,
            6 => bad.base.revision += 1,
            7 => bad.base.head_serial += 1,
            8 => {
                bad.base.head_serial = u64::MAX;
                bad.input.expected_head_serial = u64::MAX;
            }
            9 => bad.point.source_revision += 1,
            10 => bad.base.head_hash = "bad".to_string(),
            11 => bad.base.etag = "unquoted".to_string(),
            12 => bad.limits.max_points = 0,
            _ => {
                bad.point.page_count = 1;
                bad.limits.max_logical_bytes = 0;
            }
        }
        bad.input_digest = bad.digest();
        assert!(bad.bytes().is_err(), "descriptor {cut}");
        assert!(
            SnapshotDescriptor::decode(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "decode {cut}"
        );
    }
    let mut bad = original.clone();
    bad.input_digest = "0".repeat(64);
    assert!(bad.bytes().is_err());
    assert!(SnapshotDescriptor::new(
        &base,
        &bad.input,
        1,
        SnapshotLimits {
            max_points: 1,
            max_logical_bytes: 0
        }
    )
    .is_err());
    let mut invalid_head = base.clone();
    invalid_head.head.revision = 0;
    assert!(
        SnapshotDescriptor::new(&invalid_head, &original.input, 0, SnapshotLimits::default())
            .is_err()
    );
}

#[test]
fn descriptor_never_matches_a_new_head_etag_or_mutable_field() {
    let (base, descriptor) = descriptor();
    for cut in 0..8 {
        let mut changed = base.clone();
        match cut {
            0 => changed.head.scope.tenant += 1,
            1 => changed.head.revision += 1,
            2 => changed.head.head_serial += 1,
            3 => changed.etag = "\"different\"".to_string(),
            4 => changed.head.data_root = "f".repeat(64),
            5 => changed.head.sequence += 1,
            6 => {
                changed.head.snapshot_limits = Some(SnapshotLimits {
                    max_points: 1,
                    max_logical_bytes: 0,
                })
            }
            _ => changed.head.policy[0].write = false,
        }
        assert!(!descriptor.matches(&changed), "basis {cut}");
    }
    let mut adopted = base.clone();
    adopted.head.format = 9;
    adopted.head.snapshots = Some(vec![]);
    adopted.head.snapshot_limits = Some(SnapshotLimits::default());
    adopted.head.restore_origin = Some(());
    let fixed =
        SnapshotDescriptor::new(&adopted, &descriptor.input, 0, SnapshotLimits::default()).unwrap();
    assert!(fixed.matches(&adopted));
}

#[test]
fn proof_is_strict_and_contains_the_full_accepted_entry() {
    let (_, descriptor) = descriptor();
    let proof = SnapshotProof {
        version: 1,
        scope: descriptor.scope.clone(),
        entry: descriptor.entry(),
    };
    for cut in 0..4 {
        let mut bad = proof.clone();
        match cut {
            0 => bad.version = 0,
            1 => bad.scope.incarnation = 0,
            2 => bad.entry.reference.descriptor_hash = "bad".to_string(),
            _ => bad.entry.point.source_revision = bad.entry.reference.capture_serial,
        }
        assert!(bad.bytes().is_err());
        assert!(SnapshotProof::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for bad in [b"{}".to_vec(), b"null".to_vec(), vec![b' '; MAX_PROOF + 1]] {
        assert!(SnapshotProof::decode(&bad).is_err());
    }
    assert!(SnapshotDescriptor::decode(&vec![b' '; MAX_DESCRIPTOR + 1]).is_err());
}

#[test]
fn bounded_records_and_quoted_etags_have_exact_limits() {
    assert_eq!(bounded(&"x", 3).unwrap(), b"\"x\"");
    assert!(matches!(bounded(&"x", 2), Err(FormatError::Limit)));
    for etag in [
        "",
        "\"",
        "unquoted",
        "\"unterminated",
        "unterminated\"",
        "\"a\"b\"",
        "\"a b\"",
        "\"a\u{7f}\"",
        "\"中\"",
    ] {
        assert!(!valid_etag(etag), "etag {etag:?}");
    }
    assert!(valid_etag("\"\""));
    assert!(valid_etag(&format!("\"{}\"", "x".repeat(1022))));
    assert!(!valid_etag(&format!("\"{}\"", "x".repeat(1023))));
    let (_, mut descriptor) = descriptor();
    descriptor.base.etag = format!("\"{}\"", "\\".repeat(1022));
    descriptor.input.label = "\"".repeat(128);
    descriptor.input_digest = descriptor.digest();
    assert!(descriptor.bytes().unwrap().len() < MAX_DESCRIPTOR);
}
