use super::*;
use crate::tests::{deadline, fixture};

fn descriptor() -> (Snapshot, OwnerDescriptor) {
    let (_, database) = fixture();
    let mut base = database.read_head(deadline()).unwrap();
    base.etag = format!("\"{}\"", base.etag);
    let input = PrepareOwnerInput {
        creator: 7,
        operation: 101,
        expected_revision: base.head.revision,
        expected_head_serial: base.head.head_serial,
        mode: OwnerMode::Takeover,
        target_worker: 20,
        nonces: OwnerNonces {
            claim: 11,
            cancel: 12,
            activate: 13,
            abort: 14,
        },
    };
    let descriptor = OwnerDescriptor::new(&base, &input).unwrap();
    (base, descriptor)
}

fn marker(descriptor: &OwnerDescriptor, kind: OwnerPhaseKind) -> OwnerPlan {
    let pending = matches!(kind, OwnerPhaseKind::Claimed | OwnerPhaseKind::Cancelling);
    let cancel = kind == OwnerPhaseKind::Cancelling;
    OwnerPlan {
        reference: descriptor.reference(),
        admission: OwnerAdmission {
            kind: if cancel {
                OwnerAdmissionKind::Cancel
            } else {
                OwnerAdmissionKind::Claim
            },
            revision: descriptor.base.revision + 1,
            head_serial: descriptor.base.head_serial + 1,
        },
        phase: OwnerPhase {
            kind,
            revision: descriptor.base.revision + if pending { 1 } else { 2 },
            head_serial: descriptor.base.head_serial + if pending { 1 } else { 2 },
            nonce: match kind {
                OwnerPhaseKind::Claimed => descriptor.input.nonces.claim,
                OwnerPhaseKind::Cancelling => descriptor.input.nonces.cancel,
                OwnerPhaseKind::Active => descriptor.input.nonces.activate,
                OwnerPhaseKind::Aborted => descriptor.input.nonces.abort,
            },
            owner_epoch: descriptor.base.owner_epoch + u64::from(!cancel),
            owner_instance: if cancel {
                descriptor.base.owner_instance
            } else {
                descriptor.input.target_worker
            },
        },
    }
}

#[test]
fn exact_descriptor_and_terminal_proof_roundtrip_bind_all_original_fields() {
    let (base, descriptor) = descriptor();
    let bytes = descriptor.bytes().unwrap();
    assert_eq!(OwnerDescriptor::decode(&bytes).unwrap(), descriptor);
    assert!(descriptor.matches(&base));
    assert!(owner_format_key(&descriptor).len() < 512);
    for kind in [
        OwnerPhaseKind::Claimed,
        OwnerPhaseKind::Cancelling,
        OwnerPhaseKind::Active,
        OwnerPhaseKind::Aborted,
    ] {
        let marker = marker(&descriptor, kind);
        descriptor.marker(&marker).unwrap();
        let proof = OwnerProof {
            version: 1,
            scope: descriptor.scope.clone(),
            marker,
        };
        if proof.marker.pending() {
            assert!(proof.bytes().is_err());
        } else {
            assert_eq!(OwnerProof::decode(&proof.bytes().unwrap()).unwrap(), proof);
        }
    }
}

fn owner_format_key(descriptor: &OwnerDescriptor) -> String {
    key(&descriptor.scope, &descriptor.input.identity(), false)
}

#[test]
fn strict_records_and_head8_reject_missing_null_duplicate_and_wrong_versions() {
    let (base, descriptor) = descriptor();
    let text = String::from_utf8(descriptor.bytes().unwrap()).unwrap();
    for bad in [
        "{}".to_string(),
        format!("{{\"version\":1,{}", &text[1..]),
        text.replacen("\"version\":1", "\"version\":2", 1),
        text.replacen("\"previous_marker\":null", "\"extra\":null", 1),
    ] {
        assert!(OwnerDescriptor::decode(bad.as_bytes()).is_err());
    }
    let mut head = base.head;
    let marker = marker(&descriptor, OwnerPhaseKind::Claimed);
    head.format = 8;
    head.revision = marker.phase.revision;
    head.transition = crate::format::Transition {
        revision: head.revision,
        nonce: marker.phase.nonce,
    };
    head.head_serial = marker.phase.head_serial;
    head.owner_epoch = marker.phase.owner_epoch;
    head.owner_instance = marker.phase.owner_instance;
    head.active = false;
    head.owner_plan = Some(marker);
    let encoded = encode_head(&head).unwrap();
    assert_eq!(
        crate::format::decode_head(&encoded, &head.scope).unwrap(),
        head
    );
    let mut json = serde_json::to_value(&head).unwrap();
    json["owner_plan"] = serde_json::Value::Null;
    assert!(crate::format::decode_head(&serde_json::to_vec(&json).unwrap(), &head.scope).is_err());
    json.as_object_mut().unwrap().remove("owner_plan");
    assert!(crate::format::decode_head(&serde_json::to_vec(&json).unwrap(), &head.scope).is_err());
    for version in [6, 7] {
        head.format = version;
        assert!(encode_head(&head).is_err());
    }
}

#[test]
fn input_and_descriptor_independently_validate_identity_nonces_bounds_and_original_digest() {
    let (base, original) = descriptor();
    for cut in 0..11 {
        let mut input = original.input.clone();
        match cut {
            0 => input.creator = 0,
            1 => input.operation = 0,
            2 => input.expected_revision = 0,
            3 => input.expected_head_serial = input.expected_revision - 1,
            4 => input.target_worker = 0,
            5 => input.nonces.claim = 0,
            6 => input.nonces.cancel = 0,
            7 => input.nonces.activate = 0,
            8 => input.nonces.abort = 0,
            9 => input.nonces.cancel = input.nonces.claim,
            _ => input.nonces.abort = input.nonces.activate,
        }
        assert!(input.validate().is_err(), "input cut {cut}");
        assert!(OwnerDescriptor::new(&base, &input).is_err());
    }
    assert!(OwnerIdentity {
        creator: 7,
        operation: 0
    }
    .validate()
    .is_err());
    let mut reference = original.reference();
    reference.descriptor_hash = "A".repeat(64);
    assert!(reference.validate().is_err());
    for cut in 0..15 {
        let mut value = original.clone();
        match cut {
            0 => value.version = 2,
            1 => value.scope.tenant = 0,
            2 => value.base.revision += 1,
            3 => value.base.head_serial += 1,
            4 => value.base.owner_epoch = 0,
            5 => value.base.owner_instance = 0,
            6 => value.base.head_hash = "not-a-hash".into(),
            7 => value.base.etag = "unquoted".into(),
            8 => value.base.previous_marker = Some("wrong".into()),
            9 => {
                value.base.revision = u64::MAX;
                value.input.expected_revision = u64::MAX;
                value.base.head_serial = u64::MAX;
                value.input.expected_head_serial = u64::MAX;
            }
            10 => {
                value.base.head_serial = u64::MAX;
                value.input.expected_head_serial = u64::MAX;
            }
            11 => value.base.owner_epoch = u64::MAX,
            12 => value.input.mode = OwnerMode::Activate,
            13 => {
                value.input.mode = OwnerMode::Activate;
                value.base.active = false;
            }
            _ => value.input.creator = 0,
        }
        value.input_digest = value.digest();
        assert!(value.bytes().is_err(), "descriptor cut {cut}");
        assert!(OwnerDescriptor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut digest_error = original.clone();
    digest_error.input_digest = "f".repeat(64);
    assert!(digest_error.bytes().is_err());
    let mut inactive = base.clone();
    inactive.head.active = false;
    let mut input = original.input.clone();
    input.mode = OwnerMode::Activate;
    input.target_worker = inactive.head.owner_instance;
    let activate = OwnerDescriptor::new(&inactive, &input).unwrap();
    let mut active_marker = marker(&activate, OwnerPhaseKind::Active);
    active_marker.phase.owner_epoch = inactive.head.owner_epoch;
    activate.marker(&active_marker).unwrap();
    let mut previous = original.clone();
    previous.base.previous_marker = Some("e".repeat(64));
    previous.input_digest = previous.digest();
    previous.bytes().unwrap();
    assert!(!previous.matches(&base));
    for cut in 0..8 {
        let mut changed = base.clone();
        match cut {
            0 => changed.head.scope.tenant += 1,
            1 => changed.head.revision += 1,
            2 => changed.head.head_serial += 1,
            3 => changed.head.owner_epoch += 1,
            4 => changed.head.owner_instance += 1,
            5 => changed.head.active = !changed.head.active,
            6 => changed.etag = "\"different\"".into(),
            _ => changed.head.data_root = "d".repeat(64),
        }
        assert!(!original.matches(&changed));
    }
    let mut invalid = base;
    invalid.head.format = 0;
    assert!(OwnerDescriptor::new(&invalid, &original.input).is_err());
}

#[test]
fn marker_proof_and_physical_record_limits_are_not_inferred_from_the_current_head() {
    let (_, descriptor) = descriptor();
    let original = marker(&descriptor, OwnerPhaseKind::Active);
    for cut in 0..16 {
        let mut value = original.clone();
        match cut {
            0 => value.reference.creator = 0,
            1 => value.admission.revision = 1,
            2 => value.admission.head_serial = 1,
            3 => value.phase.head_serial = 1,
            4 => value.phase.nonce = 0,
            5 => value.phase.owner_epoch = 0,
            6 => value.phase.owner_instance = 0,
            7 => value.admission.kind = OwnerAdmissionKind::Cancel,
            8 => value.phase.revision = value.admission.revision,
            9 => value.phase.head_serial = value.admission.head_serial,
            10 => value.phase.head_serial += 1,
            11 => value.phase.kind = OwnerPhaseKind::Claimed,
            12 => value.reference.descriptor_hash = "f".repeat(64),
            13 => value.phase.owner_epoch += 1,
            14 => value.phase.owner_instance += 1,
            _ => value.phase.nonce += 20,
        }
        assert!(descriptor.marker(&value).is_err(), "marker cut {cut}");
    }
    let mut wrong_admission = original.clone();
    wrong_admission.admission.revision += 1;
    wrong_admission.admission.head_serial += 1;
    wrong_admission.phase.revision += 1;
    wrong_admission.phase.head_serial += 1;
    assert!(descriptor.marker(&wrong_admission).is_err());
    let mut wrong_serial = original.clone();
    wrong_serial.admission.head_serial += 1;
    wrong_serial.phase.head_serial += 1;
    assert!(descriptor.marker(&wrong_serial).is_err());
    for cut in 0..3 {
        let mut proof = OwnerProof {
            version: 1,
            scope: descriptor.scope.clone(),
            marker: original.clone(),
        };
        match cut {
            0 => proof.version = 2,
            1 => proof.scope.generation = 0,
            _ => proof.marker.reference.operation = 0,
        }
        assert!(proof.bytes().is_err());
        assert!(OwnerProof::decode(&serde_json::to_vec(&proof).unwrap()).is_err());
    }
    assert!(OwnerProof::decode(b"{}").is_err());
    assert!(OwnerDescriptor::decode(&vec![b' '; MAX_DESCRIPTOR + 1]).is_err());
    assert!(OwnerProof::decode(&vec![b' '; MAX_PROOF + 1]).is_err());
    assert_eq!(
        bounded(&"x".repeat(MAX_MARKER), MAX_MARKER),
        Err(FormatError::Limit)
    );
    assert!(bounded(&"small".to_string(), MAX_MARKER).is_ok());
    // The shared serializer's cap applies separately to every record type.
    // Exercise it with a smaller caller allowance; their strict field bounds
    // intentionally prevent valid records from reaching the format ceilings.
    assert_eq!(bounded(&descriptor, 0), Err(FormatError::Limit));
    assert_eq!(bounded(&original, 0), Err(FormatError::Limit));
    let proof = OwnerProof {
        version: 1,
        scope: descriptor.scope.clone(),
        marker: original,
    };
    assert_eq!(bounded(&proof, 0), Err(FormatError::Limit));
    for etag in ["", "\"", "a\"", "\"a", "\"a\"b\"", "\"a b\"", "\"a\nb\""] {
        assert!(!valid_etag(etag));
    }
    assert!(!valid_etag(&format!("\"{}\"", "a".repeat(1023))));
    assert!(valid_etag("\"opaque-multipart-1\""));
    assert!(key(&descriptor.scope, &descriptor.input.identity(), true).contains("/owner/v1/proof/"));
}

#[test]
fn pending_markers_bind_current_authority_and_reserve_the_terminal_counter_slot() {
    use crate::format::{CopyBasis, CopyPhase, CopyPlan, SweepCheckpoint, TerminalSeal};
    let (base, descriptor) = descriptor();
    let plan = marker(&descriptor, OwnerPhaseKind::Claimed);
    let mut head = base.head;
    head.format = 8;
    head.revision = plan.phase.revision;
    head.head_serial = plan.phase.head_serial;
    head.transition.revision = head.revision;
    head.transition.nonce = plan.phase.nonce;
    head.owner_epoch = plan.phase.owner_epoch;
    head.owner_instance = plan.phase.owner_instance;
    head.active = false;
    head.owner_plan = Some(plan.clone());
    head.validate().unwrap();
    let mut malformed = head.clone();
    malformed.owner_plan.as_mut().unwrap().phase.nonce = 0;
    assert!(encode_head(&malformed).is_err());
    assert!(
        crate::format::decode_head(&serde_json::to_vec(&malformed).unwrap(), &malformed.scope,)
            .is_err()
    );
    for cut in 0..13 {
        let mut changed = head.clone();
        match cut {
            0 => changed.revision = plan.phase.revision - 1,
            1 => changed.head_serial = plan.phase.head_serial - 1,
            2 => changed.lifecycle = Lifecycle::Provisioning,
            3 => changed.active = true,
            4 => changed.lifecycle = Lifecycle::Maintenance,
            5 => {
                changed.storage.plan = Some(CopyPlan {
                    serial: changed.head_serial,
                    source: 1,
                    target: 2,
                    phase: CopyPhase::Copying,
                    basis: CopyBasis::capture(&changed),
                })
            }
            6 => {
                changed.storage.sweep = Some(SweepCheckpoint {
                    serial: changed.head_serial,
                    generation: 2,
                    next_after: None,
                    exhausted: true,
                    entries: vec![],
                })
            }
            7 => {
                changed.storage.terminal = Some(TerminalSeal {
                    serial: changed.head_serial,
                })
            }
            8 => changed.owner_epoch += 1,
            9 => changed.owner_instance += 1,
            10 => {
                changed.revision = u64::MAX;
                changed.head_serial = u64::MAX;
            }
            11 => changed.head_serial = u64::MAX,
            _ => changed.head_serial += 1,
        }
        assert!(plan.validate_head(&changed).is_err(), "authority cut {cut}");
    }
    // Metadata advances both counters, without rewriting the accepted marker.
    let mut later = head;
    later.revision += 2;
    later.head_serial += 2;
    plan.validate_head(&later).unwrap();

    // A technical-counter gap at the base remains fixed throughout the plan.
    let mut with_gap = plan.clone();
    with_gap.admission.head_serial += 10;
    with_gap.phase.head_serial += 10;
    with_gap.validate().unwrap();
    for cut in 0..4 {
        let mut changed = with_gap.clone();
        match cut {
            0 => changed.phase.revision -= 1,
            1 => changed.phase.head_serial += 1,
            2 => {
                changed.phase.kind = OwnerPhaseKind::Active;
                changed.phase.revision += 1;
            }
            _ => changed.phase.kind = OwnerPhaseKind::Active,
        }
        assert!(changed.validate().is_err(), "phase cut {cut}");
    }
}

#[test]
fn maximal_legal_counters_and_fully_escaped_etag_still_fit_the_fixed_descriptor_cap() {
    let (mut snapshot, original) = descriptor();
    snapshot.head.scope = Scope {
        deployment: u64::MAX,
        tenant: u64::MAX,
        database: u64::MAX,
        incarnation: u64::MAX,
        generation: u64::MAX,
    };
    snapshot.head.revision = u64::MAX - 2;
    snapshot.head.head_serial = u64::MAX - 2;
    snapshot.head.transition.revision = snapshot.head.revision;
    snapshot.head.owner_epoch = u64::MAX - 1;
    snapshot.head.owner_instance = u64::MAX;
    snapshot.head.policy[0].principal = u64::MAX;
    snapshot.etag = format!("\"{}\"", "\\".repeat(1022));
    let mut input = original.input;
    input.creator = u64::MAX;
    input.operation = u64::MAX;
    input.expected_revision = snapshot.head.revision;
    input.expected_head_serial = snapshot.head.head_serial;
    input.target_worker = u64::MAX;
    input.nonces = OwnerNonces {
        claim: u64::MAX,
        cancel: u64::MAX - 1,
        activate: u64::MAX - 2,
        abort: u64::MAX - 3,
    };
    let mut previous = marker(
        &OwnerDescriptor::new(&snapshot, &input).unwrap(),
        OwnerPhaseKind::Active,
    );
    previous.reference.operation -= 1;
    previous.admission.revision = snapshot.head.revision - 1;
    previous.admission.head_serial = snapshot.head.head_serial - 1;
    previous.phase.revision = snapshot.head.revision;
    previous.phase.head_serial = snapshot.head.head_serial;
    previous.phase.owner_epoch = snapshot.head.owner_epoch;
    previous.phase.owner_instance = snapshot.head.owner_instance;
    snapshot.head.transition.nonce = previous.phase.nonce;
    snapshot.head.format = 8;
    snapshot.head.owner_plan = Some(previous);
    let descriptor = OwnerDescriptor::new(&snapshot, &input).unwrap();
    let bytes = descriptor.bytes().unwrap();
    assert!(bytes.len() < MAX_DESCRIPTOR);
    assert_eq!(OwnerDescriptor::decode(&bytes).unwrap(), descriptor);
    assert_eq!(descriptor.base.etag.len(), 1024);
    assert!(key(&descriptor.scope, &descriptor.input.identity(), false).len() < 512);
    for kind in [OwnerPhaseKind::Claimed, OwnerPhaseKind::Active] {
        descriptor.marker(&marker(&descriptor, kind)).unwrap();
    }
}

#[test]
fn phase_at_the_current_business_revision_keeps_its_nonce_across_technical_successors() {
    let (base, descriptor) = descriptor();
    let marker = marker(&descriptor, OwnerPhaseKind::Active);
    let mut head = base.head;
    head.format = 8;
    head.revision = marker.phase.revision;
    head.head_serial = marker.phase.head_serial;
    head.transition.revision = head.revision;
    head.transition.nonce = marker.phase.nonce;
    head.owner_epoch = marker.phase.owner_epoch;
    head.owner_instance = marker.phase.owner_instance;
    head.active = true;
    head.owner_plan = Some(marker);
    let encoded = encode_head(&head).unwrap();
    assert_eq!(
        crate::format::decode_head(&encoded, &head.scope).unwrap(),
        head
    );
    let mut technical = head.clone();
    technical.head_serial += 3;
    technical.active = false;
    encode_head(&technical).unwrap();
    let mut business = technical.clone();
    business.revision += 1;
    business.head_serial += 1;
    business.transition.revision = business.revision;
    business.transition.nonce += 20;
    encode_head(&business).unwrap();
    for mut invalid in [head, technical] {
        invalid.transition.nonce += 20;
        assert!(encode_head(&invalid).is_err());
        assert!(
            crate::format::decode_head(&serde_json::to_vec(&invalid).unwrap(), &invalid.scope)
                .is_err()
        );
    }
}
