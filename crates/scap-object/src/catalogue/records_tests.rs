use super::*;

type Mutation<T> = Box<dyn Fn(&mut T)>;
use records::{BindingState, Record};

fn control(descriptor: &Source, kind: NamedDeletionKind) -> Control {
    Control {
        format: 1,
        creation: descriptor.creation.clone(),
        origin: descriptor.origin(),
        principal: descriptor.creation.creator,
        operation: 20,
        expected_name_revision: 1,
        expected_head_revision: if kind == NamedDeletionKind::Delete {
            Some(2)
        } else {
            None
        },
        kind,
        nonce: 21,
    }
}

fn roundtrip<R: Record>(value: &R) {
    let bytes = records::encode(value).unwrap();
    let decoded = records::decode::<R>(&bytes).unwrap();
    assert_eq!(decoded.raw(), value);
    assert_eq!(decoded.bytes(), bytes);
    assert_eq!(decoded.hash(), format::digest(&bytes));
    assert_eq!(decoded.shape(), &value.validate().unwrap());
}

#[test]
fn fixed_identity_vectors_and_internal_key_namespaces_do_not_depend_on_name() {
    let (_, catalogue, creation) = prepared();
    assert_eq!(
        creation.scope,
        Scope {
            deployment: 1,
            tenant: 2,
            database: 10863686695873768950,
            incarnation: 11387768415012512723,
            generation: 1,
        }
    );
    assert_eq!(
        records::derive_scope(1, 2, 11, 9007199254740993).unwrap(),
        Scope {
            deployment: 1,
            tenant: 2,
            database: 12185469706493648776,
            incarnation: 16147563270719600577,
            generation: 1,
        }
    );
    assert_eq!(
        catalogue.descriptor_key(7, 1),
        "scap-object/v1/1/2/catalogue/v1/create/7/1"
    );
    assert_eq!(
        catalogue.binding_key("hello"),
        "scap-object/v1/1/2/catalogue/v1/name/2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(
        catalogue.proof_key(&creation),
        "scap-object/v1/1/2/catalogue/v1/abort-proof/7/1"
    );
    let descriptor = descriptor(&catalogue, &creation);
    assert_eq!(
        catalogue.control_key(&control(&descriptor, NamedDeletionKind::Abort)),
        "scap-object/v1/1/2/catalogue/v1/control/7/abort/20"
    );
    assert_eq!(
        catalogue.control_key(&control(&descriptor, NamedDeletionKind::Delete)),
        "scap-object/v1/1/2/catalogue/v1/control/7/delete/20"
    );
    assert_eq!(
        records::derive_scope(1, 2, 0, 1),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        records::derive_scope(1, 2, 7, 0),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        records::scope_from_hash(1, 2, &[0; 32]),
        Err(CatalogueError::Invalid)
    );
    let mut hash = [1; 32];
    hash[8..16].fill(0);
    assert_eq!(
        records::scope_from_hash(1, 2, &hash),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        records::scope_from_hash(0, 2, &[1; 32]),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        records::scope_from_hash(1, 0, &[1; 32]),
        Err(CatalogueError::Invalid)
    );
}

#[test]
fn descriptor_validation_freezes_options_and_bounded_canonical_wire() {
    let (_, catalogue, creation) = prepared();
    let descriptor = descriptor(&catalogue, &creation);
    roundtrip(descriptor.raw());
    let mutations: Vec<Mutation<Descriptor>> = vec![
        Box::new(|d| d.format = 2),
        Box::new(|d| d.creation.name.clear()),
        Box::new(|d| d.creation.name = "\n".into()),
        Box::new(|d| d.creation.name = "a".repeat(129)),
        Box::new(|d| d.creation.operation = 0),
        Box::new(|d| d.creation.creator = 0),
        Box::new(|d| d.creation.scope.database += 1),
        Box::new(|d| d.creation.expected_name_revision = Some(0)),
        Box::new(|d| d.creation.expected_name_revision = Some(u64::MAX - 2)),
        Box::new(|d| d.initial_quota.max_bytes = Some(1)),
        Box::new(|d| d.retention.max_entries = 0),
        Box::new(|d| d.options.quota = QuotaChoice::Unlimited),
        Box::new(|d| d.options.quota = QuotaChoice::Limited { max_bytes: 4096 }),
    ];
    for mutate in mutations {
        let mut bad = descriptor.raw().clone();
        mutate(&mut bad);
        assert!(bad.validate().is_err());
        assert_eq!(
            records::decode::<Descriptor>(&serde_json::to_vec(&bad).unwrap()),
            Err(CatalogueError::Corrupt)
        );
    }
    for quota in [
        QuotaChoice::Unlimited,
        QuotaChoice::Limited { max_bytes: 4096 },
    ] {
        let mut valid = descriptor.raw().clone();
        valid.options.quota = quota;
        valid.initial_quota = valid.options.effective_quota(&descriptor.initial_quota);
        roundtrip(&valid);
    }
    let bytes = records::encode(descriptor.raw()).unwrap();
    let mut whitespace = bytes.clone();
    whitespace.push(b' ');
    assert_eq!(
        records::decode::<Descriptor>(&whitespace),
        Err(CatalogueError::Corrupt)
    );
    for bytes in [
        vec![],
        b"null".to_vec(),
        vec![b' '; records::MAX_RECORD_BYTES + 1],
    ] {
        assert_eq!(
            records::decode::<Descriptor>(&bytes),
            Err(CatalogueError::Corrupt)
        );
    }
    let text = String::from_utf8(bytes).unwrap();
    for text in [
        text.replace("\"format\":1", "\"format\":1,\"format\":1"),
        text.replace("\"format\":1", "\"extra\":1,\"format\":1"),
        text.replace(",\"expected_name_revision\":null", ""),
    ] {
        assert_eq!(
            records::decode::<Descriptor>(text.as_bytes()),
            Err(CatalogueError::Corrupt)
        );
    }
}

#[test]
fn control_and_binding_records_reject_wrong_source_conditions_and_illegal_transitions() {
    let (_, catalogue, creation) = prepared();
    let descriptor = descriptor(&catalogue, &creation);
    let abort = control(&descriptor, NamedDeletionKind::Abort);
    roundtrip(&abort);
    roundtrip(&control(&descriptor, NamedDeletionKind::Delete));
    let mutations: Vec<Mutation<Control>> = vec![
        Box::new(|c| c.format = 0),
        Box::new(|c| c.creation.scope.database += 1),
        Box::new(|c| c.origin.creator += 1),
        Box::new(|c| c.origin.operation += 1),
        Box::new(|c| c.origin.name_hash = format::digest(b"other")),
        Box::new(|c| c.origin.descriptor_hash = "bad".into()),
        Box::new(|c| c.principal = 0),
        Box::new(|c| c.principal += 1),
        Box::new(|c| c.operation = 0),
        Box::new(|c| c.expected_name_revision = 0),
        Box::new(|c| c.nonce = 0),
        Box::new(|c| c.expected_head_revision = Some(1)),
        Box::new(|c| c.kind = NamedDeletionKind::Delete),
    ];
    for mutate in mutations {
        let mut bad = abort.clone();
        mutate(&mut bad);
        assert!(bad.validate().is_err());
    }
    let mut delete = control(&descriptor, NamedDeletionKind::Delete);
    delete.expected_head_revision = Some(0);
    assert!(delete.validate().is_err());

    let reserved = Binding {
        format: 1,
        creation,
        origin: descriptor.origin(),
        revision: 1,
        state: BindingState::Reserved,
        control: None,
        proof: None,
    };
    roundtrip(&reserved);
    let mut bound = reserved.clone();
    bound.state = BindingState::Bound;
    bound.revision = 2;
    roundtrip(&bound);
    let mut invalid_bound = bound.clone();
    invalid_bound.control = Some(abort.clone());
    assert!(invalid_bound.validate().is_err());
    invalid_bound = bound;
    invalid_bound.proof = Some(format::digest(b"invalid bound proof"));
    assert!(invalid_bound.validate().is_err());
    let mut aborting = reserved.clone();
    aborting.state = BindingState::Aborting;
    aborting.revision = 2;
    aborting.control = Some(abort.clone());
    roundtrip(&aborting);
    let mut tombstone = aborting.clone();
    tombstone.state = BindingState::Tombstone;
    tombstone.revision = 3;
    tombstone.proof = Some(format::digest(b"proof"));
    roundtrip(&tombstone);
    let mutations: Vec<Mutation<Binding>> = vec![
        Box::new(|b| b.format = 0),
        Box::new(|b| b.revision = 4),
        Box::new(|b| b.origin.operation += 1),
        Box::new(|b| b.control = None),
        Box::new(|b| b.control.as_mut().unwrap().creation.name = "different".into()),
        Box::new(|b| {
            let control = b.control.as_mut().unwrap();
            control.creation.name = "different".into();
            control.origin.name_hash = format::digest(b"different");
        }),
        Box::new(|b| {
            b.control.as_mut().unwrap().origin.descriptor_hash = format::digest(b"different")
        }),
        Box::new(|b| b.control.as_mut().unwrap().expected_name_revision = 2),
        Box::new(|b| b.proof = None),
        Box::new(|b| b.proof = Some("a".repeat(63))),
        Box::new(|b| b.proof = Some("G".repeat(64))),
        Box::new(|b| b.proof = Some("A".repeat(64))),
    ];
    for mutate in mutations {
        let mut bad = tombstone.clone();
        mutate(&mut bad);
        assert!(bad.validate().is_err());
    }
    aborting.proof = Some(format::digest(b"proof"));
    assert!(aborting.validate().is_err());
    let mut bad = reserved.clone();
    bad.control = Some(abort.clone());
    assert!(bad.validate().is_err());
    bad = reserved;
    bad.proof = Some(format::digest(b"proof"));
    assert!(bad.validate().is_err());
    let mut delete = control(&descriptor, NamedDeletionKind::Delete);
    delete.expected_name_revision = 2;
    tombstone.control = Some(delete);
    tombstone.proof = None;
    roundtrip(&tombstone);
    let mut bad = tombstone.clone();
    bad.state = BindingState::Aborting;
    bad.revision = 2;
    assert!(bad.validate().is_err());
    bad = tombstone.clone();
    bad.control.as_mut().unwrap().expected_name_revision = 1;
    assert!(bad.validate().is_err());
    bad = tombstone;
    bad.proof = Some(format::digest(b"proof"));
    assert!(bad.validate().is_err());
}

#[test]
fn abort_proofs_bind_permanent_identity_and_original_control_without_mutable_etag() {
    let (_, catalogue, creation) = prepared();
    let descriptor = descriptor(&catalogue, &creation);
    let control = control(&descriptor, NamedDeletionKind::Abort);
    let own = AbortProof {
        format: 1,
        control: control.clone(),
        barrier: Barrier::OwnDeleted {
            transition: format::Transition {
                revision: 1,
                nonce: control.nonce,
            },
        },
    };
    roundtrip(&own);
    for revision in [0, 3] {
        let mut bad = own.clone();
        bad.barrier = Barrier::OwnDeleted {
            transition: format::Transition {
                revision,
                nonce: control.nonce,
            },
        };
        assert!(bad.validate().is_err());
    }
    let mut bad = own.clone();
    bad.barrier = Barrier::OwnDeleted {
        transition: format::Transition {
            revision: 2,
            nonce: control.nonce + 1,
        },
    };
    assert!(bad.validate().is_err());
    bad = own.clone();
    bad.format = 2;
    assert!(bad.validate().is_err());
    bad = own.clone();
    bad.control.operation = 0;
    assert!(bad.validate().is_err());
    bad = own;
    bad.control.kind = NamedDeletionKind::Delete;
    assert!(bad.validate().is_err());
    let mut scope = creation.scope.clone();
    scope.incarnation += 1;
    let foreign = AbortProof {
        format: 1,
        control,
        barrier: Barrier::ForeignOccupied {
            scope: scope.clone(),
            creation: None,
        },
    };
    roundtrip(&foreign);
    let mut named_foreign = foreign.clone();
    named_foreign.barrier = Barrier::ForeignOccupied {
        scope: scope.clone(),
        creation: Some(descriptor.origin()),
    };
    roundtrip(&named_foreign);
    for mutate in [0, 1, 2, 3, 4] {
        let mut bad = foreign.clone();
        let Barrier::ForeignOccupied {
            scope,
            creation: origin,
        } = &mut bad.barrier
        else {
            unreachable!()
        };
        match mutate {
            0 => scope.generation = 0,
            1 => scope.deployment += 1,
            2 => scope.tenant += 1,
            3 => scope.database += 1,
            _ => {
                *scope = creation.scope.clone();
                *origin = Some(descriptor.origin());
            }
        }
        assert!(bad.validate().is_err());
    }
    let mut bad = named_foreign;
    let Barrier::ForeignOccupied {
        creation: Some(origin),
        ..
    } = &mut bad.barrier
    else {
        unreachable!()
    };
    origin.creator = 0;
    assert!(bad.validate().is_err());
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
struct CodecRecord {
    value: String,
    valid: bool,
    serializable: bool,
}
impl serde::Serialize for CodecRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        if !self.serializable {
            return Err(serde::ser::Error::custom("serialization failed"));
        }
        let mut fields = serializer.serialize_struct("CodecRecord", 3)?;
        fields.serialize_field("value", &self.value)?;
        fields.serialize_field("valid", &self.valid)?;
        fields.serialize_field("serializable", &self.serializable)?;
        fields.end()
    }
}
impl Record for CodecRecord {
    type Shape = ();
    fn validate(&self) -> Result<(), CatalogueError> {
        records::valid(self.valid)
    }
}

#[test]
fn codec_and_boundary_error_mapping_are_fail_closed() {
    let empty = CodecRecord {
        value: String::new(),
        valid: true,
        serializable: true,
    };
    roundtrip(&empty);
    let maximum = CodecRecord {
        value: "x".repeat(records::MAX_RECORD_BYTES - records::encode(&empty).unwrap().len()),
        ..empty.clone()
    };
    assert_eq!(
        records::encode(&maximum).unwrap().len(),
        records::MAX_RECORD_BYTES
    );
    roundtrip(&maximum);
    for invalid in [
        CodecRecord {
            valid: false,
            ..empty.clone()
        },
        CodecRecord {
            serializable: false,
            ..empty.clone()
        },
    ] {
        assert_eq!(records::encode(&invalid), Err(CatalogueError::Invalid));
    }
    assert_eq!(
        records::encode(&CodecRecord {
            value: "x".repeat(records::MAX_RECORD_BYTES),
            ..empty
        }),
        Err(CatalogueError::Limit)
    );
    for bytes in [
        b"{}".to_vec(),
        br#"{"value":"","valid":false,"serializable":true}"#.to_vec(),
        br#"{"value":"","valid":true,"serializable":false}"#.to_vec(),
        br#"{"value":"","valid":true,"serializable":true} "#.to_vec(),
        vec![b' '; records::MAX_RECORD_BYTES + 1],
    ] {
        assert_eq!(
            records::decode::<CodecRecord>(&bytes),
            Err(CatalogueError::Corrupt)
        );
    }
    for (error, expected) in [
        (StoreError::Missing, CatalogueError::NotFound),
        (StoreError::Conflict, CatalogueError::Conflict),
        (StoreError::Unknown, CatalogueError::Unknown),
        (StoreError::Invalid, CatalogueError::Invalid),
        (StoreError::Limit, CatalogueError::Corrupt),
        (StoreError::Corrupt, CatalogueError::Corrupt),
    ] {
        assert_eq!(store_error(error), expected);
    }
    for (error, expected) in [
        (Error::Store(StoreError::Unknown), CatalogueError::Unknown),
        (Error::Unknown, CatalogueError::Unknown),
        (Error::Denied, CatalogueError::Denied),
        (Error::Conflict, CatalogueError::Conflict),
        (Error::Store(StoreError::Conflict), CatalogueError::Conflict),
        (Error::Limit, CatalogueError::Limit),
        (Error::Store(StoreError::Missing), CatalogueError::Corrupt),
        (Error::Corrupt, CatalogueError::Corrupt),
    ] {
        assert_eq!(core_error(error), expected);
    }
    assert_eq!(
        authority::<()>(Err(CatalogueError::NotFound)),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        authority::<()>(Err(CatalogueError::Invalid)),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        authority::<()>(Err(CatalogueError::Unknown)),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(authority(Ok(1)), Ok(1));
}

#[test]
fn public_phase_wire_values_and_fixed_options_are_explicit() {
    for (phase, expected) in [
        (CreationPhase::NotReserved, "not_reserved"),
        (CreationPhase::Reserved, "reserved"),
        (CreationPhase::Provisioning, "provisioning"),
        (CreationPhase::Bound, "bound"),
        (CreationPhase::Ready, "ready"),
        (CreationPhase::Aborting, "aborting"),
        (CreationPhase::Aborted, "aborted"),
        (CreationPhase::Deleting, "deleting"),
        (CreationPhase::Deleted, "deleted"),
        (CreationPhase::NameConflict, "name_conflict"),
        (CreationPhase::IdentityConflict, "identity_conflict"),
    ] {
        let bytes = serde_json::to_vec(&phase).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!("\"{expected}\"")
        );
        assert_eq!(
            serde_json::from_slice::<CreationPhase>(&bytes).unwrap(),
            phase
        );
    }
    for phase in [
        AbortPhase::NotReserved,
        AbortPhase::CannotAbortBound,
        AbortPhase::Aborting,
        AbortPhase::Aborted,
    ] {
        assert_eq!(
            serde_json::from_slice::<AbortPhase>(&serde_json::to_vec(&phase).unwrap()).unwrap(),
            phase
        );
    }
    for phase in [
        DeletionPhase::NotDeleted,
        DeletionPhase::Deleting,
        DeletionPhase::Deleted,
    ] {
        assert_eq!(
            serde_json::from_slice::<DeletionPhase>(&serde_json::to_vec(&phase).unwrap()).unwrap(),
            phase
        );
    }
    assert_eq!(QuotaChoice::default(), QuotaChoice::Default);
    assert_eq!(
        serde_json::to_value(CreateOptions::default()).unwrap(),
        serde_json::json!({"quota":{"kind":"default"}})
    );
}
