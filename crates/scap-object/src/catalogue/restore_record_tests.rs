use super::*;
use crate::catalogue::records::{self, Canonical, Descriptor, Record};
use crate::catalogue::restore_records::{Completion, Recipe};
use crate::catalogue::QuotaChoice;
use crate::format::{decode_head, digest, FormatError, Lifecycle};

#[test]
fn public_restore_inputs_preserve_strict_identities_and_lowerable_budgets() {
    let fixture = Fixture::new(false);
    let input = fixture.input();
    input.validate().unwrap();
    for field in 0..10 {
        let mut invalid = input.clone();
        match field {
            0 => invalid.name.clear(),
            1 => invalid.name = "a".repeat(129),
            2 => invalid.operation = 0,
            3 => invalid.expected_name_revision = Some(0),
            4 => invalid.expected_name_revision = Some(u64::MAX),
            5 => invalid.source_scope.database = 0,
            6 => invalid.snapshot.creator = 0,
            7 => invalid.snapshot.capture_serial = 0,
            8 => invalid.snapshot.descriptor_hash = "invalid".into(),
            _ => invalid.options.quota = QuotaChoice::Limited { max_bytes: 0 },
        }
        assert!(invalid.validate().is_err(), "input field {field}");
    }
    let prepared = fixture.prepare();
    prepared.reference.validate().unwrap();
    let mut invalid = prepared.reference.clone();
    invalid.creation.operation += 1;
    assert!(invalid.validate().is_err());
    let mut invalid = prepared.reference.clone();
    invalid.descriptor_hash = "BAD".into();
    assert!(invalid.validate().is_err());
    for field in 0..7 {
        let mut invalid = RestoreBudget::default();
        match field {
            0 => invalid.source_gets += 1,
            1 => invalid.source_bytes += 1,
            2 => invalid.target_puts += 1,
            3 => invalid.target_put_bytes += 1,
            4 => invalid.target_gets += 1,
            5 => invalid.target_get_bytes += 1,
            _ => invalid.max_image_bytes += 1,
        }
        assert_eq!(invalid.validate(), Err(CatalogueError::Invalid));
    }
    RestoreBudget {
        source_gets: 0,
        source_bytes: 0,
        target_puts: 0,
        target_put_bytes: 0,
        target_gets: 0,
        target_get_bytes: 0,
        max_image_bytes: 0,
    }
    .validate()
    .unwrap();
    for field in [
        "name",
        "operation",
        "expected_name_revision",
        "options",
        "source_scope",
        "snapshot",
    ] {
        let mut value = serde_json::to_value(&input).unwrap();
        value.as_object_mut().unwrap().remove(field);
        // expected_name_revision is an Option DTO and may deserialize omitted;
        // the service wire separately requires its explicit nullable field.
        if field != "expected_name_revision" {
            assert!(serde_json::from_value::<PrepareRestore>(value).is_err());
        }
    }
    let mut value = serde_json::to_value(&input).unwrap();
    value["arbitrary_root"] = serde_json::json!(digest(b"not authority"));
    assert!(serde_json::from_value::<PrepareRestore>(value).is_err());
}

#[test]
fn restore_descriptor_versions_and_every_recipe_binding_are_strict() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    let source = fixture
        .catalogue
        .restore_descriptor(&prepared.reference, deadline())
        .unwrap();
    assert_eq!(
        records::decode::<Descriptor>(source.bytes()).unwrap(),
        source
    );
    for field in 0..13 {
        let mut invalid = source.raw().clone();
        match field {
            0 => invalid.format = 1,
            1 => invalid.recipe = None,
            2 => invalid.initial_quota.max_bytes = Some(0),
            3 => invalid.options.quota = QuotaChoice::Unlimited,
            _ => {
                let Recipe::SnapshotRestore {
                    source_scope,
                    snapshot,
                    point,
                    rewrap_version,
                    native_format,
                    snapshot_limits,
                } = invalid.recipe.as_mut().unwrap();
                match field {
                    4 => source_scope.database = 0,
                    5 => *source_scope = invalid.creation.scope.clone(),
                    6 => source_scope.tenant += 1,
                    7 => snapshot.operation = 0,
                    8 => point.data_root.clear(),
                    9 => point.source_revision = snapshot.capture_serial,
                    10 => *rewrap_version = 2,
                    11 => *native_format = 2,
                    _ => snapshot_limits.max_points = 65,
                }
            }
        }
        assert!(invalid.validate().is_err(), "descriptor field {field}");
        assert!(records::decode::<Descriptor>(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let empty = fixture
        .catalogue
        .prepare(
            CREATOR,
            &PrepareCreate {
                name: "empty".into(),
                operation: 701,
                expected_name_revision: None,
                options: CreateOptions::default(),
            },
            deadline(),
        )
        .unwrap();
    let original = fixture
        .catalogue
        .descriptor(&empty.creation, deadline())
        .unwrap();
    assert!(!String::from_utf8_lossy(original.bytes()).contains("recipe"));
    assert_eq!(original.prepared_restore(), Err(CatalogueError::Conflict));
    let mut added_null: serde_json::Value = serde_json::from_slice(original.bytes()).unwrap();
    added_null["recipe"] = serde_json::Value::Null;
    assert!(records::decode::<Descriptor>(&serde_json::to_vec(&added_null).unwrap()).is_err());
    for value in [
        serde_json::json!({"kind":"empty"}),
        serde_json::json!({"kind":"snapshot_restore"}),
        serde_json::Value::Null,
    ] {
        let mut body: serde_json::Value = serde_json::from_slice(source.bytes()).unwrap();
        body["recipe"] = value;
        assert!(records::decode::<Descriptor>(&serde_json::to_vec(&body).unwrap()).is_err());
    }
}

#[test]
fn completion_records_reject_rebound_source_target_point_and_version() {
    let fixture = Fixture::new(true);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
    let source = fixture
        .catalogue
        .restore_descriptor(&prepared.reference, deadline())
        .unwrap();
    let key = fixture.completion_key(&prepared);
    let bytes = fixture.memory.get_value(&key).unwrap().bytes;
    let original = records::decode::<Completion>(&bytes).unwrap();
    assert!(original.matches(&source));
    for field in 0..16 {
        let mut invalid = original.raw().clone();
        match field {
            0 => invalid.format = 2,
            1 => invalid.rewrap_version = 2,
            2 => invalid.native_format = 2,
            3 => invalid.source_scope.database = 0,
            4 => invalid.target_scope.database = 0,
            5 => invalid.snapshot.creator = 0,
            6 => invalid.point.data_root.clear(),
            7 => invalid.source_scope = invalid.target_scope.clone(),
            8 => invalid.source_scope.deployment += 1,
            9 => invalid.source_scope.tenant += 1,
            10 => invalid.descriptor_hash.clear(),
            11 => invalid.data_root.clear(),
            12 => invalid.request_root.clear(),
            13 => invalid.page_count += 1,
            14 => invalid.point.source_revision = invalid.snapshot.capture_serial,
            _ => invalid.snapshot.descriptor_hash.clear(),
        }
        assert!(invalid.validate().is_err(), "completion field {field}");
    }
    for field in 0..5 {
        let mut rebound = original.raw().clone();
        match field {
            0 => rebound.descriptor_hash = digest(b"other descriptor"),
            1 => rebound.source_scope.incarnation += 1,
            2 => rebound.snapshot.operation += 1,
            3 => rebound.point.data_root = digest(b"other retained point"),
            _ => rebound.target_scope.incarnation += 1,
        }
        let rebound = Canonical::new(rebound).unwrap();
        assert!(!rebound.matches(&source));
        fixture.memory.set(&key, rebound.bytes().to_vec());
        assert_eq!(
            fixture
                .catalogue
                .inspect_restore(CREATOR, 7, 700, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
    fixture.memory.set(&key, bytes);
    let empty = fixture
        .catalogue
        .prepare(
            CREATOR,
            &PrepareCreate {
                name: "other empty".into(),
                operation: 701,
                expected_name_revision: None,
                options: CreateOptions::default(),
            },
            deadline(),
        )
        .unwrap();
    let empty = fixture
        .catalogue
        .descriptor(&empty.creation, deadline())
        .unwrap();
    assert!(!original.matches(&empty));
}

#[test]
fn head9_restore_origin_cannot_be_unbound_partial_or_downgraded() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    let copying = fixture
        .catalogue
        .read_slot(&prepared.reference.creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    let bytes = encode_head(&copying).unwrap();
    assert_eq!(decode_head(&bytes, &copying.scope).unwrap(), copying);
    for field in 0..9 {
        let mut invalid = copying.clone();
        match field {
            0 => invalid.creation = None,
            1 => {
                invalid
                    .restore_origin
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .descriptor_hash = digest(b"another")
            }
            2 => invalid
                .restore_origin
                .as_mut()
                .unwrap()
                .as_mut()
                .unwrap()
                .descriptor_hash
                .clear(),
            3 => invalid.lifecycle = Lifecycle::Ready,
            4 => invalid.data_root = digest(b"arbitrary nonempty input"),
            5 => invalid.windows[0].root = digest(b"imported request identity"),
            6 => invalid.active = true,
            7 => invalid.sequence = 1,
            _ => invalid.windows[0].count = 1,
        }
        assert!(invalid.validate().is_err(), "copying field {field}");
    }
    for phase in [
        serde_json::json!({"kind":"copied"}),
        serde_json::json!({"kind":"copying","data_root":digest(b"bad")}),
        serde_json::json!({"kind":"unknown"}),
        serde_json::Value::Null,
    ] {
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["restore_origin"]["phase"] = phase;
        assert!(decode_head(&serde_json::to_vec(&json).unwrap(), &copying.scope).is_err());
    }
    assert_eq!(fixture.resume(&prepared, 2).phase, RestorePhase::Copied);
    let copied = fixture
        .catalogue
        .read_slot(&prepared.reference.creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    for field in 0..4 {
        let mut invalid = copied.clone();
        let RestoreCopyPhase::Copied {
            completion_hash,
            data_root,
            page_count,
        } = &mut invalid
            .restore_origin
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .phase
        else {
            panic!()
        };
        match field {
            0 => completion_hash.clear(),
            1 => data_root.clear(),
            2 => *page_count = u32::MAX,
            _ => invalid.data_root = digest(b"mismatched current root"),
        }
        assert!(matches!(invalid.validate(), Err(FormatError::Invalid)));
    }
    let source = fixture
        .catalogue
        .restore_descriptor(&prepared.reference, deadline())
        .unwrap();
    let mut erased = copying.clone();
    erased.restore_origin = Some(None);
    assert_eq!(
        fixture
            .catalogue
            .verify_restore_origin(&source, &erased, deadline()),
        Err(CatalogueError::Corrupt)
    );
    let mut ready_copying = copied;
    ready_copying.restore_origin = copying.restore_origin;
    fixture.memory.set(
        &head_key(&ready_copying.scope),
        encode_head(&ready_copying).unwrap(),
    );
    let mut binding = fixture
        .catalogue
        .read_binding(&prepared.reference.creation.name, deadline())
        .unwrap()
        .unwrap()
        .body
        .raw()
        .clone();
    binding.state = crate::catalogue::records::BindingState::Bound;
    binding.revision += 1;
    fixture.memory.set(
        &fixture.catalogue.binding_key(&binding.creation.name),
        records::encode(&binding).unwrap(),
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 700, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        fixture
            .catalogue
            .resolve(CREATOR, &prepared.reference.creation.name, deadline()),
        Err(CatalogueError::Corrupt)
    );
}
