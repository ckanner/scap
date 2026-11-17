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
    for field in 0..15 {
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
                    12 => snapshot_limits.max_points = 65,
                    13 => source_scope.deployment += 1,
                    _ => point.page_count = crate::format::MAX_PAGES,
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
    let mut ready_copying = copied.clone();
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
    let view = fixture.catalogue.view(&source, deadline()).unwrap();
    let binding = view.binding.as_ref().unwrap();
    let base = view.head.as_ref().unwrap();
    assert_eq!(
        fixture
            .catalogue
            .complete(&source, binding, base, deadline()),
        Err(CatalogueError::Corrupt)
    );
    assert_eq!(
        fixture.catalogue.metadata_state(&source, &view, deadline()),
        Err(CatalogueError::Corrupt)
    );
    let cancellation = AbortCreate {
        creation: prepared.reference.creation.clone(),
        operation: 710,
        expected_name_revision: 1,
        nonce: 711,
    };
    assert_eq!(
        fixture
            .catalogue
            .abort_restore(CREATOR, &prepared.reference, &cancellation, deadline()),
        Err(CatalogueError::Corrupt)
    );
    fixture.memory.remove(&fixture.completion_key(&prepared));
    let original = Snapshot {
        head: copied,
        etag: base.etag.clone(),
    };
    assert_eq!(
        fixture
            .catalogue
            .complete(&source, binding, &original, deadline()),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn public_admission_and_internal_scope_bindings_reject_substituted_restore_authority() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    let source = fixture
        .catalogue
        .restore_descriptor(&prepared.reference, deadline())
        .unwrap();
    for field in 0..4 {
        let mut input = fixture.input();
        match field {
            0 => input.name.clear(),
            1 => input.source_scope.deployment += 1,
            2 => input.source_scope.tenant += 1,
            _ => {
                input.operation += 1;
                input.source_scope = records::derive_scope(1, 2, 7, input.operation).unwrap();
            }
        }
        assert_eq!(
            fixture
                .catalogue
                .prepare_restore(CREATOR, &input, deadline()),
            Err(CatalogueError::Invalid)
        );
    }
    for field in 0..2 {
        let mut scope = scope();
        if field == 0 {
            scope.deployment += 1;
        } else {
            scope.tenant += 1;
        }
        assert!(matches!(
            fixture.catalogue.restore_source_database(&scope),
            Err(CatalogueError::Invalid)
        ));
    }
    for (creator, operation) in [(8, 700), (7, 701)] {
        assert_eq!(
            fixture
                .catalogue
                .restore_existing(creator, operation, source.clone()),
            Err(CatalogueError::Corrupt)
        );
    }
    for field in 0..2 {
        let mut record = source.raw().clone();
        let Recipe::SnapshotRestore { source_scope, .. } = record.recipe.as_mut().unwrap();
        if field == 0 {
            source_scope.deployment += 1;
        } else {
            source_scope.tenant += 1;
        }
        record.creation.scope =
            records::derive_scope(source_scope.deployment, source_scope.tenant, 7, 700).unwrap();
        assert_eq!(
            fixture
                .catalogue
                .restore_existing(7, 700, Canonical::new(record).unwrap()),
            Err(CatalogueError::Corrupt)
        );
    }
    assert_eq!(
        fixture.catalogue.inspect_restore(CREATOR, 7, 0, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 999, deadline()),
        Err(CatalogueError::NotFound)
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 8, 700, deadline()),
        Err(CatalogueError::Denied)
    );
    let mut denied = CREATOR;
    denied.provision = false;
    let path = fixture.directory.path().join("not-admitted");
    assert_eq!(
        fixture.catalogue.resume_restore(
            denied,
            &prepared.reference,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &path,
            RestoreBudget {
                source_gets: u64::MAX,
                ..RestoreBudget::default()
            },
            deadline()
        ),
        Err(CatalogueError::Invalid)
    );
    let mut wrong = prepared.reference.clone();
    wrong.descriptor_hash = digest(b"other valid hash");
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &wrong,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Conflict)
    );
    wrong.descriptor_hash.clear();
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &wrong,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Invalid)
    );
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
    let empty = fixture
        .catalogue
        .descriptor(&empty.creation, deadline())
        .unwrap();
    let empty_ref = RestoreRef {
        creation: empty.creation.clone(),
        descriptor_hash: empty.hash().into(),
    };
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &empty_ref,
            &path,
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        fixture
            .catalogue
            .inspect_restore(CREATOR, 7, 701, deadline()),
        Err(CatalogueError::Conflict)
    );
    let cancellation = AbortCreate {
        creation: empty.creation.clone(),
        operation: 710,
        expected_name_revision: 1,
        nonce: 711,
    };
    assert_eq!(
        fixture
            .catalogue
            .abort_restore(CREATOR, &prepared.reference, &cancellation, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        fixture
            .catalogue
            .abort_restore(denied, &prepared.reference, &cancellation, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        fixture
            .catalogue
            .abort_restore(CREATOR, &wrong, &cancellation, deadline()),
        Err(CatalogueError::Invalid)
    );
    assert!(!path.exists());
}

#[test]
fn completion_and_cold_open_bind_every_origin_field_and_preserve_metadata_failure_classes() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    for step in 0..3 {
        fixture.resume(&prepared, step);
    }
    let source = fixture
        .catalogue
        .restore_descriptor(&prepared.reference, deadline())
        .unwrap();
    let copied = fixture
        .catalogue
        .read_slot(&prepared.reference.creation.scope, deadline())
        .unwrap()
        .unwrap()
        .head;
    for field in 0..6 {
        let mut invalid = copied.clone();
        let origin = invalid.restore_origin.as_mut().unwrap().as_mut().unwrap();
        let RestoreCopyPhase::Copied {
            completion_hash,
            data_root,
            page_count,
        } = &mut origin.phase
        else {
            panic!()
        };
        match field {
            0 => origin.descriptor_hash = digest(b"another descriptor"),
            1 => *completion_hash = digest(b"other completion"),
            2 => *data_root = digest(b"other import"),
            3 => *page_count += 1,
            4 => invalid.windows[0].root = digest(b"other requests"),
            _ => invalid.restore_origin = Some(None),
        }
        assert_eq!(
            fixture
                .catalogue
                .verify_restore_origin(&source, &invalid, deadline()),
            Err(CatalogueError::Corrupt),
            "field {field}"
        );
    }
    let target = fixture.catalogue.database(&source);
    for field in 0..3 {
        let mut invalid = copied.clone();
        match field {
            0 => invalid.creation = None,
            1 => invalid.scope.incarnation += 1,
            _ => invalid.creation.as_mut().unwrap().descriptor_hash = digest(b"other origin"),
        }
        assert!(matches!(
            Catalogue::verify_database_restore(&target, &invalid, deadline()),
            Err(Error::Corrupt)
        ));
    }
    for fault in [StoreError::Unknown, StoreError::Budget] {
        fixture.memory.cut(
            false,
            &fixture.catalogue.descriptor_key(7, 700),
            None,
            0,
            Fault::Before(fault.clone()),
        );
        let result = Catalogue::verify_database_restore(&target, &copied, deadline());
        assert!(matches!(
            (fault, result),
            (StoreError::Unknown, Err(Error::Unknown)) | (StoreError::Budget, Err(Error::Limit))
        ));
    }
    // Independent semantic validators reject malformed private callers too;
    // the public full HEAD decoder often detects these common fields earlier.
    let mut copying = copied.clone();
    copying
        .restore_origin
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .phase = RestoreCopyPhase::Copying {};
    for field in 0..5 {
        let mut invalid = copying.clone();
        match field {
            0 => invalid.active = true,
            1 => invalid.sequence = 1,
            2 => invalid.request_epoch = 2,
            3 => invalid.windows[0].count = 1,
            _ => invalid.windows[0].result_bytes = 1,
        }
        assert!(crate::restore_format::validate_head(&invalid).is_err());
    }
    let mut without_origin = copying.clone();
    without_origin.restore_origin = Some(None);
    assert_eq!(
        Catalogue::provisioning(&source, &without_origin),
        Err(CatalogueError::Corrupt)
    );
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
    let empty = fixture
        .catalogue
        .descriptor(&empty.creation, deadline())
        .unwrap();
    copying.scope = empty.creation.scope.clone();
    copying.creation = Some(empty.origin());
    assert_eq!(
        Catalogue::provisioning(&empty, &copying),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn completed_copy_validation_rejects_unbound_records_and_mismatched_target_page_counts() {
    let fixture = Fixture::new(false);
    let prepared = fixture.prepare();
    fixture.copying(&prepared);
    fixture.memory.cut(
        true,
        &fixture.completion_key(&prepared),
        None,
        0,
        Fault::AfterPut,
    );
    assert_eq!(
        fixture.catalogue.resume_restore(
            CREATOR,
            &prepared.reference,
            &fixture.directory.path().join("copy"),
            RestoreBudget::default(),
            deadline()
        ),
        Err(CatalogueError::Unknown)
    );
    let source = fixture
        .catalogue
        .restore_descriptor(&prepared.reference, deadline())
        .unwrap();
    let base = fixture
        .catalogue
        .read_slot(&prepared.reference.creation.scope, deadline())
        .unwrap()
        .unwrap();
    let original = fixture
        .catalogue
        .read_completion(&source, deadline())
        .unwrap()
        .unwrap();
    for field in 0..4 {
        let mut record = original.raw().clone();
        match field {
            0 => record.descriptor_hash = digest(b"other descriptor"),
            1 => record.request_root = digest(b"other request window"),
            2 => record.data_root = digest(b"missing data tree"),
            _ => record.page_count = 1,
        }
        let path = fixture.directory.path().join("unbound-completion");
        assert_eq!(
            fixture.catalogue.validate_completed_copy(
                &source,
                &base,
                &record,
                &path,
                RestoreBudget::default(),
                deadline()
            ),
            Err(CatalogueError::Corrupt),
            "field {field}"
        );
        assert!(!path.exists());
    }
    assert_eq!(
        fixture.catalogue.validate_completed_copy(
            &source,
            &base,
            original.raw(),
            &fixture.directory.path().join("zero-disk"),
            RestoreBudget {
                max_image_bytes: 0,
                ..RestoreBudget::default()
            },
            deadline()
        ),
        Ok(())
    );
    // An empty database is legitimately zero logical image bytes; the caller
    // disables copying through the I/O directions, not this image limit alone.
}
