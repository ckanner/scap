use super::*;
use crate::tests::{until, Memory};
use std::sync::Arc;

#[test]
fn request_envelope_is_strict_required_and_versioned() {
    for operation in ["list_names", "deployment_inventory"] {
        let value = parse(
            json!({"version":1,"operation":operation,"cursor":null})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        assert!(value.cursor.is_none());
        let _ = value.operation.view();
        assert_eq!(
            parse(
                json!({"version":1,"operation":operation,"cursor":"opaque"})
                    .to_string()
                    .as_bytes()
            )
            .unwrap()
            .cursor
            .as_deref(),
            Some("opaque")
        );
    }
    for value in [
        "{}",
        r#"{"version":1,"operation":"list_names"}"#,
        r#"{"version":1,"operation":"list_names","cursor":4}"#,
        r#"{"version":1,"operation":"list_names","cursor":null,"tenant":"8"}"#,
        r#"{"version":1,"version":1,"operation":"list_names","cursor":null}"#,
        r#"{"version":1,"operation":"query","cursor":null}"#,
    ] {
        assert_eq!(parse(value.as_bytes()).unwrap_err().code, "INVALID");
    }
    assert_eq!(
        parse(br#"{"version":2,"operation":"list_names","cursor":null}"#)
            .unwrap_err()
            .code,
        "VERSION"
    );
}

#[test]
fn all_classifications_and_failures_have_lossless_explicit_wire_values() {
    use self::core::{DiscoveryError as E, MetadataState as S, RecordKind as K};
    for (e, code) in [
        (E::Invalid, "INVALID"),
        (E::Denied, "DENIED"),
        (E::Limit, "LIMIT"),
        (E::Conflict, "CONFLICT"),
        (E::Unknown, "UNKNOWN"),
        (E::SnapshotExpired, "SNAPSHOT_EXPIRED"),
        (E::Corrupt, "CORRUPT"),
    ] {
        assert_eq!(error(e).code, code);
    }
    for s in [
        S::DescriptorOnly,
        S::Reserved,
        S::Provisioning,
        S::Bound,
        S::Ready,
        S::Maintenance,
        S::Aborting,
        S::Aborted,
        S::Deleting,
        S::Deleted,
        S::NameConflict,
        S::IdentityConflict,
        S::ControlAdmitted,
        S::Orphan,
    ] {
        assert!(!state(s).is_empty());
    }
    let scope = scap_object::format::Scope {
        deployment: 1,
        tenant: 2,
        database: u64::MAX,
        incarnation: u64::MAX,
        generation: 1,
    };
    let creation = core::Creation {
        creator: u64::MAX,
        operation: u64::MAX,
        name: "原始名称".into(),
        scope: scope.clone(),
        expected_name_revision: Some(u64::MAX),
    };
    let mut record_value = core::DiscoveredRecord {
        key: "scap-object/v1/1/2/1/head".into(),
        kind: K::Head,
        state: S::Ready,
        creation: Some(creation),
        scope: Some(scope),
        binding_revision: Some(u64::MAX),
        head_revision: Some(u64::MAX),
        control: None,
    };
    for kind in [
        K::Name,
        K::Create,
        K::Control,
        K::AbortProof,
        K::Head,
        K::OrphanPrefix,
    ] {
        record_value.kind = kind;
        let value = record(&record_value);
        assert!(value["kind"].is_string());
        assert_eq!(value["head_revision"], u64::MAX.to_string());
    }
    record_value.kind = K::Control;
    for (kind, expected_head_revision) in [
        (scap_object::format::NamedDeletionKind::Abort, None),
        (
            scap_object::format::NamedDeletionKind::Delete,
            Some(u64::MAX),
        ),
    ] {
        record_value.control = Some(core::ObservedControl {
            kind,
            principal: u64::MAX,
            operation: u64::MAX,
            expected_name_revision: u64::MAX,
            expected_head_revision,
            nonce: u64::MAX,
        });
        let projected = record(&record_value);
        assert_eq!(projected["control"]["nonce"], u64::MAX.to_string());
        assert_eq!(
            projected["control"]["expected_head_revision"],
            expected_head_revision
                .map(|v| json!(v.to_string()))
                .unwrap_or(Value::Null)
        );
    }
    let memory = Arc::new(Memory::default());
    let inv = core::RecoveryInventory::new(
        memory.clone(),
        memory.clone(),
        core::RecoveryCapability::trusted_deployment(1, 100).unwrap(),
        scap_object::Options::default(),
    )
    .unwrap();
    let mut page = inv
        .page(inv.begin(), core::DiscoveryBudget::default(), until())
        .unwrap();
    page.records.push(record_value);
    page.stopped = Some(E::Unknown);
    assert_eq!(
        inventory(&page, Some("opaque".into()))["stopped"],
        "UNKNOWN"
    );
    let catalogue =
        core::Catalogue::new(memory.clone(), 1, 2, 100, scap_object::Options::default()).unwrap();
    let listing = core::VisibleNames::new(catalogue, memory);
    let caller = core::Caller {
        principal: 3,
        provision: false,
    };
    let mut page = listing
        .page(
            caller,
            listing.begin(caller).unwrap(),
            core::DiscoveryBudget::default(),
            until(),
        )
        .unwrap();
    page.stopped = Some(E::Conflict);
    assert_eq!(names(&page, Some("opaque".into()))["stopped"], "CONFLICT");
}
