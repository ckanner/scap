use super::*;
use crate::catalogue::discovery::{component, frontier, Phase};
use crate::catalogue::discovery_budget::Meter;
use scap_object_store::{
    ListEnd, ListEntry, ListError, ListKind, ListMode, ListPage, ListRequest, Listings,
};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Default)]
struct ListState {
    calls: Vec<(String, Option<String>)>,
    fault: Option<(String, Result<ListPage, ListError>)>,
}

pub(in crate::catalogue) struct Listing {
    objects: Arc<Memory>,
    size: usize,
    state: Mutex<ListState>,
}

impl Listing {
    pub(in crate::catalogue) fn new(objects: Arc<Memory>) -> Arc<Self> {
        Arc::new(Self {
            objects,
            size: 3,
            state: Mutex::new(ListState::default()),
        })
    }

    fn fault(&self, prefix: &str, outcome: Result<ListPage, ListError>) {
        self.state.lock().unwrap().fault = Some((prefix.into(), outcome));
    }
}

impl Listings for Listing {
    fn list_page(
        &self,
        request: &ListRequest<'_>,
        _deadline: Instant,
    ) -> Result<ListPage, ListError> {
        let mut state = self.state.lock().unwrap();
        state
            .calls
            .push((request.prefix.into(), request.after.map(str::to_owned)));
        if state
            .fault
            .as_ref()
            .is_some_and(|(prefix, _)| prefix == request.prefix)
        {
            return state.fault.take().unwrap().1;
        }
        drop(state);
        let values = self.objects.state.lock().unwrap();
        let mut entries = BTreeSet::new();
        for key in values
            .values
            .keys()
            .filter(|key| key.starts_with(request.prefix))
        {
            let key = if request.mode == ListMode::Children {
                match key[request.prefix.len()..].find('/') {
                    Some(index) => &key[..request.prefix.len() + index + 1],
                    None => key,
                }
            } else {
                key
            };
            if request
                .after
                .is_none_or(|after| key.as_bytes() > after.as_bytes())
            {
                entries.insert(key.to_owned());
            }
        }
        let more = entries.len() > self.size;
        let entries: Vec<_> = entries
            .into_iter()
            .take(self.size)
            .map(|key| {
                let kind = if key.ends_with('/') {
                    ListKind::Prefix
                } else {
                    ListKind::Object
                };
                ListEntry { key, kind }
            })
            .collect();
        let end = if more {
            ListEnd::More {
                after: entries.last().unwrap().key.clone(),
            }
        } else {
            ListEnd::Exhausted
        };
        Ok(ListPage {
            entries,
            end,
            response_bytes: 128,
        })
    }
}

fn inventory(objects: Arc<Memory>, listing: Arc<Listing>) -> RecoveryInventory {
    RecoveryInventory::new(
        objects,
        listing,
        RecoveryCapability::trusted_deployment(1, 10).unwrap(),
        crate::tests::test_options(),
    )
    .unwrap()
}

fn all(scan: &RecoveryInventory) -> Vec<DiscoveredRecord> {
    let mut cursor = scan.begin();
    let mut records = Vec::new();
    for _ in 0..200 {
        let page = scan
            .page(cursor, DiscoveryBudget::default(), deadline())
            .unwrap();
        assert_eq!(page.completion.data_recovery, DataRecovery::NotRun);
        assert!(!page.completion.recovery_complete);
        records.extend(page.records);
        if page.completion.traversal_exhausted {
            assert!(page.completion.preexisting_slots_covered);
            assert_eq!(page.completion.metadata_classified, records.len() as u64);
            assert!(page.stopped.is_none());
            return records;
        }
        assert_eq!(page.stopped, Some(DiscoveryError::Limit));
        cursor = scan
            .resume_authenticated(&scan.checkpoint(&page.cursor).unwrap())
            .unwrap();
    }
    panic!("finite metadata did not terminate")
}

fn set_head(objects: &Memory, scope: &Scope, change: impl FnOnce(&mut Head)) {
    let key = format::head_key(scope);
    let mut head = format::decode_head(&objects.get_value(&key).unwrap().bytes, scope).unwrap();
    change(&mut head);
    objects.set(&key, format::encode_head(&head).unwrap());
}

#[test]
fn deployment_discovery_enumerates_all_permanent_classes_without_an_inventory_input() {
    let objects = Arc::new(Memory::default());
    for tenant in [2, 10, 99, 100] {
        let cat =
            Catalogue::new(objects.clone(), 1, tenant, 10, crate::tests::test_options()).unwrap();
        for operation in 1..=4 {
            let creation = cat
                .prepare(
                    CREATOR,
                    &input(&format!("t{tenant}-n{operation}"), operation, None),
                    deadline(),
                )
                .unwrap()
                .creation;
            if operation != 4 {
                cat.resume_create(CREATOR, &creation, deadline()).unwrap();
            }
        }
        let direct = Scope {
            deployment: 1,
            tenant,
            database: 17,
            incarnation: 9,
            generation: 1,
        };
        Database::new(objects.clone(), direct, 10)
            .unwrap()
            .create(7, 1, deadline())
            .unwrap();
        objects.set(
            &format!("scap-object/v1/{tenant}/999/1/inc/1/gen/1/objects/orphan"),
            vec![1],
        );
    }
    let cat = catalogue(objects.clone());
    let old = cat
        .prepare(CREATOR, &input("reused", 55, None), deadline())
        .unwrap()
        .creation;
    cat.resume_create(CREATOR, &old, deadline()).unwrap();
    cat.delete(CREATOR, &delete(&old), deadline()).unwrap();
    let replacement = cat
        .prepare(CREATOR, &input("reused", 56, Some(3)), deadline())
        .unwrap()
        .creation;
    cat.resume_create(CREATOR, &replacement, deadline())
        .unwrap();
    let pending = cat
        .prepare(CREATOR, &input("cancelled", 60, None), deadline())
        .unwrap()
        .creation;
    objects.cut(
        true,
        &format::head_key(&pending.scope),
        Some(("lifecycle", "provisioning")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert!(cat.resume_create(CREATOR, &pending, deadline()).is_err());
    cat.abort_create(CREATOR, &abort(&pending), deadline())
        .unwrap();
    objects.clear_calls();
    let listing = Listing::new(objects.clone());
    let scan = inventory(objects.clone(), listing.clone());
    let records = all(&scan);
    let actual: BTreeSet<_> = records.iter().map(|record| record.key.clone()).collect();
    let expected: BTreeSet<_> = objects
        .state
        .lock()
        .unwrap()
        .values
        .keys()
        .filter(|key| {
            key.starts_with("scap-object/v1/1/")
                && (key.contains("/catalogue/v1/") || key.ends_with("/head"))
        })
        .cloned()
        .collect();
    assert_eq!(actual, expected);
    assert!(records
        .iter()
        .any(|record| record.kind == RecordKind::AbortProof));
    assert!(records
        .iter()
        .any(|record| record.creation.as_ref() == Some(&old)
            && record.state == MetadataState::Deleted));
    assert!(records
        .iter()
        .any(|record| record.kind == RecordKind::Head && record.creation.is_none()));
    assert!(records
        .iter()
        .any(|record| record.state == MetadataState::DescriptorOnly));
    assert!(objects.calls().iter().all(|call| !call.put));
    let calls = &listing.state.lock().unwrap().calls;
    assert!(calls
        .iter()
        .any(|(prefix, after)| prefix == "scap-object/v1/1/" && after.is_some()));
}

#[test]
fn pending_stages_are_metadata_not_ready_or_implicit_resumption() {
    for (phase, state) in [
        (CreationPhase::Reserved, MetadataState::Reserved),
        (CreationPhase::Provisioning, MetadataState::Provisioning),
        (CreationPhase::Bound, MetadataState::Bound),
        (CreationPhase::Ready, MetadataState::Ready),
    ] {
        let (objects, _, _) = stage(phase);
        objects.clear_calls();
        let records = all(&inventory(objects.clone(), Listing::new(objects.clone())));
        assert!(records
            .iter()
            .filter(|record| matches!(record.kind, RecordKind::Name | RecordKind::Create))
            .all(|record| record.state == state));
        assert!(objects.calls().iter().all(|call| !call.put));
    }
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    set_head(&objects, &creation.scope, |head| {
        head.lifecycle = Lifecycle::Maintenance;
        head.policy[0].read = false;
    });
    assert_eq!(
        cat.inspect_create_operation(CREATOR, creation.operation, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert!(all(&inventory(objects.clone(), Listing::new(objects)))
        .iter()
        .all(|record| record.state == MetadataState::Maintenance));
}

#[test]
fn budgets_keep_unclassified_tail_and_get_failures_resumable() {
    let objects = Arc::new(Memory::default());
    let cat = catalogue(objects.clone());
    for operation in 1..=5 {
        let creation = cat
            .prepare(
                CREATOR,
                &input(&format!("n{operation}"), operation, None),
                deadline(),
            )
            .unwrap()
            .creation;
        cat.resume_create(CREATOR, &creation, deadline()).unwrap();
    }
    let scan = inventory(objects.clone(), Listing::new(objects.clone()));
    let budget = DiscoveryBudget {
        candidates: 2,
        ..DiscoveryBudget::default()
    };
    let page = scan.page(scan.begin(), budget, deadline()).unwrap();
    assert_eq!(page.records.len(), 1); // The tenant prefix consumed one candidate.
    assert_eq!(page.stopped, Some(DiscoveryError::Limit));
    let remaining = scan
        .page(page.cursor.clone(), DiscoveryBudget::default(), deadline())
        .unwrap();
    assert!(!remaining
        .records
        .iter()
        .any(|record| record.key == page.records[0].key));
    for budget in [
        DiscoveryBudget {
            exact_gets: 0,
            ..DiscoveryBudget::default()
        },
        DiscoveryBudget {
            metadata_bytes: 0,
            ..DiscoveryBudget::default()
        },
        DiscoveryBudget {
            metadata_bytes: 1,
            ..DiscoveryBudget::default()
        },
        DiscoveryBudget {
            list_pages: 0,
            ..DiscoveryBudget::default()
        },
        DiscoveryBudget {
            list_bytes: 1,
            ..DiscoveryBudget::default()
        },
    ] {
        let page = scan.page(scan.begin(), budget, deadline()).unwrap();
        assert_eq!(page.stopped, Some(DiscoveryError::Limit));
        assert!(!page.completion.preexisting_slots_covered);
        assert!(page.records.is_empty());
    }
    let key = format!("{}/name/", cat.prefix());
    let listing = Listing::new(objects);
    for error in [
        ListError::Denied,
        ListError::Unknown,
        ListError::Corrupt,
        ListError::Limit,
        ListError::Invalid,
    ] {
        listing.fault(&key, Err(error));
        let scan = inventory(listing.objects.clone(), listing.clone());
        let page = scan
            .page(scan.begin(), DiscoveryBudget::default(), deadline())
            .unwrap();
        assert_eq!(page.stopped, Some(error.into()));
        assert!(!page.completion.traversal_exhausted);
    }
}

#[test]
fn visible_names_use_fresh_read_not_admin_or_provision_and_never_expose_pending_records() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    cat.prepare(CREATOR, &input("descriptor only", 2, None), deadline())
        .unwrap();
    let names = VisibleNames::new(cat, Listing::new(objects.clone()));
    let cursor = names.begin(CREATOR).unwrap();
    let page = names
        .page(
            CREATOR,
            cursor.clone(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert!(page.traversal_exhausted);
    assert_eq!(page.names[0].creation, creation);
    set_head(&objects, &creation.scope, |head| {
        head.policy[0].read = false
    });
    let page = names
        .page(
            CREATOR,
            cursor.clone(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert!(page.names.is_empty());
    assert!(page.traversal_exhausted);
    let caller = Caller {
        principal: 8,
        provision: true,
    };
    let page = names
        .page(
            caller,
            names.begin(caller).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert!(page.names.is_empty());
    set_head(&objects, &creation.scope, |head| head.policy[0].read = true);
    let page = names
        .page(
            Caller {
                provision: false,
                ..CREATOR
            },
            cursor,
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.names.len(), 1);
    assert!(page.stopped.is_none());
}

#[test]
fn cursor_roundtrip_is_strict_bound_to_context_and_has_no_health_claim() {
    let objects = Arc::new(Memory::default());
    let scan = inventory(objects.clone(), Listing::new(objects.clone()));
    let page = scan
        .page(scan.begin(), DiscoveryBudget::default(), deadline())
        .unwrap();
    assert!(page.completion.traversal_exhausted);
    let encoded = scan.checkpoint(&page.cursor).unwrap();
    let decoded = scan.resume_authenticated(&encoded).unwrap();
    assert!(
        scan.page(decoded, DiscoveryBudget::default(), deadline())
            .unwrap()
            .completion
            .traversal_exhausted
    );
    let other = inventory(objects.clone(), Listing::new(objects.clone()));
    assert_eq!(other.checkpoint(&page.cursor), Err(DiscoveryError::Invalid));
    assert!(matches!(
        other.page(page.cursor, DiscoveryBudget::default(), deadline()),
        Err(DiscoveryError::Invalid)
    ));
    for bytes in [
        b"{}".to_vec(),
        vec![b'x'; 8193],
        [encoded.clone(), vec![b' ']].concat(),
    ] {
        assert!(matches!(
            scan.resume_authenticated(&bytes),
            Err(DiscoveryError::Invalid)
        ));
    }
    let cat = catalogue(objects.clone());
    let names = VisibleNames::new(cat.clone(), Listing::new(objects.clone()));
    let name_cursor = names.begin(CREATOR).unwrap();
    let encoded = names.checkpoint(&name_cursor).unwrap();
    let restored = names.resume_authenticated(CREATOR, &encoded).unwrap();
    assert!(
        names
            .page(CREATOR, restored, DiscoveryBudget::default(), deadline())
            .unwrap()
            .traversal_exhausted
    );
    let other = VisibleNames::new(cat, Listing::new(objects));
    assert!(matches!(
        other.page(
            CREATOR,
            name_cursor.clone(),
            DiscoveryBudget::default(),
            deadline()
        ),
        Err(DiscoveryError::Invalid)
    ));
    assert_eq!(other.checkpoint(&name_cursor), Err(DiscoveryError::Invalid));
    assert!(matches!(
        names.page(
            Caller {
                principal: 8,
                provision: true
            },
            name_cursor,
            DiscoveryBudget::default(),
            deadline()
        ),
        Err(DiscoveryError::Invalid)
    ));
    for bytes in [
        b"{}".to_vec(),
        vec![b'x'; 8193],
        [encoded, vec![b' ']].concat(),
    ] {
        assert!(matches!(
            names.resume_authenticated(CREATOR, &bytes),
            Err(DiscoveryError::Invalid)
        ));
    }
}

#[test]
fn frontiers_are_typed_canonical_keys_not_numeric_sort_or_arbitrary_paths() {
    let tenant = "scap-object/v1/1/2/";
    for (phase, suffix) in [
        (
            Phase::Names,
            format!("catalogue/v1/name/{}", "a".repeat(64)),
        ),
        (Phase::Creates, "catalogue/v1/create/7/2".into()),
        (Phase::Controls, "catalogue/v1/control/7/abort/2".into()),
        (Phase::Controls, "catalogue/v1/control/7/delete/2".into()),
        (Phase::Proofs, "catalogue/v1/abort-proof/7/2".into()),
        (Phase::Slots, "catalogue/".into()),
        (Phase::Slots, "17/".into()),
    ] {
        assert_eq!(
            frontier(&format!("{tenant}{suffix}"), tenant, phase),
            Ok(())
        );
        assert_eq!(
            frontier(&format!("x{tenant}{suffix}"), tenant, phase),
            Err(DiscoveryError::Invalid)
        );
    }
    for invalid in ["0", "01", "-1", "+1", "18446744073709551616", "1/2", ""] {
        assert_eq!(component(invalid, "", false), Err(DiscoveryError::Corrupt));
    }
    assert_eq!(component("1", "", true), Err(DiscoveryError::Corrupt));
    assert_eq!(component("p/1/", "q/", true), Err(DiscoveryError::Corrupt));
    assert_eq!(component("p/1/", "p/", true), Ok(1));
}

#[test]
fn missing_or_corrupt_authority_never_becomes_complete_empty() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let listing = Listing::new(objects.clone());
    let scan = inventory(objects.clone(), listing.clone());
    objects.remove(&cat.descriptor_key(creation.creator, creation.operation));
    let page = scan
        .page(scan.begin(), DiscoveryBudget::default(), deadline())
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Corrupt));
    assert!(!page.completion.traversal_exhausted);
    assert!(page.records.is_empty());
    let names = VisibleNames::new(cat, listing);
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Corrupt));
    assert!(!page.traversal_exhausted);
}

#[test]
fn metadata_meter_counts_errors_and_blocks_writes() {
    let objects = Arc::new(Memory::default());
    objects.set("key", vec![1, 2]);
    let meter = Meter::new(objects, DiscoveryBudget::default(), Instant::now);
    assert_eq!(meter.get("key", 2, deadline()).unwrap().bytes, vec![1, 2]);
    assert_eq!(meter.get("absent", 2, deadline()), Err(StoreError::Missing));
    assert_eq!(meter.usage().exact_gets, 2);
    assert_eq!(meter.usage().metadata_bytes, 4);
    assert_eq!(
        meter.put("key", &[], Condition::Absent, deadline()),
        Err(StoreError::Invalid)
    );
    assert_eq!(
        meter.get("key", 2, Instant::now()),
        Err(StoreError::Unknown)
    );
    assert_eq!(
        meter.candidate(Instant::now()),
        Err(DiscoveryError::Unknown)
    );
    assert_eq!(meter.page(Instant::now()), Err(DiscoveryError::Unknown));
    assert_eq!(meter.listed(1024 * 1024 + 1), Err(DiscoveryError::Corrupt));
}

#[test]
fn errors_and_configuration_are_explicit() {
    assert!(RecoveryCapability::trusted_deployment(0, 1).is_err());
    assert!(RecoveryCapability::trusted_deployment(1, 0).is_err());
    let objects = Arc::new(Memory::default());
    let mut options = crate::tests::test_options();
    options.max_input_bytes = 0;
    assert!(matches!(
        RecoveryInventory::new(
            objects.clone(),
            Listing::new(objects),
            RecoveryCapability::trusted_deployment(1, 1).unwrap(),
            options
        ),
        Err(DiscoveryError::Invalid)
    ));
    for (source, expected) in [
        (CatalogueError::Invalid, DiscoveryError::Invalid),
        (CatalogueError::Denied, DiscoveryError::Denied),
        (CatalogueError::Limit, DiscoveryError::Limit),
        (CatalogueError::Conflict, DiscoveryError::Conflict),
        (CatalogueError::IdentityConflict, DiscoveryError::Conflict),
        (CatalogueError::Unknown, DiscoveryError::Unknown),
        (CatalogueError::NotFound, DiscoveryError::Corrupt),
        (CatalogueError::Corrupt, DiscoveryError::Corrupt),
    ] {
        assert_eq!(DiscoveryError::from(source), expected);
    }
    for field in 0..5 {
        let mut budget = DiscoveryBudget::default();
        match field {
            0 => budget.list_pages += 1,
            1 => budget.candidates += 1,
            2 => budget.exact_gets += 1,
            3 => budget.list_bytes += 1,
            _ => budget.metadata_bytes += 1,
        }
        assert_eq!(budget.validate(), Err(DiscoveryError::Invalid));
    }
}

fn entry(key: String, kind: ListKind) -> ListEntry {
    ListEntry { key, kind }
}

#[test]
fn admitted_and_accepted_controls_keep_their_exact_original_identity() {
    let (objects, cat, creation) = prepared();
    assert_eq!(
        cat.abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::NotReserved
    );
    let records = all(&inventory(objects.clone(), Listing::new(objects)));
    assert!(records
        .iter()
        .any(|record| record.kind == RecordKind::Control
            && record.state == MetadataState::ControlAdmitted));

    let (objects, cat, creation) = stage(CreationPhase::Reserved);
    objects.cut(
        true,
        &cat.proof_key(&creation),
        None,
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        cat.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Unknown)
    );
    let records = all(&inventory(objects.clone(), Listing::new(objects.clone())));
    assert!(records.iter().any(
        |record| record.kind == RecordKind::Control && record.state == MetadataState::Aborting
    ));
    objects.cut(
        true,
        &cat.binding_key(&creation.name),
        Some(("state", "tombstone")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        cat.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Unknown)
    );
    let records = all(&inventory(objects.clone(), Listing::new(objects.clone())));
    assert!(records
        .iter()
        .any(|record| record.kind == RecordKind::AbortProof
            && record.state == MetadataState::Aborting));
    cat.abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    let mut losing = abort(&creation);
    losing.operation += 1;
    assert_eq!(
        cat.abort_create(CREATOR, &losing, deadline()),
        Err(CatalogueError::Conflict)
    );
    let records = all(&inventory(objects.clone(), Listing::new(objects.clone())));
    assert!(records
        .iter()
        .any(|record| record.kind == RecordKind::Control
            && record.state == MetadataState::ControlAdmitted));
    let replacement = cat
        .prepare(CREATOR, &input(&creation.name, 100, Some(3)), deadline())
        .unwrap()
        .creation;
    cat.resume_create(CREATOR, &replacement, deadline())
        .unwrap();
    let records = all(&inventory(objects.clone(), Listing::new(objects)));
    assert!(records
        .iter()
        .any(|record| record.kind == RecordKind::AbortProof
            && record.creation.as_ref() == Some(&creation)
            && record.state == MetadataState::Aborted));

    let (objects, cat, creation) = stage(CreationPhase::Ready);
    objects.cut(
        true,
        &cat.binding_key(&creation.name),
        Some(("state", "tombstone")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    assert_eq!(
        cat.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::Unknown)
    );
    let records = all(&inventory(objects.clone(), Listing::new(objects)));
    assert!(records.iter().any(
        |record| record.kind == RecordKind::Control && record.state == MetadataState::Deleting
    ));
}

#[test]
fn direct_slots_orphans_and_metadata_corruption_are_distinguished() {
    let objects = Arc::new(Memory::default());
    let cat = catalogue(objects.clone());
    let scope = Scope {
        deployment: 1,
        tenant: 2,
        database: 17,
        incarnation: 9,
        generation: 1,
    };
    Database::new(objects.clone(), scope.clone(), 10)
        .unwrap()
        .create(7, 1, deadline())
        .unwrap();
    let slot = entry("scap-object/v1/1/2/17/".into(), ListKind::Prefix);
    for lifecycle in [Lifecycle::Ready, Lifecycle::Maintenance, Lifecycle::Deleted] {
        set_head(&objects, &scope, |head| head.lifecycle = lifecycle);
        assert_eq!(
            cat.discover_record(Phase::Slots, &slot, deadline())
                .unwrap()
                .unwrap()
                .kind,
            RecordKind::Head
        );
    }
    let orphan = entry("scap-object/v1/1/2/18/".into(), ListKind::Prefix);
    objects.set(
        "scap-object/v1/1/2/18/inc/9/gen/1/objects/unpublished",
        vec![9],
    );
    assert_eq!(
        cat.discover_record(Phase::Slots, &orphan, deadline())
            .unwrap()
            .unwrap()
            .state,
        MetadataState::Orphan
    );
    let key = format::head_key(&scope);
    let original = objects.get_value(&key).unwrap().bytes;
    for error in [StoreError::Unknown, StoreError::Conflict, StoreError::Limit] {
        objects.cut(false, &key, None, 0, Fault::Before(error.clone()));
        assert!(cat
            .discover_record(Phase::Slots, &slot, deadline())
            .is_err());
    }
    objects.cut(false, &key, None, 0, Fault::EmptyEtag);
    assert_eq!(
        cat.discover_record(Phase::Slots, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
    objects.set(&key, b"not JSON".to_vec());
    assert_eq!(
        cat.discover_record(Phase::Slots, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
    let mut head: Head = serde_json::from_slice(&original).unwrap();
    head.scope.deployment = 2;
    objects.set(&key, serde_json::to_vec(&head).unwrap());
    assert_eq!(
        cat.discover_record(Phase::Slots, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
    head.scope.deployment = 1;
    head.scope.tenant = 3;
    objects.set(&key, serde_json::to_vec(&head).unwrap());
    assert_eq!(
        cat.discover_record(Phase::Slots, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
    head.scope.tenant = 2;
    head.scope.database = 19;
    objects.set(&key, serde_json::to_vec(&head).unwrap());
    assert_eq!(
        cat.discover_record(Phase::Slots, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
    head.scope.database = 17;
    head.scope.incarnation = 0;
    objects.set(&key, serde_json::to_vec(&head).unwrap());
    assert_eq!(
        cat.discover_record(Phase::Slots, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
    assert_eq!(
        cat.discover_record(Phase::Slots, &entry(key, ListKind::Object), deadline()),
        Err(DiscoveryError::Corrupt)
    );
    assert_eq!(
        cat.discover_record(Phase::Names, &slot, deadline()),
        Err(DiscoveryError::Corrupt)
    );
}

#[test]
fn listed_missing_authority_and_name_races_do_not_advance_the_frontier() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let key = cat.binding_key(&creation.name);
    let scan = inventory(objects.clone(), Listing::new(objects.clone()));
    objects.cut(false, &key, None, 0, Fault::Before(StoreError::Missing));
    let page = scan
        .page(scan.begin(), DiscoveryBudget::default(), deadline())
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Corrupt));
    assert!(page.records.is_empty());
    let bytes = scan.checkpoint(&page.cursor).unwrap();
    assert!(String::from_utf8(bytes).unwrap().contains("\"after\":null"));
    assert!(!scan
        .page(page.cursor, DiscoveryBudget::default(), deadline())
        .unwrap()
        .records
        .is_empty());

    let names = VisibleNames::new(cat.clone(), Listing::new(objects.clone()));
    objects.cut(false, &key, None, 0, Fault::Before(StoreError::Missing));
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Corrupt));
    assert!(page.names.is_empty());
    let binding: Binding = serde_json::from_slice(&objects.get_value(&key).unwrap().bytes).unwrap();
    let changed = records::Binding {
        revision: 3,
        state: records::BindingState::Tombstone,
        control: Some(Control {
            format: 1,
            creation: creation.clone(),
            origin: descriptor(&cat, &creation).origin(),
            kind: NamedDeletionKind::Delete,
            principal: 7,
            operation: 30,
            expected_name_revision: 2,
            expected_head_revision: Some(2),
            nonce: 31,
        }),
        proof: None,
        ..binding
    };
    objects.cut(
        false,
        &key,
        None,
        1,
        Fault::Replace {
            key: key.clone(),
            bytes: records::encode(&changed).unwrap(),
            preserve_etag: false,
        },
    );
    assert!(names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline()
        )
        .unwrap()
        .stopped
        .is_some());
}

#[test]
fn malformed_list_candidates_and_no_progress_pages_fail_closed() {
    let objects = Arc::new(Memory::default());
    objects.set("scap-object/v1/1/2/catalogue/v1/name/unverified", vec![]);
    let listing = Listing::new(objects.clone());
    let scan = inventory(objects.clone(), listing.clone());
    for page in [
        ListPage {
            entries: vec![entry("scap-object/v1/1/2".into(), ListKind::Object)],
            end: ListEnd::Exhausted,
            response_bytes: 1,
        },
        ListPage {
            entries: vec![],
            end: ListEnd::More {
                after: "invented".into(),
            },
            response_bytes: 1,
        },
        ListPage {
            entries: vec![],
            end: ListEnd::Exhausted,
            response_bytes: 1024 * 1024 + 1,
        },
    ] {
        listing.fault("scap-object/v1/1/", Ok(page));
        assert_eq!(
            scan.page(scan.begin(), DiscoveryBudget::default(), deadline())
                .unwrap()
                .stopped,
            Some(DiscoveryError::Corrupt)
        );
    }
    let prefix = "scap-object/v1/1/2/catalogue/v1/name/";
    listing.fault(
        prefix,
        Ok(ListPage {
            entries: vec![],
            end: ListEnd::More {
                after: "invented".into(),
            },
            response_bytes: 1,
        }),
    );
    assert_eq!(
        scan.page(scan.begin(), DiscoveryBudget::default(), deadline())
            .unwrap()
            .stopped,
        Some(DiscoveryError::Corrupt)
    );
    let names = VisibleNames::new(catalogue(objects), listing.clone());
    for entries in [
        vec![],
        vec![entry(format!("{prefix}child/"), ListKind::Prefix)],
    ] {
        listing.fault(
            prefix,
            Ok(ListPage {
                entries,
                end: ListEnd::More {
                    after: "invented".into(),
                },
                response_bytes: 1,
            }),
        );
        let page = names
            .page(
                CREATOR,
                names.begin(CREATOR).unwrap(),
                DiscoveryBudget::default(),
                deadline(),
            )
            .unwrap();
        assert_eq!(page.stopped, Some(DiscoveryError::Corrupt));
        assert!(!page.traversal_exhausted);
    }
}

#[test]
fn exact_record_keys_are_not_inferred_from_valid_json() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    for (phase, key) in [
        (
            Phase::Names,
            format!("{}/name/{}", cat.prefix(), "a".repeat(64)),
        ),
        (Phase::Creates, format!("{}/create/07/1", cat.prefix())),
        (Phase::Creates, format!("{}/create/7", cat.prefix())),
        (Phase::Creates, "wrong/7/1".into()),
        (Phase::Proofs, format!("{}/abort-proof/7/1", cat.prefix())),
    ] {
        if phase == Phase::Names {
            objects.set(
                &key,
                objects
                    .get_value(&cat.binding_key(&creation.name))
                    .unwrap()
                    .bytes,
            );
        }
        assert_eq!(
            cat.discover_record(phase, &entry(key, ListKind::Object), deadline()),
            Err(DiscoveryError::Corrupt)
        );
    }
    let cancel = abort(&creation);
    assert_eq!(
        cat.abort_create(CREATOR, &cancel, deadline())
            .unwrap()
            .phase,
        AbortPhase::CannotAbortBound
    );
    let key = cat.control_address(
        CREATOR.principal,
        &NamedDeletionKind::Abort,
        cancel.operation,
    );
    let wrong = format!("{}/control/8/abort/20", cat.prefix());
    objects.set(&wrong, objects.get_value(&key).unwrap().bytes);
    assert_eq!(
        cat.discover_record(Phase::Controls, &entry(wrong, ListKind::Object), deadline()),
        Err(DiscoveryError::Corrupt)
    );
}

#[test]
fn authenticated_checkpoints_reject_wrong_scope_phase_frontier_and_overflow() {
    let (objects, _, _) = stage(CreationPhase::Ready);
    let scan = inventory(objects.clone(), Listing::new(objects.clone()));
    let page = scan
        .page(
            scan.begin(),
            DiscoveryBudget {
                list_pages: 1,
                ..DiscoveryBudget::default()
            },
            deadline(),
        )
        .unwrap();
    let encoded = String::from_utf8(scan.checkpoint(&page.cursor).unwrap()).unwrap();
    for (from, to) in [
        ("\"schema\":1", "\"schema\":2"),
        ("\"deployment\":1", "\"deployment\":9"),
        ("\"finished\":false", "\"finished\":true"),
        ("\"tenant\":2", "\"tenant\":0"),
        (
            "\"prefix\":\"scap-object/v1/1/2/\"",
            "\"prefix\":\"scap-object/v1/2/2/\"",
        ),
        (
            "\"tenant_after\":null",
            "\"tenant_after\":\"scap-object/v1/1/02/\"",
        ),
        (
            "\"tenant_after\":null",
            "\"tenant_after\":\"scap-object/v1/1/3/\"",
        ),
        ("\"phase\":\"names\"", "\"phase\":\"unknown\""),
        (
            "\"after\":null",
            "\"after\":\"scap-object/v1/1/2/catalogue/v1/name/invalid\"",
        ),
    ] {
        assert!(encoded.contains(from));
        assert!(
            matches!(
                scan.resume_authenticated(encoded.replacen(from, to, 1).as_bytes()),
                Err(DiscoveryError::Invalid)
            ),
            "{to}"
        );
    }
    let after = encoded.replacen(
        "\"tenant_after\":null",
        "\"tenant_after\":\"scap-object/v1/1/1/\"",
        1,
    );
    assert!(scan.resume_authenticated(after.as_bytes()).is_ok());
    let overflow = encoded.replacen("\"classified\":0", "\"classified\":18446744073709551615", 1);
    let cursor = scan.resume_authenticated(overflow.as_bytes()).unwrap();
    let page = scan
        .page(cursor, DiscoveryBudget::default(), deadline())
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Limit));
    assert!(page.records.is_empty());

    let names = VisibleNames::new(catalogue(objects.clone()), Listing::new(objects));
    let initial =
        String::from_utf8(names.checkpoint(&names.begin(CREATOR).unwrap()).unwrap()).unwrap();
    for (from, to) in [
        ("\"schema\":1", "\"schema\":0"),
        ("\"deployment\":1", "\"deployment\":9"),
        ("\"tenant\":2", "\"tenant\":9"),
        ("\"principal\":7", "\"principal\":9"),
        ("\"after\":null", "\"after\":\"other\""),
    ] {
        assert!(matches!(
            names.resume_authenticated(CREATOR, initial.replacen(from, to, 1).as_bytes()),
            Err(DiscoveryError::Invalid)
        ));
    }
    let valid = initial.replacen(
        "\"after\":null",
        &format!(
            "\"after\":\"scap-object/v1/1/2/catalogue/v1/name/{}\"",
            "0".repeat(64)
        ),
        1,
    );
    assert!(names
        .resume_authenticated(CREATOR, valid.as_bytes())
        .is_ok());
    let invalid = Caller {
        principal: 0,
        provision: false,
    };
    assert!(matches!(names.begin(invalid), Err(DiscoveryError::Invalid)));
    assert!(matches!(
        names.resume_authenticated(invalid, initial.as_bytes()),
        Err(DiscoveryError::Invalid)
    ));
    assert!(matches!(
        names.page(
            invalid,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline()
        ),
        Err(DiscoveryError::Invalid)
    ));
}

#[test]
fn every_checkpoint_phase_has_exact_canonical_component_boundaries() {
    let tenant = "scap-object/v1/1/2/";
    for (phase, suffix) in [
        (
            Phase::Names,
            format!("catalogue/v1/name/{}", "g".repeat(64)),
        ),
        (Phase::Creates, "catalogue/v1/create/7".into()),
        (Phase::Creates, "catalogue/v1/create/0/1".into()),
        (Phase::Creates, "catalogue/v1/create/7/0".into()),
        (Phase::Controls, "catalogue/v1/control/7".into()),
        (Phase::Controls, "catalogue/v1/control/7/abort".into()),
        (Phase::Controls, "catalogue/v1/control/0/abort/1".into()),
        (Phase::Controls, "catalogue/v1/control/7/unknown/1".into()),
        (Phase::Controls, "catalogue/v1/control/7/delete/0".into()),
        (Phase::Proofs, "catalogue/v1/abort-proof/7/01".into()),
        (Phase::Slots, "0/".into()),
    ] {
        assert_eq!(
            frontier(&format!("{tenant}{suffix}"), tenant, phase),
            Err(DiscoveryError::Invalid)
        );
    }
}

#[test]
fn visible_pagination_rechecks_revocation_and_incomplete_names_are_filtered_without_details() {
    for phase in [
        CreationPhase::Reserved,
        CreationPhase::Provisioning,
        CreationPhase::Bound,
    ] {
        let (objects, cat, _) = stage(phase);
        let names = VisibleNames::new(cat, Listing::new(objects));
        let page = names
            .page(
                CREATOR,
                names.begin(CREATOR).unwrap(),
                DiscoveryBudget::default(),
                deadline(),
            )
            .unwrap();
        assert!(page.traversal_exhausted);
        assert!(page.names.is_empty());
    }
    let objects = Arc::new(Memory::default());
    let cat = catalogue(objects.clone());
    let mut creations = Vec::new();
    for operation in 1..=5 {
        let creation = cat
            .prepare(
                CREATOR,
                &input(&format!("paged-{operation}"), operation, None),
                deadline(),
            )
            .unwrap()
            .creation;
        cat.resume_create(CREATOR, &creation, deadline()).unwrap();
        creations.push(creation);
    }
    let names = VisibleNames::new(cat.clone(), Listing::new(objects.clone()));
    let first = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget {
                list_pages: 1,
                ..DiscoveryBudget::default()
            },
            deadline(),
        )
        .unwrap();
    assert_eq!(first.names.len(), 3);
    assert_eq!(first.stopped, Some(DiscoveryError::Limit));
    assert!(!first.traversal_exhausted);
    for creation in creations
        .iter()
        .filter(|creation| !first.names.iter().any(|name| name.creation == **creation))
    {
        set_head(&objects, &creation.scope, |head| {
            head.policy[0].read = false
        });
    }
    let checkpoint = names.checkpoint(&first.cursor).unwrap();
    let cursor = names.resume_authenticated(CREATOR, &checkpoint).unwrap();
    let second = names
        .page(CREATOR, cursor, DiscoveryBudget::default(), deadline())
        .unwrap();
    assert!(second.traversal_exhausted);
    assert!(second.names.is_empty());
}

#[test]
fn legal_reuse_and_deletion_during_the_stable_view_are_conflicts() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    cat.delete(CREATOR, &delete(&creation), deadline()).unwrap();
    let key = cat.binding_key(&creation.name);
    let concurrent = cat.clone();
    let name = creation.name.clone();
    objects.cut(
        false,
        &key,
        None,
        1,
        Fault::Run(Arc::new(move || {
            let replacement = concurrent
                .prepare(CREATOR, &input(&name, 2, Some(3)), deadline())
                .unwrap()
                .creation;
            concurrent
                .resume_create(CREATOR, &replacement, deadline())
                .unwrap();
        })),
    );
    assert_eq!(
        cat.discover_record(Phase::Names, &entry(key, ListKind::Object), deadline()),
        Err(DiscoveryError::Conflict)
    );

    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let names = VisibleNames::new(cat.clone(), Listing::new(objects.clone()));
    let key = cat.binding_key(&creation.name);
    let concurrent = cat.clone();
    objects.cut(
        false,
        &key,
        None,
        2,
        Fault::Run(Arc::new(move || {
            concurrent
                .delete(CREATOR, &delete(&creation), deadline())
                .unwrap();
        })),
    );
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Conflict));
    assert!(page.names.is_empty());
    assert!(
        names
            .page(CREATOR, page.cursor, DiscoveryBudget::default(), deadline())
            .unwrap()
            .traversal_exhausted
    );

    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let names = VisibleNames::new(cat.clone(), Listing::new(objects.clone()));
    objects.cut(
        false,
        &cat.binding_key(&creation.name),
        None,
        2,
        Fault::Before(StoreError::Unknown),
    );
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Unknown));
    assert!(page.names.is_empty());
}

#[test]
fn fresh_catalogue_expectation_without_a_predecessor_is_not_a_reservation() {
    let objects = Arc::new(Memory::default());
    let cat = catalogue(objects.clone());
    cat.prepare(CREATOR, &input("not-present", 1, Some(3)), deadline())
        .unwrap();
    let records = all(&inventory(objects.clone(), Listing::new(objects)));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, MetadataState::NameConflict);
}

thread_local! {
    static CLOCK: RefCell<(Instant, Option<usize>, usize)> = RefCell::new((Instant::now(), None, 0));
}

fn clock_start(cut: Option<usize>) -> Instant {
    let now = Instant::now();
    CLOCK.with(|clock| *clock.borrow_mut() = (now, cut, 0));
    now + Duration::from_secs(60)
}

fn clock_now() -> Instant {
    CLOCK.with(|clock| {
        let mut clock = clock.borrow_mut();
        clock.2 += 1;
        if clock.1.is_some_and(|cut| clock.2 >= cut) {
            clock.0 + Duration::from_secs(60)
        } else {
            clock.0
        }
    })
}

#[test]
fn expiry_at_every_accounting_boundary_including_after_parsing_never_advances_completion() {
    let (objects, cat, _) = stage(CreationPhase::Ready);
    objects.clear_calls();
    let mut inventory = inventory(objects.clone(), Listing::new(objects.clone()));
    inventory.now = clock_now;
    let until = clock_start(None);
    inventory
        .page(inventory.begin(), DiscoveryBudget::default(), until)
        .unwrap();
    let calls = CLOCK.with(|clock| clock.borrow().2);
    for cut in 1..=calls {
        let until = clock_start(Some(cut));
        let page = inventory
            .page(inventory.begin(), DiscoveryBudget::default(), until)
            .unwrap();
        assert_eq!(
            page.stopped,
            Some(DiscoveryError::Unknown),
            "inventory cut {cut}"
        );
        assert!(!page.completion.traversal_exhausted);
    }
    let mut names = VisibleNames::new(cat, Listing::new(objects.clone()));
    names.now = clock_now;
    let until = clock_start(None);
    names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            until,
        )
        .unwrap();
    let calls = CLOCK.with(|clock| clock.borrow().2);
    for cut in 1..=calls {
        let until = clock_start(Some(cut));
        let page = names
            .page(
                CREATOR,
                names.begin(CREATOR).unwrap(),
                DiscoveryBudget::default(),
                until,
            )
            .unwrap();
        assert_eq!(
            page.stopped,
            Some(DiscoveryError::Unknown),
            "names cut {cut}"
        );
        assert!(!page.traversal_exhausted);
    }
    assert!(objects.calls().iter().all(|call| !call.put));
}

struct Oversized;
impl Objects for Oversized {
    fn get(&self, _key: &str, size: usize, _deadline: Instant) -> Result<Stored, StoreError> {
        Ok(Stored {
            bytes: vec![0; size + 1],
            etag: "unexpected".into(),
        })
    }
    fn put(&self, _: &str, _: &[u8], _: Condition<'_>, _: Instant) -> Result<String, StoreError> {
        panic!("read-only test")
    }
}

#[test]
fn transport_oversize_is_not_confused_with_exhausting_the_shared_budget() {
    let meter = Meter::new(
        Arc::new(Oversized),
        DiscoveryBudget::default(),
        Instant::now,
    );
    assert_eq!(meter.get("key", 1, deadline()), Err(StoreError::Corrupt));
    let objects = Arc::new(Memory::default());
    objects.set("key", vec![1, 2]);
    let meter = Meter::new(objects, DiscoveryBudget::default(), Instant::now);
    assert_eq!(meter.get("key", 1, deadline()), Err(StoreError::Limit));
    assert_eq!(
        meter.failure(DiscoveryError::Corrupt),
        DiscoveryError::Corrupt
    );
}

#[test]
fn failed_io_keeps_conservative_byte_reservations_and_quota_remains_distinct() {
    for failure in [
        StoreError::Missing,
        StoreError::Unknown,
        StoreError::Limit,
        StoreError::Corrupt,
    ] {
        let objects = Arc::new(Memory::default());
        let meter = Meter::new(
            objects.clone(),
            DiscoveryBudget {
                metadata_bytes: 8,
                ..DiscoveryBudget::default()
            },
            Instant::now,
        );
        objects.fail_at(1, Fault::Before(failure.clone()));
        assert_eq!(meter.get("any", 8, deadline()), Err(failure));
        assert_eq!(meter.usage().metadata_bytes, 8);
        assert_eq!(meter.usage().exact_gets, 1);
        assert_eq!(
            meter.failure(DiscoveryError::Corrupt),
            DiscoveryError::Corrupt
        );
        assert_eq!(meter.get("any", 8, deadline()), Err(StoreError::Limit));
        assert_eq!(meter.usage().exact_gets, 1);
        assert_eq!(
            meter.failure(DiscoveryError::Corrupt),
            DiscoveryError::Limit
        );
    }
    let objects = Arc::new(Memory::default());
    objects.set("key", vec![1]);
    let meter = Meter::new(objects, DiscoveryBudget::default(), clock_now);
    let until = clock_start(Some(2));
    assert_eq!(meter.get("key", 8, until), Err(StoreError::Unknown));
    assert_eq!(meter.usage().metadata_bytes, 1); // A received body has an exact size.
    let listing = Listing::new(Arc::new(Memory::default()));
    listing.fault("scap-object/v1/1/", Err(ListError::Unknown));
    let scan = inventory(listing.objects.clone(), listing);
    let page = scan
        .page(scan.begin(), DiscoveryBudget::default(), deadline())
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Unknown));
    assert_eq!(page.usage.list_pages, 1);
    assert_eq!(page.usage.list_bytes, 1024 * 1024);
}

struct AfterBindingRead {
    objects: Arc<Memory>,
    key: String,
    reads: Mutex<usize>,
    action: Arc<dyn Fn() + Send + Sync>,
}
impl Objects for AfterBindingRead {
    fn get(&self, key: &str, size: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let value = self.objects.get(key, size, deadline);
        if key == self.key {
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            if *reads == 3 {
                (self.action)();
            }
        }
        value
    }
    fn put(&self, _: &str, _: &[u8], _: Condition<'_>, _: Instant) -> Result<String, StoreError> {
        panic!("read-only observer")
    }
}

#[test]
fn one_stable_name_view_uses_one_head_get_and_later_revocation_obeys_that_read_point() {
    let (objects, cat, creation) = stage(CreationPhase::Ready);
    let names = VisibleNames::new(cat.clone(), Listing::new(objects.clone()));
    objects.clear_calls();
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.names.len(), 1);
    let key = format::head_key(&creation.scope);
    assert_eq!(
        objects
            .calls()
            .iter()
            .filter(|call| call.key == key)
            .count(),
        1
    );
    assert_eq!(page.usage.exact_gets, objects.calls().len());

    let database = Database::new(objects.clone(), creation.scope.clone(), 10).unwrap();
    let observed = Arc::new(AfterBindingRead {
        objects: objects.clone(),
        key: cat.binding_key(&creation.name),
        reads: Mutex::new(0),
        action: Arc::new(move || {
            database
                .set_policy(
                    7,
                    2,
                    99,
                    vec![Permission {
                        principal: 7,
                        read: false,
                        write: true,
                        admin: true,
                    }],
                    deadline(),
                )
                .unwrap();
        }),
    });
    let catalogue = Catalogue::new(observed, 1, 2, 10, crate::tests::test_options()).unwrap();
    let names = VisibleNames::new(catalogue, Listing::new(objects));
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.names.len(), 1);
    assert_eq!(page.names[0].head_revision, 2);
    let next = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert!(next.names.is_empty());
    assert!(next.traversal_exhausted);
}

#[test]
fn coordinator_validation_and_list_denial_are_not_acl_filtering() {
    let (objects, cat, _) = stage(CreationPhase::Ready);
    let listing = Listing::new(objects.clone());
    let scan = inventory(objects, listing.clone());
    let invalid = DiscoveryBudget {
        candidates: 129,
        ..DiscoveryBudget::default()
    };
    assert!(matches!(
        scan.page(scan.begin(), invalid, deadline()),
        Err(DiscoveryError::Invalid)
    ));
    let empty = DiscoveryBudget {
        candidates: 0,
        ..DiscoveryBudget::default()
    };
    assert_eq!(
        scan.page(scan.begin(), empty, deadline()).unwrap().stopped,
        Some(DiscoveryError::Limit)
    );
    listing.fault(
        "scap-object/v1/1/",
        Ok(ListPage {
            entries: vec![entry("scap-object/v1/1/02/".into(), ListKind::Prefix)],
            end: ListEnd::Exhausted,
            response_bytes: 1,
        }),
    );
    assert_eq!(
        scan.page(scan.begin(), DiscoveryBudget::default(), deadline())
            .unwrap()
            .stopped,
        Some(DiscoveryError::Corrupt)
    );
    let names = VisibleNames::new(cat, listing.clone());
    assert!(matches!(
        names.page(CREATOR, names.begin(CREATOR).unwrap(), invalid, deadline()),
        Err(DiscoveryError::Invalid)
    ));
    listing.fault(
        "scap-object/v1/1/2/catalogue/v1/name/",
        Err(ListError::Denied),
    );
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Denied));
    assert!(!page.traversal_exhausted);
    listing.fault(
        "scap-object/v1/1/2/catalogue/v1/name/",
        Ok(ListPage {
            entries: vec![],
            end: ListEnd::Exhausted,
            response_bytes: 1024 * 1024 + 1,
        }),
    );
    let page = names
        .page(
            CREATOR,
            names.begin(CREATOR).unwrap(),
            DiscoveryBudget::default(),
            deadline(),
        )
        .unwrap();
    assert_eq!(page.stopped, Some(DiscoveryError::Corrupt));
    assert!(!page.traversal_exhausted);
}
