//! Business publication reuses a completed immutable verification; original
//! HEAD, backend, lineage, lifetime and health remain separate prerequisites.

use super::*;
use crate::tests::{deadline, fixture, scope, sql, test_options, Memory};
use scap_object_sqlite::PageChange;
use std::time::Duration;

fn batch() -> PageBatch {
    PageBatch {
        size_after: 2,
        pages: (1..=2)
            .map(|number| PageChange {
                number,
                bytes: vec![number as u8; PAGE_SIZE],
            })
            .collect(),
    }
}

fn prepared<'a>(
    context: &'a ObjectContext,
    base: &'a Snapshot,
    until: Instant,
) -> (Head, data_tree::VerifiedManifest<'a, ObjectContext>) {
    let verified = data_tree::update(context, &base.head.data_root, &batch(), 64, until).unwrap();
    let mut next = Database::next(&base.head, 99).unwrap();
    next.data_root = verified.root().to_owned();
    (next, verified)
}

#[test]
fn business_publication_reuses_exact_readback_and_management_keeps_its_get() {
    let (objects, database) = fixture();
    let until = deadline();
    let base = database.read_head(until).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
    let (next, verified) = prepared(&context, &base, until);
    let manifest_key = object_key(&scope(), 1, verified.root());
    assert_eq!(
        objects.gets_for(&manifest_key),
        1,
        "save's exact readback remains"
    );
    let before = objects.operation_count();
    database
        .clone()
        .publish_updated(&context, &base, &next, verified, until)
        .unwrap();
    assert_eq!(
        objects.operation_count(),
        before + 1,
        "only the original HEAD CAS"
    );
    assert_eq!(objects.gets_for(&manifest_key), 1);

    let base = database.read_head(until).unwrap();
    let next = Database::next(&base.head, 100).unwrap();
    let before = objects.operation_count();
    database.publish(&base, &next, until).unwrap();
    assert_eq!(
        objects.operation_count(),
        before + 2,
        "management GET plus CAS"
    );
    assert_eq!(objects.gets_for(&manifest_key), 2);
}

#[test]
fn native_writes_and_noop_results_each_avoid_one_redundant_manifest_get() {
    let (objects, database) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let mut session = database
        .session(7, &directory.path().join("native"), deadline())
        .unwrap();
    let create = sql("CREATE TABLE value_store(value INTEGER)");
    session
        .execute(7, &request(1, 1, 7, &create).unwrap(), &create, deadline())
        .unwrap();

    for (id, statements, changing) in [
        (
            2,
            sql("INSERT INTO value_store VALUES(random()) RETURNING value"),
            true,
        ),
        (3, sql("SELECT random()"), false),
    ] {
        let before = database.read_head(deadline()).unwrap();
        let old_key = object_key(&scope(), 1, &before.head.data_root);
        let old_gets = objects.gets_for(&old_key);
        let identity = request(1, id, 7, &statements).unwrap();
        let (receipt, original) = session
            .execute(7, &identity, &statements, deadline())
            .unwrap();
        let key = object_key(&scope(), 1, &receipt.data_root);
        if changing {
            assert_ne!(receipt.data_root, before.head.data_root);
            assert_eq!(objects.gets_for(&key), 1, "new manifest exact readback");
        } else {
            assert_eq!(receipt.data_root, before.head.data_root);
            assert_eq!(
                objects.gets_for(&key) - old_gets,
                1,
                "unchanged manifest validation"
            );
        }
        let Resolution::Committed {
            receipt: saved,
            bytes,
        } = database.lookup(7, &identity, deadline()).unwrap()
        else {
            panic!("successful native ACK must retain the original result");
        };
        assert_eq!(saved, receipt);
        assert_eq!(
            scap_sql::decode_result(&bytes, durable_sql_limits()).unwrap(),
            original
        );
    }
}

#[test]
fn foreign_or_rebased_proofs_and_invalid_candidates_never_dispatch_head_put() {
    for fault in 0..14 {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = if fault == 8 {
            ObjectContext::bootstrap(&database).unwrap()
        } else {
            ObjectContext::from_snapshot(&database, &base, until).unwrap()
        };
        let (mut next, verified) = prepared(&context, &base, until);
        let other_context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let mut publisher = database.clone();
        let mut supplied = base.clone();
        let mut supplied_deadline = until;
        match fault {
            0 => publisher.objects = Arc::new(Memory::default()),
            1 => {
                publisher =
                    Database::with_options(objects.clone(), scope(), 10, test_options()).unwrap()
            }
            2 => supplied.head.scope.database += 1,
            3 => supplied.head.storage.active_generation += 1,
            4 => supplied_deadline += Duration::from_secs(1),
            5 => supplied.etag.push_str("different-original-etag"),
            6 => supplied.head.head_serial += 1,
            7 => supplied.head.storage.allocated_through += 1,
            8 | 9 => {}
            10 => supplied.head.policy[0].write = false,
            11 => next.data_root = digest(b"different-proposed-root"),
            12 => next.quota.max_bytes = Some(0),
            _ => next.transition.nonce = 0,
        }
        let before = objects.operation_count();
        let result = publisher.publish_updated(
            if fault == 9 { &other_context } else { &context },
            &supplied,
            &next,
            verified,
            supplied_deadline,
        );
        if fault >= 12 {
            assert!(
                matches!(result, Err(Error::Format(_))),
                "fault {fault}: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(Error::Corrupt)),
                "fault {fault}: {result:?}"
            );
        }
        assert_eq!(
            objects.operation_count(),
            before,
            "fault {fault} performed I/O"
        );
        assert_eq!(database.read_head(until).unwrap().head, base.head);
    }

    let (objects, database) = fixture();
    let until = deadline();
    let base = database.read_head(until).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
    let (mut next, verified) = prepared(&context, &base, until);
    next.quota.max_bytes = Some(PAGE_SIZE as u64);
    let before = objects.operation_count();
    assert!(matches!(
        database.publish_updated(&context, &base, &next, verified, until),
        Err(Error::Limit)
    ));
    assert_eq!(objects.operation_count(), before);
}

#[test]
fn verified_manifest_never_overrides_a_later_context_or_lineage_failure() {
    for fault in 0..3 {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let (next, verified) = prepared(&context, &base, until);
        match fault {
            0 => {
                objects.fail(
                    false,
                    object_key(&scope(), 1, &base.head.data_root),
                    StoreError::Unknown,
                );
                assert!(matches!(
                    context.load(&base.head.data_root, until),
                    Err(Error::Store(StoreError::Unknown))
                ));
            }
            1 => database.quarantined.store(true, Ordering::Release),
            _ => {
                let observer =
                    ObjectContext::from_snapshot(&database.clone(), &base, until).unwrap();
                objects.remove(&object_key(&scope(), 1, verified.root()));
                assert!(matches!(
                    observer.load(verified.root(), until),
                    Err(Error::Store(StoreError::Missing))
                ));
            }
        }
        let before = objects.operation_count();
        let result = database.publish_updated(&context, &base, &next, verified, until);
        if fault == 0 {
            assert!(matches!(result, Err(Error::Unknown)));
        } else {
            assert!(matches!(result, Err(Error::Corrupt)));
        }
        assert_eq!(objects.operation_count(), before);
    }
}

#[test]
fn proof_cannot_substitute_another_data_root_or_copy_target_for_its_original_basis() {
    let (objects, database) = fixture();
    let until = deadline();
    let base = database.read_head(until).unwrap();
    let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
    let (_, alternate) = prepared(&context, &base, until);
    let alternate_root = alternate.root().to_owned();
    let verified = data_tree::update(
        &context,
        &alternate_root,
        &PageBatch {
            size_after: 2,
            pages: vec![],
        },
        64,
        until,
    )
    .unwrap();
    let mut next = Database::next(&base.head, 99).unwrap();
    next.data_root = verified.root().to_owned();
    let before = objects.operation_count();
    assert!(matches!(
        database.publish_updated(&context, &base, &next, verified, until),
        Err(Error::Corrupt)
    ));
    assert_eq!(objects.operation_count(), before);

    let copying = database
        .compact_begin(7, base.head.head_serial, until)
        .unwrap();
    let base = database.read_head(until).unwrap();
    let plan = copying.storage.plan.as_ref().unwrap();
    let target = ObjectContext::target(&database, &base, plan, until).unwrap();
    let source = ObjectContext::from_snapshot(&database, &base, until).unwrap();
    let payload = source.load(&base.head.data_root, until).unwrap();
    assert_eq!(target.save(payload, until).unwrap(), base.head.data_root);
    let (mut next, verified) = prepared(&target, &base, until);
    // Matching the copy target's physical address does not change the active
    // generation captured in its original HEAD. Only the copy protocol may
    // promote it; a business proof cannot manufacture that transition.
    let mut forged = base.clone();
    forged.head.storage.active_generation = plan.target;
    next.storage = forged.head.storage.clone();
    let before = objects.operation_count();
    assert!(matches!(
        database.publish_updated(&target, &forged, &next, verified, until),
        Err(Error::Corrupt)
    ));
    assert_eq!(objects.operation_count(), before);
}

#[test]
fn late_original_publication_keeps_conflict_and_unknown_without_rebinding() {
    for lost_ack in [false, true] {
        let (objects, database) = fixture();
        let until = deadline();
        let base = database.read_head(until).unwrap();
        let context = ObjectContext::from_snapshot(&database, &base, until).unwrap();
        let (next, verified) = prepared(&context, &base, until);
        if lost_ack {
            objects.lose_next_cas();
        } else {
            let later = Database::next(&base.head, 77).unwrap();
            database.publish(&base, &later, until).unwrap();
        }
        let before = objects.operation_count();
        let result = database.publish_updated(&context, &base, &next, verified, until);
        assert_eq!(
            objects.operation_count(),
            before + 1,
            "one original CAS, no refresh GET"
        );
        if lost_ack {
            assert!(matches!(result, Err(Error::Store(StoreError::Unknown))));
            assert_eq!(database.read_head(until).unwrap().head, next);
        } else {
            assert!(matches!(result, Err(Error::Conflict)));
            assert_ne!(database.read_head(until).unwrap().head, next);
        }
    }
}
