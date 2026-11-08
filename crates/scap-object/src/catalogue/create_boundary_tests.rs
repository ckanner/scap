use super::*;
use crate::catalogue::tests::{catalogue, deadline, descriptor, input, stage, Fault, CREATOR};

#[test]
fn completion_requires_matching_bound_name_and_exact_provisioning_head() {
    let (objects, catalog, creation) = stage(CreationPhase::Bound);
    objects.clear_calls();
    let source = descriptor(&catalog, &creation);
    let view = catalog.view(&source, deadline()).unwrap();
    let binding = view.binding.as_ref().unwrap();
    let base = view.head.as_ref().unwrap();
    let other = catalog
        .prepare(CREATOR, &input("another", 2, None), deadline())
        .unwrap();
    let other_source = descriptor(&catalog, &other.creation);
    assert_eq!(
        catalog.complete(&other_source, binding, base, deadline()),
        Err(CatalogueError::Corrupt)
    );
    let (reserved_objects, reserved, creation) = stage(CreationPhase::Provisioning);
    let source = descriptor(&reserved, &creation);
    let view = reserved.view(&source, deadline()).unwrap();
    assert_eq!(
        reserved.complete(
            &source,
            view.binding.as_ref().unwrap(),
            view.head.as_ref().unwrap(),
            deadline()
        ),
        Err(CatalogueError::Corrupt)
    );
    assert!(reserved_objects
        .get_value(&format::head_key(&creation.scope))
        .is_some());
    assert!(objects
        .calls()
        .iter()
        .filter(|call| call.put && call.key.ends_with("/head"))
        .all(
            |call| serde_json::from_slice::<serde_json::Value>(&call.bytes).unwrap()["lifecycle"]
                != "ready"
        ));
}

#[test]
fn completion_does_not_reinitialize_an_already_ready_database() {
    let (_, catalog, creation) = stage(CreationPhase::Ready);
    let source = descriptor(&catalog, &creation);
    let view = catalog.view(&source, deadline()).unwrap();
    assert_eq!(
        catalog.complete(
            &source,
            view.binding.as_ref().unwrap(),
            view.head.as_ref().unwrap(),
            deadline()
        ),
        Err(CatalogueError::Corrupt)
    );
}

#[test]
fn completion_rechecks_exact_body_even_when_a_broken_store_reuses_the_etag() {
    for preserve_etag in [false, true] {
        let (objects, catalog, creation) = stage(CreationPhase::Bound);
        let key = format::head_key(&creation.scope);
        let mut head = catalog
            .read_slot(&creation.scope, deadline())
            .unwrap()
            .unwrap()
            .head;
        head.owner_instance += 1;
        objects.cut(
            false,
            &key,
            None,
            1,
            Fault::Replace {
                key: key.clone(),
                bytes: format::encode_head(&head).unwrap(),
                preserve_etag,
            },
        );
        assert_eq!(
            catalog.resume_create(CREATOR, &creation, deadline()),
            Err(CatalogueError::Conflict)
        );
        assert_eq!(
            catalogue(objects)
                .read_slot(&creation.scope, deadline())
                .unwrap()
                .unwrap()
                .head
                .lifecycle,
            Lifecycle::Provisioning
        );
    }
}

#[test]
fn final_creation_progress_obeys_a_concurrent_permission_revocation() {
    let (base, _, creation) = crate::catalogue::tests::prepared();
    let success = base.fork();
    catalogue(success.clone())
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    let head_key = format::head_key(&creation.scope);
    let index = success
        .calls()
        .iter()
        .rposition(|call| !call.put && call.key == head_key)
        .unwrap()
        + 1;
    let objects = base.fork();
    let peer = catalogue(objects.clone());
    let source = descriptor(&peer, &creation);
    let database = peer.database(&source);
    objects.fail_at(
        index,
        Fault::Run(Arc::new(move || {
            database
                .set_policy(
                    7,
                    2,
                    90,
                    vec![Permission {
                        principal: 7,
                        read: false,
                        write: true,
                        admin: true,
                    }],
                    deadline(),
                )
                .unwrap();
        })),
    );
    assert_eq!(
        catalogue(objects).resume_create(CREATOR, &creation, deadline()),
        Err(CatalogueError::Denied)
    );
}
