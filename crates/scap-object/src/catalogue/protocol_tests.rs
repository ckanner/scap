use super::*;
use records::BindingState;

#[test]
fn inspect_and_resolve_are_read_only_and_every_publication_is_conditional() {
    let (objects, catalogue, creation) = stage(CreationPhase::Ready);
    let mut head_conditions = Vec::new();
    let mut name_conditions = Vec::new();
    for call in objects.calls().into_iter().filter(|call| call.put) {
        let condition = call.condition.unwrap();
        assert!(!condition.is_empty());
        if call.key.ends_with("/head") {
            head_conditions.push(condition);
        } else if call.key == catalogue.binding_key(&creation.name) {
            name_conditions.push(condition);
        } else {
            assert_eq!(condition, "*");
        }
    }
    for conditions in [head_conditions, name_conditions] {
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0], "*");
        assert_ne!(conditions[1], "*");
    }
    objects.clear_calls();
    catalogue
        .inspect_create_operation(CREATOR, creation.operation, deadline())
        .unwrap();
    catalogue
        .resolve(CREATOR, &creation.name, deadline())
        .unwrap();
    assert!(objects.calls().iter().all(|call| !call.put));
}

#[test]
fn independent_creates_compete_once_and_same_intent_survives_default_changes() {
    let (objects, catalogue, creation) = prepared();
    let rival = catalogue
        .prepare(CREATOR, &input(&creation.name, 2, None), deadline())
        .unwrap();
    let first = catalogue
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    assert_eq!(first.phase, CreationPhase::Ready);
    let conflict = catalogue
        .resume_create(CREATOR, &rival.creation, deadline())
        .unwrap();
    assert_eq!(conflict.phase, CreationPhase::NameConflict);
    assert_eq!(conflict.binding_revision, None);
    assert_eq!(conflict.head_revision, None);
    assert!(objects
        .get_value(&format::head_key(&rival.creation.scope))
        .is_none());
    let mut options = crate::tests::test_options();
    options.quota.max_bytes = None;
    options.retention.max_entries += 1;
    let replacement = Catalogue::new(objects, 1, 2, 99, options).unwrap();
    let durable = replacement
        .prepare(CREATOR, &input(&creation.name, 1, None), deadline())
        .unwrap();
    assert_eq!(durable.initial_quota, first.initial_quota);
    assert_eq!(durable.retention, first.retention);
    assert_eq!(
        replacement
            .resume_create(CREATOR, &creation, deadline())
            .unwrap(),
        first
    );
    let mut changed = input(&creation.name, 1, None);
    changed.options.quota = QuotaChoice::Unlimited;
    assert_eq!(
        replacement.prepare(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
    changed = input("renamed", 1, None);
    assert_eq!(
        replacement.prepare(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
}

#[test]
fn explicit_quotas_and_names_preserve_exact_bytes_and_identity() {
    let (objects, catalogue, _) = prepared();
    for (operation, name, quota, expected) in [
        (2, "Name", QuotaChoice::Unlimited, None),
        (
            3,
            "name",
            QuotaChoice::Limited { max_bytes: 8192 },
            Some(8192),
        ),
        (
            4,
            "e\u{301}",
            QuotaChoice::Default,
            crate::tests::test_options().quota.max_bytes,
        ),
        (
            5,
            "é",
            QuotaChoice::Default,
            crate::tests::test_options().quota.max_bytes,
        ),
        (
            6,
            " a ",
            QuotaChoice::Default,
            crate::tests::test_options().quota.max_bytes,
        ),
    ] {
        let mut request = input(name, operation, None);
        request.options.quota = quota;
        let prepared = catalogue.prepare(CREATOR, &request, deadline()).unwrap();
        assert_eq!(prepared.initial_quota.max_bytes, expected);
        let progress = catalogue
            .resume_create(CREATOR, &prepared.creation, deadline())
            .unwrap();
        assert_eq!(progress.phase, CreationPhase::Ready);
        assert_eq!(
            catalogue
                .resolve(CREATOR, name, deadline())
                .unwrap()
                .head
                .quota
                .max_bytes,
            expected
        );
    }
    let before = objects.calls().len();
    for name in ["", "a\0b", "a\u{85}b", &"é".repeat(65)] {
        assert!(catalogue
            .prepare(CREATOR, &input(name, 7, None), deadline())
            .is_err());
    }
    assert_eq!(objects.calls().len(), before);
}

#[test]
fn cancelled_absent_or_provisioned_heads_cannot_reappear_and_name_can_be_reused() {
    for phase in [CreationPhase::Reserved, CreationPhase::Provisioning] {
        let (objects, catalogue, creation) = stage(phase.clone());
        let descriptor = descriptor(&catalogue, &creation);
        let database = catalogue.database(&descriptor).unwrap();
        let old_name = catalogue
            .read_binding(&creation.name, deadline())
            .unwrap()
            .unwrap();
        let mut late = database
            .initial_head(CREATOR.principal, creation.operation, deadline())
            .unwrap();
        late.creation = Some(descriptor.origin().unwrap());
        late.lifecycle = Lifecycle::Provisioning;
        let control = abort(&creation);
        let done = catalogue
            .abort_create(CREATOR, &control, deadline())
            .unwrap();
        assert_eq!(done.phase, AbortPhase::Aborted);
        assert_eq!(done.binding_revision, Some(3));
        assert_eq!(
            done.head_revision,
            Some(if phase == CreationPhase::Reserved {
                1
            } else {
                2
            })
        );
        assert_eq!(
            catalogue
                .abort_create(CREATOR, &control, deadline())
                .unwrap(),
            done
        );
        assert_eq!(
            catalogue
                .resume_create(CREATOR, &creation, deadline())
                .unwrap()
                .phase,
            CreationPhase::Aborted
        );
        assert_eq!(
            catalogue.resolve(CREATOR, &creation.name, deadline()),
            Err(CatalogueError::NotFound)
        );
        assert!(matches!(
            database.create_head(&late, deadline()),
            Err(Error::Store(StoreError::Conflict))
        ));
        let mut old_bound = old_name.body;
        old_bound.revision += 1;
        old_bound.state = BindingState::Bound;
        assert_eq!(
            catalogue.write_binding(&old_bound, Some(&old_name.etag), deadline()),
            Err(CatalogueError::Conflict)
        );
        let new = catalogue
            .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
            .unwrap();
        assert_ne!(new.creation.scope.database, creation.scope.database);
        let ready = catalogue
            .resume_create(CREATOR, &new.creation, deadline())
            .unwrap();
        assert_eq!(ready.phase, CreationPhase::Ready);
        assert_eq!(ready.binding_revision, Some(5));
        let old = catalogue
            .abort_create(CREATOR, &control, deadline())
            .unwrap();
        assert_eq!(old.phase, AbortPhase::Aborted);
        assert_eq!(old.binding_revision, None);
        assert_eq!(
            catalogue
                .resume_create(CREATOR, &creation, deadline())
                .unwrap()
                .binding_revision,
            None
        );
        assert_eq!(
            catalogue
                .resolve(CREATOR, &creation.name, deadline())
                .unwrap()
                .creation,
            new.creation
        );
        let key = catalogue.proof_key(&creation);
        objects.remove(&key);
        assert_eq!(
            catalogue.abort_create(CREATOR, &control, deadline()),
            Err(CatalogueError::Corrupt)
        );
    }
}

#[test]
fn a_late_provision_can_win_absent_head_but_fixed_abort_then_fences_it() {
    let (objects, catalogue, creation) = stage(CreationPhase::Reserved);
    let descriptor = descriptor(&catalogue, &creation);
    let database = catalogue.database(&descriptor).unwrap();
    let mut late = database
        .initial_head(CREATOR.principal, creation.operation, deadline())
        .unwrap();
    late.creation = Some(descriptor.origin().unwrap());
    late.lifecycle = Lifecycle::Provisioning;
    objects.cut(
        true,
        &format::head_key(&creation.scope),
        Some(("lifecycle", "deleted")),
        0,
        Fault::Before(StoreError::Unknown),
    );
    let control = abort(&creation);
    assert_eq!(
        catalogue.abort_create(CREATOR, &control, deadline()),
        Err(CatalogueError::Unknown)
    );
    assert_eq!(
        catalogue
            .inspect_create_operation(CREATOR, 1, deadline())
            .unwrap()
            .phase,
        CreationPhase::Aborting
    );
    database.create_head(&late, deadline()).unwrap();
    assert_eq!(
        catalogue
            .resume_create(CREATOR, &creation, deadline())
            .unwrap()
            .phase,
        CreationPhase::Aborting
    );
    let done = catalogue
        .abort_create(CREATOR, &control, deadline())
        .unwrap();
    assert_eq!(done.phase, AbortPhase::Aborted);
    assert_eq!(done.head_revision, Some(2));
}

#[test]
fn foreign_occupied_proof_survives_name_reuse_and_foreign_head_changes() {
    let (objects, catalogue, creation) = stage(CreationPhase::Reserved);
    let mut other = creation.scope.clone();
    other.incarnation += 1;
    let foreign =
        Database::with_options(objects.clone(), other, 20, crate::tests::test_options()).unwrap();
    let original = foreign.create(90, 91, deadline()).unwrap();
    let progress = catalogue
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    assert_eq!(progress.phase, CreationPhase::IdentityConflict);
    assert_eq!(progress.head_revision, None);
    let control = abort(&creation);
    let done = catalogue
        .abort_create(CREATOR, &control, deadline())
        .unwrap();
    assert_eq!(done.phase, AbortPhase::Aborted);
    assert_eq!(done.head_revision, None);
    assert_eq!(foreign.status(90, deadline()).unwrap(), original);
    foreign
        .set_quota(
            90,
            original.revision,
            92,
            format::DatabaseQuota { max_bytes: None },
            deadline(),
        )
        .unwrap();
    let new = catalogue
        .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
        .unwrap();
    catalogue
        .resume_create(CREATOR, &new.creation, deadline())
        .unwrap();
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &control, deadline())
            .unwrap()
            .phase,
        AbortPhase::Aborted
    );
    assert_eq!(
        catalogue
            .resume_create(CREATOR, &creation, deadline())
            .unwrap()
            .phase,
        CreationPhase::Aborted
    );
    assert_eq!(
        foreign.status(90, deadline()).unwrap().quota.max_bytes,
        None
    );
    let proof = catalogue
        .read::<AbortProof>(&catalogue.proof_key(&creation), deadline())
        .unwrap()
        .unwrap();
    assert!(matches!(
        proof.body.barrier,
        Barrier::ForeignOccupied { creation: None, .. }
    ));
}

#[test]
fn descriptor_only_is_not_cancellation_and_bound_creation_cannot_be_aborted() {
    let (_, catalogue, creation) = prepared();
    let control = abort(&creation);
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &control, deadline())
            .unwrap()
            .phase,
        AbortPhase::NotReserved
    );
    catalogue
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &control, deadline())
            .unwrap()
            .phase,
        AbortPhase::CannotAbortBound
    );
    let (_, catalogue, creation) = stage(CreationPhase::Bound);
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::CannotAbortBound
    );
    assert_eq!(
        catalogue
            .delete(CREATOR, &delete(&creation), deadline())
            .unwrap()
            .phase,
        DeletionPhase::NotDeleted
    );
    catalogue
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    assert_eq!(
        catalogue
            .delete(CREATOR, &delete(&creation), deadline())
            .unwrap()
            .phase,
        DeletionPhase::Deleted
    );
    assert_eq!(
        catalogue
            .abort_create(CREATOR, &abort(&creation), deadline())
            .unwrap()
            .phase,
        AbortPhase::CannotAbortBound
    );
}

#[test]
fn current_admin_can_delete_without_read_or_provision_and_creation_scope_is_kept() {
    let (_, catalogue, creation) = stage(CreationPhase::Ready);
    let descriptor = descriptor(&catalogue, &creation);
    let database = catalogue.database(&descriptor).unwrap();
    let head = database
        .set_policy(
            CREATOR.principal,
            2,
            50,
            vec![
                Permission {
                    principal: CREATOR.principal,
                    read: false,
                    write: false,
                    admin: false,
                },
                Permission {
                    principal: 12,
                    read: false,
                    write: false,
                    admin: true,
                },
            ],
            deadline(),
        )
        .unwrap();
    let admin = Caller {
        principal: 12,
        provision: false,
    };
    assert_eq!(
        catalogue.resolve(admin, &creation.name, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.inspect_create_operation(CREATOR, 1, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.resume_create(CREATOR, &creation, deadline()),
        Err(CatalogueError::Denied)
    );
    let mut control = delete(&creation);
    control.expected_head_revision = head.revision;
    let result = catalogue.delete(admin, &control, deadline()).unwrap();
    assert_eq!(result.phase, DeletionPhase::Deleted);
    assert_eq!(result.creation.creator, CREATOR.principal);
    assert_eq!(
        catalogue.delete(admin, &control, deadline()).unwrap(),
        result
    );
    assert_eq!(
        catalogue.delete(CREATOR, &control, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.inspect_create_operation(admin, 1, deadline()),
        Err(CatalogueError::Denied)
    );
    assert_eq!(
        catalogue.inspect_create_operation(CREATOR, 1, deadline()),
        Err(CatalogueError::Denied)
    );
}

#[test]
fn normal_delete_uses_original_control_and_old_scope_after_reuse() {
    for maintenance in [false, true] {
        let (_, catalogue, creation) = stage(CreationPhase::Ready);
        let database = catalogue
            .database(&descriptor(&catalogue, &creation))
            .unwrap();
        let mut control = delete(&creation);
        if maintenance {
            let head = database
                .set_lifecycle(CREATOR.principal, 2, 5, Lifecycle::Maintenance, deadline())
                .unwrap();
            control.expected_head_revision = head.revision;
            assert_eq!(
                catalogue.resolve(CREATOR, &creation.name, deadline()),
                Err(CatalogueError::NotFound)
            );
            assert_eq!(
                catalogue.resume_create(CREATOR, &creation, deadline()),
                Err(CatalogueError::Conflict)
            );
        }
        let done = catalogue.delete(CREATOR, &control, deadline()).unwrap();
        assert_eq!(done.phase, DeletionPhase::Deleted);
        assert_eq!(
            catalogue
                .inspect_create_operation(CREATOR, 1, deadline())
                .unwrap()
                .phase,
            CreationPhase::Deleted
        );
        let new = catalogue
            .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
            .unwrap();
        catalogue
            .resume_create(CREATOR, &new.creation, deadline())
            .unwrap();
        let old = catalogue.delete(CREATOR, &control, deadline()).unwrap();
        assert_eq!(old.phase, DeletionPhase::Deleted);
        assert_eq!(old.binding_revision, None);
        assert_eq!(
            catalogue
                .inspect_create_operation(CREATOR, 1, deadline())
                .unwrap()
                .phase,
            CreationPhase::Deleted
        );
        assert_eq!(
            catalogue
                .abort_create(CREATOR, &abort(&creation), deadline())
                .unwrap()
                .phase,
            AbortPhase::CannotAbortBound
        );
        let mut changed = control;
        changed.operation += 1;
        assert_eq!(
            catalogue.delete(CREATOR, &changed, deadline()),
            Err(CatalogueError::Conflict)
        );
    }
}

#[test]
fn control_ids_freeze_every_condition_even_when_first_target_cas_conflicts() {
    let (_, catalogue, creation) = stage(CreationPhase::Reserved);
    let mut wrong = abort(&creation);
    wrong.expected_name_revision = 99;
    assert_eq!(
        catalogue.abort_create(CREATOR, &wrong, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        catalogue.abort_create(CREATOR, &abort(&creation), deadline()),
        Err(CatalogueError::Conflict)
    );
    wrong.expected_name_revision = 1;
    wrong.operation += 1;
    catalogue.abort_create(CREATOR, &wrong, deadline()).unwrap();
    let mut changed = wrong.clone();
    changed.nonce += 1;
    assert_eq!(
        catalogue.abort_create(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
    changed = wrong;
    changed.operation += 1;
    assert_eq!(
        catalogue.abort_create(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );

    let (_, catalogue, creation) = stage(CreationPhase::Ready);
    let mut wrong = delete(&creation);
    wrong.expected_head_revision = 1;
    assert_eq!(
        catalogue.delete(CREATOR, &wrong, deadline()),
        Err(CatalogueError::Conflict)
    );
    assert_eq!(
        catalogue.delete(CREATOR, &delete(&creation), deadline()),
        Err(CatalogueError::Conflict)
    );
    wrong.expected_head_revision = 2;
    wrong.operation += 1;
    catalogue.delete(CREATOR, &wrong, deadline()).unwrap();
    let mut changed = wrong.clone();
    changed.expected_name_revision += 1;
    assert_eq!(
        catalogue.delete(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
    changed = wrong;
    changed.nonce += 1;
    assert_eq!(
        catalogue.delete(CREATOR, &changed, deadline()),
        Err(CatalogueError::Conflict)
    );
}

#[test]
fn all_ordinary_entries_reject_provisioning_and_generic_lifecycle_cannot_bypass_named_delete() {
    let (_, catalogue, creation) = stage(CreationPhase::Provisioning);
    let descriptor = descriptor(&catalogue, &creation);
    let database = catalogue.database(&descriptor).unwrap();
    let head = database.read_head(deadline()).unwrap().head;
    let directory = tempfile::tempdir().unwrap();
    let sql = crate::tests::sql("SELECT 1");
    let request = crate::request(1, 1, CREATOR.principal, &sql).unwrap();
    let results = [
        database.status(CREATOR.principal, deadline()).map(|_| ()),
        database
            .lookup(CREATOR.principal, &request, deadline())
            .map(|_| ()),
        database
            .cancel(CREATOR.principal, &request, deadline())
            .map(|_| ()),
        database
            .takeover(CREATOR.principal, 1, 1, deadline())
            .map(|_| ()),
        database
            .activate(CREATOR.principal, 1, 1, deadline())
            .map(|_| ()),
        database
            .set_policy(CREATOR.principal, 1, 1, head.policy.clone(), deadline())
            .map(|_| ()),
        database
            .set_quota(CREATOR.principal, 1, 1, head.quota.clone(), deadline())
            .map(|_| ()),
        database
            .set_lifecycle(CREATOR.principal, 1, 1, Lifecycle::Ready, deadline())
            .map(|_| ()),
        database
            .close_full(CREATOR.principal, 1, 1, deadline())
            .map(|_| ()),
        database
            .session(CREATOR.principal, directory.path(), deadline())
            .map(|_| ()),
        database
            .activate_session(CREATOR.principal, 1, 1, directory.path(), deadline())
            .map(|_| ()),
        database
            .query(CREATOR.principal, &sql, directory.path(), deadline())
            .map(|_| ()),
        database
            .execute(
                CREATOR.principal,
                &request,
                &sql,
                directory.path(),
                deadline(),
            )
            .map(|_| ()),
    ];
    for result in results {
        assert!(matches!(result, Err(Error::Lifecycle)));
    }
    catalogue
        .resume_create(CREATOR, &creation, deadline())
        .unwrap();
    for target in [Lifecycle::Provisioning, Lifecycle::Deleted] {
        assert!(matches!(
            database.set_lifecycle(CREATOR.principal, 2, 1, target, deadline()),
            Err(Error::Lifecycle)
        ));
    }
    database
        .set_lifecycle(CREATOR.principal, 2, 1, Lifecycle::Maintenance, deadline())
        .unwrap();
    database
        .set_lifecycle(CREATOR.principal, 3, 2, Lifecycle::Ready, deadline())
        .unwrap();
}
