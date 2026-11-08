use super::*;
use crate::catalogue::tests::{abort, deadline, descriptor, input, stage, CREATOR};

#[test]
fn verified_name_reuse_preserves_a_permanent_physical_head_slot() {
    let (_, catalog, creation) = stage(CreationPhase::Reserved);
    catalog
        .abort_create(CREATOR, &abort(&creation), deadline())
        .unwrap();
    let name = catalog
        .read_binding(&creation.name, deadline())
        .unwrap()
        .unwrap();
    catalog.verify_tombstone(&name, deadline()).unwrap();
    let mut colliding_slot = creation.scope.clone();
    colliding_slot.incarnation += 1;
    assert_ne!(colliding_slot, creation.scope);
    assert_eq!(
        format::head_key(&colliding_slot),
        format::head_key(&creation.scope)
    );
    assert_eq!(
        Catalogue::reuse_plan(&colliding_slot, &name).phase,
        CreationPhase::IdentityConflict
    );
    let next = catalog
        .prepare(CREATOR, &input(&creation.name, 2, Some(3)), deadline())
        .unwrap();
    let plan = Catalogue::reuse_plan(&next.creation.scope, &name);
    assert_eq!(plan.phase, CreationPhase::NotReserved);
    assert!(matches!(plan.step, CreateStep::Reserve(Some(previous)) if previous == &name));
    assert_eq!(descriptor(&catalog, &creation).creation, creation);
}
