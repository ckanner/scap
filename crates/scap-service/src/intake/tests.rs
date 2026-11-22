use super::*;
use crate::tests::principal;

#[test]
fn every_class_snapshots_the_first_rejecting_scope_before_releasing_the_lock() {
    use crate::tests::assert_budget;
    use Budget::*;
    for (class, budgets) in [
        (
            Class::Data,
            [
                IntakeDataRequestsGlobal,
                IntakeDataRequestsTenant,
                IntakeDataBodyGlobal,
                IntakeDataBodyTenant,
            ],
        ),
        (
            Class::Control,
            [
                IntakeControlRequestsGlobal,
                IntakeControlRequestsTenant,
                IntakeControlBodyGlobal,
                IntakeControlBodyTenant,
            ],
        ),
        (
            Class::Recovery,
            [
                IntakeRecoveryRequestsGlobal,
                IntakeRecoveryRequestsTenant,
                IntakeRecoveryBodyGlobal,
                IntakeRecoveryBodyTenant,
            ],
        ),
        (
            Class::Catalogue,
            [
                IntakeCatalogueRequestsGlobal,
                IntakeCatalogueRequestsTenant,
                IntakeCatalogueBodyGlobal,
                IntakeCatalogueBodyTenant,
            ],
        ),
    ] {
        for (
            index,
            total,
            requests_per_tenant,
            body_bytes,
            body_bytes_per_tenant,
            used,
            limit,
            requested,
        ) in [
            (0, 1, 1, 1024, 1024, 1, 1, 1),
            (1, 3, 1, 3072, 3072, 1, 1, 1),
            (2, 4, 4, 1024, 1024, 1024, 1024, 1024),
            (3, 4, 4, 2048, 1024, 1024, 1024, 1024),
        ] {
            let pool = Arc::new(
                Intake::new(
                    class,
                    total,
                    1024,
                    Some(Profile {
                        version: 1,
                        requests_per_tenant,
                        body_bytes,
                        body_bytes_per_tenant,
                    }),
                )
                .unwrap(),
            );
            let first = pool.acquire(&principal()).unwrap();
            let failure = pool.acquire(&principal()).err().unwrap();
            assert_budget(&failure, budgets[index], used, limit, requested);
            assert_eq!(pool.usage.lock().unwrap().tenants.len(), 1);
            drop(first);
            assert_eq!(pool.available_permits(), total);
            assert_budget(&failure, budgets[index], used, limit, requested);
        }
    }
}

fn pool(total: usize, per_tenant: usize, bytes: usize, tenant_bytes: usize) -> Arc<Intake> {
    Arc::new(
        Intake::new(
            Class::Data,
            total,
            1024,
            Some(Profile {
                version: 1,
                requests_per_tenant: per_tenant,
                body_bytes: bytes,
                body_bytes_per_tenant: tenant_bytes,
            }),
        )
        .unwrap(),
    )
}

fn other(tenant: u64) -> Principal {
    Principal {
        tenant,
        ..principal()
    }
}

/// Simulate a real owner panic without modifying any counter. HTTP tests
/// invoke this only after their body is polled, so admission already exists.
pub(crate) fn poison_accounting(pool: &Arc<Intake>) {
    let _ = std::panic::catch_unwind(|| {
        let _guard = pool.usage.lock().unwrap();
        panic!("injected accounting owner panic during upload");
    });
}

#[test]
fn version_one_defaults_preserve_single_body_capacity_and_bound_aggregate_extent() {
    let profile = Profile::resolve(1, 1, None).unwrap();
    assert_eq!(profile.version, 1);
    assert_eq!(profile.requests_per_tenant, 1);
    assert_eq!((profile.body_bytes, profile.body_bytes_per_tenant), (1, 1));
    let profile = Profile::resolve(5, 1024, None).unwrap();
    assert_eq!(profile.requests_per_tenant, 2);
    assert_eq!(
        (profile.body_bytes, profile.body_bytes_per_tenant),
        (5120, 5120)
    );
    let profile = Profile::resolve(4096, 128 * 1024 * 1024, None).unwrap();
    assert_eq!(profile.body_bytes, 256 * 1024 * 1024);
    assert_eq!(profile.body_bytes_per_tenant, 128 * 1024 * 1024);
    let pool = Arc::new(Intake::new(Class::Data, 4096, 128 * 1024 * 1024, None).unwrap());
    let first = pool.acquire(&principal()).unwrap();
    assert_eq!(
        pool.acquire(&principal()).err().unwrap().code,
        "BACKPRESSURE"
    );
    let second = pool.acquire(&other(3)).unwrap();
    assert_eq!(pool.acquire(&other(4)).err().unwrap().code, "BACKPRESSURE");
    drop((first, second));
    assert_eq!(pool.available_permits(), 4096);
}

#[test]
fn invalid_profiles_and_mismatched_routes_are_rejected_before_admission() {
    for (total, body) in [(0, 1), (4097, 1), (1, 0), (1, 128 * 1024 * 1024 + 1)] {
        assert_eq!(
            Intake::new(Class::Data, total, body, None)
                .err()
                .unwrap()
                .code,
            "CONFIG"
        );
    }
    let baseline = Profile {
        version: 1,
        requests_per_tenant: 2,
        body_bytes: 4096,
        body_bytes_per_tenant: 2048,
    };
    for profile in [
        Profile {
            version: 0,
            ..baseline
        },
        Profile {
            requests_per_tenant: 0,
            ..baseline
        },
        Profile {
            requests_per_tenant: 5,
            ..baseline
        },
        Profile {
            body_bytes: 1023,
            ..baseline
        },
        Profile {
            body_bytes_per_tenant: 1023,
            ..baseline
        },
        Profile {
            body_bytes_per_tenant: 4097,
            ..baseline
        },
    ] {
        assert_eq!(
            Profile::resolve(4, 1024, Some(profile)).err().unwrap().code,
            "CONFIG"
        );
    }
    for (class, name) in [
        (Class::Data, "data"),
        (Class::Control, "control"),
        (Class::Recovery, "recovery"),
        (Class::Catalogue, "catalogue"),
    ] {
        let pool = Intake::new(class, 4, 1024, Some(baseline)).unwrap();
        assert_eq!(class.admission(), name);
        assert!(pool.validate(class, 1024).is_ok());
        assert_eq!(pool.validate(class, 1023).unwrap_err().code, "CONFIG");
    }
    assert_eq!(
        pool(4, 2, 4096, 2048)
            .validate(Class::Control, 1024)
            .unwrap_err()
            .code,
        "CONFIG"
    );
}

#[test]
fn tenant_identity_spans_credentials_but_separates_deployments_and_cleans_empty_keys() {
    let pool = pool(4, 2, 4096, 2048);
    let first = pool.acquire(&principal()).unwrap();
    let mut same_tenant = principal();
    same_tenant.principal += 1;
    let second = pool.acquire(&same_tenant).unwrap();
    assert_eq!(
        pool.acquire(&same_tenant).err().unwrap().code,
        "BACKPRESSURE"
    );
    let third = pool.acquire(&other(3)).unwrap();
    let mut same_number_other_deployment = principal();
    same_number_other_deployment.deployment += 1;
    let fourth = pool.acquire(&same_number_other_deployment).unwrap();
    assert_eq!(pool.acquire(&other(9)).err().unwrap().code, "BACKPRESSURE");
    assert_eq!(pool.usage.lock().unwrap().tenants.len(), 3);
    let clone = first.clone();
    drop(first);
    assert_eq!(pool.available_permits(), 0);
    drop(clone);
    assert_eq!(pool.available_permits(), 1);
    assert_eq!(pool.usage.lock().unwrap().tenants.len(), 3);
    drop((second, third, fourth));
    let usage = pool.usage.lock().unwrap();
    assert_eq!((usage.all.requests, usage.all.bytes), (0, 0));
    assert!(usage.tenants.is_empty());
}

#[test]
fn global_and_tenant_byte_reservations_refund_only_proven_unused_body_extent() {
    let pool = pool(5, 3, 2048, 1024);
    let first = pool.acquire(&principal()).unwrap();
    assert_eq!(
        pool.acquire(&principal()).err().unwrap().code,
        "BACKPRESSURE"
    );
    let second = pool.acquire(&other(3)).unwrap();
    assert_eq!(pool.acquire(&other(4)).err().unwrap().code, "BACKPRESSURE");
    first.shrink_body(100).unwrap();
    assert_eq!(pool.usage.lock().unwrap().all.bytes, 1124);
    assert_eq!(first.shrink_body(101).unwrap_err().code, "LIMIT");
    first.shrink_body(100).unwrap();
    first.shrink_body(0).unwrap();
    let third = pool.acquire(&principal()).unwrap();
    assert_eq!(pool.available_permits(), 2);
    assert_eq!(pool.usage.lock().unwrap().all.bytes, 2048);
    drop((first, second, third));
    assert_eq!(pool.available_permits(), 5);
    assert!(pool.usage.lock().unwrap().tenants.is_empty());
}

#[test]
fn a_reservation_can_dispatch_only_once_for_its_original_principal_and_class() {
    let pool = pool(2, 2, 2048, 2048);
    let reservation = pool.acquire(&principal()).unwrap();
    assert_eq!(
        reservation.claim(&other(3), "data").unwrap_err().code,
        "DENIED"
    );
    assert_eq!(
        reservation.claim(&principal(), "control").unwrap_err().code,
        "DENIED"
    );
    let mut changed = principal();
    changed.principal += 1;
    assert_eq!(
        reservation.claim(&changed, "data").unwrap_err().code,
        "DENIED"
    );
    reservation.claim(&principal(), "data").unwrap();
    assert_eq!(
        reservation
            .clone()
            .claim(&principal(), "data")
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(pool.available_permits(), 1);
}

#[test]
fn poisoned_accounting_fails_closed_but_final_drop_recovers_its_existing_reservation() {
    let pool = pool(2, 2, 2048, 2048);
    let reservation = pool.acquire(&principal()).unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _guard = pool.usage.lock().unwrap();
        panic!("injected accounting poison");
    });
    assert_eq!(pool.acquire(&other(3)).err().unwrap().code, "UNAVAILABLE");
    assert_eq!(reservation.shrink_body(0).unwrap_err().code, "UNAVAILABLE");
    assert_eq!(pool.available_permits(), 1);
    drop(reservation);
    assert_eq!(pool.available_permits(), 2);
    assert!(pool
        .usage
        .lock()
        .err()
        .unwrap()
        .into_inner()
        .tenants
        .is_empty());
}

#[test]
fn checked_addition_rejects_overflow_without_mutating_tenant_map() {
    let pool = pool(4, 4, usize::MAX, usize::MAX);
    pool.usage.lock().unwrap().all.bytes = usize::MAX;
    assert_eq!(
        pool.acquire(&principal()).err().unwrap().code,
        "BACKPRESSURE"
    );
    assert!(pool.usage.lock().unwrap().tenants.is_empty());
    pool.usage.lock().unwrap().all.bytes = 0;
    let lease = pool.acquire(&principal()).unwrap();
    let tenant = (principal().deployment, principal().tenant);
    pool.usage
        .lock()
        .unwrap()
        .tenants
        .get_mut(&tenant)
        .unwrap()
        .bytes = usize::MAX;
    assert_eq!(
        pool.acquire(&principal()).err().unwrap().code,
        "BACKPRESSURE"
    );
    pool.usage
        .lock()
        .unwrap()
        .tenants
        .get_mut(&tenant)
        .unwrap()
        .bytes = 1024;
    drop(lease);
    assert_eq!(pool.available_permits(), 4);
}

#[test]
fn simultaneous_authenticated_intake_never_exceeds_the_global_reservation() {
    let pool = pool(4, 2, 4096, 2048);
    let acquired = Arc::new(std::sync::Barrier::new(17));
    let release = Arc::new(std::sync::Barrier::new(17));
    let accepted = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (10..26)
        .map(|tenant| {
            let pool = pool.clone();
            let acquired = acquired.clone();
            let release = release.clone();
            let accepted = accepted.clone();
            std::thread::spawn(move || {
                let lease = pool.acquire(&other(tenant)).ok();
                if lease.is_some() {
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
                acquired.wait();
                release.wait();
                drop(lease);
            })
        })
        .collect();
    acquired.wait();
    assert_eq!(accepted.load(Ordering::SeqCst), 4);
    assert_eq!(pool.available_permits(), 0);
    assert_eq!(pool.usage.lock().unwrap().tenants.len(), 4);
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(pool.available_permits(), 4);
    assert!(pool.usage.lock().unwrap().tenants.is_empty());
}
