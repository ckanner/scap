use super::*;

#[test]
fn only_actual_positive_budget_overruns_are_valid_without_u64_sum_overflow() {
    for (used, limit, requested, valid) in [
        (0, 0, 1, false),
        (1, 1, 0, false),
        (2, 1, 1, false),
        (0, 2, 1, false),
        (1, 2, 1, false),
        (1, 2, 2, true),
        (0, 1, u64::MAX, true),
        (u64::MAX, u64::MAX, u64::MAX, true),
    ] {
        assert_eq!(
            Rejection::Counted {
                budget: Budget::RestoreStagingGlobal,
                used,
                limit,
                requested,
            }
            .is_valid(),
            valid
        );
    }
    assert!(Rejection::Source(Source::NativeRecoveryBusy).is_valid());
}

#[test]
fn counted_reasons_have_fixed_wire_names_and_do_not_round_u64_counts() {
    let cases = [
        (
            Budget::IntakeDataRequestsGlobal,
            "intake_data_requests_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeDataRequestsTenant,
            "intake_data_requests_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeDataBodyGlobal,
            "intake_data_body_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeDataBodyTenant,
            "intake_data_body_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeControlRequestsGlobal,
            "intake_control_requests_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeControlRequestsTenant,
            "intake_control_requests_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeControlBodyGlobal,
            "intake_control_body_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeControlBodyTenant,
            "intake_control_body_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeRecoveryRequestsGlobal,
            "intake_recovery_requests_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeRecoveryRequestsTenant,
            "intake_recovery_requests_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeRecoveryBodyGlobal,
            "intake_recovery_body_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeRecoveryBodyTenant,
            "intake_recovery_body_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeCatalogueRequestsGlobal,
            "intake_catalogue_requests_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeCatalogueRequestsTenant,
            "intake_catalogue_requests_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeCatalogueBodyGlobal,
            "intake_catalogue_body_global",
            "BACKPRESSURE",
        ),
        (
            Budget::IntakeCatalogueBodyTenant,
            "intake_catalogue_body_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::QueueGlobalTotal,
            "queue_global_total",
            "BACKPRESSURE",
        ),
        (Budget::QueueGlobalData, "queue_global_data", "BACKPRESSURE"),
        (
            Budget::QueueTenantTotal,
            "queue_tenant_total",
            "BACKPRESSURE",
        ),
        (Budget::QueueTenantData, "queue_tenant_data", "BACKPRESSURE"),
        (
            Budget::QueueDatabaseTotal,
            "queue_database_total",
            "BACKPRESSURE",
        ),
        (
            Budget::QueueDatabaseData,
            "queue_database_data",
            "BACKPRESSURE",
        ),
        (Budget::ActorsGlobal, "actors_global", "BACKPRESSURE"),
        (Budget::ActorsTenant, "actors_tenant", "BACKPRESSURE"),
        (
            Budget::OutputBaseSharedGlobal,
            "output_base_shared_global",
            "BACKPRESSURE",
        ),
        (
            Budget::OutputBaseSharedTenant,
            "output_base_shared_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::OutputBaseControlGlobal,
            "output_base_control_global",
            "BACKPRESSURE",
        ),
        (
            Budget::OutputBaseControlTenant,
            "output_base_control_tenant",
            "BACKPRESSURE",
        ),
        (Budget::OutputGrowthGlobal, "output_growth_global", "LIMIT"),
        (Budget::OutputGrowthTenant, "output_growth_tenant", "LIMIT"),
        (
            Budget::CatalogueQueueGlobal,
            "catalogue_queue_global",
            "BACKPRESSURE",
        ),
        (
            Budget::CatalogueQueueTenant,
            "catalogue_queue_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::CatalogueQueueName,
            "catalogue_queue_name",
            "BACKPRESSURE",
        ),
        (
            Budget::RestoreQueueGlobal,
            "restore_queue_global",
            "BACKPRESSURE",
        ),
        (
            Budget::RestoreQueueTenant,
            "restore_queue_tenant",
            "BACKPRESSURE",
        ),
        (
            Budget::RestoreQueueName,
            "restore_queue_name",
            "BACKPRESSURE",
        ),
        (Budget::DiscoveryGlobal, "discovery_global", "BACKPRESSURE"),
        (Budget::DiscoveryTenant, "discovery_tenant", "BACKPRESSURE"),
        (
            Budget::DiscoveryThreads,
            "discovery_threads",
            "BACKPRESSURE",
        ),
        (
            Budget::RestoreStagingGlobal,
            "restore_staging_global",
            "RECOVERY_BUSY",
        ),
        (
            Budget::RestoreStagingTenant,
            "restore_staging_tenant",
            "RECOVERY_BUSY",
        ),
    ];
    for (budget, reason, code) in cases {
        let evidence = Rejection::Counted {
            budget,
            used: u64::MAX,
            limit: u64::MAX,
            requested: 1,
        };
        assert_eq!(evidence.code(), code);
        let header = evidence.header();
        assert_eq!(
            header.to_str().unwrap(),
            format!(
            "v=1;reason={reason};used=18446744073709551615;limit=18446744073709551615;requested=1"
        )
        );
        assert!(header.as_bytes().is_ascii());
        assert!(header.as_bytes().len() <= MAX_HEADER_BYTES);
    }
    // A request can exceed the entire pool; that is still a counted rejection.
    assert_eq!(
        Rejection::Counted {
            budget: Budget::RestoreStagingGlobal,
            used: 0,
            limit: 1,
            requested: u64::MAX,
        }
        .header(),
        "v=1;reason=restore_staging_global;used=0;limit=1;requested=18446744073709551615"
    );
}

#[test]
fn source_only_reasons_never_fabricate_usage_or_change_the_original_error_class() {
    let cases = [
        (Source::ActorDraining, "actor_draining", "BACKPRESSURE"),
        (
            Source::OutputBaseAllocation,
            "output_base_allocation",
            "BACKPRESSURE",
        ),
        (
            Source::OutputGrowthAllocation,
            "output_growth_allocation",
            "LIMIT",
        ),
        (
            Source::NativeRecoveryBusy,
            "native_recovery_busy",
            "RECOVERY_BUSY",
        ),
        (
            Source::NativeRecoveryClosed,
            "native_recovery_closed",
            "RECOVERY_BUSY",
        ),
    ];
    for (source, reason, code) in cases {
        let evidence = Rejection::Source(source);
        assert_eq!(evidence.code(), code);
        assert_eq!(
            evidence.header().to_str().unwrap(),
            format!("v=1;reason={reason}")
        );
    }
}
