//! Bounded, advisory rejection evidence captured at the deciding resource gate.
//! JSON outcomes and receipts remain authoritative. These facts grant no access
//! and cannot authorize a retry. The operator controls their HTTP visibility.

use axum::http::HeaderValue;

pub const HEADER: &str = "x-scap-rejection";
pub const MAX_HEADER_BYTES: usize = 256;

/// Every counted reason identifies one existing gate, its units and partition.
/// Queue counts are charged credits, including retained in-flight group credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Budget {
    IntakeDataRequestsGlobal,
    IntakeDataRequestsTenant,
    IntakeDataBodyGlobal,
    IntakeDataBodyTenant,
    IntakeControlRequestsGlobal,
    IntakeControlRequestsTenant,
    IntakeControlBodyGlobal,
    IntakeControlBodyTenant,
    IntakeRecoveryRequestsGlobal,
    IntakeRecoveryRequestsTenant,
    IntakeRecoveryBodyGlobal,
    IntakeRecoveryBodyTenant,
    IntakeCatalogueRequestsGlobal,
    IntakeCatalogueRequestsTenant,
    IntakeCatalogueBodyGlobal,
    IntakeCatalogueBodyTenant,
    QueueGlobalTotal,
    QueueGlobalData,
    QueueTenantTotal,
    QueueTenantData,
    QueueDatabaseTotal,
    QueueDatabaseData,
    ActorsGlobal,
    ActorsTenant,
    OutputBaseSharedGlobal,
    OutputBaseSharedTenant,
    OutputBaseControlGlobal,
    OutputBaseControlTenant,
    OutputGrowthGlobal,
    OutputGrowthTenant,
    CatalogueQueueGlobal,
    CatalogueQueueTenant,
    CatalogueQueueName,
    RestoreQueueGlobal,
    RestoreQueueTenant,
    RestoreQueueName,
    DiscoveryGlobal,
    DiscoveryTenant,
    DiscoveryThreads,
    RestoreStagingGlobal,
    RestoreStagingTenant,
}

/// Sources whose deciding operation provides no atomic usage snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    ActorDraining,
    OutputBaseAllocation,
    OutputGrowthAllocation,
    NativeRecoveryBusy,
    NativeRecoveryClosed,
}

impl Budget {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::IntakeDataRequestsGlobal => "intake_data_requests_global",
            Self::IntakeDataRequestsTenant => "intake_data_requests_tenant",
            Self::IntakeDataBodyGlobal => "intake_data_body_global",
            Self::IntakeDataBodyTenant => "intake_data_body_tenant",
            Self::IntakeControlRequestsGlobal => "intake_control_requests_global",
            Self::IntakeControlRequestsTenant => "intake_control_requests_tenant",
            Self::IntakeControlBodyGlobal => "intake_control_body_global",
            Self::IntakeControlBodyTenant => "intake_control_body_tenant",
            Self::IntakeRecoveryRequestsGlobal => "intake_recovery_requests_global",
            Self::IntakeRecoveryRequestsTenant => "intake_recovery_requests_tenant",
            Self::IntakeRecoveryBodyGlobal => "intake_recovery_body_global",
            Self::IntakeRecoveryBodyTenant => "intake_recovery_body_tenant",
            Self::IntakeCatalogueRequestsGlobal => "intake_catalogue_requests_global",
            Self::IntakeCatalogueRequestsTenant => "intake_catalogue_requests_tenant",
            Self::IntakeCatalogueBodyGlobal => "intake_catalogue_body_global",
            Self::IntakeCatalogueBodyTenant => "intake_catalogue_body_tenant",
            Self::QueueGlobalTotal => "queue_global_total",
            Self::QueueGlobalData => "queue_global_data",
            Self::QueueTenantTotal => "queue_tenant_total",
            Self::QueueTenantData => "queue_tenant_data",
            Self::QueueDatabaseTotal => "queue_database_total",
            Self::QueueDatabaseData => "queue_database_data",
            Self::ActorsGlobal => "actors_global",
            Self::ActorsTenant => "actors_tenant",
            Self::OutputBaseSharedGlobal => "output_base_shared_global",
            Self::OutputBaseSharedTenant => "output_base_shared_tenant",
            Self::OutputBaseControlGlobal => "output_base_control_global",
            Self::OutputBaseControlTenant => "output_base_control_tenant",
            Self::OutputGrowthGlobal => "output_growth_global",
            Self::OutputGrowthTenant => "output_growth_tenant",
            Self::CatalogueQueueGlobal => "catalogue_queue_global",
            Self::CatalogueQueueTenant => "catalogue_queue_tenant",
            Self::CatalogueQueueName => "catalogue_queue_name",
            Self::RestoreQueueGlobal => "restore_queue_global",
            Self::RestoreQueueTenant => "restore_queue_tenant",
            Self::RestoreQueueName => "restore_queue_name",
            Self::DiscoveryGlobal => "discovery_global",
            Self::DiscoveryTenant => "discovery_tenant",
            Self::DiscoveryThreads => "discovery_threads",
            Self::RestoreStagingGlobal => "restore_staging_global",
            Self::RestoreStagingTenant => "restore_staging_tenant",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::OutputGrowthGlobal | Self::OutputGrowthTenant => "LIMIT",
            Self::RestoreStagingGlobal | Self::RestoreStagingTenant => "RECOVERY_BUSY",
            _ => "BACKPRESSURE",
        }
    }
}

impl Source {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ActorDraining => "actor_draining",
            Self::OutputBaseAllocation => "output_base_allocation",
            Self::OutputGrowthAllocation => "output_growth_allocation",
            Self::NativeRecoveryBusy => "native_recovery_busy",
            Self::NativeRecoveryClosed => "native_recovery_closed",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::OutputGrowthAllocation => "LIMIT",
            Self::NativeRecoveryBusy | Self::NativeRecoveryClosed => "RECOVERY_BUSY",
            _ => "BACKPRESSURE",
        }
    }
}

/// All three integers come from the original rejection check, before releasing
/// its lock. Source-only reasons cannot carry invented counters by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Counted {
        budget: Budget,
        used: u64,
        limit: u64,
        requested: u64,
    },
    Source(Source),
}

impl Rejection {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Counted { budget, .. } => budget.code(),
            Self::Source(source) => source.code(),
        }
    }

    pub(crate) fn is_valid(self) -> bool {
        if let Self::Counted {
            used,
            limit,
            requested,
            ..
        } = self
        {
            limit > 0
                && requested > 0
                && used <= limit
                && u128::from(used) + u128::from(requested) > u128::from(limit)
        } else {
            true
        }
    }

    /// Formatting is delayed until an opted-in HTTP response is emitted. Only
    /// static ASCII reason names and bounded decimal u64 fields can be written.
    pub(crate) fn header(self) -> HeaderValue {
        let text = match self {
            Self::Counted {
                budget,
                used,
                limit,
                requested,
            } => format!(
                "v=1;reason={};used={used};limit={limit};requested={requested}",
                budget.reason(),
            ),
            Self::Source(source) => format!("v=1;reason={}", source.reason()),
        };
        HeaderValue::from_str(&text).expect("fixed ASCII rejection fields form a valid header")
    }
}

// Longest fixed reason plus three full u64 decimal values and all punctuation.
// The explicit reason inventory is also checked independently in unit tests.
const _: () = assert!(11 + 48 + 3 * 20 + 24 <= MAX_HEADER_BYTES);

#[cfg(test)]
mod tests;
