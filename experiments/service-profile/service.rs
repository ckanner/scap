//! Included only by a separately identified diagnostic source copy.
use scap_object_store::{Condition, Objects, StoreError, Stored};
use std::sync::Arc;
use std::time::Instant;

pub struct Measured(pub Arc<dyn Objects>);
impl Objects for Measured {
    fn get(&self, key: &str, max_bytes: usize, deadline: Instant) -> Result<Stored, StoreError> {
        let _span = scap_profile_metrics::Span::new(1);
        let value = self.0.get(key, max_bytes, deadline);
        if let Ok(stored) = &value {
            scap_profile_metrics::bytes(1, stored.bytes.len());
        }
        value
    }
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        let _span = scap_profile_metrics::Span::new(2);
        scap_profile_metrics::bytes(2, bytes.len());
        self.0.put(key, bytes, condition, deadline)
    }
}
pub async fn snapshot() -> axum::Json<serde_json::Value> {
    let (cpu, allocations, allocated_bytes, stages) = scap_profile_metrics::snapshot();
    axum::Json(
        serde_json::json!({"process_cpu_ns":cpu,"rust_allocation_calls":allocations,
        "http_connect_started_completed_reused":scap_profile_metrics::connections(),
        "rust_requested_bytes":allocated_bytes,"stage_names":scap_profile_metrics::STAGES,
        "stage_columns":["calls","wall_ns","caller_thread_cpu_ns","caller_allocation_calls","caller_requested_bytes","body_bytes"],
        "stages":stages}),
    )
}
