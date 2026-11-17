//! Temporary test-only harness for the real private production helper.

use super::*;
use super::fingerprint_tests::{heads, legacy, streamed};

fn measure<T>(head: &Head, iterations: u32, function: impl Fn(&Head) -> T) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(function(std::hint::black_box(head)));
    }
    start.elapsed().as_nanos() / u128::from(iterations)
}

/// This compares only HEAD fingerprint computation. It neither attributes the
/// earlier HTTP/S3 regression nor certifies end-to-end throughput or RSS.
#[test]
fn profile() {
    for (case, head) in heads().into_iter().enumerate() {
        let iterations = if case == 0 { 20_000 } else { 1_000 };
        let mut legacy_ns = Vec::new();
        let mut binary_ns = Vec::new();
        let mut streamed_ns = Vec::new();
        for round in 0..9 {
            for offset in 0..3 {
                match (round + offset) % 3 {
                    0 => legacy_ns.push(measure(&head, iterations, legacy)),
                    1 => binary_ns.push(measure(&head, iterations, head_fingerprint)),
                    _ => streamed_ns.push(measure(&head, iterations, streamed)),
                }
            }
        }
        println!(
            "FINGERPRINT_PROFILE {}",
            serde_json::json!({
                "case": if case == 0 { "small" } else { "max_principals" },
                "body_bytes": serde_json::to_vec(&head).unwrap().len(),
                "body_sha256": legacy(&head),
                "iterations_per_sample": iterations,
                "order": "rotating three alternatives, nine rounds",
                "legacy_ns_per_iteration": legacy_ns,
                "binary_ns_per_iteration": binary_ns,
                "streamed_ns_per_iteration": streamed_ns,
            })
        );
    }
}
