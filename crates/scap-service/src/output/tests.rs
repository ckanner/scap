use super::*;
use crate::tests::{principal, until};
use serde_json::json;

/// Small counter-domain fixtures exercise real allocation/ownership paths
/// without reserving hundreds of MiB. Public Profile validation is separate.
pub(crate) fn small_pool(shared: usize, tenant: usize) -> Arc<Pool> {
    Arc::new(Pool {
        profile: Profile {
            version: 1,
            bytes: shared + 2 * BASE_BYTES,
            bytes_per_tenant: tenant + BASE_BYTES,
            control_bytes: 2 * BASE_BYTES,
            control_bytes_per_tenant: BASE_BYTES,
        },
        usage: Mutex::new(Usage::default()),
    })
}

pub(crate) fn usage(pool: &Pool) -> (usize, usize, usize) {
    let usage = pool.usage.lock().unwrap_or_else(PoisonError::into_inner);
    (usage.all.shared, usage.all.control, usage.tenants.len())
}

pub(crate) fn receipt() -> Receipt {
    Receipt {
        scope: scap_object::format::Scope {
            deployment: 1,
            tenant: 2,
            database: 3,
            incarnation: 4,
            generation: 5,
        },
        request: scap_object::format::Request {
            epoch: 6,
            id: u64::MAX,
            principal: 3,
            fingerprint: "a".repeat(64),
        },
        sequence: u64::MAX,
        transition: scap_object::format::Transition {
            revision: 8,
            nonce: 9,
        },
        data_root: "b".repeat(64),
        result_hash: "c".repeat(64),
    }
}

fn refuse(_: &mut Vec<u8>, _: usize) -> Result<(), std::collections::TryReserveError> {
    Vec::<u8>::new().try_reserve_exact(usize::MAX)
}

#[test]
fn defaults_fit_one_largest_durable_output_without_shrinking_the_wire_contract() {
    let profile = Profile::default().checked().unwrap();
    assert_eq!(profile.bytes, 512 * 1024 * 1024);
    assert_eq!(profile.bytes_per_tenant, 256 * 1024 * 1024);
    assert_eq!(profile.control_bytes, 8 * 1024 * 1024);
    assert_eq!(profile.control_bytes_per_tenant, 1024 * 1024);
    assert_eq!(maximum_peak(64 * 1024 * 1024), Some(179_023_223));
    assert_eq!(maximum_peak(50 * 1024 * 1024), Some(139_876_383));
    assert_eq!(MAX_JSON_BYTES, 89_479_199);
    assert_eq!(base64_length(3).unwrap(), 4);
    assert_eq!(base64_length(usize::MAX).unwrap_err().code, "LIMIT");
    for raw in [
        usize::MAX,
        usize::MAX / 2,
        (usize::MAX / 8) * 3,
        (usize::MAX / 8 - JSON_OVERHEAD) * 3,
    ] {
        assert_eq!(maximum_peak(raw), None);
    }
    let minimum = maximum_peak(scap_object::format::MAX_RESULT_BYTES).unwrap();
    let bad = [
        Profile {
            version: 0,
            ..profile
        },
        Profile {
            bytes: usize::MAX,
            ..profile
        },
        Profile {
            bytes_per_tenant: profile.bytes + 1,
            ..profile
        },
        Profile {
            control_bytes: BASE_BYTES - 1,
            ..profile
        },
        Profile {
            control_bytes_per_tenant: BASE_BYTES - 1,
            ..profile
        },
        Profile {
            control_bytes_per_tenant: profile.control_bytes + 1,
            ..profile
        },
        Profile {
            control_bytes: profile.bytes + 1,
            ..profile
        },
        Profile {
            bytes: minimum + profile.control_bytes - 1,
            bytes_per_tenant: minimum + profile.control_bytes - 1,
            ..profile
        },
        Profile {
            bytes_per_tenant: BASE_BYTES,
            control_bytes_per_tenant: BASE_BYTES + 1,
            ..profile
        },
        Profile {
            bytes_per_tenant: minimum + profile.control_bytes_per_tenant - 1,
            ..profile
        },
        Profile {
            bytes_per_tenant: 500 * 1024 * 1024,
            control_bytes: 300 * 1024 * 1024,
            ..profile
        },
    ];
    for profile in bad {
        assert_eq!(Pool::new(profile).err().unwrap().code, "CONFIG");
    }
}

#[test]
fn both_scopes_are_atomic_and_data_cannot_spend_the_control_partition() {
    let pool = small_pool(3 * BASE_BYTES, 2 * BASE_BYTES);
    let first = principal();
    let mut second = first.clone();
    second.tenant += 1;
    let mut third = first.clone();
    third.deployment += 1;
    let a = pool.acquire(&first, false).unwrap();
    let b = pool.acquire(&first, false).unwrap();
    assert_eq!(
        pool.acquire(&first, false).err().unwrap().code,
        "BACKPRESSURE"
    );
    let c = pool.acquire(&second, false).unwrap();
    assert_eq!(
        pool.acquire(&third, false).err().unwrap().code,
        "BACKPRESSURE"
    );
    assert_eq!(usage(&pool), (3 * BASE_BYTES, 0, 2));
    let control_a = pool.acquire(&first, true).unwrap();
    assert_eq!(
        pool.acquire(&first, true).err().unwrap().code,
        "BACKPRESSURE"
    );
    let control_b = pool.acquire(&second, true).unwrap();
    assert_eq!(
        pool.acquire(&third, true).err().unwrap().code,
        "BACKPRESSURE"
    );
    assert_eq!(usage(&pool), (3 * BASE_BYTES, 2 * BASE_BYTES, 2));
    assert_eq!(a.claim(&second, false).unwrap_err().code, "DENIED");
    assert_eq!(a.claim(&first, true).unwrap_err().code, "DENIED");
    a.claim(&first, false).unwrap();
    control_a.claim(&first, true).unwrap();
    drop((a, b, c, control_a, control_b));
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn global_and_tenant_increment_failures_never_leave_partial_credit() {
    let pool = small_pool(3 * BASE_BYTES, 2 * BASE_BYTES);
    let a = pool.acquire(&principal(), false).unwrap();
    let mut second = principal();
    second.tenant += 1;
    let b = pool.acquire(&second, false).unwrap();
    assert_eq!(a.allocate(BASE_BYTES + 1).err().unwrap().code, "LIMIT");
    let buffer = a.allocate(BASE_BYTES).unwrap();
    assert_eq!(b.allocate(1).err().unwrap().code, "LIMIT");
    assert_eq!(usage(&pool), (3 * BASE_BYTES, 0, 2));
    drop(buffer);
    let local = small_pool(4 * BASE_BYTES, BASE_BYTES);
    let owner = local.acquire(&principal(), false).unwrap();
    assert_eq!(owner.allocate(1).err().unwrap().code, "LIMIT");
    assert_eq!(usage(&local), (BASE_BYTES, 0, 1));
    drop((a, b, owner));
    assert_eq!(usage(&pool), (0, 0, 0));
    assert_eq!(usage(&local), (0, 0, 0));
}

#[test]
fn small_and_dynamic_allocations_are_charged_before_calling_the_real_allocator() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let mut attempts = 0;
    let error = pool
        .acquire_with(&principal(), false, &mut |bytes, length| {
            attempts += 1;
            assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
            assert_eq!(length, SMALL_BYTES);
            assert_eq!(bytes.capacity(), 0);
            refuse(bytes, length)
        })
        .err()
        .unwrap();
    assert_eq!(attempts, 1);
    assert_eq!(error.code, "BACKPRESSURE");
    assert_eq!(usage(&pool), (0, 0, 0));
    let output = pool.acquire(&principal(), false).unwrap();
    let buffer = output
        .allocate_with(1024, &mut |bytes, length| {
            assert_eq!(usage(&pool), (BASE_BYTES + 1024, 0, 1));
            assert_eq!(bytes.capacity(), 0);
            bytes.try_reserve_exact(length)
        })
        .unwrap();
    assert_eq!(buffer.bytes.len(), 1024);
    assert_eq!(buffer.bytes.capacity(), 1024);
    assert_eq!(
        output.allocate_with(2048, &mut refuse).err().unwrap().code,
        "LIMIT"
    );
    assert_eq!(usage(&pool), (BASE_BYTES + 1024, 0, 1));
    drop(output);
    // A surviving real buffer independently retains both its capacity and E.
    assert_eq!(usage(&pool), (BASE_BYTES + 1024, 0, 1));
    drop(buffer);
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn poison_blocks_new_admission_but_does_not_leak_existing_owners() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let output = pool.acquire(&principal(), false).unwrap();
    let buffer = output.allocate(16).unwrap();
    let held = pool.clone();
    let panic = std::panic::catch_unwind(move || {
        let _guard = held.usage.lock().unwrap();
        panic!("unit poisoned ledger");
    });
    assert!(panic.is_err());
    assert_eq!(
        pool.acquire(&principal(), false).err().unwrap().code,
        "UNAVAILABLE"
    );
    assert_eq!(output.allocate(16).err().unwrap().code, "UNAVAILABLE");
    drop((output, buffer));
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn wire_base64_json_overlap_and_final_clone_capacity_are_all_retained() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let mut output = pool.acquire(&principal(), false).unwrap();
    let hold = output.work_hold();
    let raw = vec![7; 4096];
    let mut wire = output.allocate(raw.len()).unwrap();
    wire.as_mut().copy_from_slice(&raw);
    let encoded = output.base64(wire.as_slice()).unwrap();
    let base64_bytes = encoded.len();
    assert_eq!(encoded, STANDARD.encode(&raw));
    assert_eq!(usage(&pool), (BASE_BYTES + raw.len() + base64_bytes, 0, 1));
    let pointer = encoded.as_ptr();
    let value = Value::Object(serde_json::Map::from_iter([(
        "result".into(),
        Value::String(encoded),
    )]));
    assert_eq!(value["result"].as_str().unwrap().as_ptr(), pointer);
    drop(wire);
    let json_bytes = base64_bytes + 33;
    let mut allocations = 0;
    let reply = OwnedValue::new(Ok(value), output)
        .finish_with(until(), &mut Instant::now, &mut |bytes, length| {
            allocations += 1;
            assert_eq!(length, json_bytes);
            assert_eq!(usage(&pool), (BASE_BYTES + base64_bytes + json_bytes, 0, 1));
            bytes.try_reserve_exact(length)
        })
        .unwrap();
    assert_eq!(allocations, 1);
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.bytes.len(), json_bytes);
    assert_eq!(usage(&pool), (BASE_BYTES + json_bytes, 0, 1));
    let copy = reply.bytes.clone();
    let slice = copy.slice(1..2);
    drop(reply);
    drop(copy);
    assert_eq!(usage(&pool), (BASE_BYTES + json_bytes, 0, 1));
    drop(slice);
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(hold);
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn small_json_uses_prepared_backing_and_keeps_fixed_compact_bytes() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let output = pool.acquire(&principal(), false).unwrap();
    let reply = OwnedValue::new(Ok(json!({"z":null,"b":"line\n\"\\","a":[]})), output)
        .finish_with(until(), &mut Instant::now, &mut |_, _| {
            panic!("small JSON must not allocate another backing")
        })
        .unwrap();
    assert_eq!(
        &reply.bytes[..],
        br#"{"ok":true,"value":{"a":[],"b":"line\n\"\\","z":null}}"#
    );
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(reply);
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn maximum_receipt_projection_fits_the_prepared_fallback_without_new_backing() {
    let mut original = receipt();
    original.scope = scap_object::format::Scope {
        deployment: u64::MAX,
        tenant: u64::MAX,
        database: u64::MAX,
        incarnation: u64::MAX,
        generation: u64::MAX,
    };
    original.request.epoch = u64::MAX;
    original.request.id = u64::MAX;
    original.request.principal = u64::MAX;
    original.sequence = u64::MAX;
    original.transition.revision = u64::MAX;
    original.transition.nonce = u64::MAX;
    let pool = small_pool(2 * BASE_BYTES, 2 * BASE_BYTES);
    for failed in [false, true] {
        let mut output = pool.acquire(&principal(), false).unwrap();
        output.committed(original.clone());
        let value = if failed {
            Err(output.committed_unavailable())
        } else {
            Ok(wire::committed(output.receipt(), String::new()))
        };
        let reply = OwnedValue::new(value, output)
            .finish_with(until(), &mut Instant::now, &mut |_, _| {
                panic!("largest receipt projection must use prepared bytes")
            })
            .unwrap();
        assert!(reply.bytes.len() <= if failed { 753 } else { JSON_OVERHEAD });
        let decoded: Value = serde_json::from_slice(&reply.bytes).unwrap();
        let observed = if failed {
            &decoded["error"]["receipt"]
        } else {
            &decoded["value"]["receipt"]
        };
        assert_eq!(observed, &wire::receipt(&original));
        drop(reply);
        assert_eq!(usage(&pool), (0, 0, 0));
    }
}

#[test]
fn base64_allocation_refusal_refunds_only_its_new_backing() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let mut output = pool.acquire(&principal(), false).unwrap();
    assert_eq!(
        output
            .base64_with(&[1, 2, 3], &mut refuse)
            .unwrap_err()
            .code,
        "LIMIT"
    );
    assert!(output.value_charge.is_none());
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    let limited = small_pool(BASE_BYTES, BASE_BYTES);
    let mut blocked = limited.acquire(&principal(), false).unwrap();
    assert_eq!(blocked.base64(&[1]).unwrap_err().code, "LIMIT");
    drop((output, blocked));
    assert_eq!(usage(&pool), (0, 0, 0));
    assert_eq!(usage(&limited), (0, 0, 0));
}

#[test]
fn final_json_refusal_keeps_original_receipt_or_query_limit_and_never_replays() {
    for committed in [false, true] {
        let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
        let mut output = pool.acquire(&principal(), false).unwrap();
        let original = receipt();
        let encoded = output.base64(&[7; 2048]).unwrap();
        let value = if committed {
            output.committed(original.clone());
            wire::committed(output.receipt(), encoded)
        } else {
            Value::Object(serde_json::Map::from_iter([(
                "result".into(),
                Value::String(encoded),
            )]))
        };
        let mut failed_allocations = 0;
        let reply = OwnedValue::new(Ok(value), output)
            .finish_with(until(), &mut Instant::now, &mut |bytes, length| {
                failed_allocations += 1;
                assert!(length > SMALL_BYTES);
                refuse(bytes, length)
            })
            .unwrap();
        assert_eq!(
            failed_allocations, 1,
            "fallback uses the original prepared buffer"
        );
        let value: Value = serde_json::from_slice(&reply.bytes).unwrap();
        if committed {
            assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(value["error"]["code"], "COMMITTED_BUT_UNAVAILABLE");
            assert_eq!(value["error"]["receipt"], wire::receipt(&original));
        } else {
            assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(
                value,
                json!({"ok":false,"error":{"code":"LIMIT","message":"LIMIT"}})
            );
        }
        assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
        drop(reply);
        assert_eq!(usage(&pool), (0, 0, 0));
    }
}

#[test]
fn original_unknown_stays_unknown_and_head_only_encoding_failure_closes_reply() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let output = pool.acquire(&principal(), false).unwrap();
    let reply = OwnedValue::new(Err(Failure::new("UNKNOWN")), output)
        .finish_with(until(), &mut Instant::now, &mut refuse)
        .unwrap();
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        &reply.bytes[..],
        br#"{"error":{"code":"UNKNOWN","message":"UNKNOWN"},"ok":false}"#
    );
    drop(reply);
    let mut output = pool.acquire(&principal(), true).unwrap();
    output.head_result();
    let value = Value::String("x".repeat(4096));
    assert!(OwnedValue::new(Ok(value), output)
        .finish_with(until(), &mut Instant::now, &mut refuse)
        .is_none());
    assert_eq!(usage(&pool), (0, 0, 0));

    // An explicitly implemented custom worker violating the small Failure
    // contract must close instead of manufacturing a different receipt/ACK.
    let output = pool.acquire(&principal(), false).unwrap();
    let mut oversized = receipt();
    oversized.result_hash = "x".repeat(4096);
    let error = Failure {
        code: "COMMITTED_BUT_UNAVAILABLE",
        receipt: Some(Box::new(oversized)),
    };
    assert!(OwnedValue::new(Err(error), output)
        .finish_with(until(), &mut Instant::now, &mut refuse)
        .is_none());
    assert_eq!(usage(&pool), (0, 0, 0));
}

#[test]
fn original_deadline_is_checked_before_and_after_complete_encoding() {
    let pool = small_pool(4 * BASE_BYTES, 2 * BASE_BYTES);
    let before = Instant::now();
    let deadline = before + std::time::Duration::from_secs(1);
    let output = pool.acquire(&principal(), false).unwrap();
    assert!(OwnedValue::new(Ok(json!(1)), output)
        .finish_with(deadline, &mut || deadline, &mut refuse)
        .is_none());
    assert_eq!(usage(&pool), (0, 0, 0));
    for large in [false, true] {
        let mut output = pool.acquire(&principal(), false).unwrap();
        let hold = output.work_hold();
        let encoded = output
            .base64(&vec![7; if large { 4096 } else { 1 }])
            .unwrap();
        let json_len = encoded.len() + 33;
        let value = Value::Object(serde_json::Map::from_iter([(
            "result".into(),
            Value::String(encoded),
        )]));
        let mut checks = 0;
        let reply = OwnedValue::new(Ok(value), output).finish_with(
            deadline,
            &mut || {
                checks += 1;
                if checks == 1 {
                    before
                } else {
                    assert_eq!(
                        usage(&pool),
                        (BASE_BYTES + if large { json_len } else { 0 }, 0, 1)
                    );
                    deadline
                }
            },
            &mut Vec::try_reserve_exact,
        );
        assert_eq!(checks, 2);
        assert!(reply.is_none());
        assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
        drop(hold);
        assert_eq!(usage(&pool), (0, 0, 0));
    }
}

#[test]
fn count_and_fixed_writer_share_the_same_borrowed_serializer_and_fail_without_growth() {
    let value = json!({"unicode":"原文","escaped":"\n\"\\","empty":[]});
    let envelope = Envelope::Success(wire::success(&value));
    let length = json_length(&envelope, MAX_JSON_BYTES).unwrap();
    assert_eq!(
        json_length(&envelope, length - 1).unwrap_err().code,
        "LIMIT"
    );
    let mut bytes = vec![0; length];
    let pointer = bytes.as_ptr();
    write_json(&envelope, &mut bytes).unwrap();
    assert_eq!(bytes.as_ptr(), pointer);
    assert_eq!(&bytes, &serde_json::to_vec(&wire::success(&value)).unwrap());
    assert_eq!(
        write_json(&envelope, &mut bytes[..length - 1])
            .unwrap_err()
            .code,
        "LIMIT"
    );
    let mut counter = Counter {
        bytes: usize::MAX,
        maximum: usize::MAX,
    };
    assert_eq!(
        counter.write(&[1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    counter.flush().unwrap();
}

#[test]
#[should_panic(expected = "counted JSON extent")]
fn fixed_json_writer_rejects_an_oversized_safe_destination() {
    let value = json!({"empty": [], "escaped": "\n"});
    let envelope = Envelope::Success(wire::success(&value));
    let mut bytes = vec![0; json_length(&envelope, MAX_JSON_BYTES).unwrap() + 1];
    write_json(&envelope, &mut bytes).unwrap();
}

#[test]
fn oversized_safe_json_input_fails_counting_before_requesting_a_final_backing() {
    let pool = small_pool(2 * BASE_BYTES, 2 * BASE_BYTES);
    let output = pool.acquire(&principal(), false).unwrap();
    // A custom worker can construct any safe Value. NUL escaping crosses the
    // real encoded limit with roughly 15 MiB of test input, without allocating
    // a 90 MiB output or inventing an invalid private encoder plan.
    let value = Value::String("\0".repeat(MAX_JSON_BYTES / 6 + 1));
    let before = Instant::now();
    let reply = OwnedValue::new(Ok(value), output)
        .finish_with(
            before + std::time::Duration::from_secs(1),
            &mut || before,
            &mut |_, _| panic!("count limit must precede any final allocation"),
        )
        .unwrap();
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.bytes).unwrap()["error"]["code"],
        "LIMIT"
    );
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(reply);
    assert_eq!(usage(&pool), (0, 0, 0));
}
