use super::*;
use std::collections::BTreeSet;
use std::sync::Arc;

fn principal() -> Principal {
    Principal {
        deployment: 1,
        tenant: 7,
        principal: 11,
        provision: false,
        deployment_inventory: false,
    }
}

fn codec() -> CursorCodec {
    CursorCodec::derive([1; 32], [2; 32], [3; 32], 4).unwrap()
}

#[test]
fn opaque_roundtrip_is_bound_to_each_identity_view_namespace_key_and_startup() {
    let c = codec();
    let p = principal();
    let payload = br#"{"frontier":"a-hidden-database-name"}"#;
    let token = c.seal_at(&p, View::Names, payload, 10).unwrap();
    assert!(!token.contains("hidden"));
    assert_eq!(c.open_at(&p, View::Names, &token, 11).unwrap(), payload);
    assert!(c.open_at(&p, View::Inventory, &token, 11).is_err());
    let inventory = c.seal_at(&p, View::Inventory, payload, 10).unwrap();
    assert_eq!(
        c.open_at(&p, View::Inventory, &inventory, 10).unwrap(),
        payload
    );
    for changed in [
        Principal {
            deployment: 2,
            ..p.clone()
        },
        Principal {
            tenant: 8,
            ..p.clone()
        },
        Principal {
            principal: 12,
            ..p.clone()
        },
    ] {
        assert_eq!(
            c.open_at(&changed, View::Names, &token, 11)
                .unwrap_err()
                .code,
            "CURSOR_INVALID"
        );
    }
    for other in [
        CursorCodec::derive([9; 32], [2; 32], [3; 32], 4).unwrap(),
        CursorCodec::derive([1; 32], [9; 32], [3; 32], 4).unwrap(),
        CursorCodec::derive([1; 32], [2; 32], [9; 32], 4).unwrap(),
        CursorCodec::derive([1; 32], [2; 32], [3; 32], 9).unwrap(),
    ] {
        assert!(other.open_at(&p, View::Names, &token, 11).is_err());
    }
    // A cursor does not preserve a previous provision grant. Admission and
    // per-record READ are checked separately on every request.
    let changed = Principal {
        provision: true,
        deployment_inventory: false,
        ..p.clone()
    };
    assert_eq!(
        c.open_at(&changed, View::Names, &token, 11).unwrap(),
        payload
    );
    assert!(CursorCodec::derive([1; 32], [2; 32], [3; 32], 0).is_err());
}

#[test]
fn tampering_truncation_syntax_version_and_all_size_boundaries_fail_closed() {
    let c = codec();
    let p = principal();
    assert_eq!(
        c.seal_at(&p, View::Names, b"", 0).unwrap_err().code,
        "LIMIT"
    );
    assert!(c
        .seal_at(&p, View::Names, &vec![0; MAX_CHECKPOINT_BYTES + 1], 0)
        .is_err());
    let payload = vec![41; MAX_CHECKPOINT_BYTES];
    let maximum = c.seal_at(&p, View::Names, &payload, 0).unwrap();
    assert!(maximum.len() < MAX_CURSOR_BYTES);
    assert_eq!(c.open_at(&p, View::Names, &maximum, 0).unwrap(), payload);
    for token in [
        "".to_owned(),
        "+++=".to_owned(),
        "A".repeat(MAX_CURSOR_BYTES + 1),
        URL_SAFE_NO_PAD.encode(vec![1; HEADER + TAG + 8 + MAX_CHECKPOINT_BYTES + 1]),
    ] {
        assert_eq!(
            c.open_at(&p, View::Names, &token, 0).unwrap_err().code,
            "CURSOR_INVALID"
        );
    }
    let token = c.seal_at(&p, View::Names, b"checkpoint", 0).unwrap();
    let original = URL_SAFE_NO_PAD.decode(&token).unwrap();
    // This valid token ends with two unused zero bits. A different spelling
    // that decodes to the same ciphertext under a permissive decoder must be
    // rejected before authentication, not accepted as another cursor spelling.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut noncanonical = token.as_bytes().to_vec();
    let last = noncanonical.last_mut().unwrap();
    let value = alphabet.iter().position(|item| item == last).unwrap();
    assert_eq!(value & 3, 0);
    *last = alphabet[value | 1];
    let noncanonical = String::from_utf8(noncanonical).unwrap();
    assert!(URL_SAFE_NO_PAD.decode(&noncanonical).is_err());
    assert!(c.open_at(&p, View::Names, &noncanonical, 0).is_err());
    for position in [0, 1, HEADER, original.len() - 1] {
        let mut modified = original.clone();
        modified[position] ^= 1;
        assert!(c
            .open_at(&p, View::Names, &URL_SAFE_NO_PAD.encode(modified), 0)
            .is_err());
    }
    let truncated = URL_SAFE_NO_PAD.encode(&original[..original.len() - 1]);
    assert!(c.open_at(&p, View::Names, &truncated, 0).is_err());
    assert!(c.open_at(&p, View::Names, &(token + "="), 0).is_err());
}

#[test]
fn expiration_counter_exhaustion_and_failed_entropy_never_issue_unprotected_state() {
    let c = codec();
    let p = principal();
    let token = c.seal_at(&p, View::Names, b"x", 10).unwrap();
    assert!(c.open_at(&p, View::Names, &token, 9).is_err());
    assert_eq!(c.open_at(&p, View::Names, &token, 609).unwrap(), b"x");
    assert!(c.open_at(&p, View::Names, &token, 610).is_err());
    assert!(c.open_at(&p, View::Names, &token, u64::MAX).is_err());
    assert_eq!(
        c.seal_at(&p, View::Names, b"x", u64::MAX).unwrap_err().code,
        "UNAVAILABLE"
    );
    c.counter.store(MAX_ISSUED - 1, Ordering::Relaxed);
    assert!(c.seal_at(&p, View::Names, b"x", 10).is_ok());
    assert_eq!(
        c.seal_at(&p, View::Names, b"x", 10).unwrap_err().code,
        "UNAVAILABLE"
    );
    assert!(entropy_result(Ok(())).is_ok());
    assert_eq!(entropy_result(Err(Unspecified)).unwrap_err().code, "CONFIG");
    let system = CursorCodec::new([1; 32], [2; 32], 3).unwrap();
    let token = system.seal(&p, View::Names, b"current").unwrap();
    assert_eq!(system.open(&p, View::Names, &token).unwrap(), b"current");
    let restarted = CursorCodec::new([1; 32], [2; 32], 3).unwrap();
    assert!(restarted.open(&p, View::Names, &token).is_err());
}

#[test]
fn simultaneous_issuance_has_distinct_nonces_and_namespace_encoding_is_unambiguous() {
    let c = Arc::new(codec());
    let jobs: Vec<_> = (0..8)
        .map(|_| {
            let c = c.clone();
            std::thread::spawn(move || {
                (0..16)
                    .map(|_| c.seal_at(&principal(), View::Names, b"same", 0).unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let tokens: BTreeSet<_> = jobs
        .into_iter()
        .flat_map(|job| job.join().unwrap())
        .collect();
    assert_eq!(tokens.len(), 128);
    for token in tokens {
        assert_eq!(
            c.open_at(&principal(), View::Names, &token, 0).unwrap(),
            b"same"
        );
    }
    assert_eq!(
        namespace("endpoint", "region", "bucket"),
        namespace("endpoint", "region", "bucket")
    );
    assert_ne!(namespace("a", "bc", "d"), namespace("ab", "c", "d"));
    assert_ne!(
        namespace("endpoint", "region", "bucket"),
        namespace("endpoint", "other", "bucket")
    );
}

impl CursorCodec {
    // Test-only boundary injection; this module is not built in the daemon.
    pub(crate) fn exhaust_for_test(&self) {
        self.counter.store(MAX_ISSUED, Ordering::Relaxed);
    }
}

#[test]
fn entropy_failure_propagates_through_construction_without_issuing_a_key() {
    fn failure(_: &mut [u8]) -> Result<(), Unspecified> {
        Err(Unspecified)
    }
    assert_eq!(
        CursorCodec::with_entropy([1; 32], [2; 32], 3, failure)
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
}
