use super::*;

pub(crate) fn profile() -> Profile {
    Profile {
        version: 1,
        token_sha256: format!("{:x}", Sha256::digest("d".repeat(32))),
    }
}

#[test]
fn profile_and_bearer_validation_are_strict_and_independent() {
    let mut config = profile();
    assert!(config.checked().is_ok());
    config.version = 2;
    assert_eq!(Diagnostics::new(&config).err().unwrap().code, "CONFIG");
    config.version = 1;
    config.token_sha256 = "Z".repeat(64);
    assert_eq!(Diagnostics::new(&config).err().unwrap().code, "CONFIG");
    let export = Diagnostics::new(&profile()).unwrap();
    assert_eq!(export.authenticate(None).unwrap_err().code, "DENIED");
    for token in [
        "Basic invalid".into(),
        format!("Bearer {}", "d".repeat(31)),
        format!("Bearer {}", "d".repeat(1025)),
        format!("Bearer {} ", "d".repeat(32)),
        format!("Bearer {}", "é".repeat(32)),
        format!("Bearer {}", "a".repeat(32)),
    ] {
        assert_eq!(
            export.authenticate(Some(&token)).unwrap_err().code,
            "DENIED"
        );
    }
    assert!(export
        .authenticate(Some(&format!("Bearer {}", "d".repeat(32))))
        .is_ok());
}

#[test]
fn export_owns_one_permit_and_failed_serialization_refunds_it() {
    let diagnostics = Diagnostics::new(&profile()).unwrap();
    let auth = format!("Bearer {}", "d".repeat(32));
    assert_eq!(diagnostics.export(None).err().unwrap().code, "DENIED");
    let first = diagnostics.export(Some(&auth)).unwrap();
    assert!(first.bytes.len() <= MAX_RESPONSE_BYTES);
    let _: serde_json::Value = serde_json::from_slice(&first.bytes).unwrap();
    assert_eq!(
        diagnostics.export(Some(&auth)).err().unwrap().code,
        "BACKPRESSURE"
    );
    drop(first);
    assert_eq!(
        diagnostics
            .export_using(Some(&auth), |_| Err(Failure::new("UNAVAILABLE")))
            .err()
            .unwrap()
            .code,
        "UNAVAILABLE"
    );
    assert!(diagnostics.export(Some(&auth)).is_ok());
}

#[test]
fn output_bound_rejects_before_copy_and_never_returns_partial_json() {
    let mut writer = Bounded(Vec::with_capacity(MAX_RESPONSE_BYTES));
    writer.write_all(&vec![1; MAX_RESPONSE_BYTES - 1]).unwrap();
    assert_eq!(writer.write(&[2]).unwrap(), 1);
    assert_eq!(writer.write(&[]).unwrap(), 0);
    assert_eq!(
        writer.write(&[3]).unwrap_err().kind(),
        io::ErrorKind::WriteZero
    );
    assert_eq!(writer.0.len(), MAX_RESPONSE_BYTES);
    assert_eq!(writer.0[MAX_RESPONSE_BYTES - 1], 2);
    writer.flush().unwrap();
    assert_eq!(
        encode(&"x".repeat(MAX_RESPONSE_BYTES)).err().unwrap().code,
        "UNAVAILABLE"
    );
    let encoded = encode(&"x".repeat(MAX_RESPONSE_BYTES - 2)).unwrap();
    assert_eq!(encoded.len(), MAX_RESPONSE_BYTES);
}
