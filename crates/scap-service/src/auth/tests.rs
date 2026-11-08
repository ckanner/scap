use super::*;

fn credential(token: &str) -> Credential {
    Credential {
        sha256: format!("{:x}", Sha256::digest(token)),
        deployment: Decimal(1),
        tenant: Decimal(2),
        principal: Decimal(3),
        provision: false,
        deployment_inventory: false,
    }
}

#[test]
fn trusted_authentication_never_uses_client_principal() {
    let token = "a".repeat(32);
    let auth = Authenticator::new(vec![credential(&token), credential(&"b".repeat(32))]).unwrap();
    let principal = auth.authenticate(Some(&format!("Bearer {token}"))).unwrap();
    assert_eq!(principal.principal, 3);
    assert!(!principal.provision);
    let scope = Scope {
        deployment: 1,
        tenant: 2,
        database: 3,
        incarnation: 4,
        generation: 5,
    };
    assert!(principal.authorize(&scope).is_ok());
    assert!(principal
        .authorize(&Scope {
            deployment: 2,
            ..scope.clone()
        })
        .is_err());
    assert!(principal.authorize(&Scope { tenant: 3, ..scope }).is_err());
    for header in [
        None,
        Some("Basic abc"),
        Some("Bearer short"),
        Some(&format!("Bearer {}", "c".repeat(32))),
        Some(&format!("Bearer {}", "a".repeat(1025))),
        Some(&format!("Bearer {} ", "a".repeat(32))),
    ] {
        assert_eq!(
            auth.authenticate(header).unwrap_err().code,
            "UNAUTHENTICATED"
        );
    }
}

#[test]
fn credential_configuration_is_strict_and_secret_free() {
    assert!(Authenticator::new(vec![]).is_err());
    assert!(Authenticator::new((0..4097).map(|_| credential("a")).collect()).is_err());
    assert!(Authenticator::new(vec![credential("a"), credential("a")]).is_err());
    for field in 0..3 {
        let mut value = credential("a");
        match field {
            0 => value.deployment.0 = 0,
            1 => value.tenant.0 = 0,
            _ => value.principal.0 = 0,
        }
        assert!(Authenticator::new(vec![value]).is_err());
    }
    for hash in [
        "a".repeat(63),
        "g".repeat(64),
        "A".repeat(64),
        "é".repeat(32),
    ] {
        let mut value = credential("a");
        value.sha256 = hash;
        assert!(Authenticator::new(vec![value]).is_err());
    }
    assert!(decode_hash(&"0".repeat(64)).is_ok());
    assert!(decode_hash(&"abcdef0123456789".repeat(4)).is_ok());
}

#[test]
fn deployment_inventory_is_a_separate_explicit_credential_capability() {
    let token = "synthetic-inventory-credential-32bytes";
    let mut c = credential(token);
    c.deployment_inventory = true;
    c.provision = false;
    let p = Authenticator::new(vec![c])
        .unwrap()
        .authenticate(Some(&format!("Bearer {token}")))
        .unwrap();
    assert!(p.deployment_inventory);
    assert!(!p.provision);
    let encoded = serde_json::json!({"sha256":"a".repeat(64),"deployment":"1","tenant":"2","principal":"3","provision":true});
    let decoded: Credential = serde_json::from_value(encoded).unwrap();
    assert!(!decoded.deployment_inventory);
}
