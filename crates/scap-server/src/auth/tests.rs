use super::*;
use crate::tests::{config, context, TOKEN};

#[test]
fn configured_binding_preserves_immutable_scope_principal_credential_and_epoch() {
    let mut cfg = config();
    cfg.databases[0].tokens[0].auth_epoch = 7;
    let verifier = Verifier::new(&cfg.databases);
    for mode in [Mode::Read, Mode::Write] {
        let (database, admission) = verifier.verify(&context("alpha", 42), mode).unwrap();
        assert_eq!(database.name, "alpha");
        assert_eq!(database.identity, cfg.databases[0].identity);
        assert_eq!(
            admission,
            Admission {
                principal_id: 200,
                credential_id: 201,
                admission_id: 42,
                auth_epoch: 7
            }
        );
    }
}

#[test]
fn token_database_crossing_and_invalid_credentials_share_one_rejection() {
    let mut cfg = config();
    let mut other = cfg.databases[0].clone();
    other.name = "beta".into();
    other.identity.database_id = 4;
    other.tokens[0].digest = Sha256::digest(b"beta-unit-token").into();
    other.tokens[0].principal_id = 202;
    cfg.databases.push(other);
    let verifier = Verifier::new(&cfg.databases);
    for case in 0..6 {
        let mut request = context("alpha", 1);
        match case {
            0 => request.credential.clear(),
            1 => request.credential = "x".repeat(4097),
            2 => request.request_id = 0,
            3 => request.database = "missing".into(),
            4 => request.database = "beta".into(),
            _ => request.credential = "beta-unit-token".into(),
        }
        assert_eq!(
            verifier.verify(&request, Mode::Read).unwrap_err().code,
            "UNAUTHORIZED"
        );
    }
    let mut beta = context("beta", 9);
    beta.credential = "beta-unit-token".into();
    assert_eq!(
        verifier.verify(&beta, Mode::Write).unwrap().1.principal_id,
        202
    );
    assert_eq!(
        Verifier::new(&[])
            .verify(&context("alpha", 1), Mode::Read)
            .unwrap_err()
            .code,
        "UNAUTHORIZED"
    );
    assert_eq!(context("alpha", 1).credential, TOKEN);
}

#[test]
fn read_and_write_capabilities_are_separate_and_require_all_bits() {
    for permissions in [
        0,
        scap_cell::READ,
        scap_cell::WRITE,
        scap_cell::READ | scap_cell::WRITE,
    ] {
        let mut cfg = config();
        cfg.databases[0].tokens[0].permissions = permissions;
        let verifier = Verifier::new(&cfg.databases);
        assert_eq!(
            verifier.verify(&context("alpha", 1), Mode::Read).is_ok(),
            permissions & scap_cell::READ != 0
        );
        assert_eq!(
            verifier.verify(&context("alpha", 1), Mode::Write).is_ok(),
            permissions == scap_cell::READ | scap_cell::WRITE
        );
    }
    let mut cfg = config();
    let token = "x".repeat(4096);
    cfg.databases[0].tokens[0].digest = Sha256::digest(token.as_bytes()).into();
    let mut request = context("alpha", u128::MAX);
    request.credential = token;
    assert_eq!(
        Verifier::new(&cfg.databases)
            .verify(&request, Mode::Read)
            .unwrap()
            .1
            .admission_id,
        u128::MAX
    );
}
