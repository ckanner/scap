use super::*;
use crate::tests::{config, config_json};
use serde_json::json;
use sha2::{Digest, Sha256};

fn decode(value: &Value) -> Result<Config, ServiceError> {
    Config::decode(&serde_json::to_vec(value).unwrap())
}

fn rejects(path: &str, replacement: Value, code: &str) {
    let mut value = config_json();
    *value.pointer_mut(path).unwrap() = replacement;
    assert_eq!(decode(&value).unwrap_err().code, code, "{path}");
}

#[test]
fn decoded_identity_paths_limits_and_boundaries_remain_explicit() {
    let parsed = config();
    assert_eq!(parsed.cluster_id, 1);
    assert_eq!(
        parsed.cell,
        CellIdentity {
            cell_id: 2,
            cell_incarnation: 1
        }
    );
    assert_eq!(parsed.node_id, 1);
    assert_eq!(parsed.bootstrap_voters, vec![1, 2, 3]);
    assert!(parsed.management.is_none());
    assert_eq!(parsed.administrator_id, 100);
    assert_eq!(parsed.service_credential_id, 101);
    assert_eq!(
        parsed.peers.iter().map(|p| p.node_id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(parsed.peers.iter().all(|p| p.certificate_der.is_absolute()));
    assert_eq!(parsed.databases[0].identity.database_id, 3);
    assert_eq!(parsed.databases[0].tokens[0].credential_id, 201);
    assert_eq!(parsed.idle_timeout, Duration::from_secs(5));
    assert!(parsed.archive.is_none());
    for seconds in [5, 86_400] {
        let mut value = config_json();
        value["idle_seconds"] = json!(seconds);
        value["databases"][0]["name"] = json!("Ab_9-z");
        assert_eq!(decode(&value).unwrap().idle_timeout.as_secs(), seconds);
    }
    let sql = worker_limits();
    sql.sqlite.sql.validate().unwrap();
    assert_eq!(sql.engine.max_database_pages, 64);
    assert!(sql.sqlite.sql.max_result_bytes <= cell_limits().max_result_bytes);
    assert!(sql.engine.max_transaction_bytes <= cell_limits().max_transaction_bytes);
    assert_eq!(cell_limits().max_policy_grants, 33);
    let mut exact = serde_json::to_vec(&config_json()).unwrap();
    exact.resize(1024 * 1024, b' ');
    assert!(Config::decode(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(Config::decode(&exact).unwrap_err().code, "CONFIG_LIMIT");
    assert_eq!(Config::decode(b"{").unwrap_err().code, "CONFIG_JSON");
}

#[test]
fn every_required_field_rejects_missing_or_malformed_input() {
    for (path, code) in [
        ("/version", "CONFIG_INTEGER"),
        ("/cluster_id", "CONFIG_STRING"),
        ("/node_id", "CONFIG_INTEGER"),
        ("/administrator_id", "CONFIG_STRING"),
        ("/peers", "CONFIG_ARRAY"),
        ("/peers/0/node_id", "CONFIG_INTEGER"),
        ("/peers/0/uri", "CONFIG_STRING"),
        ("/peers/0/certificate_der", "CONFIG_STRING"),
        ("/databases", "CONFIG_ARRAY"),
        ("/databases/0/name", "CONFIG_STRING"),
        ("/databases/0/database_id", "CONFIG_STRING"),
        ("/databases/0/tokens", "CONFIG_ARRAY"),
        ("/databases/0/tokens/0/sha256", "CONFIG_STRING"),
        ("/databases/0/tokens/0/principal_id", "CONFIG_STRING"),
        ("/databases/0/tokens/0/permissions", "CONFIG_INTEGER"),
        ("/databases/0/tokens/0/credential_id", "CONFIG_STRING"),
        ("/databases/0/tokens/0/auth_epoch", "CONFIG_INTEGER"),
        ("/databases/0/incarnation", "CONFIG_INTEGER"),
        ("/databases/0/placement_generation", "CONFIG_INTEGER"),
        ("/http_listen", "CONFIG_STRING"),
        ("/idle_seconds", "CONFIG_INTEGER"),
        ("/cell_id", "CONFIG_STRING"),
        ("/cell_incarnation", "CONFIG_INTEGER"),
        ("/service_credential_id", "CONFIG_STRING"),
        ("/data_dir", "CONFIG_STRING"),
        ("/peer_listen", "CONFIG_STRING"),
        ("/certificate_pem", "CONFIG_STRING"),
        ("/private_key_pem", "CONFIG_STRING"),
        ("/ca_pem", "CONFIG_STRING"),
    ] {
        rejects(path, Value::Null, code);
    }
    for (path, bad, code) in [
        ("/version", json!(2), "CONFIG_VERSION"),
        ("/version", json!(-1), "CONFIG_INTEGER"),
        ("/version", json!(1.5), "CONFIG_INTEGER"),
        ("/cluster_id", json!("1"), "CONFIG_ID"),
        (
            "/cluster_id",
            json!("+0000000000000000000000000000001"),
            "CONFIG_ID",
        ),
        (
            "/cluster_id",
            json!("z0000000000000000000000000000001"),
            "CONFIG_ID",
        ),
        (
            "/cluster_id",
            json!("00000000000000000000000000000000"),
            "CONFIG_ID",
        ),
        ("/cluster_id", json!(""), "CONFIG_STRING"),
        ("/cluster_id", json!("x".repeat(4097)), "CONFIG_STRING"),
        ("/cell_incarnation", json!(0), "CONFIG_ID"),
        ("/databases/0/tokens/0/auth_epoch", json!(0), "CONFIG_ID"),
        ("/databases/0/incarnation", json!(0), "CONFIG_ID"),
        ("/databases/0/placement_generation", json!(0), "CONFIG_ID"),
        ("/http_listen", json!("not an address"), "CONFIG_ADDRESS"),
        (
            "/peer_listen",
            json!("https://example.com"),
            "CONFIG_ADDRESS",
        ),
        ("/data_dir", json!("relative/path"), "CONFIG_PATH"),
        ("/idle_seconds", json!(4), "CONFIG_IDLE"),
        ("/idle_seconds", json!(86_401), "CONFIG_IDLE"),
        ("/peers/0/uri", json!("http://127.0.0.1:1"), "CONFIG_PEER"),
        (
            "/databases/0/name",
            json!("x".repeat(65)),
            "CONFIG_DATABASE",
        ),
        ("/databases/0/name", json!("a/b"), "CONFIG_DATABASE"),
    ] {
        rejects(path, bad, code);
    }
}

#[test]
fn fixed_membership_and_all_bounded_collections_are_checked() {
    for path in ["/peers", "/databases", "/databases/0/tokens"] {
        rejects(path, json!([]), "CONFIG_LIMIT");
        let mut value = config_json();
        let array = value.pointer_mut(path).unwrap().as_array_mut().unwrap();
        let limit = if path == "/peers" { 16 } else { 32 };
        array.resize(limit + 1, array[0].clone());
        assert_eq!(decode(&value).unwrap_err().code, "CONFIG_LIMIT");
    }
    rejects("/node_id", json!(4), "CONFIG_MEMBERS");
    rejects("/peers/0/node_id", json!(0), "CONFIG_MEMBERS");
    rejects("/peers/1/node_id", json!(1), "CONFIG_MEMBERS");
    let mut value = config_json();
    value["peers"].as_array_mut().unwrap().pop();
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_MEMBERS");
    let mut value = config_json();
    let mut db = value["databases"][0].clone();
    db["database_id"] = json!(format!("{:032x}", 4));
    value["databases"].as_array_mut().unwrap().push(db);
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_DATABASE");
    value["databases"][1]["name"] = json!("beta");
    value["databases"][1]["database_id"] = json!(format!("{:032x}", 3));
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_DATABASE");
    // Different names/IDs cannot share one bearer token across databases.
    value["databases"][1]["database_id"] = json!(format!("{:032x}", 4));
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_TOKEN");
}

#[test]
fn trusted_pool_is_distinct_from_exact_three_bootstrap_voters() {
    let mut value = config_json();
    let mut duplicate = value.clone();
    let peer = duplicate["peers"][0].clone();
    duplicate["peers"].as_array_mut().unwrap().push(peer);
    assert_eq!(decode(&duplicate).unwrap_err().code, "CONFIG_MEMBERS");
    for id in 4..=16 {
        let mut peer = value["peers"][0].clone();
        peer["node_id"] = json!(id);
        value["peers"].as_array_mut().unwrap().push(peer);
    }
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_BOOTSTRAP");
    value["bootstrap_voters"] = json!([3, 1, 2]);
    value["node_id"] = json!(16);
    let config = decode(&value).unwrap();
    assert_eq!(config.peers.len(), 16);
    assert_eq!(config.bootstrap_voters, vec![1, 2, 3]);
    for voters in [
        json!(false),
        json!([1, 2, "3"]),
        json!([1, 2]),
        json!([1, 2, 3, 4]),
        json!([1, 2, 2]),
        json!([1, 2, 17]),
    ] {
        value["bootstrap_voters"] = voters;
        assert_eq!(decode(&value).unwrap_err().code, "CONFIG_BOOTSTRAP");
    }
}

#[test]
fn management_requires_an_independent_secret_and_loopback_listener() {
    let mut value = config_json();
    value["management"] = json!(false);
    assert!(decode(&value).unwrap().management.is_none());
    value["management"] = json!({
        "listen":"127.0.0.1:9099",
        "token_sha256":"ab".repeat(32),
    });
    let config = decode(&value).unwrap();
    let management = config.management.unwrap();
    assert_eq!(management.listen, "127.0.0.1:9099".parse().unwrap());
    assert_eq!(management.token_digest, [0xab; 32]);
    value["management"]["listen"] = json!("[::1]:9099");
    assert!(decode(&value).is_ok());
    for address in ["not-an-address", "0.0.0.0:9099", "[::]:9099"] {
        value["management"]["listen"] = json!(address);
        assert_eq!(
            decode(&value).unwrap_err().code,
            "CONFIG_MANAGEMENT_ADDRESS"
        );
    }
    value["management"]["listen"] = json!("127.0.0.1:9099");
    for token in [
        json!("00".repeat(32)),
        value["databases"][0]["tokens"][0]["sha256"].clone(),
    ] {
        value["management"]["token_sha256"] = token;
        assert_eq!(decode(&value).unwrap_err().code, "CONFIG_MANAGEMENT_TOKEN");
    }
    value["management"]["token_sha256"] = json!("invalid");
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_DIGEST");
    value["management"]["token_sha256"] = Value::Null;
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_STRING");
    value["management"] = json!(true);
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_STRING");
}

#[test]
fn token_hex_identity_permissions_and_global_uniqueness_are_strict() {
    for (bad, code) in [
        ("ab".to_owned(), "CONFIG_DIGEST"),
        ("é".repeat(32), "CONFIG_DIGEST"),
        (format!("+1{}", "ab".repeat(31)), "CONFIG_DIGEST"),
        ("zz".repeat(32), "CONFIG_DIGEST"),
        ("00".repeat(32), "CONFIG_TOKEN"),
    ] {
        rejects("/databases/0/tokens/0/sha256", json!(bad), code);
    }
    rejects(
        "/databases/0/tokens/0/principal_id",
        json!(format!("{:032x}", 100)),
        "CONFIG_TOKEN",
    );
    rejects(
        "/databases/0/tokens/0/principal_id",
        json!("0"),
        "CONFIG_ID",
    );
    rejects(
        "/databases/0/tokens/0/credential_id",
        json!("0"),
        "CONFIG_ID",
    );
    for bad in [0, 4, 255] {
        rejects(
            "/databases/0/tokens/0/permissions",
            json!(bad),
            "CONFIG_TOKEN",
        );
    }
    for valid in [1, 2, 3] {
        let mut value = config_json();
        value["databases"][0]["tokens"][0]["permissions"] = json!(valid);
        assert_eq!(
            decode(&value).unwrap().databases[0].tokens[0].permissions,
            valid
        );
    }
    assert_eq!(digest(&"aB".repeat(32)).unwrap(), [0xab; 32]);
    let mut value = config_json();
    let original = value["databases"][0]["tokens"][0].clone();
    value["databases"][0]["tokens"] = Value::Array(
        (0..32)
            .map(|i| {
                let mut token = original.clone();
                token["sha256"] = json!(format!("{:x}", Sha256::digest(format!("unit-token-{i}"))));
                token
            })
            .collect(),
    );
    assert_eq!(decode(&value).unwrap().databases[0].tokens.len(), 32);
}

#[test]
fn public_cleartext_listeners_require_explicit_tls_proxy_intent() {
    let mut value = config_json();
    value["http_listen"] = json!("0.0.0.0:8080");
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_TLS_PROXY");
    for flag in [json!(false), json!("true"), Value::Null] {
        value["proxy_terminates_tls"] = flag;
        assert_eq!(decode(&value).unwrap_err().code, "CONFIG_TLS_PROXY");
    }
    value["proxy_terminates_tls"] = json!(true);
    assert_eq!(decode(&value).unwrap().http_listen.port(), 8080);
    value["http_listen"] = json!("[::1]:0");
    value["proxy_terminates_tls"] = json!(false);
    assert!(decode(&value).is_ok());
}

#[test]
fn archive_configuration_is_optional_and_all_fields_are_required_when_present() {
    let mut value = config_json();
    value["archive"] = json!({
        "endpoint":"https://s3.example.test", "region":"test-region", "bucket":"scap-unit",
        "access_key_env":"SCAP_TEST_ACCESS", "secret_key_env":"SCAP_TEST_SECRET",
        "allow_http":true,
    });
    let parsed = decode(&value).unwrap().archive.unwrap();
    assert_eq!(parsed.endpoint, "https://s3.example.test");
    assert_eq!(parsed.region, "test-region");
    assert_eq!(parsed.bucket, "scap-unit");
    assert_eq!(parsed.access_key_env, "SCAP_TEST_ACCESS");
    assert_eq!(parsed.secret_key_env, "SCAP_TEST_SECRET");
    assert!(parsed.allow_http);
    value["archive"]
        .as_object_mut()
        .unwrap()
        .remove("allow_http");
    assert!(!decode(&value).unwrap().archive.unwrap().allow_http);
    for key in [
        "endpoint",
        "region",
        "bucket",
        "access_key_env",
        "secret_key_env",
    ] {
        let mut invalid = value.clone();
        invalid["archive"][key] = Value::Null;
        assert_eq!(decode(&invalid).unwrap_err().code, "CONFIG_STRING");
    }
    value["archive"] = Value::Null;
    assert_eq!(decode(&value).unwrap_err().code, "CONFIG_STRING");
}
