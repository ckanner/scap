use super::*;
use crate::tests::sample_config;
use serde_json::json;

fn parsed(value: serde_json::Value) -> Config {
    Config::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn environment(_: &str) -> Option<OsString> {
    Some(OsString::from("unit-secret"))
}

#[test]
fn configuration_resolves_only_named_credentials_and_keeps_production_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let value = sample_config(directory.path());
    let prepared = parsed(value.clone()).prepare_with(&environment).unwrap();
    assert_eq!(prepared.s3.max_object_bytes, MAX_OBJECT_BYTES);
    assert_eq!(prepared.s3.access_key, "unit-secret");
    assert!(prepared.s3.session_token.is_none());
    assert_eq!(prepared.service.worker_instance, 100);
    assert!(prepared.service.catalogue.is_none());
    assert_eq!(prepared.service.admission.limits().control_workers, 1);
    let mut value = value;
    value["s3"]["session_token_env"] = json!("TOKEN");
    let prepared = parsed(value.clone()).prepare_with(&environment).unwrap();
    assert_eq!(prepared.s3.session_token.as_deref(), Some("unit-secret"));
    assert!(parsed(value).prepare_with(&|_| None).is_err());
    // Public environment resolver is exercised using test-owned keys only.
    std::env::set_var("SCAP_TEST_ACCESS", "access");
    std::env::set_var("SCAP_TEST_SECRET", "secret");
    let result = parsed(sample_config(directory.path())).prepare().unwrap();
    assert_eq!(result.s3.secret_key, "secret");
    std::env::remove_var("SCAP_TEST_ACCESS");
    std::env::remove_var("SCAP_TEST_SECRET");
}

#[test]
fn catalogue_budget_is_explicit_independent_and_globally_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let mut base = sample_config(directory.path());
    base["catalogue"] = json!({"workers":2,"queued_total":32,"queued_per_tenant":16,"queued_per_name":4,"intake":8,"max_body_bytes":65536,"timeout_ms":1000});
    let prepared = parsed(base.clone()).prepare_with(&environment).unwrap();
    let admission = prepared.service.catalogue.unwrap();
    assert_eq!(admission.limits().queued_total, 32);
    assert_eq!(admission.limits().queued_per_name, 4);
    for (field, values) in [
        ("workers", vec![json!(0), json!(33)]),
        ("queued_total", vec![json!(0), json!(65537)]),
        ("queued_per_tenant", vec![json!(0), json!(33)]),
        ("queued_per_name", vec![json!(0), json!(17)]),
        ("intake", vec![json!(0), json!(4097)]),
        ("max_body_bytes", vec![json!(0), json!(65537)]),
        ("timeout_ms", vec![json!(0), json!(86400001)]),
    ] {
        for value in values {
            let mut config = base.clone();
            config["catalogue"][field] = value;
            assert!(
                parsed(config)
                    .prepare_with(&|_| panic!("budget must fail before credentials"))
                    .is_err(),
                "{field}"
            );
        }
        let mut config = base.clone();
        config["catalogue"].as_object_mut().unwrap().remove(field);
        assert!(Config::parse(config.to_string().as_bytes()).is_err());
    }
    base["catalogue"]["queued_per_worker"] = json!(8);
    assert!(Config::parse(base.to_string().as_bytes()).is_err());
}

#[test]
fn every_structural_and_budget_error_is_rejected_before_opening_a_listener() {
    let directory = tempfile::tempdir().unwrap();
    let mut changes = vec![
        ("version", json!(2)),
        ("listen", json!("0.0.0.0:8080")),
        ("worker_instance", json!("0")),
        ("cache_directory", json!("relative")),
        ("cache_directory", json!(directory.path().join("absent"))),
    ];
    let base = sample_config(directory.path());
    for (field, replacement) in changes.drain(..) {
        let mut value = base.clone();
        value[field] = replacement;
        assert!(parsed(value).prepare_with(&environment).is_err(), "{field}");
    }
    for (group, field, replacements) in [
        ("cache", "pages_per_actor", vec![json!(0)]),
        ("cache", "parallel_recoveries", vec![json!(0), json!(257)]),
        (
            "admission",
            "max_body_bytes",
            vec![json!(0), json!(134217729)],
        ),
        ("admission", "queued_total", vec![json!(65537)]),
        ("admission", "data_intake", vec![json!(0), json!(4097)]),
        ("admission", "control_intake", vec![json!(0), json!(4097)]),
        ("admission", "recovery_intake", vec![json!(0), json!(4097)]),
        ("admission", "timeout_ms", vec![json!(0), json!(86400001)]),
        (
            "admission",
            "recovery_timeout_ms",
            vec![json!(999), json!(604800001)],
        ),
        ("s3", "timeout_ms", vec![json!(0), json!(86400001)]),
    ] {
        for replacement in replacements {
            let mut value = base.clone();
            value[group][field] = replacement;
            assert!(
                parsed(value).prepare_with(&environment).is_err(),
                "{group}/{field}"
            );
        }
    }
    let mut value = base.clone();
    value["credentials"] = json!([]);
    assert!(parsed(value).prepare_with(&environment).is_err());
    let mut value = base;
    value["unexpected"] = json!(1);
    assert!(Config::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(Config::parse(b"{}").is_err());
    assert!(Config::parse(&vec![0; 4 * 1024 * 1024 + 1]).is_err());
}

#[test]
fn actor_configuration_rejects_legacy_fields_without_silently_reinterpreting_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let base = sample_config(directory.path());
    for (group, field) in [
        ("admission", "workers"),
        ("admission", "queued_per_worker"),
        ("cache", "sessions_per_worker"),
        ("cache", "pages_per_worker"),
    ] {
        let mut value = base.clone();
        value[group][field] = json!(4);
        assert!(
            Config::parse(value.to_string().as_bytes()).is_err(),
            "{field}"
        );
    }
    for field in [
        "active_database_actors",
        "active_database_actors_per_tenant",
        "actor_idle_timeout_ms",
        "queued_total",
    ] {
        let mut value = base.clone();
        value["admission"].as_object_mut().unwrap().remove(field);
        assert!(
            Config::parse(value.to_string().as_bytes()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn empty_missing_nonunicode_and_invalid_environment_names_fail_without_disclosing_values() {
    use std::os::unix::ffi::OsStringExt;
    for name in ["", "BAD=NAME", &"x".repeat(129), "空"] {
        assert_eq!(secret(name, &environment).unwrap_err().code, "CONFIG");
    }
    assert!(secret("NAME_01", &environment).is_ok());
    assert!(secret("NAME", &|_| None).is_err());
    assert!(secret("NAME", &|_| Some(OsString::new())).is_err());
    assert!(secret("NAME", &|_| Some(OsString::from_vec(vec![255]))).is_err());
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    value["s3"]["secret_key_env"] = json!("secret name");
    assert!(parsed(value).prepare_with(&environment).is_err());
    let mut value = sample_config(directory.path());
    value["s3"]["session_token_env"] = json!("");
    assert!(parsed(value).prepare_with(&environment).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn unsupported_cache_mount_is_rejected_before_resolving_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    value["cache_directory"] = json!("/proc");
    let error = parsed(value)
        .prepare_with(&|_| panic!("unsupported storage must fail before credential lookup"))
        .err()
        .unwrap();
    assert_eq!(error.code, "CACHE_IO");
}
