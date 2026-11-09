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
fn output_profile_is_explicit_and_checked_before_resolving_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    let defaults = parsed(value.clone())
        .prepare_with(&environment)
        .unwrap()
        .service
        .output;
    assert_eq!(defaults.bytes, 512 * 1024 * 1024);
    assert_eq!(defaults.bytes_per_tenant, 256 * 1024 * 1024);
    let profile = json!({"version":1,"bytes":805306368,"bytes_per_tenant":536870912,
        "control_bytes":16777216,"control_bytes_per_tenant":2097152});
    value["output"] = profile.clone();
    let prepared = parsed(value.clone()).prepare_with(&environment).unwrap();
    assert_eq!(prepared.service.output.bytes, 805306368);
    assert_eq!(prepared.service.output.bytes_per_tenant, 536870912);
    assert_eq!(prepared.service.output.control_bytes, 16777216);
    assert_eq!(prepared.service.output.control_bytes_per_tenant, 2097152);
    value["output"]["version"] = json!(2);
    assert_eq!(
        parsed(value.clone())
            .prepare_with(&|_| panic!("output before credentials"))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    for field in profile.as_object().unwrap().keys() {
        value["output"] = profile.clone();
        value["output"].as_object_mut().unwrap().remove(field);
        assert!(Config::parse(value.to_string().as_bytes()).is_err());
    }
    value["output"] = profile;
    value["output"]["rss_limit"] = json!(1);
    assert!(Config::parse(value.to_string().as_bytes()).is_err());
}

#[test]
fn transport_defaults_and_explicit_profiles_are_checked_before_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    assert_eq!(
        parsed(value.clone())
            .prepare_with(&environment)
            .unwrap()
            .service
            .transport,
        crate::transport::Profile::default()
    );
    let profile = json!({"version":1,"max_connections":7,"max_headers":32,
        "max_header_bytes":8192,"max_buffer_bytes":16384,"header_timeout_ms":1000});
    value["transport"] = profile.clone();
    let prepared = parsed(value.clone()).prepare_with(&environment).unwrap();
    assert_eq!(prepared.service.transport.max_connections, 7);
    assert_eq!(prepared.service.transport.header_timeout_ms, 1000);
    value["transport"]["max_connections"] = json!(0);
    assert_eq!(
        parsed(value.clone())
            .prepare_with(&|_| panic!("validate before credentials"))
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
    for field in profile.as_object().unwrap().keys() {
        value["transport"] = profile.clone();
        value["transport"].as_object_mut().unwrap().remove(field);
        assert!(Config::parse(value.to_string().as_bytes()).is_err());
    }
    value["transport"] = profile;
    value["transport"]["unknown"] = json!(1);
    assert!(Config::parse(value.to_string().as_bytes()).is_err());
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
    let _credentials = crate::tests::test_credentials();
    let result = parsed(sample_config(directory.path())).prepare().unwrap();
    assert_eq!(result.s3.secret_key, "secret");
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

#[test]
fn discovery_is_disabled_by_default_and_requires_a_named_strict_cursor_secret() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    assert!(parsed(value.clone())
        .prepare_with(&environment)
        .unwrap()
        .service
        .discovery
        .is_none());
    value["discovery"] = json!({"cursor_key_env":"CURSOR_KEY"});
    let config = parsed(value.clone())
        .prepare_with(&|name| {
            Some(OsString::from(if name == "CURSOR_KEY" {
                "ab".repeat(32)
            } else {
                "unit-secret".into()
            }))
        })
        .unwrap();
    assert!(config.service.discovery.is_some());
    for key in [None, Some("bad".into()), Some("AB".repeat(32))] {
        assert!(parsed(value.clone())
            .prepare_with(&|name| if name == "CURSOR_KEY" {
                key.clone().map(OsString::from)
            } else {
                environment(name)
            })
            .is_err());
    }
    value["discovery"]["workers"] = json!(0);
    assert!(Config::parse(value.to_string().as_bytes()).is_err());
}

#[test]
fn cursor_key_construction_failure_blocks_startup() {
    fn failed(
        _: [u8; 32],
        _: [u8; 32],
        _: u64,
    ) -> Result<crate::discovery_cursor::CursorCodec, Failure> {
        Err(Failure::new("CONFIG"))
    }
    let directory = tempfile::tempdir().unwrap();
    let mut value = sample_config(directory.path());
    value["discovery"] = json!({"cursor_key_env":"CURSOR_KEY"});
    assert_eq!(
        parsed(value)
            .prepare_using(
                &|name| Some(OsString::from(if name == "CURSOR_KEY" {
                    "ab".repeat(32)
                } else {
                    "unit-secret".into()
                })),
                failed
            )
            .err()
            .unwrap()
            .code,
        "CONFIG"
    );
}

#[test]
fn optional_versioned_intake_profiles_preserve_existing_configuration_and_reject_unsafe_overrides()
{
    let directory = tempfile::tempdir().unwrap();
    let base = sample_config(directory.path());
    let prepared = parsed(base.clone()).prepare_with(&environment).unwrap();
    assert!(prepared.service.admission.data_profile.is_none());
    assert!(prepared.service.admission.control_profile.is_none());
    assert!(prepared.service.admission.recovery_profile.is_none());
    let body = base["admission"]["max_body_bytes"].as_u64().unwrap();
    let profile = json!({"version":1,"requests_per_tenant":1,"body_bytes":body*2,"body_bytes_per_tenant":body});
    for name in ["data_profile", "control_profile", "recovery_profile"] {
        let mut value = base.clone();
        value["admission"][name] = profile.clone();
        assert!(parsed(value.clone()).prepare_with(&environment).is_ok());
        for (field, replacement) in [
            ("version", json!(2)),
            ("requests_per_tenant", json!(0)),
            ("requests_per_tenant", json!(4097)),
            ("body_bytes", json!(body - 1)),
            ("body_bytes_per_tenant", json!(body - 1)),
            ("body_bytes_per_tenant", json!(body * 2 + 1)),
        ] {
            let mut invalid = value.clone();
            invalid["admission"][name][field] = replacement;
            assert!(parsed(invalid)
                .prepare_with(&|_| panic!("intake validation precedes secrets"))
                .is_err());
        }
        value["admission"][name]["unexpected"] = json!(1);
        assert!(Config::parse(value.to_string().as_bytes()).is_err());
    }
    let mut value = base;
    value["catalogue"] = json!({"workers":1,"queued_total":4,"queued_per_tenant":3,"queued_per_name":2,"intake":2,"max_body_bytes":65536,"timeout_ms":1000,"intake_profile":{"version":1,"requests_per_tenant":1,"body_bytes":131072,"body_bytes_per_tenant":65536}});
    assert!(parsed(value.clone()).prepare_with(&environment).is_ok());
    value["catalogue"]["intake_profile"]["body_bytes"] = json!(65535);
    assert!(parsed(value)
        .prepare_with(&|_| panic!("catalogue intake validation precedes secrets"))
        .is_err());
}

#[test]
fn execution_graph_budget_is_explicit_and_does_not_reinterpret_wire_or_database_limits() {
    let directory = tempfile::tempdir().unwrap();
    let base = sample_config(directory.path());
    let baseline = parsed(base.clone())
        .prepare_with(&environment)
        .unwrap()
        .service
        .options;
    assert_eq!(baseline.result_memory_bytes, 128 * 1024 * 1024);
    let minimum = std::mem::size_of::<scap_sql::TransactionResult>() as u64;
    for bytes in [minimum, 1024, 256 * 1024 * 1024, u64::MAX] {
        let mut value = base.clone();
        value["execution"] = json!({"result_memory_bytes": bytes});
        let options = parsed(value)
            .prepare_with(&environment)
            .unwrap()
            .service
            .options;
        assert_eq!(options.result_memory_bytes, bytes);
        assert_eq!(options.sql, baseline.sql);
        assert_eq!(options.quota, baseline.quota);
        assert_eq!(options.retention, baseline.retention);
    }
    for value in [
        json!({"result_memory_bytes": 0}),
        json!({"result_memory_bytes": minimum-1}),
    ] {
        let mut input = base.clone();
        input["execution"] = value;
        assert!(parsed(input)
            .prepare_with(&|_| panic!("execution budget precedes secrets"))
            .is_err());
    }
    for value in [
        json!({}),
        json!({"result_memory_bytes": -1}),
        json!({"result_memory_bytes": 1024,"max_result_bytes":1}),
    ] {
        let mut input = base.clone();
        input["execution"] = value;
        assert!(Config::parse(input.to_string().as_bytes()).is_err());
    }
}
