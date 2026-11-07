use super::*;

fn call(extra: &str) -> String {
    format!(
        r#"{{"version":1,"scope":{{"deployment":"1","tenant":"2","database":"3","incarnation":"4","generation":"5"}},{extra}}}"#
    )
}

#[test]
fn canonical_identities_reject_lossy_or_ambiguous_json() {
    for good in ["0", "1", "9007199254740993", "18446744073709551615"] {
        let encoded = format!("\"{good}\"");
        let parsed: Decimal = serde_json::from_str(&encoded).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), encoded);
    }
    for bad in [
        "1",
        "null",
        "true",
        "[]",
        "{}",
        "\"\"",
        "\"01\"",
        "\"+1\"",
        "\"-1\"",
        "\"18446744073709551616\"",
    ] {
        assert!(serde_json::from_str::<Decimal>(bad).is_err(), "{bad}");
    }
    let good = call(r#""operation":"status""#);
    assert!(parse(good.as_bytes()).is_ok());
    for bad in [
        good.replace("\"version\":1", "\"version\":2"),
        good.replace("\"deployment\":\"1\"", "\"deployment\":\"0\""),
        call(r#""operation":"status","unknown":1"#),
        call(r#""operation":"status","operation":"query","statements":[]"#),
        call(r#""operation":"status","version":1"#),
        call(r#""operation":"missing"#),
        "{bad".to_owned(),
        call(r#""operation":"quota","expected_revision":"1","nonce":"2""#),
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "accepted {bad}");
    }
    assert!(parse(
        call(r#""operation":"quota","expected_revision":"1","nonce":"2","max_bytes":null"#)
            .as_bytes()
    )
    .is_ok());
    assert!(parse(
        call(r#""operation":"quota","expected_revision":"1","nonce":"2","max_bytes":"4096""#)
            .as_bytes()
    )
    .is_ok());
}

#[test]
fn all_typed_parameters_are_lossless_and_noncanonical_values_fail() {
    let wire: Vec<WireStatement> = serde_json::from_value(json!([{
    "sql": "SELECT ?,?,?,?,?,?", "params": [
        {"type":"null"}, {"type":"integer","value":"-9223372036854775808"},
        {"type":"real","bits":"8000000000000000"}, {"type":"text","value":"\u{feff}中文\0"},
        {"type":"blob","base64":"AAH/"}, {"type":"integer","value":"9223372036854775807"}
    ]}]))
    .unwrap();
    let native = statements(&wire).unwrap();
    assert_eq!(native[0].parameters[0], Value::Null);
    assert_eq!(native[0].parameters[1], Value::Integer(i64::MIN));
    assert!(
        matches!(native[0].parameters[2], Value::Real(v) if v.to_bits() == (-0.0_f64).to_bits())
    );
    assert_eq!(
        native[0].parameters[3],
        Value::Text("\u{feff}中文\0".to_owned())
    );
    assert_eq!(native[0].parameters[4], Value::Blob(vec![0, 1, 255]));
    for bad in [
        json!({"type":"integer","value":"-0"}),
        json!({"type":"integer","value":"oops"}),
        json!({"type":"real","bits":"oops"}),
        json!({"type":"real","bits":"0"}),
        json!({"type":"real","bits":"7ff0000000000000"}),
        json!({"type":"real","bits":"7ff8000000000001"}),
        json!({"type":"real","bits":"3FF0000000000000"}),
        json!({"type":"blob","base64":"?"}),
        json!({"type":"blob","base64":"AB=="}),
    ] {
        let parameter = serde_json::from_value::<Parameter>(bad).unwrap();
        assert!(parameter.native().is_err());
        assert!(statements(&[WireStatement {
            sql: "SELECT ?".to_owned(),
            params: vec![parameter]
        }])
        .is_err());
    }
    assert_eq!(
        Parameter::Real {
            bits: "0000000000000000".into()
        }
        .native()
        .unwrap(),
        Value::Real(0.0)
    );
    let identity = Identity {
        epoch: Decimal(1),
        id: Decimal(2),
        principal: Decimal(3),
        fingerprint: "a".repeat(64),
    };
    assert!(identity.native(3).is_ok());
    assert_eq!(identity.native(4).unwrap_err().code, "DENIED");
    assert_eq!(
        Identity {
            id: Decimal(0),
            ..identity
        }
        .native(3)
        .unwrap_err()
        .code,
        "INVALID"
    );
    let permission = WirePermission {
        principal: Decimal(9),
        read: true,
        write: false,
        admin: false,
    };
    assert_eq!(permission.native().principal, 9);
}

#[test]
fn public_resolutions_keep_original_receipts_and_status_hides_policy() {
    let scope = Scope {
        deployment: 1,
        tenant: 2,
        database: 3,
        incarnation: 4,
        generation: 5,
    };
    let receipt_value = Receipt {
        scope: scope.clone(),
        request: Request {
            epoch: 1,
            id: u64::MAX,
            principal: 7,
            fingerprint: "a".repeat(64),
        },
        sequence: u64::MAX,
        transition: scap_object::format::Transition {
            revision: 8,
            nonce: 9,
        },
        data_root: "b".repeat(64),
        result_hash: "c".repeat(64),
    };
    let result_value = TransactionResult { statements: vec![] };
    let encoded = result(&result_value).unwrap();
    let bytes = STANDARD.decode(&encoded).unwrap();
    let resolution = resolved(Resolution::Committed {
        receipt: receipt_value.clone(),
        bytes,
    });
    assert_eq!(resolution["result"], encoded);
    assert_eq!(resolution["receipt"]["sequence"], u64::MAX.to_string());
    assert_eq!(resolution["receipt"]["result_hash"], "c".repeat(64));
    assert_eq!(resolved(Resolution::Unknown)["state"], "unknown");
    assert_eq!(resolved(Resolution::Closed)["state"], "closed");
    assert_eq!(resolved(Resolution::Retired)["state"], "retired");
    assert_eq!(
        resolved(Resolution::Cancelled {
            transition: receipt_value.transition.clone()
        })["state"],
        "cancelled"
    );
    let head = Head {
        format: 2,
        scope,
        revision: 2,
        transition: receipt_value.transition.clone(),
        sequence: 1,
        owner_epoch: 1,
        owner_instance: 2,
        active: false,
        auth_epoch: 3,
        policy: vec![],
        lifecycle: scap_object::format::Lifecycle::Ready,
        data_root: "d".repeat(64),
        quota: scap_object::format::DatabaseQuota { max_bytes: None },
        retention: scap_object::format::Retention {
            max_entries: 4096,
            max_result_bytes: 64 * 1024 * 1024,
        },
        request_epoch: 3,
        windows: vec![],
    };
    let status_value = status(&head);
    assert!(status_value.get("policy").is_none());
    assert!(status_value.get("data_root").is_none());
    assert_eq!(status_value["retention"]["oldest_epoch"], "3");
    let mut head = head;
    head.windows.push(scap_object::format::Window {
        epoch: 1,
        root: "a".repeat(64),
        count: 0,
        result_bytes: 0,
    });
    assert_eq!(status(&head)["retention"]["oldest_epoch"], "1");
    assert!(failed(&Failure::new("INVALID"))["error"]
        .get("receipt")
        .is_none());
    assert_eq!(
        failed(&Failure {
            code: "COMMITTED_BUT_UNAVAILABLE",
            receipt: Some(Box::new(receipt_value))
        })["error"]["receipt"]["sequence"],
        u64::MAX.to_string()
    );
    let invalid = TransactionResult {
        statements: vec![scap_sql::StatementResult {
            columns: vec![],
            rows: vec![vec![]],
            affected_rows: 0,
            last_insert_rowid: 0,
        }],
    };
    assert_eq!(result(&invalid).unwrap_err().code, "CORRUPT");
    let status_call = parse(call(r#""operation":"status""#).as_bytes()).unwrap();
    assert!(status_call.action.priority());
    assert!(!Action::Create { nonce: Decimal(1) }.priority());
    assert!(!Action::Query { statements: vec![] }.priority());
    assert!(!Action::Execute {
        request: Identity {
            epoch: Decimal(1),
            id: Decimal(1),
            principal: Decimal(1),
            fingerprint: "a".repeat(64)
        },
        statements: vec![]
    }
    .priority());
}

#[test]
fn envelope_rejects_unknown_or_duplicate_fields_at_every_identity_boundary() {
    for bad in [
        "null".to_owned(),
        "[]".to_owned(),
        "{}".to_owned(),
        r#"{"version":1,"operation":"status"}"#.to_owned(),
        call(r#""operation":"open","unknown":1"#),
        call(r#""operation":"query","statements":[],"unknown":1"#),
        call(
            r#""operation":"query","statements":[{"sql":"SELECT 1","params":[],"sql":"SELECT 2"}]"#,
        ),
        call(
            r#""operation":"query","statements":[{"sql":"SELECT ?","params":[{"type":"null","value":"ignored"}]}]"#,
        ),
        call(
            r#""operation":"query","statements":[{"sql":"SELECT ?","params":[{"type":"integer","value":"1","value":"2"}]}]"#,
        ),
        call(
            r#""operation":"lookup","request":{"epoch":"1","id":"1","principal":"3","fingerprint":"x","principal":"4"}"#,
        ),
        call(
            r#""operation":"status","scope":{"deployment":"1","tenant":"2","database":"3","incarnation":"4","generation":"5"}"#,
        ),
        call(r#""operation":"status""#).replace("\"version\":1,", ""),
        call(r#""operation":"status""#).replace(
            "\"generation\":\"5\"",
            "\"generation\":\"5\",\"generation\":\"6\"",
        ),
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "accepted {bad}");
    }
    assert_eq!(
        parse(call(r#""operation":"open""#).as_bytes())
            .unwrap()
            .action
            .admission(),
        "recovery"
    );
    assert_eq!(
        Action::Activate {
            expected_revision: Decimal(1),
            nonce: Decimal(1)
        }
        .admission(),
        "recovery"
    );
    assert_eq!(Action::Create { nonce: Decimal(1) }.admission(), "data");
}

#[test]
fn invalid_transitions_quotas_and_policies_are_client_errors_before_object_access() {
    assert_eq!(
        Action::Create { nonce: Decimal(0) }
            .validate()
            .unwrap_err()
            .code,
        "INVALID"
    );
    assert_eq!(
        Action::Takeover {
            expected_revision: Decimal(0),
            nonce: Decimal(1)
        }
        .validate()
        .unwrap_err()
        .code,
        "INVALID"
    );
    for operation in [
        "activate",
        "takeover",
        "close_full",
        "quota",
        "policy",
        "lifecycle",
    ] {
        let mut value =
            serde_json::from_str::<serde_json::Value>(&call(r#""operation":"status""#)).unwrap();
        value["operation"] = json!(operation);
        value["expected_revision"] = json!("1");
        value["nonce"] = json!("0");
        match operation {
            "quota" => value["max_bytes"] = Json::Null,
            "policy" => value["permissions"] = json!([]),
            "lifecycle" => value["lifecycle"] = json!("ready"),
            _ => {}
        }
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let admin = WirePermission {
        principal: Decimal(1),
        read: true,
        write: true,
        admin: true,
    };
    let policy = |permissions| Action::Policy {
        expected_revision: Decimal(1),
        nonce: Decimal(2),
        permissions,
    };
    assert!(policy(vec![admin.clone()]).validate().is_ok());
    assert!(policy(vec![]).validate().is_err());
    assert!(policy(vec![WirePermission {
        admin: false,
        ..admin.clone()
    }])
    .validate()
    .is_err());
    assert!(
        policy(vec![admin.clone(); scap_object::format::MAX_PRINCIPALS + 1])
            .validate()
            .is_err()
    );
    assert!(policy(vec![admin.clone(), admin.clone()])
        .validate()
        .is_err());
    assert!(policy(vec![WirePermission {
        principal: Decimal(0),
        ..admin
    }])
    .validate()
    .is_err());
    for maximum in [
        Some(Decimal(0)),
        Some(Decimal(4095)),
        Some(Decimal(u64::MAX)),
    ] {
        assert!(Action::Quota {
            expected_revision: Decimal(1),
            nonce: Decimal(2),
            max_bytes: maximum
        }
        .validate()
        .is_err());
    }
    assert!(Action::Quota {
        expected_revision: Decimal(1),
        nonce: Decimal(2),
        max_bytes: Some(Decimal(4096))
    }
    .validate()
    .is_ok());
}

#[test]
fn nonnumeric_versions_are_rejected_without_coercion() {
    for bad in ["null", "true", "\"1\"", "-1", "256"] {
        assert!(parse(
            call(r#""operation":"status""#)
                .replace("\"version\":1", &format!("\"version\":{bad}"))
                .as_bytes()
        )
        .is_err());
    }
}
