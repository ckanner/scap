use super::*;

#[test]
fn success_envelopes_keep_exact_wire_bytes_and_owned_backing() {
    let value: Json = serde_json::from_str(
        r#"{"empty":[],"escaped":"quote:\" slash:\\ newline:\n 中文","result":"AAH/AA=="}"#,
    )
    .unwrap();
    let result_backing = value["result"].as_str().unwrap().as_ptr();
    let owned = success(value);
    assert_eq!(
        owned.value["result"].as_str().unwrap().as_ptr(),
        result_backing
    );
    let expected = r#"{"ok":true,"value":{"empty":[],"escaped":"quote:\" slash:\\ newline:\n 中文","result":"AAH/AA=="}}"#;
    assert_eq!(serde_json::to_vec(&owned).unwrap(), expected.as_bytes());
    assert_eq!(
        serde_json::to_vec(&success(&owned.value)).unwrap(),
        expected.as_bytes()
    );
}

#[test]
fn result_encoding_resource_failure_is_not_durable_corruption() {
    for (error, expected) in [
        (scap_sql::SqlError::ResourceExhausted, "LIMIT"),
        (scap_sql::SqlError::Invalid, "CORRUPT"),
        (scap_sql::SqlError::Limit, "CORRUPT"),
        (scap_sql::SqlError::Malformed, "CORRUPT"),
    ] {
        let failure = result_encoding_failure(error);
        assert_eq!(failure.code, expected);
        assert!(failure.receipt.is_none());
        assert_eq!(
            failed(&failure),
            json!({"ok":false,"error":{"code":expected,"message":expected}})
        );
    }
    assert_eq!(
        result(&TransactionResult { statements: vec![] }).unwrap(),
        "U0NBUFJFUzEAAAAA"
    );
}

#[test]
fn budgeted_result_counts_wire_and_base64_overlap_before_either_allocation() {
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    let empty = TransactionResult { statements: vec![] };
    let pool = small_pool(BASE_BYTES + 12, BASE_BYTES + 12);
    let mut output = pool.acquire(&crate::tests::principal(), false).unwrap();
    // The 12-byte SCAPRES1 buffer fits, but its simultaneous 16-byte Base64
    // backing does not. Returning must refund the already-created wire Vec.
    assert_eq!(
        budgeted_result(&empty, &mut output).unwrap_err().code,
        "LIMIT"
    );
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(output);
    assert_eq!(usage(&pool), (0, 0, 0));
    let pool = small_pool(BASE_BYTES + 28, BASE_BYTES + 28);
    let mut output = pool.acquire(&crate::tests::principal(), false).unwrap();
    let encoded = budgeted_result(&empty, &mut output).unwrap();
    assert_eq!(encoded, "U0NBUFJFUzEAAAAA");
    assert_eq!(encoded.capacity(), 16);
    assert_eq!(usage(&pool), (BASE_BYTES + 16, 0, 1));
    let reply = crate::output::OwnedValue::new(Ok(Json::String(encoded)), output)
        .finish(crate::tests::until())
        .unwrap();
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
    drop(reply);
    assert_eq!(usage(&pool), (0, 0, 0));

    let pool = small_pool(2 * BASE_BYTES, 2 * BASE_BYTES);
    let mut output = pool.acquire(&crate::tests::principal(), false).unwrap();
    let invalid = TransactionResult {
        statements: vec![scap_sql::StatementResult {
            columns: vec![],
            rows: vec![vec![]],
            affected_rows: 0,
            last_insert_rowid: 0,
        }],
    };
    assert_eq!(
        budgeted_result(&invalid, &mut output).unwrap_err().code,
        "CORRUPT"
    );
    assert_eq!(usage(&pool), (BASE_BYTES, 0, 1));
}

#[test]
fn budgeted_noncommitted_resolutions_keep_the_existing_small_wire_contract() {
    use crate::output::{
        tests::{small_pool, usage},
        BASE_BYTES,
    };
    let pool = small_pool(BASE_BYTES, BASE_BYTES);
    for (resolution, expected) in [
        (Resolution::Unknown, json!({"state":"unknown"})),
        (Resolution::Closed, json!({"state":"closed"})),
        (Resolution::Retired, json!({"state":"retired"})),
        (
            Resolution::Cancelled {
                transition: scap_object::format::Transition {
                    revision: 7,
                    nonce: 9,
                },
            },
            json!({"state":"cancelled","transition":{"revision":"7","nonce":"9"}}),
        ),
    ] {
        let mut output = pool.acquire(&crate::tests::principal(), true).unwrap();
        let value = budgeted_resolved(resolution, &mut output).unwrap();
        assert_eq!(value, expected);
        let reply = crate::output::OwnedValue::new(Ok(value), output)
            .finish(crate::tests::until())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Json>(&reply.bytes).unwrap(),
            json!({"ok":true,"value":expected})
        );
        assert_eq!(usage(&pool), (0, BASE_BYTES, 1));
        drop(reply);
        assert_eq!(usage(&pool), (0, 0, 0));
    }
}

fn call(extra: &str) -> String {
    format!(
        r#"{{"version":1,"scope":{{"deployment":"1","tenant":"2","database":"3","incarnation":"4","generation":"5"}},{extra}}}"#
    )
}

#[test]
fn optional_worker_guard_is_canonical_nonzero_and_only_for_status_or_owner_actions() {
    for base in [
        r#""operation":"status""#,
        r#""operation":"activate","expected_revision":"1","nonce":"2""#,
        r#""operation":"takeover","expected_revision":"1","nonce":"2""#,
    ] {
        assert_eq!(
            parse(call(base).as_bytes())
                .unwrap()
                .action
                .expected_worker(),
            None
        );
        for worker in ["1", "18446744073709551615"] {
            let text = call(&format!(r#"{base},"expected_worker_instance":"{worker}""#));
            assert_eq!(
                parse(text.as_bytes()).unwrap().action.expected_worker(),
                Some(worker.parse().unwrap())
            );
        }
        for bad in [
            "null",
            "1",
            "true",
            "[]",
            "{}",
            "\"0\"",
            "\"01\"",
            "\"+1\"",
            "\"18446744073709551616\"",
        ] {
            assert!(
                parse(call(&format!(r#"{base},"expected_worker_instance":{bad}"#)).as_bytes())
                    .is_err()
            );
        }
    }
    assert!(
        parse(call(r#""operation":"open","expected_worker_instance":"1""#).as_bytes()).is_err()
    );
    assert_eq!(
        Action::Status {
            expected_worker_instance: None
        }
        .expected_worker(),
        None
    );
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
        format: 6,
        head_serial: 7,
        storage: scap_object::format::Storage {
            active_generation: 1,
            allocated_through: 1,
            plan: None,
            sweep: None,
            terminal: None,
        },
        creation: None,
        deletion: None,
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
fn ordinary_lifecycle_cannot_enter_internal_provisioning() {
    assert_eq!(
        Action::Lifecycle {
            expected_revision: Decimal(1),
            nonce: Decimal(2),
            lifecycle: scap_object::format::Lifecycle::Provisioning
        }
        .validate()
        .unwrap_err()
        .code,
        "INVALID"
    );
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
            expected_worker_instance: None,
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
            expected_worker_instance: None,
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

#[test]
fn maintenance_actions_have_explicit_serials_bounded_frontiers_and_separate_admission() {
    for (operation, fields, admission) in [
        ("storage_status", json!({}), "control"),
        (
            "retire_storage",
            json!({"expected_head_serial":"1"}),
            "control",
        ),
        (
            "compact_begin",
            json!({"expected_head_serial":"1"}),
            "control",
        ),
        ("compact_copy", json!({"plan_serial":"2"}), "recovery"),
        ("compact_promote", json!({"plan_serial":"2"}), "control"),
        ("compact_abort", json!({"plan_serial":"2"}), "control"),
        (
            "gc_prepare",
            json!({"expected_head_serial":"3","generation":"1","after":null}),
            "recovery",
        ),
        ("gc_resume", json!({"batch_serial":"4"}), "recovery"),
    ] {
        let mut value: Json =
            serde_json::from_str(&call(&format!("\"operation\":\"{operation}\""))).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let action = parse(value.to_string().as_bytes()).unwrap().action;
        assert_eq!(action.admission(), admission);
        assert!(action.priority());
        assert_eq!(action.expected_worker(), None);
        for field in fields.as_object().unwrap().keys() {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(
                parse(bad.to_string().as_bytes()).is_err(),
                "{operation}/{field}"
            );
        }
        for field in fields
            .as_object()
            .unwrap()
            .keys()
            .filter(|field| *field != "after")
        {
            let mut bad = value.clone();
            bad[field] = json!("0");
            assert_eq!(
                parse(bad.to_string().as_bytes()).unwrap_err().code,
                "INVALID"
            );
        }
        value["key"] = json!("arbitrary/object");
        assert!(parse(value.to_string().as_bytes()).is_err());
    }
    for after in [
        json!("?"),
        json!("A".repeat(64)),
        json!("prefix/"),
        json!(1),
    ] {
        let value = call(&format!(
            r#""operation":"gc_prepare","expected_head_serial":"1","generation":"2","after":{after}"#
        ));
        assert_eq!(parse(value.as_bytes()).unwrap_err().code, "INVALID");
    }
    let value = call(&format!(
        r#""operation":"gc_prepare","expected_head_serial":"1","generation":"2","after":"{}""#,
        "a".repeat(64)
    ));
    assert!(parse(value.as_bytes()).is_ok());
}

#[test]
fn maintenance_status_exposes_only_small_plan_and_checkpoint_summaries() {
    use scap_object::format::{
        CopyBasis, CopyPhase, CopyPlan, Lifecycle, Storage, SweepCheckpoint, SweepDisposition,
        SweepEntry, TerminalSeal,
    };
    let memory = std::sync::Arc::new(crate::tests::Memory::default());
    let db =
        scap_object::Database::new(memory, crate::tests::scope().native().unwrap(), 100).unwrap();
    let mut head = db.create(3, 1, crate::tests::until()).unwrap();
    assert_eq!(status(&head)["head_serial"], "1");
    assert_eq!(status(&head)["storage"]["terminal"], Json::Null);
    head.head_serial = 5;
    head.storage = Storage {
        active_generation: 1,
        allocated_through: 2,
        sweep: None,
        terminal: None,
        plan: Some(CopyPlan {
            serial: 2,
            source: 1,
            target: 2,
            phase: CopyPhase::Copying,
            basis: CopyBasis {
                data_root: head.data_root.clone(),
                windows: head.windows.clone(),
                sequence: head.sequence,
                revision: head.revision,
                quota: head.quota.clone(),
                retention: head.retention.clone(),
                request_epoch: head.request_epoch,
            },
        }),
    };
    assert_eq!(
        status(&head)["storage"]["plan"],
        json!({"serial":"2","source":"1","target":"2","phase":"copying"})
    );
    head.storage.plan.as_mut().unwrap().phase = CopyPhase::Sealed;
    assert_eq!(status(&head)["storage"]["plan"]["phase"], "sealed");
    head.storage.plan = None;
    head.format = 7;
    head.lifecycle = Lifecycle::Deleted;
    head.active = false;
    head.storage.terminal = Some(TerminalSeal { serial: 4 });
    assert_eq!(status(&head)["storage"]["terminal"], json!({"serial":"4"}));
    head.storage.sweep = Some(SweepCheckpoint {
        serial: 5,
        generation: 2,
        next_after: Some("f".repeat(64)),
        exhausted: false,
        entries: [
            SweepDisposition::Pending,
            SweepDisposition::Applied,
            SweepDisposition::ObservedAbsent,
            SweepDisposition::ConditionMismatch,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, disposition)| SweepEntry {
            key: format!("private-key-{index}"),
            hash: format!("{index:064x}"),
            etag: format!("\"private-etag-{index}\""),
            disposition,
        })
        .collect(),
    });
    let report = scap_object::SweepReport {
        head,
        generation: 2,
        scanned: 4,
        next_after: Some("f".repeat(64)),
        exhausted: false,
    };
    let output = sweep(&report);
    assert_eq!(
        output["status"]["storage"]["sweep"],
        json!({"serial":"5","generation":"2",
        "next_after":"f".repeat(64),"exhausted":false,"pending":1,"applied":1,"observed_absent":1,"condition_mismatch":1})
    );
    assert_eq!(output["scanned"], 4);
    assert_eq!(
        output["status"]["storage"]["terminal"],
        json!({"serial":"4"})
    );
    let encoded = output.to_string();
    assert!(
        !encoded.contains("private-key")
            && !encoded.contains("private-etag")
            && !encoded.contains("basis")
    );
}
