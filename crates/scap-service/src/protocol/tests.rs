use super::*;
use crate::tests::limits;

fn execute(stmt: Value) -> Value {
    json!({"requests":[{"type":"execute","stmt":stmt},{"type":"close"}]})
}

fn batch_request(begin: &str) -> Value {
    json!({"steps":[
        {"stmt":{"sql":begin,"want_rows":false}},
        {"stmt":{"sql":"SELECT ?","args":[{"type":"integer","value":"7"}]},"condition":{"type":"ok","step":0}},
        {"stmt":{"sql":"COMMIT","want_rows":false},"condition":{"type":"ok","step":1}},
        {"stmt":{"sql":"ROLLBACK","want_rows":false},"condition":{"type":"not","cond":{"type":"ok","step":2}}}
    ]})
}

pub(crate) fn retained_result() -> TransactionResult {
    TransactionResult {
        statements: vec![StatementResult {
            columns: vec!["n".into(), "i".into(), "r".into(), "t".into(), "b".into()],
            rows: vec![vec![
                SqlValue::Null,
                SqlValue::Integer(i64::MIN),
                SqlValue::Real(1.5),
                SqlValue::Text("x".into()),
                SqlValue::Blob(vec![0, 255]),
            ]],
            affected_rows: 1,
            last_insert_rowid: i64::MAX,
        }],
    }
}

#[test]
fn parameter_types_and_malformed_inputs() {
    assert_eq!(parameter(&json!({"type":"null"})).unwrap(), SqlValue::Null);
    assert_eq!(
        parameter(&json!({"type":"integer","value":"-9223372036854775808"})).unwrap(),
        SqlValue::Integer(i64::MIN)
    );
    assert_eq!(
        parameter(&json!({"type":"float","value":1.25})).unwrap(),
        SqlValue::Real(1.25)
    );
    assert_eq!(
        parameter(&json!({"type":"text","value":"你好"})).unwrap(),
        SqlValue::Text("你好".into())
    );
    assert_eq!(
        parameter(&json!({"type":"blob","base64":"AP8="})).unwrap(),
        SqlValue::Blob(vec![0, 255])
    );
    for input in [
        Value::Null,
        json!({"type":"null","extra":0}),
        json!({}),
        json!({"type":1}),
        json!({"type":"null","value":1}),
        json!({"type":"null","base64":""}),
        json!({"type":"integer","value":1}),
        json!({"type":"integer","value":"9223372036854775808"}),
        json!({"type":"float","value":"1.0"}),
        json!({"type":"text","value":null}),
        json!({"type":"blob","base64":"!!"}),
        json!({"type":"blob","base64":0}),
        json!({"type":"other"}),
    ] {
        assert!(parameter(&input).is_err(), "{input}");
    }
}

#[test]
fn statement_and_cached_sql_are_exact_and_bounded() {
    let cache = BTreeMap::from([(0, "SELECT ?".to_owned())]);
    let (stmt, rows) = statement(&json!({"sql_id":0,"args":[{"type":"integer","value":"1"}],"want_rows":false,"named_args":[]}), &cache).unwrap();
    assert_eq!(
        stmt,
        Statement {
            sql: "SELECT ?".into(),
            parameters: vec![SqlValue::Integer(1)]
        }
    );
    assert!(!rows);
    assert!(
        statement(&json!({"sql":"SELECT 1","want_rows":true}), &cache)
            .unwrap()
            .1
    );
    for input in [
        Value::Null,
        json!({"sql":"SELECT 1","unknown":0}),
        json!({"sql":"SELECT 1","named_args":[1]}),
        json!({"sql":"SELECT 1","named_args":0}),
        json!({"sql":"SELECT 1","replication_index":"1"}),
        json!({}),
        json!({"sql":1}),
        json!({"sql":"SELECT 1","sql_id":0}),
        json!({"sql_id":1}),
        json!({"sql_id":-1}),
        json!({"sql_id":2147483648_u64}),
        json!({"sql":"SELECT 1","args":0}),
        json!({"sql":"SELECT 1","args":[{}]}),
        json!({"sql":"SELECT 1","want_rows":0}),
    ] {
        assert!(statement(&input, &cache).is_err(), "{input}");
    }
    let request = json!({"baton":null,"requests":[
        {"type":"store_sql","sql_id":0,"sql":"SELECT ?"},
        {"type":"execute","stmt":{"sql_id":0,"args":[{"type":"integer","value":"1"}]}},
        {"type":"close_sql","sql_id":0}, {"type":"close"}
    ]});
    let plan = pipeline(&request, limits(), Mode::Read).unwrap();
    assert_eq!(plan.statements, vec![stmt]);
    assert_eq!(plan.mode, Mode::Read);
    let result = plan.finish(Ok(retained_result()), limits());
    assert_eq!(result["baton"], Value::Null);
    assert_eq!(result["results"][0]["response"]["type"], "store_sql");
    assert_eq!(
        result["results"][1]["response"]["result"]["rows"][0][1]["value"],
        i64::MIN.to_string()
    );
    assert_eq!(result["results"][2]["response"]["type"], "close_sql");
}

#[test]
fn complete_pipeline_is_validated_before_any_effect() {
    for body in [
        json!({"requests":[null,{"type":"close"}]}),
        execute(json!({})),
        json!({"requests":[{"type":"batch","batch":null},{"type":"close"}]}),
    ] {
        assert!(pipeline(&body, limits(), Mode::Write).is_err());
    }
    let invalids = [
        Value::Null,
        json!({"requests":[],"extra":1}),
        json!({"baton":"old","requests":[]}),
        json!({"requests":null}),
        json!({"requests":[]}),
        json!({"requests":[{"type":"close"}]}),
        json!({"requests":[{}, {"type":"close"}]}),
        json!({"requests":[{"type":0},{"type":"close"}]}),
        json!({"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}},{"type":"get_autocommit"}]}),
        json!({"requests":[{"type":"close"},{"type":"close"}]}),
        json!({"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}},{"type":"close","sql":"bad"}]}),
        json!({"requests":[{"type":"sequence","sql":"SELECT 1"},{"type":"close"}]}),
        json!({"requests":[{"type":"store_sql","sql_id":0,"sql":"SELECT 1"},{"type":"close"}]}),
        json!({"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"}},{"type":"execute","stmt":{"sql":"SELECT 2"}},{"type":"close"}]}),
        json!({"requests":[{"type":"execute","stmt":{"sql":"SELECT 1"},"sql":null},{"type":"close"}]}),
        execute(json!({"sql":""})),
        execute(json!({"sql":"a\0b"})),
        json!({"requests":[{"type":"store_sql","sql_id":0},{"type":"close"}]}),
        json!({"requests":[{"type":"store_sql","sql_id":0,"sql":1},{"type":"close"}]}),
        json!({"requests":[{"type":"store_sql","sql_id":-1,"sql":"x"},{"type":"close"}]}),
        json!({"requests":[{"type":"store_sql","sql_id":0,"sql":"x"},{"type":"store_sql","sql_id":0,"sql":"y"},{"type":"close"}]}),
        json!({"requests":[{"type":"close_sql"},{"type":"close"}]}),
        json!({"requests":[{"type":"close_sql","sql_id":-1},{"type":"close"}]}),
        json!({"requests":[{"type":"close_sql","sql_id":0},{"type":"close"}]}),
    ];
    for input in invalids {
        assert!(pipeline(&input, limits(), Mode::Write).is_err(), "{input}");
    }
    let mut limits = limits();
    limits.max_pipeline_requests = 1;
    assert!(pipeline(&execute(json!({"sql":"SELECT 1"})), limits, Mode::Write).is_err());
    limits.max_pipeline_requests = 16;
    limits.max_cached_statements = 0;
    let store = json!({"requests":[{"type":"store_sql","sql_id":0,"sql":"x"},{"type":"close"}]});
    assert!(pipeline(&store, limits, Mode::Write).is_err());
    limits.max_cached_statements = 4;
    limits.max_cached_sql_bytes = 0;
    assert!(pipeline(&store, limits, Mode::Write).is_err());
}

#[test]
fn recognizes_only_exact_atomic_sdk_programs() {
    for begin in [
        "BEGIN DEFERRED",
        "BEGIN IMMEDIATE",
        "BEGIN TRANSACTION READONLY",
    ] {
        let request =
            json!({"requests":[{"type":"batch","batch":batch_request(begin)}, {"type":"close"}]});
        let plan = pipeline(&request, limits(), Mode::Write).unwrap();
        assert_eq!(plan.statements.len(), 1);
        assert_eq!(
            plan.mode,
            if begin.ends_with("READONLY") {
                Mode::Read
            } else {
                Mode::Write
            }
        );
        let output = plan.finish(Ok(retained_result()), limits());
        assert_eq!(
            output["results"][0]["response"]["result"]["step_results"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert!(output["results"][0]["response"]["result"]["step_results"][3].is_null());
    }
    let base = batch_request("BEGIN DEFERRED");
    let mut bad = vec![
        Value::Null,
        json!({"steps":[],"unknown":0}),
        json!({"steps":[],"replication_index":"1"}),
        json!({"steps":null}),
        json!({"steps":[]}),
    ];
    for (index, property, value) in [
        (0, "condition", json!({})),
        (0, "stmt", json!({"sql":"BEGIN","want_rows":false})),
        (
            0,
            "stmt",
            json!({"sql":"BEGIN DEFERRED","args":[{"type":"null"}],"want_rows":false}),
        ),
        (0, "stmt", json!({"sql":"BEGIN DEFERRED","want_rows":true})),
        (1, "condition", json!({"type":"ok","step":2})),
        (1, "stmt", json!({"sql_id":0})),
        (2, "stmt", json!({"sql":"END","want_rows":false})),
        (2, "stmt", json!({"sql":"COMMIT","want_rows":true})),
        (
            2,
            "stmt",
            json!({"sql":"COMMIT","args":[{"type":"null"}],"want_rows":false}),
        ),
        (3, "condition", json!({"type":"ok","step":2})),
        (3, "stmt", json!({"sql":"END","want_rows":false})),
        (3, "stmt", json!({"sql":"ROLLBACK","want_rows":true})),
        (
            3,
            "stmt",
            json!({"sql":"ROLLBACK","args":[{"type":"null"}],"want_rows":false}),
        ),
    ] {
        let mut request = base.clone();
        request["steps"][index][property] = value;
        bad.push(request);
    }
    let mut unknown = base.clone();
    unknown["steps"][1]["unknown"] = json!(1);
    bad.push(unknown);
    for request in bad {
        assert!(
            batch(&request, &BTreeMap::new(), limits(), Mode::Write).is_err(),
            "{request}"
        );
    }
    let mut tiny = limits();
    tiny.sql.max_statements = 0;
    assert!(batch(&base, &BTreeMap::new(), tiny, Mode::Write).is_err());
}

#[test]
fn responses_retain_all_values_and_fail_closed_on_backend_mismatch() {
    let request = execute(json!({"sql":"SELECT 1"}));
    let output = pipeline(&request, limits(), Mode::Write)
        .unwrap()
        .finish(Ok(retained_result()), limits());
    let result = &output["results"][0]["response"]["result"];
    assert_eq!(result["rows"][0][4]["base64"], "AP8=");
    assert_eq!(result["last_insert_rowid"], i64::MAX.to_string());
    let no_rows = execute(json!({"sql":"SELECT 1","want_rows":false}));
    let output = pipeline(&no_rows, limits(), Mode::Write)
        .unwrap()
        .finish(Ok(retained_result()), limits());
    assert!(output["results"][0]["response"]["result"]["rows"]
        .as_array()
        .unwrap()
        .is_empty());
    let mut bad_value = retained_result();
    bad_value.statements[0].rows[0][0] = SqlValue::Real(f64::NAN);
    let mut bad_count = retained_result();
    bad_count.statements[0].affected_rows = 1_u64 << 53;
    for result in [
        Err(ServiceError::new("COMMIT_UNKNOWN", "unknown")),
        Ok(TransactionResult { statements: vec![] }),
        Ok(bad_value),
        Ok(bad_count),
    ] {
        let output = pipeline(&request, limits(), Mode::Write)
            .unwrap()
            .finish(result, limits());
        assert_eq!(output["results"][0]["type"], "error");
        assert_eq!(output["results"][1]["response"]["type"], "close");
    }
}

#[test]
fn outcome_protocol_preserves_explicit_resolution_and_unknown() {
    for (action, resolve) in [("lookup", false), ("resolve_or_cancel", true)] {
        let (statements, actual) = outcome_request(
            &json!({"action":action,"statements":[{"sql":"SELECT 1"}]}),
            limits(),
        )
        .unwrap();
        assert_eq!(statements[0].sql, "SELECT 1");
        assert_eq!(actual, resolve);
    }
    for input in [
        Value::Null,
        json!({"action":"unknown","statements":[]}),
        json!({"action":0,"statements":[]}),
        json!({"action":"lookup","statements":0}),
        json!({"action":"lookup","statements":[]}),
        json!({"action":"lookup","statements":[{}]}),
    ] {
        assert!(outcome_request(&input, limits()).is_err());
    }
    assert_eq!(
        outcome_result(Outcome::Unknown, limits()).unwrap()["state"],
        "unknown"
    );
    assert_eq!(
        outcome_result(Outcome::Cancelled, limits()).unwrap()["state"],
        "cancelled"
    );
    let response = outcome_result(
        Outcome::Committed {
            result: retained_result(),
            sequence: 9,
        },
        limits(),
    )
    .unwrap();
    assert_eq!(response["sequence"], "9");
    assert_eq!(response["results"][0]["rows"].as_array().unwrap().len(), 1);
    let mut bad = retained_result();
    bad.statements[0].rows.push(vec![]);
    assert!(outcome_result(
        Outcome::Committed {
            result: bad,
            sequence: 9
        },
        limits()
    )
    .is_err());
}
