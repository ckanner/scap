use super::*;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

pub(crate) fn view(config: &Config) -> Value {
    json!({"scope":{
        "cluster_id":format!("{:032x}",config.cluster_id),
        "cell_id":format!("{:032x}",config.cell.cell_id),
        "cell_incarnation":config.cell.cell_incarnation,
        "bootstrap_voters":config.bootstrap_voters,
        "genesis_sha256":management::hex_digest(crate::node::genesis(config,crate::config::cell_limits()).unwrap().digest),
    },"membership":{
        "conf_state":{"voters":[1,2,3],"learners":[],"voters_outgoing":[],"learners_next":[],"auto_leave":false},
        "leader_id":1,"applied":3,"pending_conf_index":0,
    }})
}

pub(crate) fn server(status: u16, value: Value) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            let mut buffer = [0; 8192];
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
        }
        let request = String::from_utf8(bytes).unwrap();
        assert!(request.starts_with("GET /v1/admin/membership HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer join-unit-secret"));
        let bytes = value.to_string();
        let _ = write!(
            stream,
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bytes}",
            bytes.len()
        );
    });
    (endpoint, task)
}

#[test]
fn preflight_endpoint_is_literal_loopback_with_one_fixed_management_path() {
    assert_eq!(
        address("http://127.0.0.1:9091").unwrap(),
        "127.0.0.1:9091".parse().unwrap()
    );
    assert_eq!(
        address("http://[::1]/v1/admin/membership").unwrap(),
        "[::1]:80".parse().unwrap()
    );
    for bad in [
        "invalid",
        "https://127.0.0.1:9091",
        "http://user@127.0.0.1:9091",
        "http://:password@127.0.0.1:9091",
        "http://127.0.0.1:9091/?a=b",
        "http://127.0.0.1:9091/#fragment",
        "http://127.0.0.1:9091/other",
        "http://localhost:9091",
        "http://192.0.2.1:9091",
        "http://127.0.0.1:0",
    ] {
        assert_eq!(
            address(bad).unwrap_err().code,
            "JOIN_MANAGEMENT_URL",
            "{bad}"
        );
    }
}

#[test]
fn scope_current_members_and_pending_changes_fence_reused_identities() {
    let mut config = crate::tests::config();
    config.node_id = 4;
    validate(&config, &view(&config)).unwrap();
    for field in ["cluster_id", "cell_id", "cell_incarnation"] {
        let mut value = view(&config);
        value["scope"][field] = Value::Null;
        assert_eq!(validate(&config, &value).unwrap_err().code, "JOIN_SCOPE");
    }
    let mut value = view(&config);
    value["membership"]["conf_state"] = Value::Null;
    assert_eq!(
        validate(&config, &value).unwrap_err().code,
        "JOIN_MEMBERSHIP"
    );
    let mut value = view(&config);
    value["membership"]["conf_state"]["voters"] = json!([1, 2]);
    assert_eq!(
        validate(&config, &value).unwrap_err().code,
        "JOIN_MEMBERSHIP"
    );
    for field in ["leader_id", "applied", "pending_conf_index"] {
        let mut value = view(&config);
        value["membership"][field] = Value::Null;
        assert_eq!(
            validate(&config, &value).unwrap_err().code,
            "JOIN_MEMBERSHIP"
        );
    }
    for (field, bad) in [("leader_id", 0), ("applied", 0), ("pending_conf_index", 4)] {
        let mut value = view(&config);
        value["membership"][field] = json!(bad);
        assert_eq!(
            validate(&config, &value).unwrap_err().code,
            "JOIN_MEMBERSHIP"
        );
    }
    for field in ["learners", "voters_outgoing", "learners_next"] {
        let mut value = view(&config);
        value["membership"]["conf_state"][field] = json!([4]);
        assert_eq!(
            validate(&config, &value).unwrap_err().code,
            "JOIN_ID_REUSED"
        );
    }
    config.node_id = 3;
    assert_eq!(
        validate(&config, &view(&config)).unwrap_err().code,
        "JOIN_ID_REUSED"
    );
    config.node_id = 6;
    let mut joint = view(&config);
    joint["membership"]["conf_state"]["voters"] = json!([1, 2, 5]);
    joint["membership"]["conf_state"]["voters_outgoing"] = json!([1, 2, 4]);
    joint["membership"]["leader_id"] = json!(4);
    validate(&config, &joint).unwrap();
    Permit {
        deadline: Instant::now() + Duration::from_secs(1),
    }
    .current()
    .unwrap();
    Permit::new(Instant::now() + Duration::from_secs(1)).unwrap();
    assert!(Permit::new(Instant::now()).is_err());
    assert_eq!(
        Permit {
            deadline: Instant::now()
        }
        .current()
        .unwrap_err()
        .code,
        "JOIN_EXPIRED"
    );
}

#[test]
fn join_genesis_binds_administrator_limits_and_canonical_bootstrap_voters() {
    let mut config = crate::tests::config();
    config.node_id = 4;
    let source = view(&config);
    for voters in [
        Value::Null,
        json!([1, 2]),
        json!([1, 1, 3]),
        json!([1, 2, 5]),
    ] {
        let mut value = source.clone();
        value["scope"]["bootstrap_voters"] = voters;
        assert_eq!(
            validate(&config, &value).unwrap_err().code,
            "JOIN_BOOTSTRAP"
        );
    }
    for voters in [vec![1, 2], vec![1, 1, 3]] {
        let mut wrong = config.clone();
        wrong.bootstrap_voters = voters;
        assert_eq!(
            validate(&wrong, &source).unwrap_err().code,
            "JOIN_BOOTSTRAP"
        );
    }
    let mut canonical = source.clone();
    canonical["scope"]["bootstrap_voters"] = json!([3, 2, 1]);
    config.bootstrap_voters = vec![2, 3, 1];
    validate(&config, &canonical).unwrap();
    let mut wrong = config.clone();
    wrong.administrator_id += 1;
    assert_eq!(validate(&wrong, &source).unwrap_err().code, "JOIN_GENESIS");
    let mut limits = crate::config::cell_limits();
    limits.max_result_bytes += 1;
    let mut changed = source.clone();
    changed["scope"]["genesis_sha256"] = json!(management::hex_digest(
        crate::node::genesis(&config, limits).unwrap().digest
    ));
    assert_eq!(
        validate(&config, &changed).unwrap_err().code,
        "JOIN_GENESIS"
    );
    let mut missing = source.clone();
    missing["scope"]["genesis_sha256"] = Value::Null;
    assert_eq!(
        validate(&config, &missing).unwrap_err().code,
        "JOIN_GENESIS"
    );
    wrong.administrator_id = 0;
    assert_eq!(validate(&wrong, &source).unwrap_err().code, "CELL_GENESIS");
}

#[tokio::test]
async fn authenticated_fresh_preflight_rejects_missing_health_scope_and_used_ids() {
    let mut config = crate::tests::config();
    config.node_id = 4;
    assert!(verify(&config, None, Some("join-unit-secret".into()))
        .await
        .is_err());
    for token in [None, Some(String::new()), Some("x".repeat(4097))] {
        assert!(verify(&config, Some("http://127.0.0.1:9091".into()), token)
            .await
            .is_err());
    }
    for status in [200, 401, 409, 503] {
        let (endpoint, owner) = server(status, view(&config));
        let result = verify(&config, Some(endpoint), Some("join-unit-secret".into())).await;
        assert_eq!(result.is_ok(), status == 200);
        owner.join().unwrap();
    }
    for value in [Value::Null, {
        let mut value = view(&config);
        value["membership"]["conf_state"]["learners"] = json!([4]);
        value
    }] {
        let (endpoint, owner) = server(200, value);
        assert!(
            verify(&config, Some(endpoint), Some("join-unit-secret".into()))
                .await
                .is_err()
        );
        owner.join().unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    assert!(
        verify(&config, Some(endpoint), Some("join-unit-secret".into()))
            .await
            .is_err()
    );
}
