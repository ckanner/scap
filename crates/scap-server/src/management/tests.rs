use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

use axum::http::HeaderValue;
use http_body_util::BodyExt;
use scap_raft_driver::MemberProgress;
use tower::ServiceExt;

const TOKEN: &str = "independent-management-unit-secret";

fn digest() -> [u8; 32] {
    Sha256::digest(TOKEN.as_bytes()).into()
}

fn conf() -> Value {
    json!({"voters":[1,2,3],"learners":[],"voters_outgoing":[],"learners_next":[],"auto_leave":false})
}

fn command(action: &str) -> Value {
    let mut value = json!({"action":action,"expected_conf_state":conf()});
    if matches!(action, "add_learner" | "replace_voter") {
        value["node_id"] = json!(4);
    }
    if action == "replace_voter" {
        value["remove_id"] = json!(3);
    }
    value
}

fn membership() -> MembershipStatus {
    MembershipStatus {
        conf_state: parse_conf_state(&conf()).unwrap(),
        term: 9,
        applied: 17,
        commit: 17,
        snapshot_index: 10,
        leader_id: 1,
        pending_conf_index: 0,
        progress: vec![MemberProgress {
            node_id: 4,
            matched: 17,
            is_learner: true,
        }],
    }
}

struct TestPort {
    answers: Mutex<VecDeque<Result<MembershipStatus, ServiceError>>>,
    calls: Mutex<Vec<(Action, Instant)>>,
}

fn status() -> Status {
    Status {
        role: raft::StateRole::Follower,
        term: 9,
        leader_id: 1,
        commit: 17,
        applied: 17,
        last_index: 17,
        snapshot_index: 10,
        is_voter: false,
    }
}

impl Port for TestPort {
    fn identity(&self) -> scap_raft_store::Identity {
        scap_raft_store::Identity {
            cluster_id: 1,
            cell_id: 2,
            cell_incarnation: 1,
            node_id: 1,
        }
    }
    fn request(&self, action: Action, deadline: Instant) -> Result<MembershipStatus, ServiceError> {
        self.calls.lock().unwrap().push((action, deadline));
        self.answers.lock().unwrap().pop_front().unwrap()
    }
    fn status(&self, _: Instant) -> Result<LocalStatus, ServiceError> {
        Ok(LocalStatus {
            node_id: 4,
            status: status(),
        })
    }
}

fn admin(answers: Vec<Result<MembershipStatus, ServiceError>>) -> (Administration, Arc<TestPort>) {
    let port = Arc::new(TestPort {
        answers: Mutex::new(answers.into()),
        calls: Mutex::new(Vec::new()),
    });
    (
        Administration {
            token: digest(),
            port: port.clone(),
            slots: Arc::new(Semaphore::new(4)),
            bootstrap_voters: vec![1, 2, 3],
            genesis_digest: [7; 32],
        },
        port,
    )
}

fn request(method: Method, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(PATH)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(body.into())
        .unwrap()
}

#[test]
fn configuration_cas_actions_and_original_deadline_are_strictly_decoded() {
    assert!(matches!(parse_request(false, b"").unwrap().0, Action::Read));
    assert!(parse_request(false, b"{}").is_err());
    assert_eq!(
        parse_request(true, &vec![b' '; MAX_BODY + 1])
            .unwrap_err()
            .code,
        "MEMBERSHIP_LIMIT"
    );
    for (name, expected) in [
        ("add_learner", MembershipChange::AddLearner { node_id: 4 }),
        (
            "replace_voter",
            MembershipChange::ReplaceVoter {
                remove_id: 3,
                learner_id: 4,
            },
        ),
        ("leave_joint", MembershipChange::LeaveJoint),
    ] {
        let (action, timeout) = parse_request(true, command(name).to_string().as_bytes()).unwrap();
        let Action::Change {
            expected: state,
            change,
        } = action
        else {
            panic!("mutation lost")
        };
        assert_eq!(change, expected);
        assert_eq!(state, parse_conf_state(&conf()).unwrap());
        assert_eq!(timeout, Duration::from_secs(5));
    }
    let mut value = command("add_learner");
    for millis in [1, 30_000] {
        value["deadline_ms"] = json!(millis);
        assert_eq!(
            parse_request(true, value.to_string().as_bytes())
                .unwrap()
                .1
                .as_millis(),
            millis
        );
    }
    for invalid in [json!(0), json!(30_001), json!(-1), json!("5"), json!(null)] {
        value["deadline_ms"] = invalid;
        assert!(parse_request(true, value.to_string().as_bytes()).is_err());
    }
    for bytes in [b"{".as_slice(), b"{}", b"null"] {
        assert!(parse_request(true, bytes).is_err());
    }
    for bad in [json!(0), json!("4"), Value::Null] {
        let mut value = command("add_learner");
        value["node_id"] = bad;
        assert!(parse_request(true, value.to_string().as_bytes()).is_err());
    }
    for key in ["node_id", "remove_id"] {
        let mut value = command("replace_voter");
        value.as_object_mut().unwrap().remove(key);
        assert!(parse_request(true, value.to_string().as_bytes()).is_err());
    }
    for action in [Value::Null, json!("invalid")] {
        let mut value = command("leave_joint");
        value["action"] = action;
        assert!(parse_request(true, value.to_string().as_bytes()).is_err());
    }
    for (action, key) in [
        ("add_learner", "remove_id"),
        ("add_learner", "node"),
        ("replace_voter", "remove_node"),
        ("leave_joint", "node_id"),
        ("leave_joint", "remove_id"),
        ("leave_joint", "deadline"),
    ] {
        let mut value = command(action);
        value[key] = json!(4);
        assert_eq!(
            parse_request(true, value.to_string().as_bytes())
                .unwrap_err()
                .code,
            "MEMBERSHIP_INVALID"
        );
    }
    let mut unknown_conf = conf();
    unknown_conf["voter"] = json!([1, 2, 3]);
    assert_eq!(
        parse_conf_state(&unknown_conf).unwrap_err().code,
        "MEMBERSHIP_INVALID"
    );
    assert_eq!(
        parse_conf_state(&Value::Null).unwrap_err().code,
        "MEMBERSHIP_INVALID"
    );
    for key in [
        "voters",
        "learners",
        "voters_outgoing",
        "learners_next",
        "auto_leave",
    ] {
        let mut value = command("leave_joint");
        value["expected_conf_state"][key] = Value::Null;
        assert!(parse_request(true, value.to_string().as_bytes()).is_err());
    }
    for invalid in [json!([1, 1]), json!([0]), json!(["1"]), json!(vec![1; 17])] {
        let mut value = conf();
        value["voters"] = invalid;
        assert!(parse_conf_state(&value).is_err());
    }
    let mut value = conf();
    value["voters"] = json!([3, 2, 1]);
    assert_eq!(parse_conf_state(&value).unwrap().voters, vec![1, 2, 3]);
}

#[test]
fn management_secret_cannot_be_missing_malformed_or_a_tenant_token() {
    assert!(authorize(None, digest()).is_err());
    for token in [
        "Basic abc".to_owned(),
        "Bearer ".into(),
        format!("Bearer {}", "x".repeat(4097)),
        format!("Bearer {}", crate::tests::TOKEN),
    ] {
        assert_eq!(
            authorize(Some(&HeaderValue::from_str(&token).unwrap()), digest())
                .unwrap_err()
                .code,
            "UNAUTHORIZED"
        );
    }
    assert!(authorize(Some(&HeaderValue::from_bytes(&[0xff]).unwrap()), digest()).is_err());
    authorize(
        Some(&HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap()),
        digest(),
    )
    .unwrap();
}

#[test]
fn only_matching_durable_answers_are_successful_and_rejections_remain_distinct() {
    decode_answer(Ok(Answer::Membership(membership())), false).unwrap();
    decode_answer(Ok(Answer::MembershipChanged(membership())), true).unwrap();
    for (answer, changing) in [
        (Answer::Membership(membership()), true),
        (Answer::MembershipChanged(membership()), false),
        (Answer::Checkpointed, true),
    ] {
        assert_eq!(
            decode_answer(Ok(answer), changing).unwrap_err().code,
            "MEMBERSHIP_UNKNOWN"
        );
    }
    for (error, code) in [
        (Error::MembershipConflict, "MEMBERSHIP_CONFLICT"),
        (Error::MembershipPending, "MEMBERSHIP_PENDING"),
        (Error::LearnerNotCaughtUp, "LEARNER_NOT_CAUGHT_UP"),
        (Error::NotLeader, "NOT_LEADER"),
        (Error::Invalid("invalid action"), "MEMBERSHIP_INVALID"),
        (Error::InputLimit, "MEMBERSHIP_INVALID"),
        (Error::Full, "OVERLOADED"),
        (Error::Unknown, "MEMBERSHIP_UNKNOWN"),
        (Error::Expired, "MEMBERSHIP_UNKNOWN"),
        (Error::Closed, "MEMBERSHIP_UNKNOWN"),
    ] {
        assert_eq!(decode_answer(Err(error), true).unwrap_err().code, code);
    }
    for (code, status) in [
        ("UNAUTHORIZED", 401),
        ("MEMBERSHIP_INVALID", 400),
        ("MEMBERSHIP_LIMIT", 400),
        ("MEMBERSHIP_CONFLICT", 409),
        ("MEMBERSHIP_PENDING", 409),
        ("LEARNER_NOT_CAUGHT_UP", 409),
        ("NOT_LEADER", 409),
        ("MEMBERSHIP_UNKNOWN", 503),
    ] {
        assert_eq!(reply(Err(failure(code))).status().as_u16(), status);
    }
    local_status(4, Ok(Answer::Status(status()))).unwrap();
    assert!(local_status(4, Ok(Answer::Checkpointed)).is_err());
    assert!(local_status(4, Err(Error::Closed)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_http_returns_exact_membership_and_does_not_ack_queued_work() {
    let (admin, port) = admin(vec![
        Ok(membership()),
        Ok(membership()),
        Err(failure("MEMBERSHIP_UNKNOWN")),
    ]);
    let routes = routes(
        admin.token,
        admin.port.clone(),
        admin.bootstrap_voters.clone(),
        admin.genesis_digest,
    );
    for (method, body, status, changing) in [
        (Method::GET, String::new(), 200, false),
        (Method::POST, command("add_learner").to_string(), 200, true),
        (Method::POST, command("leave_joint").to_string(), 503, true),
    ] {
        let response = routes.clone().oneshot(request(method, body)).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        let bytes = to_bytes(response.into_body(), MAX_RESPONSE).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        if status == 200 {
            assert_eq!(value["membership"]["conf_state"], conf());
            assert_eq!(value["scope"]["cluster_id"], format!("{:032x}", 1));
            assert_eq!(value["membership"]["applied"], 17);
            assert_eq!(value["membership"]["progress"][0]["matched"], 17);
            assert_eq!(
                value.get("outcome").and_then(Value::as_str),
                changing.then_some("applied")
            );
        } else {
            assert_eq!(value["code"], "MEMBERSHIP_UNKNOWN");
            assert!(value.get("outcome").is_none());
        }
    }
    assert_eq!(port.calls.lock().unwrap().len(), 3);
    for (_, deadline) in port.calls.lock().unwrap().iter() {
        assert!(*deadline > Instant::now());
        assert!(*deadline <= Instant::now() + Duration::from_secs(5));
    }
    let mut query = request(Method::GET, "");
    *query.uri_mut() = STATUS_PATH.parse().unwrap();
    let response = routes.oneshot(query).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), MAX_RESPONSE).await.unwrap())
            .unwrap();
    assert_eq!(value["authoritative"], false);
    assert_eq!(value["node_id"], 4);
    assert_eq!(value["status"]["snapshot_index"], 10);
    assert_eq!(value["status"]["is_voter"], false);
    assert!(value.get("membership").is_none());
}

#[tokio::test]
async fn body_admission_and_deadlines_cannot_bypass_management_limits() {
    let (admin, port) = admin(vec![]);
    let guard = admin.slots.clone().acquire_many_owned(4).await.unwrap();
    assert_eq!(
        handle_request(admin.clone(), request(Method::GET, ""))
            .await
            .unwrap_err()
            .code,
        "OVERLOADED"
    );
    drop(guard);
    let mut invalid = request(Method::GET, "");
    invalid.headers_mut().remove(header::AUTHORIZATION);
    assert_eq!(
        handle_request(admin.clone(), invalid)
            .await
            .unwrap_err()
            .code,
        "UNAUTHORIZED"
    );
    assert_eq!(
        handle_request(admin.clone(), request(Method::POST, vec![0; MAX_BODY + 1]))
            .await
            .unwrap_err()
            .code,
        "MEMBERSHIP_LIMIT"
    );
    assert_eq!(
        handle_request(admin.clone(), request(Method::POST, "{"))
            .await
            .unwrap_err()
            .code,
        "MEMBERSHIP_INVALID"
    );
    let stalled = Body::new(Body::empty().with_trailers(std::future::pending()));
    assert_eq!(
        read_body(to_bytes(stalled, MAX_BODY), Instant::now())
            .await
            .unwrap_err()
            .code,
        "MEMBERSHIP_UNKNOWN"
    );
    let mut value = command("leave_joint");
    value["deadline_ms"] = json!(1);
    assert_eq!(
        handle_at(
            admin,
            request(Method::POST, value.to_string()),
            Instant::now() - Duration::from_secs(1)
        )
        .await
        .unwrap_err()
        .code,
        "MEMBERSHIP_UNKNOWN"
    );
    assert!(port.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bounded_waiter_reports_timeout_thread_failure_and_runtime_failure_as_unknown() {
    let pending = tokio::spawn(std::future::pending::<Result<Value, ServiceError>>());
    let abort = pending.abort_handle();
    assert_eq!(
        finish(pending, Instant::now()).await.unwrap_err().code,
        "MEMBERSHIP_UNKNOWN"
    );
    abort.abort();
    let panicked: tokio::task::JoinHandle<Result<Value, ServiceError>> = tokio::spawn(async {
        panic!("injected management worker failure");
    });
    assert_eq!(
        finish(panicked, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap_err()
            .code,
        "MEMBERSHIP_UNKNOWN"
    );
    let failed = tokio::spawn(async { Err::<Value, _>(failure("MEMBERSHIP_UNKNOWN")) });
    assert_eq!(
        finish(failed, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap_err()
            .code,
        "MEMBERSHIP_UNKNOWN"
    );
}

#[test]
fn native_runtime_port_preserves_strong_read_and_fixed_policy_rejection() {
    struct NoNetwork;
    impl scap_raft_runtime::Network for NoNetwork {
        fn try_send(&mut self, _: scap_raft_runtime::Delivery) -> Result<(), Error> {
            panic!("single voter")
        }
    }
    let (mut runtime, port) = crate::local::tests::runtime(true);
    let handle = port.handle;
    let owner = std::thread::spawn(move || runtime.run(&mut NoNetwork));
    let port = RuntimePort(handle.clone());
    assert_eq!(port.identity().node_id, 1);
    let status = port
        .request(Action::Read, Instant::now() + Duration::from_secs(2))
        .unwrap();
    assert_eq!(status.conf_state.voters, vec![1]);
    assert!(
        port.status(Instant::now() + Duration::from_secs(2))
            .unwrap()
            .status
            .is_voter
    );
    assert!(port
        .request(
            Action::Change {
                expected: status.conf_state,
                change: MembershipChange::AddLearner { node_id: 4 }
            },
            Instant::now() + Duration::from_secs(2)
        )
        .is_err());
    handle.stop();
    owner.join().unwrap().unwrap();
    assert!(port
        .request(Action::Read, Instant::now() + Duration::from_secs(1))
        .is_err());
}
