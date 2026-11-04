//! Local, separately authenticated membership administration. HTTP admission is
//! never membership completion: the runtime returns the exact durable result.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use raft::eraftpb::ConfState;
use scap_raft_driver::{MembershipChange, MembershipStatus, Status};
use scap_raft_runtime::{Answer, Error, Handle, Input};
use scap_service::ServiceError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::config::ManagementConfig;
use crate::failure;

pub(crate) const PATH: &str = "/v1/admin/membership";
pub(crate) const STATUS_PATH: &str = "/v1/admin/status";
pub(crate) const MAX_BODY: usize = 16 * 1024;
pub(crate) const MAX_RESPONSE: usize = 64 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug)]
pub(crate) enum Action {
    Read,
    Change {
        expected: ConfState,
        change: MembershipChange,
    },
}

trait Port: Send + Sync + 'static {
    fn identity(&self) -> scap_raft_store::Identity;
    fn request(&self, action: Action, deadline: Instant) -> Result<MembershipStatus, ServiceError>;
    fn status(&self, deadline: Instant) -> Result<LocalStatus, ServiceError>;
}

struct LocalStatus {
    node_id: u64,
    status: Status,
}

struct RuntimePort(Handle);

impl Port for RuntimePort {
    fn identity(&self) -> scap_raft_store::Identity {
        self.0.identity()
    }

    fn request(&self, action: Action, deadline: Instant) -> Result<MembershipStatus, ServiceError> {
        let changing = matches!(action, Action::Change { .. });
        let input = match action {
            Action::Read => Input::Membership,
            Action::Change { expected, change } => Input::ChangeMembership { expected, change },
        };
        decode_answer(
            self.0
                .submit(input, deadline)
                .and_then(|pending| pending.wait()),
            changing,
        )
    }

    fn status(&self, deadline: Instant) -> Result<LocalStatus, ServiceError> {
        local_status(
            self.0.identity().node_id,
            self.0
                .submit(Input::Status, deadline)
                .and_then(|pending| pending.wait()),
        )
    }
}

fn local_status(node_id: u64, answer: Result<Answer, Error>) -> Result<LocalStatus, ServiceError> {
    match answer {
        Ok(Answer::Status(status)) => Ok(LocalStatus { node_id, status }),
        _ => Err(failure("MEMBERSHIP_UNKNOWN")),
    }
}

fn decode_answer(
    answer: Result<Answer, Error>,
    changing: bool,
) -> Result<MembershipStatus, ServiceError> {
    match answer {
        Ok(Answer::Membership(status)) if !changing => Ok(status),
        Ok(Answer::MembershipChanged(status)) if changing => Ok(status),
        Err(Error::MembershipConflict) => Err(failure("MEMBERSHIP_CONFLICT")),
        Err(Error::MembershipPending) => Err(failure("MEMBERSHIP_PENDING")),
        Err(Error::LearnerNotCaughtUp) => Err(failure("LEARNER_NOT_CAUGHT_UP")),
        Err(Error::NotLeader) => Err(failure("NOT_LEADER")),
        Err(Error::Invalid(_)) | Err(Error::InputLimit) => Err(failure("MEMBERSHIP_INVALID")),
        Err(Error::Full) => Err(failure("OVERLOADED")),
        _ => Err(failure("MEMBERSHIP_UNKNOWN")),
    }
}

#[derive(Clone)]
struct Administration {
    token: [u8; 32],
    port: Arc<dyn Port>,
    slots: Arc<Semaphore>,
    bootstrap_voters: Vec<u64>,
    genesis_digest: [u8; 32],
}

pub(crate) fn router(
    config: &ManagementConfig,
    handle: Handle,
    bootstrap_voters: &[u64],
    genesis_digest: [u8; 32],
) -> Router {
    routes(
        config.token_digest,
        Arc::new(RuntimePort(handle)),
        bootstrap_voters.to_vec(),
        genesis_digest,
    )
}

fn routes(
    token: [u8; 32],
    port: Arc<dyn Port>,
    bootstrap_voters: Vec<u64>,
    genesis_digest: [u8; 32],
) -> Router {
    Router::new()
        .route(PATH, get(handle).post(handle))
        .route(STATUS_PATH, get(handle))
        .with_state(Administration {
            token,
            port,
            slots: Arc::new(Semaphore::new(4)),
            bootstrap_voters,
            genesis_digest,
        })
}

async fn handle(State(admin): State<Administration>, request: Request<Body>) -> Response {
    reply(handle_request(admin, request).await)
}

async fn handle_request(
    admin: Administration,
    request: Request<Body>,
) -> Result<Value, ServiceError> {
    handle_at(admin, request, Instant::now()).await
}

async fn handle_at(
    admin: Administration,
    request: Request<Body>,
    started: Instant,
) -> Result<Value, ServiceError> {
    authorize(request.headers().get(header::AUTHORIZATION), admin.token)?;
    let permit = admin
        .slots
        .try_acquire_owned()
        .map_err(|_| failure("OVERLOADED"))?;
    let changing = request.method() == Method::POST;
    let local = request.uri().path() == STATUS_PATH;
    let body = read_body(
        to_bytes(request.into_body(), MAX_BODY),
        started + Duration::from_millis(MAX_TIMEOUT_MS),
    )
    .await?;
    let (action, timeout) = parse_request(changing, &body)?;
    let deadline = started + timeout;
    if Instant::now() >= deadline {
        return Err(failure("MEMBERSHIP_UNKNOWN"));
    }
    let identity = admin.port.identity();
    let scope = json!({
        "cluster_id":format!("{:032x}",identity.cluster_id),
        "cell_id":format!("{:032x}",identity.cell_id),
        "cell_incarnation":identity.cell_incarnation,
        "bootstrap_voters":admin.bootstrap_voters,
        "genesis_sha256":hex_digest(admin.genesis_digest),
    });
    let result = tokio::task::spawn_blocking(move || {
        // A cancelled HTTP waiter does not release this execution reservation
        // until the original bounded runtime request itself has finished.
        let _permit = permit;
        if local {
            admin.port.status(deadline).map(local_status_json)
        } else {
            admin.port.request(action, deadline).map(membership_json)
        }
    });
    let view = finish(result, deadline).await?;
    Ok(if local {
        view
    } else if changing {
        json!({"outcome":"applied", "scope":scope, "membership":view})
    } else {
        json!({"scope":scope, "membership":view})
    })
}

pub(crate) fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn read_body(
    body: impl std::future::Future<Output = Result<axum::body::Bytes, axum::Error>>,
    deadline: Instant,
) -> Result<axum::body::Bytes, ServiceError> {
    tokio::time::timeout_at(deadline.into(), body)
        .await
        .map_err(|_| failure("MEMBERSHIP_UNKNOWN"))?
        .map_err(|_| failure("MEMBERSHIP_LIMIT"))
}

async fn finish<T>(
    result: tokio::task::JoinHandle<Result<T, ServiceError>>,
    deadline: Instant,
) -> Result<T, ServiceError> {
    tokio::time::timeout_at(deadline.into(), result)
        .await
        .map_err(|_| failure("MEMBERSHIP_UNKNOWN"))?
        .map_err(|_| failure("MEMBERSHIP_UNKNOWN"))?
}

fn authorize(
    value: Option<&axum::http::HeaderValue>,
    expected: [u8; 32],
) -> Result<(), ServiceError> {
    let token = value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty() && token.len() <= 4096)
        .ok_or_else(|| failure("UNAUTHORIZED"))?;
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let difference = actual
        .iter()
        .zip(expected)
        .fold(0, |difference, (actual, expected)| {
            difference | (actual ^ expected)
        });
    if difference != 0 {
        return Err(failure("UNAUTHORIZED"));
    }
    Ok(())
}

pub(crate) fn parse_request(
    changing: bool,
    bytes: &[u8],
) -> Result<(Action, Duration), ServiceError> {
    if bytes.len() > MAX_BODY {
        return Err(failure("MEMBERSHIP_LIMIT"));
    }
    if !changing {
        if !bytes.is_empty() {
            return Err(failure("MEMBERSHIP_INVALID"));
        }
        return Ok((Action::Read, Duration::from_millis(DEFAULT_TIMEOUT_MS)));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| failure("MEMBERSHIP_INVALID"))?;
    let timeout_ms = match value.get("deadline_ms") {
        None => DEFAULT_TIMEOUT_MS,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| failure("MEMBERSHIP_INVALID"))?,
    };
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(failure("MEMBERSHIP_INVALID"));
    }
    let expected = parse_conf_state(&value["expected_conf_state"])?;
    let (change, allowed): (_, &[&str]) = match value.get("action").and_then(Value::as_str) {
        Some("add_learner") => (
            MembershipChange::AddLearner {
                node_id: node_id(&value, "node_id")?,
            },
            &["action", "expected_conf_state", "deadline_ms", "node_id"],
        ),
        Some("replace_voter") => (
            MembershipChange::ReplaceVoter {
                remove_id: node_id(&value, "remove_id")?,
                learner_id: node_id(&value, "node_id")?,
            },
            &[
                "action",
                "expected_conf_state",
                "deadline_ms",
                "node_id",
                "remove_id",
            ],
        ),
        Some("leave_joint") => (
            MembershipChange::LeaveJoint,
            &["action", "expected_conf_state", "deadline_ms"],
        ),
        _ => return Err(failure("MEMBERSHIP_INVALID")),
    };
    allowed_fields(&value, allowed)?;
    Ok((
        Action::Change { expected, change },
        Duration::from_millis(timeout_ms),
    ))
}

fn node_id(value: &Value, key: &str) -> Result<u64, ServiceError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or_else(|| failure("MEMBERSHIP_INVALID"))
}

pub(crate) fn parse_conf_state(value: &Value) -> Result<ConfState, ServiceError> {
    allowed_fields(
        value,
        &[
            "voters",
            "learners",
            "voters_outgoing",
            "learners_next",
            "auto_leave",
        ],
    )?;
    let mut state = ConfState::default();
    state.set_voters(nodes(value, "voters")?);
    state.set_learners(nodes(value, "learners")?);
    state.set_voters_outgoing(nodes(value, "voters_outgoing")?);
    state.set_learners_next(nodes(value, "learners_next")?);
    state.auto_leave = value
        .get("auto_leave")
        .and_then(Value::as_bool)
        .ok_or_else(|| failure("MEMBERSHIP_INVALID"))?;
    Ok(state)
}

fn allowed_fields(value: &Value, allowed: &[&str]) -> Result<(), ServiceError> {
    let object = value
        .as_object()
        .ok_or_else(|| failure("MEMBERSHIP_INVALID"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(failure("MEMBERSHIP_INVALID"));
    }
    Ok(())
}

pub(crate) fn nodes(value: &Value, key: &str) -> Result<Vec<u64>, ServiceError> {
    let array = value
        .get(key)
        .and_then(Value::as_array)
        .filter(|values| values.len() <= 16)
        .ok_or_else(|| failure("MEMBERSHIP_INVALID"))?;
    let mut nodes = array
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|id| *id != 0)
                .ok_or_else(|| failure("MEMBERSHIP_INVALID"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    nodes.sort_unstable();
    if nodes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(failure("MEMBERSHIP_INVALID"));
    }
    Ok(nodes)
}

fn membership_json(status: MembershipStatus) -> Value {
    let state = status.conf_state;
    json!({
        "conf_state": {
            "voters":state.voters, "learners":state.learners,
            "voters_outgoing":state.voters_outgoing, "learners_next":state.learners_next,
            "auto_leave":state.auto_leave,
        },
        "term":status.term, "applied":status.applied, "commit":status.commit,
        "snapshot_index":status.snapshot_index, "leader_id":status.leader_id,
        "pending_conf_index":status.pending_conf_index,
        "progress":status.progress.into_iter().map(|peer| json!({
            "node_id":peer.node_id, "matched":peer.matched, "is_learner":peer.is_learner,
        })).collect::<Vec<_>>(),
    })
}

fn local_status_json(local: LocalStatus) -> Value {
    let status = local.status;
    json!({
        "authoritative":false,
        "node_id":local.node_id,
        "status":{
            "role":format!("{:?}", status.role).to_ascii_lowercase(),
            "term":status.term,"leader_id":status.leader_id,"commit":status.commit,
            "applied":status.applied,"snapshot_index":status.snapshot_index,
            "is_voter":status.is_voter,
        }
    })
}

fn reply(result: Result<Value, ServiceError>) -> Response {
    let (status, value) = match result {
        Ok(value) => (StatusCode::OK, value),
        Err(error) => {
            let status = match error.code.as_str() {
                "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
                "MEMBERSHIP_INVALID" | "MEMBERSHIP_LIMIT" => StatusCode::BAD_REQUEST,
                "MEMBERSHIP_CONFLICT"
                | "MEMBERSHIP_PENDING"
                | "LEARNER_NOT_CAUGHT_UP"
                | "NOT_LEADER" => StatusCode::CONFLICT,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            (status, json!({"code":error.code}))
        }
    };
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONNECTION, "close"),
        ],
        value.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
