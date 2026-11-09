//! HTTP authentication and bounded intake; SQL stays on confined workers.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body, Bytes, HttpBody};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::{
    auth::{Authenticator, Principal},
    intake::{Class, Intake, Lease},
    scheduler::Scheduler,
    wire, Failure,
};

pub struct HttpState {
    pub auth: Authenticator,
    pub scheduler: Arc<Scheduler>,
    pub catalogue: Option<CatalogueState>,
    pub discovery: Option<Arc<crate::discovery::Discovery>>,
    pub max_body_bytes: usize,
    pub timeout: Duration,
    pub recovery_timeout: Duration,
    pub intake: Arc<Intake>,
    pub control_intake: Arc<Intake>,
    pub recovery_intake: Arc<Intake>,
}

pub struct CatalogueState {
    pub scheduler: Arc<crate::catalogue_scheduler::Scheduler>,
    pub max_body_bytes: usize,
    pub timeout: Duration,
    pub intake: Arc<Intake>,
}

pub fn router(state: Arc<HttpState>) -> Result<Router, Failure> {
    if state.max_body_bytes == 0
        || state.timeout.is_zero()
        || state.timeout > Duration::from_secs(86400)
        || state.recovery_timeout.is_zero()
        || state.recovery_timeout > Duration::from_secs(7 * 86400)
    {
        return Err(Failure::new("CONFIG"));
    }
    state.intake.validate(Class::Data, state.max_body_bytes)?;
    state
        .control_intake
        .validate(Class::Control, state.max_body_bytes)?;
    state
        .recovery_intake
        .validate(Class::Recovery, state.max_body_bytes)?;
    if let Some(catalogue) = &state.catalogue {
        if !(1..=65536).contains(&catalogue.max_body_bytes)
            || catalogue.timeout.is_zero()
            || catalogue.timeout > Duration::from_secs(86400)
        {
            return Err(Failure::new("CONFIG"));
        }
        catalogue
            .intake
            .validate(Class::Catalogue, catalogue.max_body_bytes)?;
    }
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/v1", post(call))
        .route("/v1/catalogue", post(catalogue_call))
        .route("/v1/discovery", post(discovery::call))
        .with_state(state))
}

async fn health() -> Json<serde_json::Value> {
    // Liveness only: it makes no S3 or database availability claim.
    Json(json!({ "status": "alive", "protocol": 1 }))
}

fn failure(error: Failure) -> Response {
    let status = match error.code {
        "UNAUTHENTICATED" => StatusCode::UNAUTHORIZED,
        "DENIED" => StatusCode::FORBIDDEN,
        "NOT_FOUND" => StatusCode::NOT_FOUND,
        "INVALID" | "VERSION" | "CURSOR_INVALID" => StatusCode::BAD_REQUEST,
        "LIMIT" => StatusCode::PAYLOAD_TOO_LARGE,
        "BACKPRESSURE" | "RECOVERY_BUSY" => StatusCode::TOO_MANY_REQUESTS,
        "UNKNOWN" | "UNAVAILABLE" | "DEADLINE" | "COMMITTED_BUT_UNAVAILABLE" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::CONFLICT,
    };
    (status, Json(wire::failed(&error))).into_response()
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

/// A transport can retain the last data frame after dropping its body. Keep
/// the reservation with those bytes, including every clone and nonempty slice,
/// without copying the potentially large response allocation.
struct ReservedBytes {
    bytes: Bytes,
    _reservation: Arc<dyn Send + Sync>,
}

impl AsRef<[u8]> for ReservedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Keep intake reserved while either the body or emitted data is still owned.
/// Dropping a client does not cancel or repeat a running SQL call.
struct ReservedBody {
    inner: Body,
    reservation: Arc<dyn Send + Sync>,
}

impl HttpBody for ReservedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx).map(|frame| {
            frame.map(|result| {
                result.map(|frame| {
                    frame.map_data(|bytes| {
                        Bytes::from_owner(ReservedBytes {
                            bytes,
                            _reservation: self.reservation.clone(),
                        })
                    })
                })
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

async fn call(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let received = Instant::now();
    let principal = match state
        .auth
        .authenticate(single(request.headers(), "authorization"))
    {
        Ok(principal) => principal,
        Err(error) => return failure(error),
    };
    let class = match single(request.headers(), "x-scap-admission") {
        Some("control") => "control",
        Some("recovery") => "recovery",
        Some("data") => "data",
        None if !request.headers().contains_key("x-scap-admission") => "data",
        _ => return failure(Failure::new("INVALID")),
    };
    let slots = match class {
        "control" => &state.control_intake,
        "recovery" => &state.recovery_intake,
        _ => &state.intake,
    };
    let reservation = match slots.acquire(&principal) {
        Ok(reservation) => reservation,
        Err(error) => return failure(error),
    };
    let response = admitted(
        &state,
        principal,
        class,
        reservation.clone(),
        received,
        request,
    )
    .await;
    reserved(response, reservation)
}

fn reserved(response: Response, reservation: impl Send + Sync + 'static) -> Response {
    let (parts, inner) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(ReservedBody {
            inner,
            reservation: Arc::new(reservation),
        }),
    )
}

async fn catalogue_call(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let received = Instant::now();
    let principal = match state
        .auth
        .authenticate(single(request.headers(), "authorization"))
    {
        Ok(principal) => principal,
        Err(error) => return failure(error),
    };
    if single(request.headers(), "x-scap-admission") != Some("catalogue") {
        return failure(Failure::new("INVALID"));
    }
    let catalogue = match &state.catalogue {
        Some(catalogue) => catalogue,
        None => return failure(Failure::new("UNAVAILABLE")),
    };
    let reservation = match catalogue.intake.acquire(&principal) {
        Ok(reservation) => reservation,
        Err(error) => return failure(error),
    };
    let response =
        catalogue_admitted(catalogue, principal, reservation.clone(), received, request).await;
    reserved(response, reservation)
}

async fn catalogue_admitted(
    state: &CatalogueState,
    principal: Principal,
    reservation: Arc<Lease>,
    received: Instant,
    request: Request,
) -> Response {
    if single(request.headers(), "content-type") != Some("application/json") {
        return failure(Failure::new("INVALID"));
    }
    let deadline = received + state.timeout;
    let bytes = match tokio::time::timeout_at(
        deadline.into(),
        to_bytes(request.into_body(), state.max_body_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return failure(Failure::new("LIMIT")),
        Err(_) => return failure(Failure::new("DEADLINE")),
    };
    if let Err(error) = reservation.shrink_body(bytes.len()) {
        return failure(error);
    }
    let call = match parse_catalogue_before(&bytes, deadline) {
        Ok(call) => call,
        Err(error) => return failure(error),
    };
    let receiver = match state
        .scheduler
        .submit_reserved(principal, call, deadline, reservation)
    {
        Ok(receiver) => receiver,
        Err(error) => return failure(error),
    };
    match tokio::time::timeout_at(deadline.into(), receiver).await {
        Ok(Ok(Ok(value))) => Json(wire::success(value)).into_response(),
        Ok(Ok(Err(error))) => failure(error),
        Ok(Err(_)) | Err(_) => failure(Failure::new("UNKNOWN")),
    }
}

fn parse_catalogue_before(
    bytes: &[u8],
    deadline: Instant,
) -> Result<crate::catalogue_wire::Call, Failure> {
    let call = crate::catalogue_wire::parse(bytes)?;
    if Instant::now() >= deadline {
        return Err(Failure::new("DEADLINE"));
    }
    Ok(call)
}

async fn admitted(
    state: &HttpState,
    principal: Principal,
    class: &str,
    reservation: Arc<Lease>,
    received: Instant,
    request: Request,
) -> Response {
    if single(request.headers(), "content-type") != Some("application/json") {
        return failure(Failure::new("INVALID"));
    }
    // Even a recovery call must finish uploading/parsing under the short
    // request budget. Its overall recovery budget starts at the same instant.
    let bytes = match tokio::time::timeout_at(
        (received + state.timeout).into(),
        to_bytes(request.into_body(), state.max_body_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return failure(Failure::new("LIMIT")),
        Err(_) => return failure(Failure::new("DEADLINE")),
    };
    if let Err(error) = reservation.shrink_body(bytes.len()) {
        return failure(error);
    }
    let call = match parse_before(&bytes, received + state.timeout) {
        Ok(call) => call,
        Err(error) => return failure(error),
    };
    if call.action.admission() != class {
        return failure(Failure::new("INVALID"));
    }
    let duration = if class == "recovery" {
        state.recovery_timeout
    } else {
        state.timeout
    };
    let deadline = received + duration;
    let receiver = match state
        .scheduler
        .submit_reserved(principal, call, deadline, reservation)
    {
        Ok(receiver) => receiver,
        Err(error) => return failure(error),
    };
    match tokio::time::timeout_at(deadline.into(), receiver).await {
        Ok(Ok(Ok(value))) => Json(wire::success(value)).into_response(),
        Ok(Ok(Err(error))) => failure(error),
        // A missing response never proves that publication rolled back.
        Ok(Err(_)) | Err(_) => failure(Failure::new("UNKNOWN")),
    }
}

fn parse_before(bytes: &[u8], deadline: Instant) -> Result<wire::Call, Failure> {
    let call = wire::parse(bytes)?;
    // Parsing is bounded by the body cap but is synchronous. Do not let an
    // expired short admission budget turn into a fresh recovery budget.
    if Instant::now() >= deadline {
        return Err(Failure::new("DEADLINE"));
    }
    Ok(call)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod catalogue_tests;

#[cfg(test)]
mod intake_tests;

mod discovery;
