//! Every discovery page reauthenticates and uses its original short deadline.

use super::*;
use crate::{discovery as scan, discovery_wire};

pub(super) async fn call(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let received = Instant::now();
    let principal = match state
        .auth
        .authenticate(single(request.headers(), "authorization"))
    {
        Ok(principal) => principal,
        Err(error) => return failure(error),
    };
    if single(request.headers(), "x-scap-admission") != Some("discovery") {
        return failure(Failure::new("INVALID"));
    }
    let discovery = match &state.discovery {
        Some(discovery) => discovery.clone(),
        None => return failure(Failure::new("UNAVAILABLE")),
    };
    let reservation = match discovery.admission.acquire(&principal) {
        Ok(reservation) => reservation,
        Err(error) => return failure(error),
    };
    let response = admitted(
        discovery,
        principal,
        reservation.clone(),
        received + scan::TIMEOUT,
        request,
    )
    .await;
    reserved(response, reservation)
}

async fn admitted(
    discovery: Arc<scan::Discovery>,
    principal: Principal,
    reservation: Arc<scan::Reservation>,
    deadline: Instant,
    request: Request,
) -> Response {
    if single(request.headers(), "content-type") != Some("application/json") {
        return failure(Failure::new("INVALID"));
    }
    let bytes = match tokio::time::timeout_at(
        deadline.into(),
        to_bytes(request.into_body(), scan::MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return failure(Failure::new("LIMIT")),
        Err(_) => return failure(Failure::new("DEADLINE")),
    };
    let call = match discovery_wire::parse(&bytes) {
        Ok(call) => call,
        Err(error) => return failure(error),
    };
    let operation = match discovery.submit(principal, call, reservation, deadline) {
        Ok(operation) => operation,
        Err(error) => return failure(error),
    };
    match tokio::time::timeout_at(deadline.into(), operation).await {
        Ok(Ok(Ok(bytes))) => ([("content-type", "application/json")], bytes).into_response(),
        Ok(Ok(Err(error))) => failure(error),
        Ok(Err(_)) => failure(Failure::new("UNAVAILABLE")),
        Err(_) => failure(Failure::new("DEADLINE")),
    }
}

#[cfg(test)]
mod tests;
