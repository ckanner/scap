use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use crate::{
    invalid, parse_request_id, protocol, validate_database, Backend, Call, CancelGuard, Mode,
    OutcomeCall, RequestContext, Service, ServiceError,
};

pub fn router<B: Backend>(service: Arc<Service<B>>) -> Router {
    Router::new()
        .route("/v2/pipeline", post(default_pipeline::<B>))
        .route("/db/{database}/v2/pipeline", post(pipeline::<B>))
        .route(
            "/db/{database}/v1/requests/{request_id}",
            post(outcome::<B>),
        )
        .route("/db/{database}/v1/status", get(status::<B>))
        .with_state(service)
}

async fn default_pipeline<B: Backend>(
    State(service): State<Arc<Service<B>>>,
    request: Request<Body>,
) -> Response {
    service
        .handle(service.default_database.clone(), Route::Pipeline, request)
        .await
}

async fn pipeline<B: Backend>(
    State(service): State<Arc<Service<B>>>,
    Path(database): Path<String>,
    request: Request<Body>,
) -> Response {
    service.handle(database, Route::Pipeline, request).await
}

async fn outcome<B: Backend>(
    State(service): State<Arc<Service<B>>>,
    Path((database, request_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    service
        .handle(database, Route::Outcome(request_id), request)
        .await
}

async fn status<B: Backend>(
    State(service): State<Arc<Service<B>>>,
    Path(database): Path<String>,
    request: Request<Body>,
) -> Response {
    service.handle(database, Route::Status, request).await
}

enum Route {
    Pipeline,
    Outcome(String),
    Status,
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ServiceError> {
    if headers.get_all(name).iter().count() > 1 {
        return Err(invalid("duplicate request header"));
    }
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| invalid("invalid request header"))
        })
        .transpose()
}

impl<B: Backend> Service<B> {
    fn context(
        &self,
        database: String,
        outcome_id: Option<&str>,
        headers: &HeaderMap,
        requires_json: bool,
    ) -> Result<(RequestContext, Mode), ServiceError> {
        validate_database(&database)?;
        let credential = header_value(headers, "authorization")?
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| ServiceError::new("UNAUTHORIZED", "Bearer credential required"))?;
        if credential.is_empty() || credential.len() > self.limits.max_token_bytes {
            return Err(ServiceError::new(
                "UNAUTHORIZED",
                "invalid credential length",
            ));
        }
        let content_type = header_value(headers, "content-type")?.unwrap_or("");
        if requires_json && content_type != "application/json" {
            return Err(invalid("application/json required"));
        }
        let id_header = header_value(headers, "x-scap-request-id")?;
        let request_id = match (outcome_id, id_header) {
            (Some(path), Some(header)) if path != header => {
                return Err(invalid("conflicting request IDs"))
            }
            (Some(value), _) | (_, Some(value)) => parse_request_id(value)?,
            _ => self.generate_request_id()?,
        };
        let mode = match header_value(headers, "x-scap-mode")? {
            None | Some("write") => Mode::Write,
            Some("read") => Mode::Read,
            _ => return Err(invalid("invalid operation mode")),
        };
        let remaining = match header_value(headers, "x-scap-deadline-unix-ms")? {
            Some(value) => {
                let deadline: u64 = value.parse().map_err(|_| invalid("invalid deadline"))?;
                let remaining = deadline
                    .checked_sub(self.environment.unix_millis()?)
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        ServiceError::new("EXPIRED", "request deadline elapsed before admission")
                    })?;
                Duration::from_millis(remaining).min(self.limits.max_timeout)
            }
            None => self.limits.max_timeout,
        };
        let deadline = self.environment.now() + remaining;
        Ok((
            RequestContext {
                database,
                credential: credential.to_owned(),
                request_id,
                deadline,
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            mode,
        ))
    }

    async fn handle(&self, database: String, route: Route, request: Request<Body>) -> Response {
        let (parts, body) = request.into_parts();
        let outcome_id = match &route {
            Route::Outcome(id) => Some(id.as_str()),
            _ => None,
        };
        let (context, mode) = match self.context(
            database,
            outcome_id,
            &parts.headers,
            !matches!(route, Route::Status),
        ) {
            Ok(context) => context,
            Err(error) => return error_response(error, None),
        };
        let id = context.request_id;
        let _cancel = CancelGuard(context.cancelled.clone());
        let _permit = match self.permits.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                return error_response(
                    ServiceError::new("OVERLOADED", "HTTP admission capacity exhausted"),
                    Some(id),
                )
            }
        };
        let deadline = context.deadline;
        let operation = async {
            let bytes = to_bytes(body, self.limits.max_body_bytes)
                .await
                .map_err(|_| invalid("invalid or oversized body"))?;
            if matches!(route, Route::Status) {
                if !bytes.is_empty() {
                    return Err(invalid("status request must not contain a body"));
                }
                let status = self.backend.status(context).await?;
                return Ok(json!({
                    "revision": status.revision.to_string(),
                    "base_revision": status.base_revision.to_string(),
                    "tail_entries": status.tail_entries.to_string(),
                    "tail_bytes": status.tail_bytes.to_string(),
                    "suspended": status.suspended,
                    "cold": status.cold,
                    "owner_active": status.owner_active,
                    "archived_revision": status.archived_revision.map(|revision| revision.to_string()),
                }));
            }
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| invalid("invalid JSON body"))?;
            if matches!(route, Route::Outcome(_)) {
                let (statements, resolve_or_cancel) =
                    protocol::outcome_request(&value, self.limits)?;
                let result = self
                    .backend
                    .outcome(OutcomeCall {
                        context,
                        statements,
                        resolve_or_cancel,
                    })
                    .await?;
                protocol::outcome_result(result, self.limits)
            } else {
                let mut plan = protocol::pipeline(&value, self.limits, mode)?;
                let statements = std::mem::take(&mut plan.statements);
                let result = self
                    .backend
                    .execute(Call {
                        context,
                        statements,
                        mode: plan.mode,
                    })
                    .await;
                Ok(plan.finish(result, self.limits))
            }
        };
        let result = tokio::time::timeout_at(deadline.into(), operation).await;
        match result {
            Ok(result) if self.environment.now() < deadline => match result {
                Ok(value) => bounded_response(value, id, self.limits.max_response_bytes),
                Err(error) => error_response(error, Some(id)),
            },
            _ => error_response(
                ServiceError::new(
                    "COMMIT_UNKNOWN",
                    "request deadline elapsed; resolve its stable request ID",
                ),
                Some(id),
            ),
        }
    }
}

fn response(value: Value, status: StatusCode, id: Option<u128>) -> Response {
    let mut response = Response::new(Body::from(serde_json::to_vec(&value).unwrap()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(id) = id {
        response.headers_mut().insert(
            "x-scap-request-id",
            HeaderValue::from_str(&format!("{id:032x}")).unwrap(),
        );
    }
    response
}

fn bounded_response(value: Value, id: u128, maximum: usize) -> Response {
    if serde_json::to_vec(&value).unwrap().len() > maximum {
        return error_response(
            ServiceError::new(
                "COMMITTED_RESULT_UNAVAILABLE",
                "response exceeds HTTP limit; query the request outcome",
            ),
            Some(id),
        );
    }
    response(value, StatusCode::OK, Some(id))
}

fn error_response(error: ServiceError, id: Option<u128>) -> Response {
    let status = match error.code.as_str() {
        "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
        "INVALID_REQUEST" | "UNSUPPORTED_FEATURE" => StatusCode::BAD_REQUEST,
        "EXPIRED" => StatusCode::REQUEST_TIMEOUT,
        "COMMIT_UNKNOWN" => StatusCode::GATEWAY_TIMEOUT,
        "NOT_LEADER" | "OVERLOADED" | "COMMITTED_RESULT_UNAVAILABLE" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    response(
        json!({"code":error.code,"message":error.message,"request_id":id.map(|value|format!("{value:032x}"))}),
        status,
        id,
    )
}

#[cfg(test)]
mod tests;
