use super::*;
use std::error::Error;
use std::sync::Mutex;

use object_store::client::HttpRequestBody;

use crate::listing::{ListMode, Proof};
use crate::listing_xml::tests::{context, xml};

#[derive(Debug)]
struct Once(Mutex<Option<Result<HttpResponse, HttpError>>>);

#[async_trait::async_trait]
impl HttpService for Once {
    async fn call(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.0.lock().unwrap().take().unwrap()
    }
}

fn response(status: u16, bytes: Vec<u8>) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .body(bytes.into())
        .unwrap()
}

fn request(list: bool) -> HttpRequest {
    let mut request = HttpRequest::new(HttpRequestBody::empty());
    if list {
        request
            .extensions_mut()
            .insert(context(ListMode::Keys, None));
    }
    request
}

fn service(result: Result<HttpResponse, HttpError>) -> Service {
    Service(HttpClient::new(Once(Mutex::new(Some(result)))))
}

#[test]
fn guard_bounds_success_streams_and_preserves_unrelated_exact_requests() {
    let runtime = crate::runtime().unwrap();
    let large = vec![b' '; MAX_LIST_RESPONSE_BYTES + 1];
    let value = runtime
        .block_on(service(Ok(response(200, large.clone()))).call(request(false)))
        .unwrap();
    assert_eq!(
        runtime.block_on(value.into_body().bytes()).unwrap().len(),
        large.len()
    );
    let error = runtime
        .block_on(service(Ok(response(200, large))).call(request(true)))
        .unwrap_err();
    assert_eq!(
        error.source().unwrap().downcast_ref::<ListError>(),
        Some(&ListError::Limit)
    );
    let context = context(ListMode::Keys, None);
    let bytes = xml("", 0, false, &context);
    let value = runtime
        .block_on(service(Ok(response(200, bytes.clone()))).call(request(true)))
        .unwrap();
    assert_eq!(value.extensions().get::<Proof>().unwrap().context, context);
    assert_eq!(runtime.block_on(value.into_body().bytes()).unwrap(), bytes);
    let value = runtime
        .block_on(service(Ok(response(200, b"invalid".to_vec()))).call(request(true)))
        .unwrap_err();
    assert_eq!(
        value.source().unwrap().downcast_ref::<ListError>(),
        Some(&ListError::Corrupt)
    );
}

#[test]
fn errors_do_not_collect_error_bodies_or_become_pages() {
    let runtime = crate::runtime().unwrap();
    for status in [403, 404, 500, 204] {
        let value = runtime
            .block_on(
                service(Ok(response(status, vec![0; MAX_LIST_RESPONSE_BYTES + 1])))
                    .call(request(true)),
            )
            .unwrap_err();
        let expected = if status == 403 {
            ListError::Denied
        } else {
            ListError::Unknown
        };
        assert_eq!(
            value.source().unwrap().downcast_ref::<ListError>(),
            Some(&expected)
        );
        assert_eq!(value.kind(), HttpErrorKind::Decode);
    }
    let error = HttpError::new(
        HttpErrorKind::Connect,
        std::io::Error::other("transport unavailable"),
    );
    let value = runtime
        .block_on(service(Err(error)).call(request(true)))
        .unwrap_err();
    assert_eq!(value.kind(), HttpErrorKind::Connect);
}

#[test]
fn non_listing_error_body_bound_preserves_complete_statuses_and_unknown_writes() {
    use crate::tests::{config, deadline, reply, transport};
    use crate::{Condition, Objects, StoreError, S3};

    let maximum = vec![b'e'; MAX_ERROR_RESPONSE_BYTES];
    let excess = vec![b'e'; MAX_ERROR_RESPONSE_BYTES + 1];
    let mut short = reply(404, b"partial error");
    short.declared_size += 20;
    let (endpoint, server, requests) = transport(vec![
        reply(404, &maximum),
        reply(404, &excess),
        reply(412, &maximum),
        reply(412, &excess),
        reply(500, &excess),
        short,
    ]);
    let s3 = S3::new(config(endpoint)).unwrap();
    assert_eq!(s3.get("missing", 1, deadline()), Err(StoreError::Missing));
    assert_eq!(s3.get("too-large", 1, deadline()), Err(StoreError::Unknown));
    assert_eq!(
        s3.put("conflict", b"x", Condition::Absent, deadline()),
        Err(StoreError::Conflict)
    );
    for key in ["unproven-conflict", "possibly-accepted"] {
        assert_eq!(
            s3.put(key, b"x", Condition::Absent, deadline()),
            Err(StoreError::Unknown)
        );
    }
    assert_eq!(
        s3.get("short-error", 1, deadline()),
        Err(StoreError::Unknown)
    );
    server.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 6);
}

#[test]
fn error_collector_keeps_empty_bodies_and_rejects_overflow_as_transport_decode() {
    let runtime = crate::runtime().unwrap();
    let empty = runtime
        .block_on(service(Ok(response(404, vec![]))).call(request(false)))
        .unwrap();
    assert_eq!(empty.status(), 404);
    assert!(runtime
        .block_on(empty.into_body().bytes())
        .unwrap()
        .is_empty());
    let error = runtime
        .block_on(
            service(Ok(response(500, vec![0; MAX_ERROR_RESPONSE_BYTES + 1]))).call(request(false)),
        )
        .unwrap_err();
    assert_eq!(error.kind(), HttpErrorKind::Decode);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .to_string(),
        "S3 error response exceeds 64 KiB"
    );
}

#[derive(Debug)]
struct BrokenConnector;

impl HttpConnector for BrokenConnector {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        Err(object_store::Error::Generic {
            store: "fixture",
            source: "connector unavailable".into(),
        })
    }
}

#[test]
fn connector_uses_the_sdk_client_and_propagates_construction_failure() {
    assert!(Connector(Direct {
        timeout: Duration::from_secs(1),
        allow_http: true,
    })
    .connect(&ClientOptions::new())
    .is_ok());
    assert!(Connector(BrokenConnector)
        .connect(&ClientOptions::new())
        .is_err());
    let direct = Direct {
        timeout: Duration::from_secs(1),
        allow_http: false,
    };
    assert!(direct
        .build(|builder| builder.user_agent("\0").build())
        .is_err());
}
