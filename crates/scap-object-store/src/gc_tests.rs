use super::*;
use crate::tests::{config, deadline, reply, transport};
use std::time::Duration;

const PREFIX: &str = "scap-object/v1/1/2/3/inc/4/gen/5/storage/6/objects/";
const HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const EMPTY: &[u8] =
    b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
const NO_LOCK: &[u8] =
    b"<Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>none</Message></Error>";

fn ready_replies() -> Vec<crate::tests::Reply> {
    vec![reply(200, EMPTY), reply(404, NO_LOCK)]
}

#[test]
fn signed_gc_capability_and_conditional_delete_use_exact_single_requests() {
    let mut replies = ready_replies();
    replies.extend([
        reply(204, b""),
        reply(412, b"<Error><Code>PreconditionFailed</Code></Error>"),
        reply(404, b"<Error><Code>NoSuchKey</Code></Error>"),
    ]);
    let (endpoint, server, capture) = transport(replies);
    let mut settings = config(endpoint);
    settings.session_token = Some("gc-session".into());
    let store = GcS3::new(settings, 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    assert_eq!(
        batch.delete(HASH, "\"original\""),
        Ok(DeleteOutcome::Applied)
    );
    assert_eq!(
        batch.delete(HASH, "\"original\""),
        Ok(DeleteOutcome::Conflict)
    );
    assert_eq!(
        batch.delete(HASH, "\"original\""),
        Ok(DeleteOutcome::Missing)
    );
    server.join().unwrap();
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].starts_with("get /scap-unit?versioning "));
    assert!(requests[1].starts_with("get /scap-unit?object-lock "));
    for request in requests.iter() {
        assert!(request.contains("authorization: aws4-hmac-sha256"));
        assert!(request.contains("x-amz-security-token: gc-session"));
        assert!(!request.contains("versionid="));
        assert!(!request.contains("bypass-governance"));
    }
    for request in &requests[2..] {
        assert!(request.starts_with(&format!("delete /scap-unit/{PREFIX}{HASH} ")));
        assert!(request.contains("if-match: \"original\""));
        assert!(request.contains("signedheaders=host;if-match;"));
    }
}

#[test]
fn preflight_denials_never_issue_a_delete_or_alias_a_missing_bucket() {
    let cases: Vec<(Vec<crate::tests::Reply>,GcError)>=vec![
        (vec![reply(403,b"denied")],GcError::Denied),
        (vec![reply(404,b"<Error><Code>NoSuchBucket</Code></Error>")],GcError::Unknown),
        (vec![reply(200,b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>")],GcError::Unsupported),
        (vec![reply(200,b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Suspended</Status></VersioningConfiguration>")],GcError::Unsupported),
        (vec![reply(200,b"invalid")],GcError::Corrupt),
        (vec![reply(200,EMPTY),reply(200,b"<ObjectLockConfiguration/>")],GcError::Unsupported),
        (vec![reply(200,EMPTY),reply(404,b"<Error><Code>NoSuchBucket</Code></Error>")],GcError::Unsupported),
        (vec![reply(200,EMPTY),reply(404,b"invalid")],GcError::Corrupt),
        (vec![reply(200,EMPTY),reply(403,b"denied")],GcError::Denied),
        (vec![reply(200,EMPTY),reply(500,b"error")],GcError::Unknown),
    ];
    for (replies, expected) in cases {
        let count = replies.len();
        let (endpoint, server, capture) = transport(replies);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        assert!(matches!(store.begin_batch(PREFIX,deadline()),Err(error) if error==expected));
        server.join().unwrap();
        let requests = capture.lock().unwrap();
        assert_eq!(requests.len(), count);
        assert!(requests.iter().all(|request| request.starts_with("get ")));
    }
}

#[test]
fn batch_bounds_errors_and_original_deadline_do_not_retry_deletes() {
    let mut replies = ready_replies();
    replies.extend((0..MAX_DELETE_BATCH).map(|_| reply(204, b"")));
    let (endpoint, server, capture) = transport(replies);
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    for _ in 0..MAX_DELETE_BATCH {
        assert_eq!(batch.delete(HASH, "\"x\""), Ok(DeleteOutcome::Applied));
    }
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Limit));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 34);
    for (status, body, expected) in [
        (409, b"conflict".as_slice(), GcError::Unknown),
        (500, b"error", GcError::Unknown),
        (200, b"", GcError::Unknown),
        (
            404,
            b"<Error><Code>NoSuchBucket</Code></Error>",
            GcError::Unknown,
        ),
        (403, b"denied", GcError::Denied),
    ] {
        let mut replies = ready_replies();
        replies.push(reply(status, body));
        let (endpoint, server, capture) = transport(replies);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
        assert_eq!(batch.delete(HASH, "\"x\""), Err(expected));
        assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Limit));
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 3);
    }
    let (endpoint, server, capture) = transport(ready_replies());
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    batch.deadline = Instant::now();
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Unknown));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 2);
}

#[test]
fn configuration_and_fixed_prefix_validation_precede_any_io() {
    for case in 0..9 {
        let mut settings = config("http://127.0.0.1:1");
        match case {
            0 => settings.bucket = "UPPER".into(),
            1 => settings.bucket = "aa".into(),
            2 => settings.bucket = "a".repeat(64),
            3 => settings.bucket = "bucket--zone--x-s3".into(),
            4 => settings.access_key = "a\nb".into(),
            5 => settings.region = "a\nb".into(),
            6 => settings.session_token = Some("a\nb".into()),
            7 => settings.endpoint = "bad".into(),
            _ => settings.endpoint = "http://host/path".into(),
        }
        assert!(
            matches!(GcS3::new(settings, 1), Err(GcError::Invalid)),
            "case {case}"
        );
    }
    assert!(matches!(
        GcS3::new(config("http://127.0.0.1:1"), 0),
        Err(GcError::Invalid)
    ));
    assert!(matches!(
        GcS3::build(config("http://127.0.0.1:1"), 1, |_| Err(GcError::Invalid)),
        Err(GcError::Invalid)
    ));
    let store = GcS3::new(config("http://127.0.0.1:1"), 1).unwrap();
    let mut bad = vec![
        String::new(),
        "a".repeat(961),
        PREFIX.trim_end_matches('/').into(),
        PREFIX.replace("scap-object", "other"),
        PREFIX.replace("v1", "v2"),
        PREFIX.replace("inc/", "other/"),
        PREFIX.replace("gen/", "other/"),
        PREFIX.replace("storage/", "other/"),
        PREFIX.replace("objects/", "head/"),
        format!("{PREFIX}x"),
    ];
    for value in ["0", "01", "+1", "-1", "one", "18446744073709551616", "2"] {
        bad.push(PREFIX.replacen("v1/1/", &format!("v1/{value}/"), 1));
    }
    for value in bad {
        assert!(
            matches!(store.begin_batch(&value, deadline()), Err(GcError::Invalid)),
            "{value}"
        );
    }
    assert!(valid_prefix(PREFIX, 1));
    assert!(valid_prefix(
        "scap-object/v1/18446744073709551615/2/3/inc/4/gen/5/storage/6/objects/",
        u64::MAX
    ));
    assert!(matches!(
        store.begin_batch(PREFIX, Instant::now()),
        Err(GcError::Unknown)
    ));
    assert!(matches!(
        store.begin_batch(PREFIX, deadline()),
        Err(GcError::Unknown)
    ));
    let runtime = crate::runtime().unwrap();
    let guard = runtime.enter();
    assert!(matches!(
        store.begin_batch(PREFIX, deadline()),
        Err(GcError::Invalid)
    ));
    drop(guard);
}

#[test]
fn invalid_hashes_and_etags_cannot_escape_the_payload_namespace() {
    let (endpoint, server, capture) = transport(ready_replies());
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store.begin_batch(PREFIX, deadline()).unwrap();
    for hash in [
        "".into(),
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        format!("/{}", "a".repeat(63)),
        format!("../{}", "a".repeat(61)),
    ] {
        assert_eq!(batch.delete(&hash, "\"x\""), Err(GcError::Invalid));
    }
    for etag in ["*", "x", "W/\"x\"", "\"a\nb\"", "\"a\"b\""] {
        assert_eq!(batch.delete(HASH, etag), Err(GcError::Invalid));
    }
    let runtime = crate::runtime().unwrap();
    let guard = runtime.enter();
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Invalid));
    drop(guard);
    assert_eq!(batch.remaining, MAX_DELETE_BATCH);
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 2);
}

#[test]
fn truncated_large_redirected_and_late_responses_stay_unknown() {
    let mut short = reply(200, EMPTY);
    short.declared_size += 1;
    let mut redirect = reply(301, b"");
    redirect.location = Some("http://127.0.0.1:1/".into());
    for response in [
        short,
        redirect,
        reply(200, &vec![b' '; MAX_GC_RESPONSE_BYTES + 1]),
    ] {
        let (endpoint, server, capture) = transport(vec![response]);
        let store = GcS3::new(config(endpoint), 1).unwrap();
        assert!(matches!(
            store.begin_batch(PREFIX, deadline()),
            Err(GcError::Unknown)
        ));
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 1);
    }
    let mut replies = ready_replies();
    let mut late = reply(204, b"");
    late.delay = Duration::from_millis(80);
    replies.push(late);
    let (endpoint, server, capture) = transport(replies);
    let store = GcS3::new(config(endpoint), 1).unwrap();
    let mut batch = store
        .begin_batch(PREFIX, Instant::now() + Duration::from_millis(40))
        .unwrap();
    assert_eq!(batch.delete(HASH, "\"x\""), Err(GcError::Unknown));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 3);
}

#[test]
fn unexpected_version_metadata_and_malformed_delete_results_are_uncertain() {
    for name in ["x-amz-version-id", "x-amz-delete-marker"] {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static("null"));
        assert_eq!(
            deletion(Response {
                status: 204,
                headers,
                bytes: vec![]
            }),
            Err(GcError::Unknown)
        );
    }
    for (status, body) in [(204, b"body".as_slice()), (404, b"invalid")] {
        assert_eq!(
            deletion(Response {
                status,
                headers: HeaderMap::new(),
                bytes: body.to_vec()
            }),
            Err(GcError::Unknown)
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
    assert_eq!(
        deletion(Response {
            status: 204,
            headers,
            bytes: vec![]
        }),
        Err(GcError::Unknown)
    );
    assert_eq!(
        deletion(Response {
            status: 204,
            headers: HeaderMap::new(),
            bytes: vec![]
        }),
        Ok(DeleteOutcome::Applied)
    );
}
