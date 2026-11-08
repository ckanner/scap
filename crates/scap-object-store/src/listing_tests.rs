use super::*;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::listing_xml::tests::{context, object, prefix, xml};
use crate::tests::{config, deadline, reply, transport};
use crate::Objects;

#[test]
fn signed_pages_are_one_request_with_original_prefix_and_start_after() {
    let first = context(ListMode::Keys, None);
    let second = context(ListMode::Keys, Some("scope/b"));
    let children = context(ListMode::Children, Some("scope/c"));
    let replies = vec![
        reply(
            200,
            &xml(&(object("scope/a") + &object("scope/b")), 2, true, &first),
        ),
        reply(200, &xml(&object("scope/c"), 1, false, &second)),
        reply(
            200,
            &xml(
                &(object("scope/z") + &prefix("scope/d/")),
                2,
                false,
                &children,
            ),
        ),
        reply(200, &xml("", 0, false, &first)),
    ];
    let (endpoint, server, capture) = transport(replies);
    let mut settings = config(endpoint);
    settings.session_token = Some("unit-session".into());
    let s3 = S3::new(settings).unwrap();
    let request = ListRequest {
        prefix: "scope/",
        mode: ListMode::Keys,
        after: None,
    };
    let page = s3.list_page(&request, deadline()).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(
        page.end,
        ListEnd::More {
            after: "scope/b".into()
        }
    );
    let next = s3
        .clone()
        .list_page(
            &ListRequest {
                after: Some("scope/b"),
                ..request
            },
            deadline(),
        )
        .unwrap();
    assert_eq!(next.end, ListEnd::Exhausted);
    assert_eq!(next.entries[0].key, "scope/c");
    let children = s3
        .list_page(
            &ListRequest {
                after: Some("scope/c"),
                mode: ListMode::Children,
                ..request
            },
            deadline(),
        )
        .unwrap();
    assert_eq!(
        children.entries[0],
        ListEntry {
            key: "scope/d/".into(),
            kind: ListKind::Prefix
        }
    );
    assert_eq!(
        children.entries[1],
        ListEntry {
            key: "scope/z".into(),
            kind: ListKind::Object
        }
    );
    let empty = s3.list_page(&request, deadline()).unwrap();
    assert!(empty.entries.is_empty());
    assert_eq!(empty.end, ListEnd::Exhausted);
    server.join().unwrap();
    let requests = capture.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for request in &*requests {
        assert!(request.starts_with("get /scap-unit?"));
        assert!(request.contains("list-type=2"));
        assert!(request.contains("max-keys=32"));
        assert!(request.contains("prefix=scope%2f"));
        assert!(request.contains("authorization: aws4-hmac-sha256"));
        assert!(request.contains("x-amz-security-token: unit-session"));
        assert!(!request.contains("continuation-token="));
    }
    assert!(!requests[0].contains("start-after="));
    assert!(requests[1].contains("start-after=scope%2fb"));
    assert!(requests[2].contains("start-after=scope%2fc"));
    assert!(requests[2].contains("delimiter=%2f"));
}

#[test]
fn invalid_requests_and_runtime_contexts_fail_before_io() {
    let s3 = S3::new(config("http://127.0.0.1:1")).unwrap();
    for prefix in [
        "",
        "/",
        "/scope/",
        "scope",
        "scope//",
        "scope/../",
        "scope/\0/",
    ] {
        assert_eq!(
            s3.list_page(
                &ListRequest {
                    prefix,
                    mode: ListMode::Keys,
                    after: None
                },
                deadline()
            ),
            Err(ListError::Invalid),
            "{prefix:?}"
        );
    }
    let long = format!("{}/", "a".repeat(1024));
    assert_eq!(
        s3.list_page(
            &ListRequest {
                prefix: &long,
                mode: ListMode::Keys,
                after: None
            },
            deadline()
        ),
        Err(ListError::Invalid)
    );
    let request = ListRequest {
        prefix: "scope/",
        mode: ListMode::Keys,
        after: None,
    };
    for after in [
        "",
        "scope/",
        "scope//a",
        "scope/../a",
        "other/key",
        "/scope/a",
        "scope/a/",
        "scope/\0",
    ] {
        assert_eq!(
            s3.list_page(
                &ListRequest {
                    after: Some(after),
                    ..request
                },
                deadline()
            ),
            Err(ListError::Invalid),
            "{after:?}"
        );
    }
    assert_eq!(
        s3.list_page(
            &ListRequest {
                after: Some(&"a".repeat(1025)),
                ..request
            },
            deadline()
        ),
        Err(ListError::Invalid)
    );
    assert_eq!(
        s3.list_page(
            &ListRequest {
                after: Some(&format!("scope/{}", "a".repeat(1025))),
                ..request
            },
            deadline()
        ),
        Err(ListError::Invalid)
    );
    for after in ["scope/a/b", "scope/a/b/", "scope/a//"] {
        assert_eq!(
            s3.list_page(
                &ListRequest {
                    mode: ListMode::Children,
                    after: Some(after),
                    ..request
                },
                deadline()
            ),
            Err(ListError::Invalid)
        );
    }
    assert!(Context::new(
        "bucket",
        &ListRequest {
            mode: ListMode::Children,
            after: Some("scope/a/"),
            ..request
        }
    )
    .is_ok());
    assert!(Context::new(
        "bucket",
        &ListRequest {
            after: Some("scope/a/b"),
            ..request
        }
    )
    .is_ok());
    assert_eq!(
        s3.list_page(&request, Instant::now()),
        Err(ListError::Unknown)
    );
    assert_eq!(s3.list_page(&request, deadline()), Err(ListError::Unknown));
    let runtime = crate::runtime().unwrap();
    let guard = runtime.enter();
    assert_eq!(s3.list_page(&request, deadline()), Err(ListError::Invalid));
    drop(guard);
    let mut settings = config("http://127.0.0.1:1");
    settings.bucket = "directory--zone--x-s3".into();
    let directory_bucket = S3::new(settings).unwrap();
    assert_eq!(
        directory_bucket.list_page(&request, deadline()),
        Err(ListError::Invalid)
    );
    assert!(!canonical_key(""));
    assert!(!canonical_key(&"a".repeat(1025)));
    assert!(!canonical_key("a/"));
    assert!(canonical_key(&"a".repeat(1024)));
    assert!(canonical_prefix(&format!("{}/", "a".repeat(1023))));
}

#[test]
fn error_statuses_corrupt_xml_and_incomplete_bodies_never_mean_empty() {
    let context = context(ListMode::Keys, None);
    let valid = xml("", 0, false, &context);
    let statuses = [403, 404, 412, 429, 500, 301, 204, 206];
    let mut replies = statuses
        .iter()
        .map(|status| reply(*status, &valid))
        .collect::<Vec<_>>();
    replies.push(reply(200, b"<ListBucketResult/>"));
    replies.push(reply(200, &vec![b' '; MAX_LIST_RESPONSE_BYTES + 1]));
    let mut short = reply(200, &valid);
    short.declared_size += 1;
    replies.push(short);
    replies.push(reply(
        200,
        &xml(
            &object("scope/key").replace("2026-11-08T01:02:03.000Z", "invalid-date"),
            1,
            false,
            &context,
        ),
    ));
    let count = replies.len();
    let (endpoint, server, capture) = transport(replies);
    let s3 = S3::new(config(endpoint)).unwrap();
    let request = ListRequest {
        prefix: "scope/",
        mode: ListMode::Keys,
        after: None,
    };
    for status in statuses {
        let expected = if status == 403 {
            ListError::Denied
        } else {
            ListError::Unknown
        };
        assert_eq!(
            s3.list_page(&request, deadline()),
            Err(expected),
            "status {status}"
        );
    }
    for error in [
        ListError::Corrupt,
        ListError::Limit,
        ListError::Unknown,
        ListError::Unknown,
    ] {
        assert_eq!(s3.list_page(&request, deadline()), Err(error));
    }
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), count, "no hidden retries");
}

#[test]
fn absolute_deadline_applies_to_the_single_page_and_preserves_clone_isolation() {
    let context = context(ListMode::Keys, None);
    let mut delayed = reply(200, &xml("", 0, false, &context));
    delayed.delay = Duration::from_millis(100);
    let (endpoint, server, capture) = transport(vec![delayed]);
    let s3 = S3::new(config(endpoint)).unwrap();
    let request = ListRequest {
        prefix: "scope/",
        mode: ListMode::Keys,
        after: None,
    };
    let bound = Instant::now() + Duration::from_millis(20);
    assert_eq!(s3.list_page(&request, bound), Err(ListError::Unknown));
    server.join().unwrap();
    assert_eq!(capture.lock().unwrap().len(), 1);
    assert!(Arc::ptr_eq(&s3.store, &s3.clone().store));
    assert!(Arc::ptr_eq(&s3.runtime, &s3.clone().runtime));
}

fn parsed(proof: &Proof) -> PaginatedListResult {
    let objects = proof
        .objects
        .iter()
        .map(|key| object_store::ObjectMeta {
            location: Path::parse(key).unwrap(),
            last_modified: SystemTime::UNIX_EPOCH.into(),
            size: 4,
            e_tag: Some("metadata-is-not-authority".into()),
            version: None,
        })
        .collect();
    let common_prefixes = proof
        .prefixes
        .iter()
        .map(|key| Path::parse(key).unwrap())
        .collect();
    let mut result = PaginatedListResult {
        result: object_store::ListResult {
            objects,
            common_prefixes,
            extensions: Default::default(),
        },
        page_token: proof.token.clone(),
    };
    result.result.extensions.insert(proof.clone());
    result
}

#[test]
fn sdk_outputs_must_carry_the_same_verified_context_tokens_and_raw_names() {
    let context = context(ListMode::Children, None);
    let proof = crate::listing_xml::validate(
        &xml(
            &(object("scope/a") + &prefix("scope/b/")),
            2,
            true,
            &context,
        ),
        &context,
    )
    .unwrap();
    assert_eq!(
        validate_result(&context, parsed(&proof)),
        Ok(proof.page.clone())
    );
    for case in 0..7 {
        let mut result = parsed(&proof);
        match case {
            0 => {
                result.result.extensions.clear();
            }
            1 => {
                let mut wrong = proof.clone();
                wrong.context.prefix = "other/".into();
                result.result.extensions.insert(wrong);
            }
            2 => result.page_token = Some("other-token".into()),
            3 => {
                result.result.objects.clear();
            }
            4 => {
                result.result.common_prefixes.clear();
            }
            5 => result.result.objects[0].location = Path::parse("scope/other").unwrap(),
            _ => result.result.common_prefixes[0] = Path::parse("scope/other").unwrap(),
        }
        assert_eq!(
            validate_result(&context, result),
            Err(ListError::Corrupt),
            "case {case}"
        );
    }
    for error in [
        ListError::Invalid,
        ListError::Limit,
        ListError::Corrupt,
        ListError::Denied,
        ListError::Unknown,
    ] {
        assert_eq!(error.to_string(), format!("{error:?}"));
        assert_eq!(
            list_error(object_store::Error::Generic {
                store: "test",
                source: Box::new(error)
            }),
            error
        );
    }
    assert_eq!(
        list_error(object_store::Error::Generic {
            store: "test",
            source: "unrecognized SDK error".into()
        }),
        ListError::Unknown
    );
}

#[test]
fn redirect_locations_never_trigger_second_get_put_or_list_requests() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    for (operation, status) in [("get", 302), ("put", 308), ("list", 307)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let destination = format!("http://{}/redirected", listener.local_addr().unwrap());
        let destination_thread = thread::spawn(move || {
            let bound = Instant::now() + Duration::from_millis(150);
            while Instant::now() < bound {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap();
                        let mut bytes = [0; 8192];
                        let count = socket.read(&mut bytes).unwrap_or(0);
                        let _ = socket.write_all(b"HTTP/1.1 500 Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        return count > 0;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            false
        });
        let mut redirect = reply(status, b"");
        redirect.location = Some(destination);
        let (endpoint, server, capture) = transport(vec![redirect]);
        let s3 = S3::new(config(endpoint)).unwrap();
        match operation {
            "get" => assert_eq!(
                s3.get("scope/key", 1024, deadline()),
                Err(crate::StoreError::Unknown)
            ),
            "put" => assert_eq!(
                s3.put("scope/key", b"body", crate::Condition::Absent, deadline()),
                Err(crate::StoreError::Unknown)
            ),
            _ => assert_eq!(
                s3.list_page(
                    &ListRequest {
                        prefix: "scope/",
                        mode: ListMode::Keys,
                        after: None
                    },
                    deadline()
                ),
                Err(ListError::Unknown)
            ),
        }
        server.join().unwrap();
        assert_eq!(capture.lock().unwrap().len(), 1);
        assert!(
            !destination_thread.join().unwrap(),
            "{operation} followed a redirect"
        );
    }
}
