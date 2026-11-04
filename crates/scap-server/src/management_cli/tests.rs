use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use serde_json::json;

const TOKEN: &str = "unit-management-cli-token";

fn config() -> ManagementConfig {
    ManagementConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        token_digest: [7; 32],
    }
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn body() -> Vec<u8> {
    json!({"action":"add_learner","node_id":4,"expected_conf_state":{
        "voters":[1,2,3],"learners":[],"voters_outgoing":[],"learners_next":[],"auto_leave":false,
    }})
    .to_string()
    .into_bytes()
}

fn server(response: Vec<u8>) -> (ManagementConfig, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = config();
    config.listen = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(header_end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|size| size.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if bytes.len() >= header_end + 4 + length {
                    break;
                }
            }
        }
        let _ = stream.write_all(&response);
        String::from_utf8(bytes).unwrap()
    });
    (config, task)
}

fn response(status: u16, bytes: &[u8]) -> Vec<u8> {
    [
        format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .into_bytes(),
        bytes.to_vec(),
    ]
    .concat()
}

#[test]
fn management_command_reads_only_explicit_config_and_optional_bounded_request() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.json");
    let request_path = temp.path().join("change.json");
    let mut value = crate::tests::config_json();
    std::fs::write(&path, value.to_string()).unwrap();
    assert_eq!(
        read_command(&[path.clone().into_os_string()])
            .unwrap_err()
            .code,
        "MANAGEMENT_DISABLED"
    );
    value["management"] = json!({"listen":"127.0.0.1:0","token_sha256":"07".repeat(32)});
    std::fs::write(&path, value.to_string()).unwrap();
    std::fs::write(&request_path, body()).unwrap();
    let (_, read) = read_command(&[path.clone().into_os_string()]).unwrap();
    assert!(read.is_none());
    let (_, read) = read_command(&[
        path.clone().into_os_string(),
        request_path.clone().into_os_string(),
    ])
    .unwrap();
    assert_eq!(read.unwrap(), body());
    assert!(command(&[path.clone().into_os_string()]).is_err());
    assert!(command(&[]).is_err());
    assert!(crate::command(vec!["--membership".into(), path.clone().into_os_string()]).is_err());
    assert!(read_command(&[]).is_err());
    assert!(read_command(&["a".into(), "b".into(), "c".into()]).is_err());
    assert!(read_command(&["/absent/config.json".into()]).is_err());
    assert!(read_command(&[path.clone().into_os_string(), "/absent/request.json".into()]).is_err());
    std::fs::write(&request_path, vec![0; management::MAX_BODY + 1]).unwrap();
    assert_eq!(
        read_command(&[path.clone().into_os_string(), request_path.into_os_string()])
            .unwrap_err()
            .code,
        "CONFIG_LIMIT"
    );
    std::fs::write(&path, b"{}").unwrap();
    assert!(read_command(&[path.into_os_string()]).is_err());
}

#[test]
fn cli_credentials_parse_runtime_and_output_failures_are_not_silent() {
    for token in [None, Some(String::new()), Some("x".repeat(4097))] {
        assert_eq!(
            execute(config(), None, token, runtime(), &mut Vec::new())
                .unwrap_err()
                .code,
            "MANAGEMENT_TOKEN"
        );
    }
    assert_eq!(
        execute(
            config(),
            Some(b"{".to_vec()),
            Some(TOKEN.into()),
            runtime(),
            &mut Vec::new()
        )
        .unwrap_err()
        .code,
        "MEMBERSHIP_INVALID"
    );
    assert_eq!(
        execute(
            config(),
            None,
            Some(TOKEN.into()),
            Err(std::io::Error::other("injected runtime failure")),
            &mut Vec::new()
        )
        .unwrap_err()
        .code,
        "EXECUTOR"
    );
    struct CannotWrite;
    impl Write for CannotWrite {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed output"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (config, owner) = server(response(200, b"{}"));
    assert_eq!(
        execute(
            config,
            None,
            Some(TOKEN.into()),
            runtime(),
            &mut CannotWrite
        )
        .unwrap_err()
        .code,
        "MANAGEMENT_OUTPUT"
    );
    owner.join().unwrap();
}

#[test]
fn cli_get_and_post_print_exact_results_once_and_never_retry_unknown() {
    for mutation in [false, true] {
        let (config, owner) = server(response(
            200,
            b"{\"outcome\":\"applied\",\"membership\":{\"applied\":7}}",
        ));
        let mut output = Vec::new();
        execute(
            config,
            mutation.then(body),
            Some(TOKEN.into()),
            runtime(),
            &mut output,
        )
        .unwrap();
        let request = owner.join().unwrap();
        assert!(request.starts_with(if mutation { "POST " } else { "GET " }));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}")));
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap()["membership"]["applied"],
            7
        );
        if mutation {
            assert!(request.contains("add_learner"));
        }
    }
    for (status, body, code) in [
        (
            409,
            b"{\"code\":\"MEMBERSHIP_CONFLICT\"}".as_slice(),
            "MEMBERSHIP_CONFLICT",
        ),
        (
            503,
            b"{\"code\":\"MEMBERSHIP_UNKNOWN\"}".as_slice(),
            "MEMBERSHIP_UNKNOWN",
        ),
        (302, b"{}".as_slice(), "MANAGEMENT_HTTP"),
    ] {
        let (config, owner) = server(response(status, body));
        let mut output = Vec::new();
        assert_eq!(
            execute(
                config,
                Some(self::body()),
                Some(TOKEN.into()),
                runtime(),
                &mut output
            )
            .unwrap_err()
            .code,
            code
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            serde_json::from_slice::<Value>(body).unwrap()
        );
        owner.join().unwrap();
    }
    for (mutation, value, code) in [
        (
            true,
            json!({"outcome":"admitted","membership":{}}),
            "MEMBERSHIP_UNKNOWN",
        ),
        (true, json!({"membership":{}}), "MEMBERSHIP_UNKNOWN"),
        (false, json!({}), "MANAGEMENT_RESPONSE"),
        (
            true,
            json!({"outcome":"applied","membership":null}),
            "MANAGEMENT_RESPONSE",
        ),
    ] {
        let (config, owner) = server(response(200, value.to_string().as_bytes()));
        assert_eq!(
            execute(
                config,
                mutation.then(self::body),
                Some(TOKEN.into()),
                runtime(),
                &mut Vec::new()
            )
            .unwrap_err()
            .code,
            code
        );
        owner.join().unwrap();
    }
}

#[test]
fn local_client_fails_closed_on_invalid_http_partial_body_and_bounded_response() {
    let failed_client = client(|builder| builder.user_agent("\n").build());
    assert_eq!(failed_client.as_ref().unwrap_err().code, "MANAGEMENT_HTTP");
    assert_eq!(
        runtime()
            .unwrap()
            .block_on(request_with(
                failed_client,
                config().listen,
                None,
                TOKEN.into(),
                Instant::now() + Duration::from_secs(1)
            ))
            .unwrap_err()
            .code,
        "MANAGEMENT_HTTP"
    );
    let large = vec![b'x'; management::MAX_RESPONSE + 1];
    let chunked = [
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            large.len()
        )
        .into_bytes(),
        large.clone(),
        b"\r\n0\r\n\r\n".to_vec(),
    ]
    .concat();
    for (raw, code) in [
        (response(200, &large), "MANAGEMENT_RESPONSE_LIMIT"),
        (chunked, "MANAGEMENT_RESPONSE_LIMIT"),
        (response(200, b"not-json"), "MANAGEMENT_RESPONSE"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
            "MEMBERSHIP_UNKNOWN",
        ),
    ] {
        let (config, owner) = server(raw);
        assert_eq!(
            execute(config, None, Some(TOKEN.into()), runtime(), &mut Vec::new())
                .unwrap_err()
                .code,
            code
        );
        owner.join().unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut absent = config();
    absent.listen = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(
        execute(absent, None, Some(TOKEN.into()), runtime(), &mut Vec::new())
            .unwrap_err()
            .code,
        "MEMBERSHIP_UNKNOWN"
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut waiting = config();
    waiting.listen = listener.local_addr().unwrap();
    let executor = runtime().unwrap();
    assert_eq!(
        executor
            .block_on(request(waiting.listen, None, TOKEN.into(), Instant::now()))
            .unwrap_err()
            .code,
        "MEMBERSHIP_UNKNOWN"
    );
}
