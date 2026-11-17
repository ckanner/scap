//! Unit HTTP fixture for actual startup-adapter wiring, not a cloud S3 verdict.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub(super) struct Backend {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Backend {
    pub(super) fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut objects = BTreeMap::<String, Vec<u8>>::new();
            for connection in listener.incoming() {
                let mut connection = connection.unwrap();
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                connection
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut input = BufReader::new(&mut connection);
                let mut request = String::new();
                input.read_line(&mut request).unwrap();
                let words: Vec<_> = request.split_whitespace().collect();
                assert_eq!(words.len(), 3);
                let (method, key) = (words[0], words[1]);
                assert!(key.starts_with("/scap-test/scap-worker/v1/instances/"));
                let mut headers = BTreeMap::new();
                loop {
                    let mut line = String::new();
                    input.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                    assert!(headers.len() < 64);
                }
                assert!(headers["authorization"].starts_with("AWS4-HMAC-SHA256 "));
                let length: usize = headers
                    .get("content-length")
                    .map_or(0, |v| v.parse().unwrap());
                assert!(length <= 128);
                let mut bytes = vec![0; length];
                input.read_exact(&mut bytes).unwrap();
                drop(input);
                let (status, response) = match method {
                    "PUT" => {
                        assert_eq!(headers["if-none-match"], "*");
                        if objects.contains_key(key) {
                            (
                                "412 Precondition Failed",
                                b"<Error><Code>PreconditionFailed</Code></Error>".to_vec(),
                            )
                        } else {
                            objects.insert(key.into(), bytes);
                            ("200 OK", vec![])
                        }
                    }
                    "GET" => match objects.get(key) {
                        Some(bytes) => ("200 OK", bytes.clone()),
                        None => (
                            "404 Not Found",
                            b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
                        ),
                    },
                    _ => panic!("unexpected startup request"),
                };
                write!(connection,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nETag: \"instance\"\r\nLast-Modified: Tue, 17 Nov 2026 00:00:00 GMT\r\nConnection: close\r\n\r\n",
                    response.len()).unwrap();
                connection.write_all(&response).unwrap();
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }

    pub(super) fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.thread.take().unwrap().join().unwrap();
    }
}
