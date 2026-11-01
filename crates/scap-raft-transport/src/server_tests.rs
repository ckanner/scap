use super::*;
use crate::tests::{envelope, limits, Fixture, Sink};

#[tokio::test]
async fn accepted_tcp_has_nodelay_and_option_failure_rejects_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    stream.set_nodelay(false).unwrap();
    let stream = configure_tcp(Ok(stream), TcpStream::set_nodelay).unwrap();
    assert!(stream.nodelay().unwrap());
    let error = configure_tcp(Ok(stream), |_, enabled| {
        assert!(enabled);
        Err(std::io::Error::other("injected setsockopt failure"))
    })
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    let error = configure_tcp(
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "injected accept failure",
        )),
        |_, _| panic!("failed accept must not configure a socket"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[test]
fn server_tls_configuration_fails_closed() {
    let fixture = Fixture::new();
    let mut invalid = limits();
    invalid.max_connections = 0;
    assert!(PeerServer::new(
        Arc::new(Sink::default()),
        fixture.server_security(),
        invalid
    )
    .is_err());
    let mut empty = fixture.server_security();
    empty.client_ca_pem.clear();
    assert!(PeerServer::new(Arc::new(Sink::default()), empty, limits()).is_err());
    let invalid = ServerSecurity {
        certificate_pem: b"not a certificate".to_vec(),
        private_key_pem: b"not a key".to_vec(),
        client_ca_pem: b"not a CA".to_vec(),
    };
    assert!(matches!(
        PeerServer::new(Arc::new(Sink::default()), invalid, limits()),
        Err(Error::Transport(_))
    ));
}

#[tokio::test]
async fn errors_and_missing_tls_never_admit_a_message() {
    let sink = Sink::default();
    let packet = || Packet {
        data: scap_raft_wire::encode_envelope(&envelope(), 4096).unwrap(),
    };
    assert_eq!(
        admit_request(&sink, Request::new(packet()), 4096)
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        admit_verified_chain(&sink, Some(&[]), packet(), 4096)
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let der = Fixture::new().credentials(1).der;
    let chain = vec![tonic::transport::CertificateDer::from(der.clone())];
    assert_eq!(
        admit_verified_chain(&sink, Some(&chain), Packet { data: vec![0] }, 4096)
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for error in [
        crate::AdmissionError::Unauthenticated,
        crate::AdmissionError::PermissionDenied,
        crate::AdmissionError::Invalid,
        crate::AdmissionError::Limit,
        crate::AdmissionError::Unavailable,
    ] {
        let sink = Sink {
            error: Some(error),
            ..Sink::default()
        };
        assert_eq!(
            admit_verified_chain(&sink, Some(&chain), packet(), 4096)
                .unwrap_err()
                .code(),
            admission_status(error).code()
        );
    }
    assert_eq!(
        admit_verified_chain(&sink, Some(&chain), packet(), 4096)
            .unwrap()
            .into_inner()
            .version,
        1
    );
    assert_eq!(sink.seen.lock().unwrap()[0].0, der);
    let native_error = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(Identity::from_pem("invalid", "invalid")))
        .unwrap_err();
    assert!(matches!(
        finish_server(future::ready(Err(native_error))).await,
        Err(Error::Transport(_))
    ));
}

#[tokio::test]
async fn unknown_methods_and_global_admission_fail_before_body_decode() {
    let mut service = PeerService {
        ingress: Arc::new(Sink::default()),
        requests: Arc::new(Semaphore::new(1)),
        max_wire_bytes: 4096,
        max_grpc_bytes: 4102,
    };
    assert!(std::future::poll_fn(|cx| service.poll_ready(cx))
        .await
        .is_ok());
    for (path, method) in [("/wrong", "POST"), (RPC_PATH, "GET")] {
        let request = http::Request::builder()
            .uri(path)
            .method(method)
            .body(Body::empty())
            .unwrap();
        let response = service.call(request).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "12");
    }
    let held = service.requests.clone().acquire_owned().await.unwrap();
    let request = http::Request::builder()
        .uri(RPC_PATH)
        .method("POST")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        service.call(request).await.unwrap().headers()["grpc-status"],
        "8"
    );
    drop(held);
    assert_eq!(service.requests.available_permits(), 1);
    let mut method = Admit {
        ingress: Arc::clone(&service.ingress),
        max_wire_bytes: 4096,
    };
    assert_eq!(
        method
            .call(Request::new(Packet { data: vec![] }))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
}
