use super::*;
use crate::tests::{limits, Fixture};

fn endpoint(uri: &str) -> PeerEndpoint {
    PeerEndpoint {
        uri: uri.into(),
        cluster_id: 7,
        node_id: 2,
    }
}

#[test]
fn endpoints_bind_a_cluster_node_dns_identity_and_https_origin() {
    let valid = endpoint("https://127.0.0.1:12345");
    assert_eq!(
        valid.server_name(),
        "node-2.cluster-00000000000000000000000000000007.scap.internal"
    );
    valid.validate().unwrap();
    for uri in [
        "http://127.0.0.1:12345",
        "https:/missing-authority",
        "https://host/path",
        "https://host/?query",
        "https://user:password@host/",
        "\ninvalid",
    ] {
        assert!(endpoint(uri).validate().is_err(), "{uri}");
    }
    let mut invalid = valid.clone();
    invalid.cluster_id = 0;
    assert!(invalid.validate().is_err());
    invalid.cluster_id = 7;
    invalid.node_id = 0;
    assert!(invalid.validate().is_err());
}

#[tokio::test]
async fn invalid_security_transport_errors_and_total_deadline_are_distinct() {
    let fixture = Fixture::new();
    let mut invalid = limits();
    invalid.max_connections = 0;
    assert!(PeerClient::connect(
        endpoint("https://127.0.0.1:1"),
        fixture.client_security(),
        invalid
    )
    .await
    .is_err());
    assert!(PeerClient::connect(
        endpoint("http://127.0.0.1:1"),
        fixture.client_security(),
        limits()
    )
    .await
    .is_err());
    let mut invalid = fixture.client_security();
    invalid.server_ca_pem.clear();
    assert!(
        PeerClient::connect(endpoint("https://127.0.0.1:1"), invalid, limits())
            .await
            .is_err()
    );
    let invalid = ClientSecurity {
        certificate_pem: vec![1],
        private_key_pem: vec![1],
        server_ca_pem: vec![1],
    };
    assert!(
        PeerClient::connect(endpoint("https://127.0.0.1:1"), invalid, limits())
            .await
            .is_err()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(matches!(
        PeerClient::connect(
            endpoint(&format!("https://{address}")),
            fixture.client_security(),
            limits()
        )
        .await,
        Err(Error::Transport(_))
    ));
    // This native TCP peer accepts no TLS handshake. The overall connect
    // budget must expire before the longer TLS handshake budget.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let transport = Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(fixture.ca.pem())))
        .unwrap()
        .connect_timeout(std::time::Duration::from_secs(10));
    tokio::time::pause();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(10);
    assert!(matches!(
        connect_before(deadline, transport.connect()).await,
        Err(Error::Deadline)
    ));
    drop(listener);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1);
    assert!(matches!(
        connect_before(deadline, std::future::pending()).await,
        Err(Error::Deadline)
    ));
}

struct ScriptedIo {
    ready_error: bool,
    call_error: bool,
    pending: bool,
    version: u32,
}

impl tonic::codegen::Service<http::Request<tonic::body::Body>> for ScriptedIo {
    type Response = http::Response<tonic::body::Body>;
    type Error = tonic::Status;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.ready_error {
            return std::task::Poll::Ready(Err(tonic::Status::unavailable(
                "injected readiness failure",
            )));
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: http::Request<tonic::body::Body>) -> Self::Future {
        if self.pending {
            return Box::pin(std::future::pending());
        }
        if self.call_error {
            return Box::pin(std::future::ready(Err(tonic::Status::unavailable(
                "injected transport failure",
            ))));
        }
        let encoder =
            tonic_prost::ProstEncoder::<Received>::new(tonic::codec::BufferSettings::default());
        let body = tonic::codec::EncodeBody::new_server(
            encoder,
            tokio_stream::iter([Ok(Received {
                version: self.version,
            })]),
            None,
            tonic::codec::SingleMessageCompressionOverride::default(),
            Some(16),
        );
        let response = http::Response::builder()
            .header("content-type", "application/grpc")
            .body(tonic::body::Body::new(body))
            .unwrap();
        Box::pin(std::future::ready(Ok(response)))
    }
}

fn scripted(
    ready_error: bool,
    call_error: bool,
    pending: bool,
    version: u32,
) -> tonic::client::Grpc<ScriptedIo> {
    tonic::client::Grpc::new(ScriptedIo {
        ready_error,
        call_error,
        pending,
        version,
    })
}

#[tokio::test(start_paused = true)]
async fn one_absolute_deadline_covers_readiness_call_and_receipt_validation() {
    let now = tokio::time::Instant::now();
    let deadline = now + std::time::Duration::from_secs(1);
    send_before(&mut scripted(false, false, false, 1), vec![], deadline)
        .await
        .unwrap();
    assert!(matches!(
        send_before(&mut scripted(true, false, false, 1), vec![], deadline).await,
        Err(Error::Transport(_))
    ));
    assert!(matches!(
        send_before(&mut scripted(false, true, false, 1), vec![], deadline).await,
        Err(Error::Rpc(_))
    ));
    assert!(matches!(
        send_before(&mut scripted(false, false, false, 2), vec![], deadline).await,
        Err(Error::UnexpectedReceipt)
    ));
    assert!(matches!(
        send_before(&mut scripted(false, false, false, 1), vec![], now).await,
        Err(Error::Deadline)
    ));
    assert!(matches!(
        send_before(
            &mut scripted(false, false, false, 1),
            vec![],
            now - std::time::Duration::from_secs(1)
        )
        .await,
        Err(Error::Deadline)
    ));
    assert!(matches!(
        send_before(&mut scripted(false, false, true, 1), vec![], deadline).await,
        Err(Error::Deadline)
    ));
}

#[tokio::test]
async fn channel_identity_and_wire_budget_are_checked_before_send() {
    let mut client = PeerClient {
        grpc: tonic::client::Grpc::new(Channel::from_static("http://127.0.0.1:1").connect_lazy()),
        endpoint: endpoint("https://127.0.0.1:1"),
        max_wire_bytes: 4096,
    };
    let mut wrong = crate::tests::envelope();
    wrong.cluster_id = 99;
    assert!(matches!(
        client.send(wrong, std::time::Instant::now()).await,
        Err(Error::Invalid(_))
    ));
    let mut wrong = crate::tests::envelope();
    wrong.to_node = 99;
    assert!(matches!(
        client.send(wrong, std::time::Instant::now()).await,
        Err(Error::Invalid(_))
    ));
    let mut huge = crate::tests::envelope();
    huge.payload = vec![0; 8192];
    assert!(matches!(
        client.send(huge, std::time::Instant::now()).await,
        Err(Error::Wire(_))
    ));
}
