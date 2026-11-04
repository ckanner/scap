use super::*;
use crate::tests::{limits, Fixture};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tonic::transport::Certificate;

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
    let mut invalid_identity = fixture.client_security();
    invalid_identity.private_key_pem = b"invalid private key".to_vec();
    assert!(
        PeerClient::connect(endpoint("https://127.0.0.1:1"), invalid_identity, limits(),)
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
    calls: Arc<AtomicUsize>,
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
        self.calls.fetch_add(1, Ordering::SeqCst);
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
        calls: Arc::new(AtomicUsize::new(0)),
    })
}

// Use one transport/auth/clock instance for the decision-table cases. The
// complete production send routine is still exercised; each scenario controls
// only its actual I/O, current-authority and monotonic-clock boundaries.
async fn checked_send(
    grpc: &mut tonic::client::Grpc<ScriptedIo>,
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
    mut authorize: impl FnMut() -> Result<(), Error>,
    mut now: impl FnMut() -> tokio::time::Instant,
) -> Result<(), Error> {
    send_before(
        grpc,
        bytes,
        deadline,
        &mut authorize as &mut dyn FnMut() -> Result<(), Error>,
        &mut now as &mut dyn FnMut() -> tokio::time::Instant,
    )
    .await
}

#[tokio::test]
async fn current_authorization_is_checked_after_readiness_and_again_before_receipt() {
    for reject_check in [0, 1] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut grpc = tonic::client::Grpc::new(ScriptedIo {
            ready_error: false,
            call_error: false,
            pending: false,
            version: 1,
            calls: Arc::clone(&calls),
        });
        let mut checks = 0;
        assert!(matches!(
            checked_send(
                &mut grpc,
                vec![],
                tokio::time::Instant::now() + Duration::from_secs(1),
                || {
                    let check = checks;
                    checks += 1;
                    if check == reject_check {
                        Err(Error::Invalid("revoked during request"))
                    } else {
                        Ok(())
                    }
                },
                tokio::time::Instant::now,
            )
            .await,
            Err(Error::Invalid("revoked during request"))
        ));
        assert_eq!(checks, reject_check + 1);
        assert_eq!(calls.load(Ordering::SeqCst), reject_check);
    }
}

#[tokio::test(start_paused = true)]
async fn synchronous_post_receipt_validation_cannot_extend_the_original_deadline() {
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(1);
    let mut clock = std::collections::VecDeque::from([start, deadline]);
    let mut checks = 0;
    assert!(matches!(
        checked_send(
            &mut scripted(false, false, false, 1),
            vec![],
            deadline,
            || {
                checks += 1;
                Ok(())
            },
            || clock.pop_front().unwrap(),
        )
        .await,
        Err(Error::Deadline)
    ));
    assert_eq!(checks, 2);
    assert!(clock.is_empty());
}

#[derive(Default)]
struct LiveAuthority {
    reject: AtomicBool,
    calls: AtomicUsize,
}

impl PeerAuthorizer for LiveAuthority {
    fn authorize(&self, peer: &PeerEndpoint, leaf: &[u8]) -> Result<(), AdmissionError> {
        assert_eq!(peer.cluster_id, 7);
        assert_eq!(peer.node_id, 2);
        assert!(!leaf.is_empty());
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject.load(Ordering::SeqCst) {
            return Err(AdmissionError::PermissionDenied);
        }
        Ok(())
    }
}

#[test]
fn native_certificate_revalidation_rejects_untrusted_names_times_and_revoked_pins() {
    let fixture = Fixture::new();
    for ca in [
        &b""[..],
        &b"-----BEGIN CERTIFICATE-----\n?\n-----END CERTIFICATE-----\n"[..],
        &b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"[..],
    ] {
        assert!(PeerVerifier::new(ca, endpoint("https://127.0.0.1:1"), None).is_err());
    }
    let authority = Arc::new(LiveAuthority::default());
    let verifier = PeerVerifier::new(
        fixture.ca.pem().as_bytes(),
        endpoint("https://127.0.0.1:1"),
        Some(authority.clone()),
    )
    .unwrap();
    assert_eq!(format!("{verifier:?}"), "PeerVerifier { .. }");
    assert!(matches!(
        verifier.revalidate(UnixTime::now()),
        Err(Error::Invalid(_))
    ));
    let credentials = fixture.credentials(2);
    let leaf = CertificateDer::from(credentials.der);
    let server_name = ServerName::try_from(endpoint("https://127.0.0.1:1").server_name()).unwrap();
    let now = UnixTime::now();
    let roots = [fixture.ca.der().clone()];
    verifier
        .verify_server_cert(&leaf, &roots, &server_name, &[1], now)
        .unwrap();
    verifier.revalidate(now).unwrap();
    verifier.revalidate(now).unwrap();
    assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
    let wrong_name = ServerName::try_from("other.scap.internal").unwrap();
    assert!(verifier
        .verify_server_cert(&leaf, &[], &wrong_name, &[], now)
        .is_err());
    let untrusted = CertificateDer::from(Fixture::new().credentials(2).der);
    assert!(verifier
        .verify_server_cert(&untrusted, &[], &server_name, &[], now)
        .is_err());
    let identity = scap_raft_wire::certificate_identity(&leaf, 8192).unwrap();
    for seconds in [identity.not_before - 1, identity.not_after + 1] {
        let when = UnixTime::since_unix_epoch(Duration::from_secs(seconds.try_into().unwrap()));
        assert!(verifier.revalidate(when).is_err());
        assert!(verifier
            .verify_server_cert(&leaf, &[], &server_name, &[], when)
            .is_err());
    }
    authority.reject.store(true, Ordering::SeqCst);
    assert!(verifier.revalidate(now).is_err());
    assert!(verifier
        .verify_server_cert(&leaf, &[], &server_name, &[], now)
        .is_err());
    authority.reject.store(false, Ordering::SeqCst);
    verifier.revalidate(now).unwrap();

    // Size and count bound the evidence retained from a peer before copying.
    let oversized = CertificateDer::from(vec![0; MAX_PEM_BYTES + 1]);
    assert!(verifier
        .verify_server_cert(&oversized, &[], &server_name, &[], now)
        .is_err());
    let many = vec![CertificateDer::from(vec![]); 33];
    assert!(verifier
        .verify_server_cert(&leaf, &many, &server_name, &[], now)
        .is_err());
    let oversized_intermediate = [CertificateDer::from(vec![0; MAX_PEM_BYTES])];
    assert!(verifier
        .verify_server_cert(&leaf, &oversized_intermediate, &server_name, &[], now)
        .is_err());
    // Failed replacement cannot turn an unverified chain into cached authority.
    verifier.revalidate(now).unwrap();
}

#[tokio::test]
async fn tls12_signature_verification_delegates_to_the_native_verifier() {
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;
    let fixture = Fixture::new();
    let server_credentials = fixture.credentials(2);
    let mut roots = RootCertStore::empty();
    roots.add(fixture.ca.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![CertificateDer::from(server_credentials.der)],
            PrivateKeyDer::from_pem_slice(&server_credentials.key).unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        acceptor.accept(stream).await.unwrap()
    });
    let verifier = Arc::new(
        PeerVerifier::new(
            fixture.ca.pem().as_bytes(),
            endpoint(&format!("https://{address}")),
            None,
        )
        .unwrap(),
    );
    let credentials = fixture.credentials(1);
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_cert(
            vec![CertificateDer::from(credentials.der)],
            PrivateKeyDer::from_pem_slice(&credentials.key).unwrap(),
        )
        .unwrap();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let name = ServerName::try_from(endpoint("https://127.0.0.1:1").server_name()).unwrap();
    let connected = connector.connect(name, stream).await.unwrap();
    assert_eq!(
        connected.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    verifier.revalidate(UnixTime::now()).unwrap();
    drop(connected);
    drop(server.await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn one_absolute_deadline_covers_readiness_call_and_receipt_validation() {
    let now = tokio::time::Instant::now();
    let deadline = now + std::time::Duration::from_secs(1);
    checked_send(
        &mut scripted(false, false, false, 1),
        vec![],
        deadline,
        || Ok(()),
        tokio::time::Instant::now,
    )
    .await
    .unwrap();
    assert!(matches!(
        checked_send(
            &mut scripted(true, false, false, 1),
            vec![],
            deadline,
            || Ok(()),
            tokio::time::Instant::now,
        )
        .await,
        Err(Error::Transport(_))
    ));
    assert!(matches!(
        checked_send(
            &mut scripted(false, true, false, 1),
            vec![],
            deadline,
            || Ok(()),
            tokio::time::Instant::now,
        )
        .await,
        Err(Error::Rpc(_))
    ));
    assert!(matches!(
        checked_send(
            &mut scripted(false, false, false, 2),
            vec![],
            deadline,
            || Ok(()),
            tokio::time::Instant::now,
        )
        .await,
        Err(Error::UnexpectedReceipt)
    ));
    assert!(matches!(
        checked_send(
            &mut scripted(false, false, false, 1),
            vec![],
            now,
            || Ok(()),
            tokio::time::Instant::now,
        )
        .await,
        Err(Error::Deadline)
    ));
    assert!(matches!(
        checked_send(
            &mut scripted(false, false, false, 1),
            vec![],
            now - std::time::Duration::from_secs(1),
            || Ok(()),
            tokio::time::Instant::now,
        )
        .await,
        Err(Error::Deadline)
    ));
    assert!(matches!(
        checked_send(
            &mut scripted(false, false, true, 1),
            vec![],
            deadline,
            || Ok(()),
            tokio::time::Instant::now,
        )
        .await,
        Err(Error::Deadline)
    ));
}

#[tokio::test]
async fn channel_identity_and_wire_budget_are_checked_before_send() {
    let fixture = Fixture::new();
    let mut client = PeerClient {
        grpc: tonic::client::Grpc::new(Channel::from_static("http://127.0.0.1:1").connect_lazy()),
        endpoint: endpoint("https://127.0.0.1:1"),
        max_wire_bytes: 4096,
        verifier: Arc::new(
            PeerVerifier::new(
                fixture.ca.pem().as_bytes(),
                endpoint("https://127.0.0.1:1"),
                None,
            )
            .unwrap(),
        ),
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
