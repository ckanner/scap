use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use scap_raft_wire::Envelope;

use crate::*;

pub(crate) fn limits() -> TransportLimits {
    TransportLimits {
        max_wire_bytes: 4096,
        max_connections: 8,
        max_inflight_requests: 8,
        max_streams_per_connection: 4,
        max_header_bytes: 4096,
        handshake_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(2),
        max_connection_age: Duration::from_secs(10),
        connection_grace: Duration::from_secs(1),
    }
}

pub(crate) fn envelope() -> Envelope {
    Envelope {
        version: scap_raft_wire::VERSION,
        codec: scap_raft_wire::CODEC,
        cluster_id: 7,
        cell_id: 9,
        cell_incarnation: 11,
        from_node: 1,
        to_node: 2,
        payload: vec![8, 8, 16, 2, 24, 1],
    }
}

pub(crate) struct Fixture {
    pub ca: Certificate,
    key: KeyPair,
}

pub(crate) struct Credentials {
    pub pem: Vec<u8>,
    pub key: Vec<u8>,
    pub der: Vec<u8>,
}

impl Fixture {
    pub fn new() -> Self {
        let mut parameters = CertificateParams::new(Vec::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let ca = parameters.self_signed(&key).unwrap();
        Self { ca, key }
    }

    pub fn credentials(&self, node: u64) -> Credentials {
        let endpoint = PeerEndpoint {
            uri: "https://127.0.0.1:12345".into(),
            cluster_id: 7,
            node_id: node,
        };
        let mut parameters = CertificateParams::new(vec![endpoint.server_name()]).unwrap();
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = parameters.signed_by(&key, &self.ca, &self.key).unwrap();
        Credentials {
            pem: cert.pem().into_bytes(),
            key: key.serialize_pem().into_bytes(),
            der: cert.der().to_vec(),
        }
    }

    pub fn server_security(&self) -> ServerSecurity {
        let credentials = self.credentials(2);
        ServerSecurity {
            certificate_pem: credentials.pem,
            private_key_pem: credentials.key,
            client_ca_pem: self.ca.pem().into_bytes(),
        }
    }

    pub fn client_security(&self) -> ClientSecurity {
        let credentials = self.credentials(1);
        ClientSecurity {
            certificate_pem: credentials.pem,
            private_key_pem: credentials.key,
            server_ca_pem: self.ca.pem().into_bytes(),
        }
    }
}

#[derive(Default)]
pub(crate) struct Sink {
    pub seen: Mutex<Vec<(Vec<u8>, Envelope)>>,
    pub error: Option<AdmissionError>,
}

impl Ingress for Sink {
    fn admit(&self, peer_leaf_der: &[u8], envelope: Envelope) -> Result<(), AdmissionError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.seen
            .lock()
            .unwrap()
            .push((peer_leaf_der.to_vec(), envelope));
        Ok(())
    }
}

#[test]
fn configuration_and_error_contracts_are_explicit() {
    limits().validate().unwrap();
    for bytes in [0, 127, 64 * 1024 * 1024 + 1] {
        let mut invalid = limits();
        invalid.max_wire_bytes = bytes;
        assert!(matches!(invalid.validate(), Err(Error::Invalid(_))));
    }
    for field in 0..3 {
        for value in [0, 65_537] {
            let mut invalid = limits();
            match field {
                0 => invalid.max_connections = value,
                1 => invalid.max_inflight_requests = value,
                _ => invalid.max_streams_per_connection = value,
            }
            assert!(invalid.validate().is_err());
        }
    }
    for bytes in [0, 1023, 65_537] {
        let mut invalid = limits();
        invalid.max_header_bytes = bytes;
        assert!(invalid.validate().is_err());
    }
    for field in 0..5 {
        for value in [Duration::ZERO, Duration::from_secs(3601)] {
            let mut invalid = limits();
            match field {
                0 => invalid.handshake_timeout = value,
                1 => invalid.request_timeout = value,
                2 => invalid.connect_timeout = value,
                3 => invalid.max_connection_age = value,
                _ => invalid.connection_grace = value,
            }
            assert!(invalid.validate().is_err());
        }
    }
    assert_eq!(limits().grpc_bytes(), 4102);
    assert!(check_pem(&[&[]]).is_err());
    assert!(check_pem(&[&vec![0; MAX_PEM_BYTES + 1]]).is_err());
    check_pem(&[b"bounded native validation follows"]).unwrap();
    assert_eq!(
        format!("{}", transport_error("native failure")),
        "Transport(\"native failure\")"
    );
    for (error, code) in [
        (
            AdmissionError::Unauthenticated,
            tonic::Code::Unauthenticated,
        ),
        (
            AdmissionError::PermissionDenied,
            tonic::Code::PermissionDenied,
        ),
        (AdmissionError::Invalid, tonic::Code::InvalidArgument),
        (AdmissionError::Limit, tonic::Code::ResourceExhausted),
        (AdmissionError::Unavailable, tonic::Code::Unavailable),
    ] {
        assert_eq!(admission_status(error).code(), code);
    }
}

#[tokio::test]
async fn native_mtls_adapter_carries_only_verified_der_and_exact_envelope() {
    let fixture = Fixture::new();
    let sink = Arc::new(Sink::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = PeerServer::new(Arc::clone(&sink), fixture.server_security(), limits()).unwrap();
    let credentials = fixture.credentials(1);
    let expected_der = credentials.der;
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.serve(listener, async {
        let _ = shutdown.await;
    }));
    let mut client = PeerClient::connect(
        PeerEndpoint {
            uri: format!("https://{address}"),
            cluster_id: 7,
            node_id: 2,
        },
        ClientSecurity {
            certificate_pem: credentials.pem,
            private_key_pem: credentials.key,
            server_ca_pem: fixture.ca.pem().into_bytes(),
        },
        limits(),
    )
    .await
    .unwrap();
    let expected = envelope();
    client
        .send(
            expected.clone(),
            std::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
    {
        let seen = sink.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, expected_der);
        assert_eq!(seen[0].1, expected);
    }
    drop(client);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
