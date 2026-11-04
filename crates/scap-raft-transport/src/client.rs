use std::sync::{Arc, Mutex};
use std::time::Instant;

use scap_raft_wire::Envelope;
use tokio_rustls::rustls::{
    self,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tonic::codegen::http;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::Request;

use crate::{
    check_pem, transport_error, AdmissionError, Error, Packet, Received, TransportLimits,
    MAX_PEM_BYTES, RECEIVED_VERSION, RPC_PATH,
};

pub struct ClientSecurity {
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub server_ca_pem: Vec<u8>,
}

impl ClientSecurity {
    /// Check finite material before a runtime stores or clones it. Native key,
    /// chain and DNS verification still take place during client construction
    /// and TLS connection; this is not a successful authentication assertion.
    pub fn validate(&self) -> Result<(), Error> {
        check_pem(&[
            &self.certificate_pem,
            &self.private_key_pem,
            &self.server_ca_pem,
        ])
    }
}

#[derive(Clone, Debug)]
pub struct PeerEndpoint {
    pub uri: String,
    pub cluster_id: u128,
    pub node_id: u64,
}

impl PeerEndpoint {
    pub fn server_name(&self) -> String {
        format!(
            "node-{}.cluster-{:032x}.scap.internal",
            self.node_id, self.cluster_id
        )
    }

    /// Validate the complete route before starting workers or storing it.
    /// This is an offline syntax/identity check, not a TLS authentication.
    pub fn validate(&self) -> Result<(), Error> {
        self.transport_endpoint().map(|_| ())
    }

    fn transport_endpoint(&self) -> Result<Endpoint, Error> {
        if self.cluster_id == 0 || self.node_id == 0 {
            return Err(Error::Invalid("zero peer endpoint identity"));
        }
        let endpoint = Endpoint::from_shared(self.uri.clone()).map_err(transport_error)?;
        let uri = endpoint.uri();
        // http::Uri rejects a scheme without an authority during parsing.
        if uri.scheme_str() != Some("https")
            || uri.path() != "/"
            || uri.query().is_some()
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(Error::Invalid("peer endpoint must be an HTTPS origin"));
        }
        Ok(endpoint)
    }
}

/// Current authorization for the actual server leaf verified by TLS. The
/// runtime supplies its live pin policy; implementations must not cache a
/// prior grant. This runs during each handshake and before/after every RPC.
pub trait PeerAuthorizer: Send + Sync + 'static {
    fn authorize(
        &self,
        endpoint: &PeerEndpoint,
        verified_leaf_der: &[u8],
    ) -> Result<(), AdmissionError>;
}

// Rustls authenticates the handshake signature. Retaining its verified chain
// lets each RPC repeat the native chain/name/time verification without another
// network handshake. An established TLS channel is never an authorization lease.
struct Evidence {
    leaf: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
    server_name: ServerName<'static>,
    ocsp: Vec<u8>,
}

struct PeerVerifier {
    verifier: Arc<WebPkiServerVerifier>,
    endpoint: PeerEndpoint,
    authorizer: Option<Arc<dyn PeerAuthorizer>>,
    evidence: Mutex<Option<Arc<Evidence>>>,
}

impl std::fmt::Debug for PeerVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerVerifier")
            .finish_non_exhaustive()
    }
}

impl PeerVerifier {
    fn new(
        ca_pem: &[u8],
        endpoint: PeerEndpoint,
        authorizer: Option<Arc<dyn PeerAuthorizer>>,
    ) -> Result<Self, Error> {
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(ca_pem) {
            roots
                .add(certificate.map_err(transport_error)?)
                .map_err(transport_error)?;
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(transport_error)?;
        Ok(Self {
            verifier,
            endpoint,
            authorizer,
            evidence: Mutex::new(None),
        })
    }

    fn authorize(&self, leaf: &[u8]) -> Result<(), rustls::Error> {
        if let Some(authorizer) = &self.authorizer {
            authorizer
                .authorize(&self.endpoint, leaf)
                .map_err(|error| {
                    rustls::Error::General(format!("peer authorization: {error:?}"))
                })?;
        }
        Ok(())
    }

    fn revalidate(&self, now: UnixTime) -> Result<(), Error> {
        let evidence = self
            .evidence
            .lock()
            .expect("peer evidence lock")
            .clone()
            .ok_or(Error::Invalid("channel has no authenticated peer"))?;
        self.verifier
            .verify_server_cert(
                &evidence.leaf,
                &evidence.intermediates,
                &evidence.server_name,
                &evidence.ocsp,
                now,
            )
            .map_err(transport_error)?;
        self.authorize(&evidence.leaf).map_err(transport_error)
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let bytes = intermediates.iter().fold(
            end_entity.len().saturating_add(ocsp_response.len()),
            |total, certificate| total.saturating_add(certificate.len()),
        );
        if bytes > MAX_PEM_BYTES || intermediates.len() > 32 {
            return Err(rustls::Error::General(
                "server certificate chain limit".into(),
            ));
        }
        let verified = self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        self.authorize(end_entity)?;
        *self.evidence.lock().expect("peer evidence lock") = Some(Arc::new(Evidence {
            leaf: end_entity.clone().into_owned(),
            intermediates: intermediates
                .iter()
                .map(|certificate| certificate.clone().into_owned())
                .collect(),
            server_name: server_name.to_owned(),
            ocsp: ocsp_response.to_vec(),
        }));
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

/// One serial outgoing channel. Do not create unbounded clients or tasks: the
/// runtime owns the finite route set and outstanding message/byte admission.
pub struct PeerClient {
    grpc: tonic::client::Grpc<Channel>,
    endpoint: PeerEndpoint,
    max_wire_bytes: usize,
    verifier: Arc<PeerVerifier>,
}

impl PeerClient {
    /// Chain/DNS verified standalone client. The production runtime uses
    /// connect_authorized so its replaceable node pins also apply to sends.
    pub async fn connect(
        endpoint: PeerEndpoint,
        security: ClientSecurity,
        limits: TransportLimits,
    ) -> Result<Self, Error> {
        Self::connect_inner(endpoint, security, limits, None).await
    }

    pub async fn connect_authorized(
        endpoint: PeerEndpoint,
        security: ClientSecurity,
        limits: TransportLimits,
        authorizer: Arc<dyn PeerAuthorizer>,
    ) -> Result<Self, Error> {
        Self::connect_inner(endpoint, security, limits, Some(authorizer)).await
    }

    async fn connect_inner(
        endpoint: PeerEndpoint,
        security: ClientSecurity,
        limits: TransportLimits,
        authorizer: Option<Arc<dyn PeerAuthorizer>>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let deadline = tokio::time::Instant::now() + limits.connect_timeout;
        let transport = endpoint.transport_endpoint()?;
        security.validate()?;
        let verifier = Arc::new(PeerVerifier::new(
            &security.server_ca_pem,
            endpoint.clone(),
            authorizer,
        )?);
        let tls = ClientTlsConfig::new()
            .domain_name(endpoint.server_name())
            .identity(Identity::from_pem(
                security.certificate_pem,
                security.private_key_pem,
            ))
            .timeout(limits.handshake_timeout);
        let transport = transport
            .tls_config_with_verifier(tls, verifier.clone())
            .map_err(transport_error)?
            .connect_timeout(limits.connect_timeout)
            .buffer_size(1)
            .concurrency_limit(1)
            .timeout(limits.request_timeout);
        let channel = connect_before(deadline, transport.connect()).await?;
        Ok(Self {
            grpc: tonic::client::Grpc::new(channel)
                .max_decoding_message_size(16)
                .max_encoding_message_size(limits.grpc_bytes()),
            endpoint,
            max_wire_bytes: limits.max_wire_bytes as usize,
            verifier,
        })
    }

    /// No retry, including for transport failures. `deadline` is absolute and
    /// must have been assigned before runtime queueing; readiness consumes the
    /// same budget as the actual send. Success only means bounded admission.
    pub async fn send(&mut self, envelope: Envelope, deadline: Instant) -> Result<(), Error> {
        if envelope.cluster_id != self.endpoint.cluster_id
            || envelope.to_node != self.endpoint.node_id
        {
            return Err(Error::Invalid("envelope does not match channel identity"));
        }
        let bytes = scap_raft_wire::encode_envelope(&envelope, self.max_wire_bytes)
            .map_err(|error| Error::Wire(error.to_string()))?;
        send_before(
            &mut self.grpc,
            bytes,
            tokio::time::Instant::from_std(deadline),
            || self.verifier.revalidate(UnixTime::now()),
            tokio::time::Instant::now,
        )
        .await
    }
}

async fn send_before<T>(
    grpc: &mut tonic::client::Grpc<T>,
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
    mut authorize: impl FnMut() -> Result<(), Error>,
    mut now: impl FnMut() -> tokio::time::Instant,
) -> Result<(), Error>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: std::fmt::Display,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError>,
{
    let call = async {
        grpc.ready().await.map_err(transport_error)?;
        authorize()?;
        let remaining = deadline
            .checked_duration_since(now())
            .filter(|value| !value.is_zero())
            .ok_or(Error::Deadline)?;
        let mut request = Request::new(Packet { data: bytes });
        request.set_timeout(remaining);
        let response: tonic::Response<Received> = grpc
            .unary(
                request,
                http::uri::PathAndQuery::from_static(RPC_PATH),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map_err(Error::Rpc)?;
        if response.into_inner().version != RECEIVED_VERSION {
            return Err(Error::UnexpectedReceipt);
        }
        authorize()?;
        if now() >= deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    };
    tokio::time::timeout_at(deadline, call)
        .await
        .map_err(|_| Error::Deadline)?
}

async fn connect_before(
    deadline: tokio::time::Instant,
    connecting: impl std::future::Future<Output = Result<Channel, tonic::transport::Error>>,
) -> Result<Channel, Error> {
    tokio::time::timeout_at(deadline, connecting)
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(transport_error)
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
