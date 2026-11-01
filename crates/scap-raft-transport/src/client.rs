use std::time::Instant;

use scap_raft_wire::Envelope;
use tonic::codegen::http;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::Request;

use crate::{
    check_pem, transport_error, Error, Packet, Received, TransportLimits, RECEIVED_VERSION,
    RPC_PATH,
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

/// One serial outgoing channel. Do not create unbounded clients or tasks: the
/// runtime owns the finite route set and outstanding message/byte admission.
pub struct PeerClient {
    grpc: tonic::client::Grpc<Channel>,
    endpoint: PeerEndpoint,
    max_wire_bytes: usize,
}

impl PeerClient {
    pub async fn connect(
        endpoint: PeerEndpoint,
        security: ClientSecurity,
        limits: TransportLimits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let deadline = tokio::time::Instant::now() + limits.connect_timeout;
        let transport = endpoint.transport_endpoint()?;
        security.validate()?;
        let tls = ClientTlsConfig::new()
            .domain_name(endpoint.server_name())
            .identity(Identity::from_pem(
                security.certificate_pem,
                security.private_key_pem,
            ))
            .ca_certificate(Certificate::from_pem(security.server_ca_pem))
            .timeout(limits.handshake_timeout);
        let transport = transport
            .tls_config(tls)
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
        )
        .await
    }
}

async fn send_before<T>(
    grpc: &mut tonic::client::Grpc<T>,
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
) -> Result<(), Error>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: std::fmt::Display,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError>,
{
    let call = async {
        grpc.ready().await.map_err(transport_error)?;
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
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
