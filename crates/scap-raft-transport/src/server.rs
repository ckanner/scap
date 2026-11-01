use std::convert::Infallible;
use std::future::{self, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tonic::body::Body;
use tonic::codegen::{http, Service};
use tonic::server::{NamedService, UnaryService};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use crate::incoming::BoundedIncoming;
use crate::{
    admission_status, check_pem, transport_error, Error, Ingress, Packet, Received,
    TransportLimits, RECEIVED_VERSION, RPC_PATH, SERVICE_NAME,
};

/// Private trust bundle. Public/native trust roots and anonymous client
/// authentication are never enabled. Do not log these bytes.
pub struct ServerSecurity {
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub client_ca_pem: Vec<u8>,
}

pub struct PeerServer<I> {
    builder: Server,
    service: PeerService<I>,
    connections: Arc<Semaphore>,
}

impl<I: Ingress> PeerServer<I> {
    pub fn new(
        ingress: Arc<I>,
        security: ServerSecurity,
        limits: TransportLimits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        check_pem(&[
            &security.certificate_pem,
            &security.private_key_pem,
            &security.client_ca_pem,
        ])?;
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                security.certificate_pem,
                security.private_key_pem,
            ))
            .client_ca_root(Certificate::from_pem(security.client_ca_pem))
            .client_auth_optional(false)
            .timeout(limits.handshake_timeout);
        let builder = Server::builder()
            .tls_config(tls)
            .map_err(transport_error)?
            .concurrency_limit_per_connection(limits.max_streams_per_connection as usize)
            .max_concurrent_streams(limits.max_streams_per_connection)
            .load_shed(true)
            .timeout(limits.request_timeout)
            .http2_max_header_list_size(limits.max_header_bytes)
            .max_connection_age(limits.max_connection_age)
            .max_connection_age_grace(limits.connection_grace);
        Ok(Self {
            builder,
            service: PeerService {
                ingress,
                requests: Arc::new(Semaphore::new(limits.max_inflight_requests as usize)),
                max_wire_bytes: limits.max_wire_bytes as usize,
                max_grpc_bytes: limits.grpc_bytes(),
            },
            connections: Arc::new(Semaphore::new(limits.max_connections as usize)),
        })
    }

    /// A supplied listener avoids hidden bind races and allows the caller to
    /// record its actual address. Shutdown stops admission and asks Tonic to
    /// drain; every connection also has a finite age and forced-close grace.
    pub async fn serve(
        mut self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), Error> {
        // Tonic's builder TCP options do not apply to supplied incoming streams.
        // Fail this accepted connection if its latency-critical option cannot
        // be installed; the outer wrapper still reserves before accepting.
        let sockets = TcpListenerStream::new(listener)
            .map(|accepted| configure_tcp(accepted, TcpStream::set_nodelay));
        let incoming = BoundedIncoming::new(sockets, self.connections);
        finish_server(
            self.builder
                .add_service(self.service)
                .serve_with_incoming_shutdown(incoming, shutdown),
        )
        .await
    }
}

fn configure_tcp(
    accepted: std::io::Result<TcpStream>,
    set_nodelay: fn(&TcpStream, bool) -> std::io::Result<()>,
) -> std::io::Result<TcpStream> {
    let stream = accepted?;
    set_nodelay(&stream, true)?;
    Ok(stream)
}

async fn finish_server(
    serving: impl Future<Output = Result<(), tonic::transport::Error>>,
) -> Result<(), Error> {
    serving.await.map_err(transport_error)
}

struct PeerService<I> {
    ingress: Arc<I>,
    requests: Arc<Semaphore>,
    max_wire_bytes: usize,
    max_grpc_bytes: usize,
}

impl<I> Clone for PeerService<I> {
    fn clone(&self) -> Self {
        Self {
            ingress: Arc::clone(&self.ingress),
            requests: Arc::clone(&self.requests),
            max_wire_bytes: self.max_wire_bytes,
            max_grpc_bytes: self.max_grpc_bytes,
        }
    }
}

impl<I> NamedService for PeerService<I> {
    const NAME: &'static str = SERVICE_NAME;
}

impl<I: Ingress> Service<http::Request<Body>> for PeerService<I> {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        if request.uri().path() != RPC_PATH || request.method() != http::Method::POST {
            return Box::pin(future::ready(Ok(
                Status::unimplemented("unknown peer RPC").into_http()
            )));
        }
        let permit = match Arc::clone(&self.requests).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Box::pin(future::ready(Ok(Status::resource_exhausted(
                    "global peer RPC capacity exceeded",
                )
                .into_http())));
            }
        };
        let method = Admit {
            ingress: Arc::clone(&self.ingress),
            max_wire_bytes: self.max_wire_bytes,
        };
        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
            .max_decoding_message_size(self.max_grpc_bytes)
            .max_encoding_message_size(16);
        Box::pin(async move {
            let _permit = permit;
            Ok(grpc.unary(method, request).await)
        })
    }
}

struct Admit<I> {
    ingress: Arc<I>,
    max_wire_bytes: usize,
}

impl<I: Ingress> UnaryService<Packet> for Admit<I> {
    type Response = Received;
    type Future = Ready<Result<Response<Self::Response>, Status>>;

    fn call(&mut self, request: Request<Packet>) -> Self::Future {
        future::ready(admit_request(
            self.ingress.as_ref(),
            request,
            self.max_wire_bytes,
        ))
    }
}

fn admit_request(
    ingress: &impl Ingress,
    request: Request<Packet>,
    max_wire_bytes: usize,
) -> Result<Response<Received>, Status> {
    // These are TLS connection extensions populated by Tonic, never a header
    // asserted by the caller. Missing evidence fails before parsing the body.
    let chain = request.peer_certs();
    admit_verified_chain(
        ingress,
        chain.as_deref().map(Vec::as_slice),
        request.into_inner(),
        max_wire_bytes,
    )
}

fn admit_verified_chain(
    ingress: &impl Ingress,
    chain: Option<&[tonic::transport::CertificateDer<'static>]>,
    packet: Packet,
    max_wire_bytes: usize,
) -> Result<Response<Received>, Status> {
    let chain = chain.ok_or_else(|| Status::unauthenticated("mTLS connection required"))?;
    let leaf = chain
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let envelope = scap_raft_wire::decode_envelope(&packet.data, max_wire_bytes)
        .map_err(|_| Status::invalid_argument("invalid bounded peer envelope"))?;
    ingress
        .admit(leaf.as_ref(), envelope)
        .map_err(admission_status)?;
    Ok(Response::new(Received {
        version: RECEIVED_VERSION,
    }))
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
