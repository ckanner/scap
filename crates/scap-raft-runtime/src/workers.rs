//! A finite pair of async senders per configured peer. Snapshot traffic does
//! not occupy the ordinary-message worker, and one unavailable peer cannot
//! occupy the worker for another peer. Each lane reuses at most one mTLS
//! channel; every RPC revalidates the actual server chain and current pins.
//! Failure, cancellation or bounded connection age discards the channel.
//! No SQL or Raft retry is hidden inside this adapter.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use scap_raft_transport::{
    AdmissionError, ClientSecurity, PeerAuthorizer, PeerClient, PeerEndpoint, TransportLimits,
};
use scap_raft_wire::HEADER_BYTES;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{Delivery, DeliveryResult, Error, Handle, Network};

#[derive(Clone)]
pub struct NetworkSender {
    routes: BTreeMap<(u64, bool), mpsc::Sender<Queued>>,
    budget: Arc<Budget>,
}

impl Network for NetworkSender {
    fn try_send(&mut self, delivery: Delivery) -> Result<(), Error> {
        let Some(sender) = self.routes.get(&(delivery.peer, delivery.snapshot)) else {
            return Err(Error::Invalid("peer route"));
        };
        let bytes = HEADER_BYTES.saturating_add(delivery.envelope.payload.len());
        let Some(reservation) = self.budget.reserve(bytes) else {
            return Err(Error::Full);
        };
        sender
            .try_send(Queued {
                delivery,
                _reservation: reservation,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::Full,
                mpsc::error::TrySendError::Closed(_) => Error::Closed,
            })
    }
}

#[derive(Default)]
struct Held {
    messages: usize,
    bytes: usize,
}

struct Budget {
    held: Mutex<Held>,
    max_messages: usize,
    max_bytes: usize,
}

impl Budget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        let mut held = self.held.lock();
        if held.messages >= self.max_messages || bytes > self.max_bytes.saturating_sub(held.bytes) {
            return None;
        }
        held.messages += 1;
        held.bytes += bytes;
        Some(Reservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut held = self.budget.held.lock();
        held.messages -= 1;
        held.bytes -= self.bytes;
    }
}

struct Queued {
    delivery: Delivery,
    // Held through queueing and the entire network attempt, independently of
    // the owner's logical delivery record expiring or its feedback arriving.
    _reservation: Reservation,
}

pub struct NetworkWorkers {
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl NetworkWorkers {
    /// Call inside the node's Tokio runtime. Only configured fixed peers are
    /// accepted. No connection is required at startup: healthy peers can form
    /// a quorum while another endpoint is unavailable.
    pub fn start(
        handle: Handle,
        endpoints: Vec<PeerEndpoint>,
        security: ClientSecurity,
        limits: TransportLimits,
        queue_capacity: usize,
    ) -> Result<(Self, NetworkSender), Error> {
        limits.validate().map_err(network_error)?;
        security.validate().map_err(network_error)?;
        if queue_capacity == 0
            || queue_capacity > handle.mailbox.config.max_pending_deliveries
            || queue_capacity > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(Error::Invalid("sender queue limit"));
        }
        let shared = handle.mailbox.state.lock();
        if shared.closed {
            return Err(Error::Closed);
        }
        let scope = shared.policy.scope();
        let mut expected = shared.policy.members().clone();
        expected.remove(&scope.node_id);
        if endpoints.len() != expected.len() {
            return Err(Error::Invalid("peer endpoint set"));
        }
        if endpoints.len().saturating_mul(2) > limits.max_connections as usize {
            return Err(Error::Invalid(
                "connection budget does not cover peer lanes",
            ));
        }
        for endpoint in &endpoints {
            endpoint.validate().map_err(network_error)?;
            if endpoint.cluster_id != scope.cluster_id || !expected.remove(&endpoint.node_id) {
                return Err(Error::Invalid("peer endpoint identity"));
            }
        }
        drop(shared);
        let executor = tokio::runtime::Handle::try_current().map_err(network_error)?;
        let security = Arc::new(security);
        let stop = CancellationToken::new();
        let budget = Arc::new(Budget {
            held: Mutex::new(Held::default()),
            max_messages: handle.mailbox.config.max_pending_deliveries,
            max_bytes: handle.mailbox.config.max_pending_delivery_bytes,
        });
        let mut tasks = Vec::new();
        let mut routes = BTreeMap::new();
        for endpoint in endpoints {
            for snapshot in [false, true] {
                let (sender, receiver) = mpsc::channel(queue_capacity);
                routes.insert((endpoint.node_id, snapshot), sender);
                let link = TonicDelivery {
                    endpoint: endpoint.clone(),
                    security: Arc::clone(&security),
                    limits: limits.clone(),
                    authorizer: Arc::new(handle.clone()),
                    cached: None,
                };
                tasks.push(executor.spawn(send_loop(handle.clone(), receiver, stop.clone(), link)));
            }
        }
        Ok((Self { stop, tasks }, NetworkSender { routes, budget }))
    }

    /// Stops senders; the caller separately stops/joins the serial cell owner.
    /// Deadline failure means tasks were aborted, not that graceful drain was
    /// proven. Raft/application outcomes remain queryable by their own rules.
    pub async fn shutdown(mut self, deadline: Instant) -> Result<(), Error> {
        self.stop.cancel();
        while let Some(mut task) = self.tasks.pop() {
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut task).await
            {
                Ok(result) => result.map_err(network_error)?,
                Err(_) => {
                    task.abort();
                    return Err(Error::Expired);
                }
            }
        }
        Ok(())
    }
}

impl Drop for NetworkWorkers {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

trait Deliver: Send + 'static {
    fn deliver(&mut self, delivery: Delivery) -> impl Future<Output = bool> + Send;
}

struct TonicDelivery {
    endpoint: PeerEndpoint,
    security: Arc<ClientSecurity>,
    limits: TransportLimits,
    authorizer: Arc<dyn PeerAuthorizer>,
    cached: Option<CachedPeer>,
}

struct CachedPeer {
    client: PeerClient,
    connected: Instant,
}

impl PeerAuthorizer for Handle {
    fn authorize(
        &self,
        endpoint: &PeerEndpoint,
        verified_leaf_der: &[u8],
    ) -> Result<(), AdmissionError> {
        let now = self
            .mailbox
            .clock
            .now()
            .map_err(|_| AdmissionError::Unavailable)?;
        let shared = self.mailbox.state.lock();
        if shared.closed {
            return Err(AdmissionError::Unavailable);
        }
        if endpoint.cluster_id != shared.policy.scope().cluster_id {
            return Err(AdmissionError::PermissionDenied);
        }
        let certificate = scap_raft_wire::certificate_identity(
            verified_leaf_der,
            shared.policy.limits().max_certificate_bytes,
        )
        .map_err(crate::admission_error)?;
        shared
            .policy
            .authorize_peer(certificate, endpoint.node_id, now.unix_seconds)
            .map_err(crate::admission_error)
    }
}

impl Deliver for TonicDelivery {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        // Move the channel out before awaiting. Cancellation drops the in-flight
        // channel instead of leaving a partially used one in the cache.
        let now = Instant::now();
        let cached = self.cached.take().filter(|cached| {
            now.saturating_duration_since(cached.connected) < self.limits.max_connection_age
        });
        let mut completed = None;
        let call = async {
            let mut cached = match cached {
                Some(cached) => cached,
                None => {
                    let security = ClientSecurity {
                        certificate_pem: self.security.certificate_pem.clone(),
                        private_key_pem: self.security.private_key_pem.clone(),
                        server_ca_pem: self.security.server_ca_pem.clone(),
                    };
                    let client = PeerClient::connect_authorized(
                        self.endpoint.clone(),
                        security,
                        self.limits.clone(),
                        Arc::clone(&self.authorizer),
                    )
                    .await?;
                    CachedPeer {
                        client,
                        connected: now,
                    }
                }
            };
            cached
                .client
                .send(delivery.envelope, delivery.deadline)
                .await?;
            completed = Some(cached);
            Ok(())
        };
        let received = attempt_before(delivery.deadline, call, Instant::now).await;
        if received {
            self.cached = completed;
        }
        received
    }
}

async fn attempt_before(
    deadline: Instant,
    call: impl Future<Output = Result<(), scap_raft_transport::Error>>,
    mut now: impl FnMut() -> Instant,
) -> bool {
    if deadline <= now() {
        return false;
    }
    let completed = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), call).await;
    // A future that does not yield can finish after its budget before Tokio
    // observes its timer. Recheck completion against the original deadline.
    matches!(completed, Ok(Ok(()))) && now() < deadline
}

async fn send_loop(
    mut_handle: Handle,
    mut receiver: mpsc::Receiver<Queued>,
    stop: CancellationToken,
    mut link: impl Deliver,
) {
    while let Some(Some(queued)) = stop.run_until_cancelled(receiver.recv()).await {
        let Queued {
            delivery,
            _reservation,
        } = queued;
        let id = delivery.id;
        let outcome = stop.run_until_cancelled(link.deliver(delivery)).await;
        let result = match outcome {
            Some(true) => DeliveryResult::Received,
            _ => DeliveryResult::Failed,
        };
        mut_handle.complete(id, result);
        if outcome.is_none() {
            break;
        }
    }
}

fn network_error(error: impl std::fmt::Display) -> Error {
    Error::Network(error.to_string())
}

#[cfg(test)]
#[path = "workers_tests.rs"]
mod tests;
