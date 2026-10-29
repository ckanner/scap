//! Research fixture only: real TCP/gRPC and two distinct protobuf ecosystems.
//! No RawNode, durable log, consensus, TLS identity, or production transport.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use protobuf::Message as RustProtobufMessage;
use raft::eraftpb::{Entry, Message as RaftMessage, MessageType, Snapshot};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request, Response, Status};

mod wire {
    tonic::include_proto!("scap.experiment.rpc.v1");
}

use wire::codec_probe_client::CodecProbeClient;
use wire::codec_probe_server::{CodecProbe, CodecProbeServer};
use wire::{Envelope, Observed};

const MAX_PAYLOAD: usize = 2048;
const MAX_WIRE_MESSAGE: usize = 4096;
const CODEC: &str = "raft-rs/protobuf-v2/ad13f3d";

#[derive(Clone, Default)]
struct DecodeFixture {
    decoded: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl CodecProbe for DecodeFixture {
    async fn exchange(&self, request: Request<Envelope>) -> Result<Response<Observed>, Status> {
        let envelope = request.into_inner();
        if envelope.protocol_version != 1 || envelope.codec != CODEC {
            return Err(Status::failed_precondition("unsupported probe wire format"));
        }
        if envelope.cluster_id != "synthetic-cluster"
            || envelope.cell_id != "synthetic-cell"
            || envelope.cell_incarnation != 17
            || envelope.from_node != 1
            || envelope.to_node != 2
        {
            return Err(Status::permission_denied(
                "unexpected fixture routing identity",
            ));
        }
        if envelope.payload.len() > MAX_PAYLOAD {
            return Err(Status::resource_exhausted("probe payload limit exceeded"));
        }
        let message = RaftMessage::parse_from_bytes(&envelope.payload)
            .map_err(|_| Status::invalid_argument("malformed raft protobuf"))?;
        if message.get_from() != envelope.from_node || message.get_to() != envelope.to_node {
            return Err(Status::invalid_argument(
                "envelope and payload identity differ",
            ));
        }
        self.decoded.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(Observed {
            // Preserve exact payload bytes, including unknown fields. Do not re-encode.
            original_payload: envelope.payload,
            decoded_term: message.get_term(),
            decoded_from: message.get_from(),
            decoded_to: message.get_to(),
        }))
    }
}

struct RunningProbe {
    client: CodecProbeClient<Channel>,
    decoded: Arc<AtomicUsize>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl RunningProbe {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = DecodeFixture::default();
        let decoded = Arc::clone(&fixture.decoded);
        let service = CodecProbeServer::new(fixture)
            .max_decoding_message_size(MAX_WIRE_MESSAGE)
            .max_encoding_message_size(MAX_WIRE_MESSAGE);
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown.await;
                })
                .await
        });
        let channel = Channel::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(3))
            .connect()
            .await
            .unwrap();
        let client = CodecProbeClient::new(channel)
            .max_decoding_message_size(MAX_WIRE_MESSAGE)
            .max_encoding_message_size(MAX_WIRE_MESSAGE * 2);
        Self {
            client,
            decoded,
            stop,
            task,
        }
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        drop(self.client);
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .expect("fixture server should shut down")
            .expect("server task should not panic")
            .expect("server should terminate cleanly");
    }
}

fn message(kind: MessageType) -> RaftMessage {
    let mut message = RaftMessage::default();
    message.set_msg_type(kind);
    message.set_from(1);
    message.set_to(2);
    message.set_term(7);
    message
}

fn envelope(message: &RaftMessage) -> Envelope {
    Envelope {
        protocol_version: 1,
        cluster_id: "synthetic-cluster".into(),
        cell_id: "synthetic-cell".into(),
        cell_incarnation: 17,
        from_node: 1,
        to_node: 2,
        codec: CODEC.into(),
        payload: message.write_to_bytes().unwrap(),
    }
}

async fn round_trip(probe: &mut RunningProbe, original: &RaftMessage) -> Observed {
    let request = envelope(original);
    let raw = request.payload.clone();
    let response = probe.client.exchange(request).await.unwrap().into_inner();
    assert_eq!(response.original_payload, raw);
    assert_eq!(response.decoded_term, original.get_term());
    assert_eq!(response.decoded_from, original.get_from());
    assert_eq!(response.decoded_to, original.get_to());
    assert_eq!(
        RaftMessage::parse_from_bytes(&response.original_payload).unwrap(),
        *original
    );
    response
}

#[tokio::test]
async fn append_entries_cross_real_grpc_without_field_loss() {
    let mut probe = RunningProbe::start().await;
    let mut original = message(MessageType::MsgAppend);
    original.set_index(41);
    original.set_log_term(6);
    original.set_commit(40);
    original.set_context(vec![0, 1, 0xff, 0, 42].into());
    let mut entry = Entry::default();
    entry.set_term(7);
    entry.set_index(42);
    entry.set_data(vec![0, 0xff, 5, 0, 9].into());
    entry.set_context(b"synthetic-request-17".to_vec().into());
    original.mut_entries().push(entry);
    round_trip(&mut probe, &original).await;
    assert_eq!(probe.decoded.load(Ordering::SeqCst), 1);
    probe.stop().await;
}

#[tokio::test]
async fn snapshot_metadata_and_joint_configuration_survive_transport() {
    let mut probe = RunningProbe::start().await;
    let mut original = message(MessageType::MsgSnapshot);
    let mut snapshot = Snapshot::default();
    snapshot.set_data(
        b"synthetic snapshot bytes, not an installed database"
            .to_vec()
            .into(),
    );
    let metadata = snapshot.mut_metadata();
    metadata.set_index(64);
    metadata.set_term(7);
    let members = metadata.mut_conf_state();
    members.set_voters(vec![1, 2, 3]);
    members.set_voters_outgoing(vec![1, 2, 4]);
    members.set_learners(vec![5]);
    members.set_learners_next(vec![4]);
    members.set_auto_leave(true);
    original.set_snapshot(snapshot);
    round_trip(&mut probe, &original).await;
    probe.stop().await;
}

#[tokio::test]
async fn read_index_context_and_rejection_fields_survive_transport() {
    let mut probe = RunningProbe::start().await;
    let mut read = message(MessageType::MsgReadIndex);
    // RawNode::read_index carries the request context in entries[0].data.
    let mut read_context = Entry::default();
    read_context.set_data(b"unique-read-context-17".to_vec().into());
    read.mut_entries().push(read_context);
    round_trip(&mut probe, &read).await;
    let mut reject = message(MessageType::MsgAppendResponse);
    reject.set_reject(true);
    reject.set_reject_hint(39);
    reject.set_log_term(6);
    reject.set_index(40);
    round_trip(&mut probe, &reject).await;
    assert_eq!(probe.decoded.load(Ordering::SeqCst), 2);
    probe.stop().await;
}

#[tokio::test]
async fn unknown_fields_remain_exact_bytes_through_outer_prost_envelope() {
    let mut probe = RunningProbe::start().await;
    let mut request = envelope(&message(MessageType::MsgHeartbeat));
    // Unknown inner protobuf field 100, varint 1, deliberately non-canonical encoding.
    request.payload.extend_from_slice(&[0xa0, 0x06, 0x81, 0x00]);
    let raw = request.payload.clone();
    let decoded = RaftMessage::parse_from_bytes(&raw).unwrap();
    assert_ne!(decoded.write_to_bytes().unwrap(), raw);
    let observed = probe.client.exchange(request).await.unwrap().into_inner();
    assert_eq!(observed.original_payload, raw);
    assert_eq!(observed.decoded_term, 7);
    probe.stop().await;
}

#[tokio::test]
async fn unsupported_wire_version_and_codec_are_rejected() {
    let mut probe = RunningProbe::start().await;
    let valid = envelope(&message(MessageType::MsgHeartbeat));
    let mut wrong_version = valid.clone();
    wrong_version.protocol_version = 2;
    let mut wrong_codec = valid;
    wrong_codec.codec = "unrecognized-codec".into();
    for request in [wrong_version, wrong_codec] {
        assert_eq!(
            probe.client.exchange(request).await.unwrap_err().code(),
            Code::FailedPrecondition
        );
    }
    assert_eq!(probe.decoded.load(Ordering::SeqCst), 0);
    probe.stop().await;
}

#[tokio::test]
async fn wrong_routing_identity_is_rejected_before_inner_decode() {
    let mut probe = RunningProbe::start().await;
    let valid = envelope(&message(MessageType::MsgHeartbeat));
    let variants: Vec<Envelope> = (0..5)
        .map(|field| {
            let mut request = valid.clone();
            match field {
                0 => request.cluster_id = "another-cluster".into(),
                1 => request.cell_id = "another-cell".into(),
                2 => request.cell_incarnation += 1,
                3 => request.from_node = 999,
                _ => request.to_node = 999,
            }
            request.payload = vec![0xff]; // A routing mismatch wins before codec decoding.
            request
        })
        .collect();
    for request in variants {
        assert_eq!(
            probe.client.exchange(request).await.unwrap_err().code(),
            Code::PermissionDenied
        );
    }
    assert_eq!(probe.decoded.load(Ordering::SeqCst), 0);
    probe.stop().await;
}

#[tokio::test]
async fn malformed_inner_bytes_and_envelope_payload_mismatch_are_rejected() {
    let mut probe = RunningProbe::start().await;
    let mut malformed = envelope(&message(MessageType::MsgHeartbeat));
    malformed.payload = vec![0xff];
    let mut from_mismatch = message(MessageType::MsgHeartbeat);
    from_mismatch.set_from(8);
    let mut to_mismatch = message(MessageType::MsgHeartbeat);
    to_mismatch.set_to(8);
    for request in [malformed, envelope(&from_mismatch), envelope(&to_mismatch)] {
        assert_eq!(
            probe.client.exchange(request).await.unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    assert_eq!(probe.decoded.load(Ordering::SeqCst), 0);
    probe.stop().await;
}

#[tokio::test]
async fn bounded_payload_and_grpc_message_are_independently_enforced() {
    let mut probe = RunningProbe::start().await;
    let mut oversized_payload = envelope(&message(MessageType::MsgHeartbeat));
    oversized_payload.payload = vec![0; MAX_PAYLOAD + 1];
    assert_eq!(
        probe
            .client
            .exchange(oversized_payload)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    let mut oversized_wire = envelope(&message(MessageType::MsgHeartbeat));
    oversized_wire.payload = vec![0; MAX_WIRE_MESSAGE + 1];
    assert_eq!(
        probe
            .client
            .exchange(oversized_wire)
            .await
            .unwrap_err()
            .code(),
        Code::OutOfRange
    );
    assert_eq!(probe.decoded.load(Ordering::SeqCst), 0);
    // Rejections do not kill the connection or turn later valid messages into failures.
    round_trip(&mut probe, &message(MessageType::MsgHeartbeat)).await;
    probe.stop().await;
}
