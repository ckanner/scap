//! A real formal-adapter writer, killed while holding a durable acceptance.
mod common;
mod protocol;

use common::{engine_identity, engine_limits, kill_batch, writer_limits, KILL_REQUEST};
use protocol::{read_frame, write_frame, Wire, TIMEOUT};
use scap_core::{CommitReceipt, CommitTicket, PreparedWrite};
use scap_engine::Image;
use scap_sqlite::{CommitGate, GateDecision, LookupDecision, SqliteWriter};
use std::io;
use std::sync::mpsc::{self, Receiver};

struct ParentGate {
    input: Receiver<Result<Wire, String>>,
}

impl ParentGate {
    fn receive(&self) -> Wire {
        self.input.recv_timeout(TIMEOUT).unwrap().unwrap()
    }
}

impl CommitGate for ParentGate {
    fn lookup(&mut self, ticket: &CommitTicket, fingerprint: [u8; 32]) -> LookupDecision {
        assert_eq!(ticket.request_id, KILL_REQUEST);
        assert_eq!(
            fingerprint,
            scap_sql::request_fingerprint(&kill_batch(), writer_limits().sql).unwrap()
        );
        write_frame(&mut io::stdout().lock(), &Wire::Lookup).unwrap();
        assert_eq!(self.receive(), Wire::NotFound);
        LookupDecision::NotFound
    }

    fn propose(&mut self, write: &PreparedWrite, _: [u8; 32], result: &[u8]) -> GateDecision {
        write_frame(
            &mut io::stdout().lock(),
            &Wire::Proposal {
                changes: write.physical_changes.clone(),
                result: result.to_vec(),
            },
        )
        .unwrap();
        assert_eq!(self.receive(), Wire::Accept);
        // The parent sent Accept only after the actual durable quorum and exact
        // business outcome. Native publication is still below this call stack.
        write_frame(&mut io::stdout().lock(), &Wire::AcceptedHeld).unwrap();
        assert_eq!(self.receive(), Wire::Proceed);
        GateDecision::Accepted(CommitReceipt {
            ticket: write.ticket.clone(),
            sequence: 1,
        })
    }
}

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    assert_eq!(arguments.len(), 2);
    let (sender, input) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        loop {
            let frame = read_frame(&mut input).map_err(|error| error.to_string());
            let failed = frame.is_err();
            if sender.send(frame).is_err() || failed {
                break;
            }
        }
    });
    let image = Image::empty(engine_identity(), engine_limits()).unwrap();
    let mut writer = SqliteWriter::create_new(
        std::path::Path::new(&arguments[1]),
        image,
        writer_limits(),
        ParentGate { input },
    )
    .unwrap();
    let identity = engine_identity();
    let ticket = CommitTicket {
        cell_id: identity.cell.cell_id,
        cell_incarnation: identity.cell.cell_incarnation,
        database_id: identity.database.database_id,
        incarnation: identity.database.incarnation,
        placement_generation: identity.database.placement_generation,
        owner_epoch: 1,
        worker_instance_id: 9001,
        auth_epoch: 1,
        request_id: KILL_REQUEST,
        predecessor: 0,
        payload_digest: [0; 32],
    };
    let completed = writer.execute(ticket, &kill_batch()).unwrap();
    let result = scap_sql::encode_result(&completed.result, writer_limits().sql).unwrap();
    write_frame(&mut io::stdout().lock(), &Wire::Ack(result)).unwrap();
}
