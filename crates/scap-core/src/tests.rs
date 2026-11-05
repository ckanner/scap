use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

type Events = Rc<RefCell<Vec<&'static str>>>;

struct Consensus {
    decisions: VecDeque<Decision>,
    events: Events,
    panic: bool,
}

impl ConsensusPort for Consensus {
    fn propose(&mut self, write: &PreparedWrite) -> Decision {
        assert_eq!(write.physical_changes, vec![1, 2, 3]);
        self.events.borrow_mut().push("propose");
        assert!(!self.panic, "injected adapter panic");
        self.decisions
            .pop_front()
            .expect("unexpected repeated proposal")
    }
}

struct Visibility {
    events: Events,
    fail: bool,
    panic: bool,
}

impl VisibilityPort for Visibility {
    type Error = &'static str;

    fn publish(
        &mut self,
        write: &PreparedWrite,
        receipt: &CommitReceipt,
    ) -> Result<(), Self::Error> {
        assert_eq!(write.ticket, receipt.ticket);
        assert_eq!(self.events.borrow().last(), Some(&"propose"));
        self.events.borrow_mut().push("publish");
        assert!(!self.panic, "injected publication panic");
        if self.fail {
            Err("local publication failed")
        } else {
            Ok(())
        }
    }
}

fn write() -> PreparedWrite {
    PreparedWrite {
        ticket: CommitTicket {
            cell_id: 1,
            cell_incarnation: 2,
            database_id: 3,
            incarnation: 4,
            placement_generation: 5,
            owner_epoch: 6,
            worker_instance_id: 7,
            auth_epoch: 8,
            request_id: 9,
            predecessor: 10,
            payload_digest: [11; 32],
        },
        physical_changes: vec![1, 2, 3],
    }
}

fn receipt(write: &PreparedWrite) -> CommitReceipt {
    CommitReceipt {
        ticket: write.ticket.clone(),
        sequence: 11,
    }
}

fn coordinator(
    decisions: Vec<Decision>,
    fail: bool,
) -> (CommitCoordinator<Consensus, Visibility>, Events) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let consensus = Consensus {
        decisions: decisions.into(),
        events: events.clone(),
        panic: false,
    };
    let visibility = Visibility {
        events: events.clone(),
        fail,
        panic: false,
    };
    (CommitCoordinator::new(consensus, visibility), events)
}

#[test]
fn acknowledgement_requires_acceptance_then_publication() {
    let first = write();
    let first_receipt = receipt(&first);
    let mut second = first.clone();
    second.ticket.predecessor = first_receipt.sequence;
    second.ticket.request_id += 1;
    let second_receipt = CommitReceipt {
        ticket: second.ticket.clone(),
        sequence: 12,
    };
    let (mut c, events) = coordinator(
        vec![
            Decision::Accepted(first_receipt.clone()),
            Decision::Accepted(second_receipt.clone()),
        ],
        false,
    );
    assert_eq!(c.complete(&first), Ok(first_receipt));
    assert_eq!(c.complete(&second), Ok(second_receipt));
    assert_eq!(
        *events.borrow(),
        ["propose", "publish", "propose", "publish"]
    );
}

#[test]
fn every_authoritative_rejection_stops_without_publishing() {
    for reason in [
        Rejection::Fenced,
        Rejection::Unauthorized,
        Rejection::Conflict,
        Rejection::Retired,
        Rejection::InvalidTransaction,
    ] {
        let (mut c, events) = coordinator(vec![Decision::Rejected(reason)], false);
        assert_eq!(c.complete(&write()), Err(CompletionError::Rejected(reason)));
        assert_eq!(c.complete(&write()), Err(CompletionError::Stopped));
        assert_eq!(*events.borrow(), ["propose"]);
    }
}

#[test]
fn unknown_is_never_replayed_or_published() {
    let (mut c, events) = coordinator(vec![Decision::Unknown], false);
    assert_eq!(c.complete(&write()), Err(CompletionError::OutcomeUnknown));
    assert_eq!(c.complete(&write()), Err(CompletionError::Stopped));
    assert_eq!(*events.borrow(), ["propose"]);
}

#[test]
fn a_deduplicated_old_commit_never_republishes_pages_over_newer_state() {
    let first = write();
    let first_receipt = receipt(&first);
    let mut second = first.clone();
    second.ticket.predecessor = first_receipt.sequence;
    second.ticket.request_id += 1;
    let second_receipt = CommitReceipt {
        ticket: second.ticket.clone(),
        sequence: 12,
    };
    let (mut c, events) = coordinator(
        vec![
            Decision::Accepted(first_receipt.clone()),
            Decision::Accepted(second_receipt.clone()),
            Decision::AlreadyCommitted(first_receipt.clone()),
        ],
        false,
    );
    assert_eq!(c.complete(&first), Ok(first_receipt.clone()));
    assert_eq!(c.complete(&second), Ok(second_receipt));
    assert_eq!(
        c.complete(&first),
        Err(CompletionError::AlreadyCommitted {
            receipt: Box::new(first_receipt)
        })
    );
    assert_eq!(c.complete(&first), Err(CompletionError::Stopped));
    assert_eq!(
        *events.borrow(),
        ["propose", "publish", "propose", "publish", "propose"]
    );
}

#[test]
fn a_deduplication_receipt_is_still_bound_to_the_request() {
    let original = write();
    let mut wrong = receipt(&original);
    wrong.ticket.request_id += 1;
    let (mut c, events) = coordinator(vec![Decision::AlreadyCommitted(wrong)], false);
    assert_eq!(c.complete(&original), Err(CompletionError::InvalidReceipt));
    assert_eq!(*events.borrow(), ["propose"]);
}

#[test]
fn receipt_binds_every_identity_and_payload_field() {
    let original = write();
    for field in 0..11 {
        let mut wrong = receipt(&original);
        let t = &mut wrong.ticket;
        match field {
            0 => t.cell_id += 1,
            1 => t.cell_incarnation += 1,
            2 => t.database_id += 1,
            3 => t.incarnation += 1,
            4 => t.placement_generation += 1,
            5 => t.owner_epoch += 1,
            6 => t.worker_instance_id += 1,
            7 => t.auth_epoch += 1,
            8 => t.request_id += 1,
            9 => t.predecessor += 1,
            10 => t.payload_digest[0] += 1,
            _ => unreachable!(),
        }
        let (mut c, events) = coordinator(vec![Decision::Accepted(wrong)], false);
        assert_eq!(c.complete(&original), Err(CompletionError::InvalidReceipt));
        assert_eq!(c.complete(&original), Err(CompletionError::Stopped));
        assert_eq!(*events.borrow(), ["propose"]);
    }
}

#[test]
fn receipt_sequence_must_be_the_exact_successor() {
    let original = write();
    for sequence in [0, 10, 12, u64::MAX] {
        let mut wrong = receipt(&original);
        wrong.sequence = sequence;
        let (mut c, events) = coordinator(vec![Decision::Accepted(wrong)], false);
        assert_eq!(c.complete(&original), Err(CompletionError::InvalidReceipt));
        assert_eq!(*events.borrow(), ["propose"]);
    }
}

#[test]
fn exhausted_sequence_cannot_wrap_and_acknowledge() {
    let mut exhausted = write();
    exhausted.ticket.predecessor = u64::MAX;
    let wrong = CommitReceipt {
        ticket: exhausted.ticket.clone(),
        sequence: 0,
    };
    let (mut c, events) = coordinator(vec![Decision::Accepted(wrong)], false);
    assert_eq!(c.complete(&exhausted), Err(CompletionError::InvalidReceipt));
    assert_eq!(*events.borrow(), ["propose"]);
}

#[test]
fn publication_failure_preserves_the_committed_receipt() {
    let original = write();
    let accepted = receipt(&original);
    let (mut c, events) = coordinator(vec![Decision::Accepted(accepted.clone())], true);
    assert_eq!(
        c.complete(&original),
        Err(CompletionError::CommittedButUnavailable {
            receipt: Box::new(accepted),
            source: "local publication failed"
        })
    );
    assert_eq!(c.complete(&original), Err(CompletionError::Stopped));
    assert_eq!(*events.borrow(), ["propose", "publish"]);
}

#[test]
fn caught_adapter_panic_does_not_reenable_the_context() {
    for publish in [false, true] {
        let original = write();
        let (mut c, events) = coordinator(vec![Decision::Accepted(receipt(&original))], false);
        c.consensus.panic = !publish;
        c.visibility.panic = publish;
        assert!(catch_unwind(AssertUnwindSafe(|| c.complete(&original))).is_err());
        assert_eq!(c.complete(&original), Err(CompletionError::Stopped));
        assert_eq!(events.borrow().len(), if publish { 2 } else { 1 });
    }
}
