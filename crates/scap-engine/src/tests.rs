use super::*;
use raft::eraftpb::Entry;
use scap_cell::{
    encode_command, CellApplication, CellIdentity, Command, CommandKind, DatabaseIdentity, Grant,
    Outcome, OwnerToken, ADMIN, READ, WRITE,
};
use scap_raft_driver::Application;

use sha2::{Digest, Sha256};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn identity() -> EngineIdentity {
    EngineIdentity {
        cell: CellIdentity {
            cell_id: 17,
            cell_incarnation: 2,
        },
        database: DatabaseIdentity {
            database_id: 23,
            incarnation: 3,
            placement_generation: 4,
        },
    }
}

fn limits() -> Limits {
    Limits {
        max_database_pages: 4,
        max_changed_pages: 3,
        max_transaction_bytes: 20_000,
    }
}

fn empty() -> Image {
    Image::empty(identity(), limits()).unwrap()
}

fn ticket(image: &Image) -> CommitTicket {
    CommitTicket {
        cell_id: identity().cell.cell_id,
        cell_incarnation: identity().cell.cell_incarnation,
        database_id: identity().database.database_id,
        incarnation: identity().database.incarnation,
        placement_generation: identity().database.placement_generation,
        owner_epoch: 1,
        worker_instance_id: 90,
        auth_epoch: 1,
        request_id: u128::from(image.head().revision) + 100,
        predecessor: image.head().revision,
        payload_digest: [0; 32],
    }
}

fn page(number: u32, fill: u8) -> PageChange {
    let mut bytes = vec![fill; PAGE_SIZE];
    if number == 1 {
        bytes[..16].copy_from_slice(SQLITE_MAGIC);
        bytes[16..18].copy_from_slice(&[0x10, 0]);
    }
    PageChange { number, bytes }
}

fn batch() -> PageBatch {
    PageBatch {
        size_after: 1,
        pages: vec![page(1, 9)],
    }
}

fn noop(image: &Image) -> PageBatch {
    PageBatch {
        size_after: (image.bytes().len() / PAGE_SIZE) as u32,
        pages: vec![],
    }
}

fn receipt(prepared: &Prepared) -> CommitReceipt {
    CommitReceipt {
        ticket: prepared.write().ticket.clone(),
        sequence: prepared.write().ticket.predecessor + 1,
    }
}

fn cell_limits() -> scap_cell::Limits {
    scap_cell::Limits {
        max_state_bytes: 128_000,
        max_command_bytes: 30_000,
        max_databases: 1,
        max_policy_grants: 2,
        max_admin_operations: 10,
        max_requests_per_database: 16,
        max_transaction_bytes: 20_000,
        max_result_bytes: 128,
    }
}

fn admission() -> Admission {
    Admission {
        principal_id: 11,
        credential_id: 12,
        admission_id: 13,
        auth_epoch: 1,
    }
}

fn apply(state: &mut CellState, kind: CommandKind) -> Outcome {
    let command = Command {
        cell: identity().cell,
        database: identity().database,
        admission: admission(),
        kind,
    };
    let position = Position {
        term: 1,
        index: state.position().index + 1,
    };
    let entry = Entry {
        term: position.term,
        index: position.index,
        data: encode_command(&command, cell_limits()).unwrap().into(),
        ..Entry::default()
    };
    let bytes = CellApplication::new(identity().cell, cell_limits())
        .unwrap()
        .apply(&state.encode(), &[entry])
        .unwrap();
    *state = CellState::decode_bound(&bytes, identity().cell, position, cell_limits()).unwrap();
    state.last_outcome().unwrap().outcome.clone()
}

fn cell() -> CellState {
    let mut state = CellState::bootstrap(
        identity().cell,
        admission().principal_id,
        Position { term: 1, index: 1 },
        cell_limits(),
    )
    .unwrap();
    for kind in [
        CommandKind::Create {
            operation_id: 1,
            policy: vec![Grant {
                principal_id: admission().principal_id,
                permissions: READ | WRITE | ADMIN,
            }],
        },
        CommandKind::ClaimOwner {
            operation_id: 2,
            expected_epoch: 0,
            worker_instance_id: 90,
        },
        CommandKind::ActivateOwner {
            operation_id: 3,
            token: OwnerToken {
                epoch: 1,
                worker_instance_id: 90,
            },
            restored_revision: 0,
            restored_hash: [0; 32],
        },
    ] {
        assert!(matches!(
            apply(&mut state, kind),
            Outcome::Administrative(_)
        ));
    }
    state
}

fn target(state: &CellState) -> RecoveryTarget {
    let database = state.database(identity().database.database_id).unwrap();
    RecoveryTarget {
        position: state.position(),
        revision: database.revision,
        commit_hash: database.commit_hash,
    }
}

fn recover(state: &CellState) -> Result<Image, Error> {
    Image::recover(state, identity(), admission(), target(state), limits())
}

#[test]
fn authoritative_recovery_rebuilds_exact_pages_and_empty_commits_without_sql() {
    let mut state = cell();
    assert_eq!(recover(&state).unwrap(), empty());
    let mut image = empty();
    for step in 0..3 {
        let pages = match step {
            0 => batch(),
            1 => PageBatch {
                size_after: 2,
                pages: vec![page(2, 44)],
            },
            _ => noop(&image),
        };
        let staged = image.prepare(ticket(&image), pages).unwrap();
        let outcome = apply(
            &mut state,
            CommandKind::Commit {
                write: staged.write().clone(),
                request_fingerprint: [step; 32],
                result: vec![step, 0, 255],
            },
        );
        let Outcome::Accepted(result) = outcome else {
            panic!("not accepted")
        };
        image = staged.accepted(&result.receipt).unwrap();
        assert_eq!(recover(&state).unwrap(), image);
    }
    assert_eq!(image.head().revision, 3);
    assert_eq!(&image.bytes()[PAGE_SIZE..], page(2, 44).bytes);
    assert_ne!(image.head().image_digest, target(&state).commit_hash);
}

#[test]
fn recovery_requires_the_exact_authoritative_view_and_current_authorization() {
    let state = cell();
    let mut wrong_identity = identity();
    wrong_identity.cell.cell_incarnation += 1;
    assert_eq!(
        Image::recover(
            &state,
            wrong_identity,
            admission(),
            target(&state),
            limits()
        ),
        Err(Error::Head)
    );
    for field in 0..3 {
        let mut expected = target(&state);
        match field {
            0 => expected.position.index += 1,
            1 => expected.revision += 1,
            _ => expected.commit_hash[0] ^= 1,
        }
        assert_eq!(
            Image::recover(&state, identity(), admission(), expected, limits()),
            Err(Error::Head)
        );
    }
    let mut wrong_admission = admission();
    wrong_admission.auth_epoch += 1;
    assert_eq!(
        Image::recover(
            &state,
            identity(),
            wrong_admission,
            target(&state),
            limits()
        ),
        Err(Error::Authorization(Reject::Unauthorized))
    );
    wrong_identity = identity();
    wrong_identity.database.incarnation += 1;
    assert_eq!(
        Image::recover(
            &state,
            wrong_identity,
            admission(),
            target(&state),
            limits()
        ),
        Err(Error::Authorization(Reject::Fenced))
    );
    assert_eq!(
        Image::recover(
            &state,
            identity(),
            admission(),
            target(&state),
            Limits {
                max_database_pages: 0,
                ..limits()
            }
        ),
        Err(Error::Limits)
    );
}

#[test]
fn a_cell_accepted_opaque_transaction_with_an_invalid_engine_format_blocks_recovery() {
    let mut state = cell();
    let changes = vec![0; HEADER_SIZE];
    let mut bound = ticket(&empty());
    bound.payload_digest = digest(&changes);
    assert!(matches!(
        apply(
            &mut state,
            CommandKind::Commit {
                write: PreparedWrite {
                    ticket: bound,
                    physical_changes: changes
                },
                request_fingerprint: [3; 32],
                result: vec![9],
            }
        ),
        Outcome::Accepted(_)
    ));
    assert_eq!(recover(&state), Err(Error::Malformed));
}

#[test]
fn recovery_uses_a_nonzero_baseline_and_only_its_contiguous_tail() {
    let mut state = cell();
    let mut image = empty();
    assert_eq!(image.limits(), limits());
    for step in 0..9 {
        let staged = image
            .prepare(
                ticket(&image),
                PageBatch {
                    size_after: 1,
                    pages: vec![page(1, step)],
                },
            )
            .unwrap();
        let Outcome::Accepted(commit) = apply(
            &mut state,
            CommandKind::Commit {
                write: staged.write().clone(),
                request_fingerprint: [step; 32],
                result: vec![step],
            },
        ) else {
            panic!("physical commit rejected");
        };
        image = staged.accepted(&commit.receipt).unwrap();
        assert_eq!(recover(&state).unwrap(), image);
    }
    let recovery = state
        .recovery_source(identity().database, admission())
        .unwrap();
    assert_eq!(recovery.base.unwrap().revision, 8);
    assert_eq!(recovery.tail.len(), 1);
    let view = state.database(identity().database.database_id).unwrap();
    assert_eq!(view.base_revision, 8);
    assert_eq!(view.tail_entries, 1);
    assert_eq!(view.tail_bytes, (HEADER_SIZE + 4 + PAGE_SIZE) as u64);
    assert_eq!(image.head().revision, 9);
    assert_eq!(image.bytes(), page(1, 8).bytes);
}

#[test]
fn recovery_rejects_a_valid_baseline_that_exceeds_the_workers_page_budget() {
    let mut state = cell();
    let mut image = empty();
    for step in 0..8 {
        let pages = if step == 0 {
            PageBatch {
                size_after: 2,
                pages: vec![page(1, 9), page(2, 17)],
            }
        } else {
            noop(&image)
        };
        let staged = image.prepare(ticket(&image), pages).unwrap();
        let Outcome::Accepted(commit) = apply(
            &mut state,
            CommandKind::Commit {
                write: staged.write().clone(),
                request_fingerprint: [step; 32],
                result: vec![step],
            },
        ) else {
            panic!("physical commit rejected");
        };
        image = staged.accepted(&commit.receipt).unwrap();
    }
    let source = state
        .recovery_source(identity().database, admission())
        .unwrap();
    assert_eq!(source.base.unwrap().revision, 8);
    assert!(source.tail.is_empty());
    assert_eq!(recover(&state).unwrap(), image);
    let before = state.encode();
    assert_eq!(
        Image::recover(
            &state,
            identity(),
            admission(),
            target(&state),
            Limits {
                max_database_pages: 1,
                max_changed_pages: 1,
                ..limits()
            }
        ),
        Err(Error::TooLarge)
    );
    assert_eq!(state.encode(), before);
    assert_eq!(recover(&state).unwrap(), image);
}

#[test]
fn physical_error_mapping_keeps_the_public_engine_error_contract() {
    assert_eq!(Error::from(physical::Error::Limits), Error::Limits);
    assert_eq!(Error::from(physical::Error::Identity), Error::Identity);
    assert_eq!(Error::from(physical::Error::Ticket), Error::Ticket);
    assert_eq!(Error::from(physical::Error::Receipt), Error::Receipt);
    assert_eq!(Error::from(physical::Error::Exhausted), Error::Exhausted);
    assert_eq!(Error::from(physical::Error::TooLarge), Error::TooLarge);
    assert_eq!(Error::from(physical::Error::Malformed), Error::Malformed);
    assert_eq!(Error::from(physical::Error::PageOrder), Error::PageOrder);
    assert_eq!(
        Error::from(physical::Error::MissingPage),
        Error::MissingPage
    );
    assert_eq!(
        Error::from(physical::Error::SqliteHeader),
        Error::SqliteHeader
    );
    assert_eq!(Error::from(physical::Error::Head), Error::Head);
    assert_eq!(Error::from(physical::Error::Integrity), Error::Integrity);
    let mut wrong = ticket(&empty());
    wrong.payload_digest[0] = 1;
    assert_eq!(empty().prepare(wrong, batch()), Err(Error::Ticket));
    let prepared = empty().prepare(ticket(&empty()), batch()).unwrap();
    let mut wrong = receipt(&prepared);
    wrong.sequence += 1;
    assert_eq!(prepared.accepted(&wrong), Err(Error::Receipt));
}
