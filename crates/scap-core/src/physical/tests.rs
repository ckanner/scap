use super::*;

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
        request_id: u128::from(image.head.revision) + 100,
        predecessor: image.head.revision,
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
        ticket: prepared.write.ticket.clone(),
        sequence: prepared.image.head.revision,
    }
}

fn committed() -> Image {
    let staged = empty().prepare(ticket(&empty()), batch()).unwrap();
    let result = receipt(&staged);
    staged.accepted(&result).unwrap()
}

#[test]
fn limits_and_identity_are_validated_before_creating_a_capability() {
    assert_eq!(empty().head().image_digest, digest(&[]));
    assert_eq!(empty().limits(), limits());
    let bad_limits = [
        Limits {
            max_database_pages: 0,
            ..limits()
        },
        Limits {
            max_database_pages: MAX_DATABASE_PAGES + 1,
            ..limits()
        },
        Limits {
            max_changed_pages: 0,
            ..limits()
        },
        Limits {
            max_changed_pages: 5,
            ..limits()
        },
        Limits {
            max_transaction_bytes: HEADER_SIZE as u32 - 1,
            ..limits()
        },
    ];
    for value in bad_limits {
        assert_eq!(Image::empty(identity(), value), Err(Error::Limits));
    }
    for field in 0..5 {
        let mut value = identity();
        match field {
            0 => value.cell.cell_id = 0,
            1 => value.cell.cell_incarnation = 0,
            2 => value.database.database_id = 0,
            3 => value.database.incarnation = 0,
            _ => value.database.placement_generation = 0,
        }
        assert_eq!(Image::empty(value, limits()), Err(Error::Identity));
    }
}

#[test]
fn preparation_is_immutable_and_acceptance_requires_the_exact_receipt() {
    let original = empty();
    let staged = original.prepare(ticket(&original), batch()).unwrap();
    assert_eq!(original, empty());
    assert_eq!(staged.image.head().revision, 1);
    assert_eq!(staged.image.bytes(), page(1, 9).bytes);
    assert_eq!(staged.write().physical_changes.len(), HEADER_SIZE + 4100);
    assert_eq!(&staged.write().physical_changes[..8], b"SCAPIMG!");
    assert_eq!(
        staged.write().ticket.payload_digest,
        digest(&staged.write().physical_changes)
    );
    let accepted = receipt(&staged);
    let mut wrong = accepted.clone();
    wrong.ticket.worker_instance_id += 1;
    assert_eq!(staged.clone().accepted(&wrong), Err(Error::Receipt));
    wrong = accepted.clone();
    wrong.sequence += 1;
    assert_eq!(staged.clone().accepted(&wrong), Err(Error::Receipt));
    assert_eq!(staged.clone().accepted(&accepted).unwrap(), staged.image);
    assert_eq!(
        original
            .replay(&accepted, &staged.write().physical_changes)
            .unwrap(),
        staged.image
    );
}

#[test]
fn empty_records_grow_shrink_and_changed_pages_keep_a_complete_image() {
    // Independent v1 format vector: empty database, identity (17,2,23,3,4),
    // predecessor 0, empty SHA-256 as both image digests, and no page records.
    let vector = empty().prepare(ticket(&empty()), noop(&empty())).unwrap();
    assert_eq!(
        vector.write().ticket.payload_digest,
        [
            223, 158, 157, 206, 167, 62, 146, 174, 156, 26, 103, 217, 128, 108, 3, 72, 119, 77,
            189, 63, 126, 158, 142, 128, 90, 220, 216, 249, 106, 231, 170, 90,
        ]
    );
    for image in [empty(), committed()] {
        let staged = image.prepare(ticket(&image), noop(&image)).unwrap();
        let next = staged.clone().accepted(&receipt(&staged)).unwrap();
        assert_eq!(next.head().revision, image.head().revision + 1);
        assert_eq!(next.head().image_digest, image.head().image_digest);
        assert_eq!(next.bytes(), image.bytes());
        assert_eq!(
            image
                .replay(&receipt(&staged), &staged.write().physical_changes)
                .unwrap(),
            next
        );
    }
    let base = committed();
    let growth = PageBatch {
        size_after: 3,
        pages: vec![page(2, 2), page(3, 3)],
    };
    let prepared = base.prepare(ticket(&base), growth).unwrap();
    let grown = prepared.clone().accepted(&receipt(&prepared)).unwrap();
    assert_eq!(&grown.bytes()[..PAGE_SIZE], base.bytes());
    assert_eq!(&grown.bytes()[PAGE_SIZE..2 * PAGE_SIZE], page(2, 2).bytes);
    assert_eq!(&grown.bytes()[2 * PAGE_SIZE..], page(3, 3).bytes);
    let shrinking = grown.prepare(ticket(&grown), batch()).unwrap();
    assert_eq!(shrinking.image.bytes(), base.bytes());
    assert_eq!(shrinking.image.head().revision, 3);
}

#[test]
fn every_ticket_binding_is_independently_checked() {
    let image = empty();
    for field in 0..11 {
        let mut value = ticket(&image);
        match field {
            0 => value.cell_id += 1,
            1 => value.cell_incarnation += 1,
            2 => value.database_id += 1,
            3 => value.incarnation += 1,
            4 => value.placement_generation += 1,
            5 => value.predecessor += 1,
            6 => value.owner_epoch = 0,
            7 => value.worker_instance_id = 0,
            8 => value.auth_epoch = 0,
            9 => value.request_id = 0,
            _ => value.payload_digest = [1; 32],
        }
        assert_eq!(image.prepare(value, batch()), Err(Error::Ticket));
        assert_eq!(image, empty());
    }
}

#[test]
fn physical_bounds_and_page_order_reject_without_mutating_the_base() {
    let image = empty();
    for value in [
        PageBatch {
            size_after: 5,
            pages: vec![],
        },
        PageBatch {
            size_after: 4,
            pages: vec![page(1, 1), page(2, 2), page(3, 3), page(4, 4)],
        },
    ] {
        assert_eq!(image.prepare(ticket(&image), value), Err(Error::TooLarge));
    }
    let image = Image::empty(
        identity(),
        Limits {
            max_transaction_bytes: HEADER_SIZE as u32,
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(image.prepare(ticket(&image), batch()), Err(Error::TooLarge));
    for changes in [vec![page(1, 1), page(1, 2)], vec![page(2, 2), page(1, 1)]] {
        let image = committed();
        assert_eq!(
            image.prepare(
                ticket(&image),
                PageBatch {
                    size_after: 2,
                    pages: changes
                }
            ),
            Err(Error::PageOrder)
        );
        assert_eq!(image, committed());
    }
    for changes in [
        vec![page(0, 0)],
        vec![page(2, 2)],
        vec![PageChange {
            number: 1,
            bytes: vec![0; PAGE_SIZE - 1],
        }],
    ] {
        assert_eq!(
            empty().prepare(
                ticket(&empty()),
                PageBatch {
                    size_after: 1,
                    pages: changes
                }
            ),
            Err(Error::Malformed)
        );
    }
}

#[test]
fn missing_pages_invalid_sqlite_headers_and_revision_overflow_fail_closed() {
    for value in [
        PageBatch {
            size_after: 1,
            pages: vec![],
        },
        PageBatch {
            size_after: 2,
            pages: vec![page(2, 2)],
        },
        PageBatch {
            size_after: 2,
            pages: vec![page(1, 1)],
        },
    ] {
        assert_eq!(
            empty().prepare(ticket(&empty()), value),
            Err(Error::MissingPage)
        );
    }
    assert_eq!(
        committed().prepare(ticket(&committed()), noop(&empty())),
        Err(Error::MissingPage)
    );
    for offset in [0, 16] {
        let mut value = batch();
        value.pages[0].bytes[offset] ^= 1;
        assert_eq!(
            empty().prepare(ticket(&empty()), value),
            Err(Error::SqliteHeader)
        );
    }
    let mut exhausted = empty();
    exhausted.head.revision = u64::MAX;
    let mut bound = ticket(&empty());
    bound.predecessor = u64::MAX;
    assert_eq!(exhausted.prepare(bound, batch()), Err(Error::Exhausted));
}

fn replay_changed(mutator: impl FnOnce(&mut Vec<u8>)) -> Result<Image, Error> {
    let source = empty();
    let staged = source.prepare(ticket(&source), batch()).unwrap();
    let mut accepted = receipt(&staged);
    let mut changes = staged.write.physical_changes;
    mutator(&mut changes);
    accepted.ticket.payload_digest = digest(&changes);
    source.replay(&accepted, &changes)
}

#[test]
fn replay_checks_ticket_receipt_size_and_full_payload_integrity() {
    let staged = empty().prepare(ticket(&empty()), batch()).unwrap();
    let accepted = receipt(&staged);
    let mut bad = accepted.clone();
    bad.ticket.cell_id += 1;
    assert_eq!(
        empty().replay(&bad, &staged.write.physical_changes),
        Err(Error::Ticket)
    );
    bad = accepted.clone();
    bad.sequence += 1;
    assert_eq!(
        empty().replay(&bad, &staged.write.physical_changes),
        Err(Error::Receipt)
    );
    bad = accepted.clone();
    bad.ticket.payload_digest[0] ^= 1;
    assert_eq!(
        empty().replay(&bad, &staged.write.physical_changes),
        Err(Error::Integrity)
    );
    assert_eq!(
        empty().replay(&accepted, &[0; HEADER_SIZE - 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        empty().replay(&accepted, &vec![0; 20_001]),
        Err(Error::TooLarge)
    );
    let mut exhausted = empty();
    exhausted.head.revision = u64::MAX;
    bad = accepted;
    bad.ticket.predecessor = u64::MAX;
    assert_eq!(
        exhausted.replay(&bad, &staged.write.physical_changes),
        Err(Error::Receipt)
    );
}

#[test]
fn replay_rejects_wrong_format_and_every_independent_base_binding() {
    for offset in [0, 8, 12] {
        assert_eq!(
            replay_changed(|bytes| bytes[offset] ^= 1),
            Err(Error::Malformed)
        );
    }
    for offset in [16, 32, 40, 56, 64, 72, 80] {
        assert_eq!(replay_changed(|bytes| bytes[offset] ^= 1), Err(Error::Head));
    }
    assert_eq!(
        replay_changed(|bytes| bytes[112] ^= 1),
        Err(Error::Integrity)
    );
    assert_eq!(
        replay_changed(|bytes| bytes[148..152].copy_from_slice(&4_u32.to_le_bytes())),
        Err(Error::Malformed)
    );
    assert_eq!(
        replay_changed(|bytes| {
            bytes.pop();
        }),
        Err(Error::Malformed)
    );
    assert_eq!(
        replay_changed(|bytes| bytes[144..148].copy_from_slice(&5_u32.to_le_bytes())),
        Err(Error::TooLarge)
    );
    assert_eq!(
        replay_changed(|bytes| bytes[HEADER_SIZE] = 0),
        Err(Error::Malformed)
    );
}

#[test]
fn snapshots_round_trip_empty_and_nonempty_images_and_preserve_limits() {
    for image in [empty(), committed()] {
        assert_eq!(
            Image::from_snapshot(image.snapshot(), limits()).unwrap(),
            image
        );
    }
    let mut empty_later = empty().snapshot();
    empty_later.head.revision = 9;
    assert_eq!(
        Image::from_snapshot(empty_later, limits())
            .unwrap()
            .head()
            .revision,
        9
    );
}

#[test]
fn snapshot_bounds_identity_header_revision_and_digest_fail_closed() {
    let good = committed().snapshot();
    assert_eq!(
        Image::from_snapshot(
            good.clone(),
            Limits {
                max_database_pages: 0,
                ..limits()
            }
        ),
        Err(Error::Limits)
    );
    let mut bad = good.clone();
    bad.head.identity.database.incarnation = 0;
    assert_eq!(Image::from_snapshot(bad, limits()), Err(Error::Identity));
    let mut bad = good.clone();
    bad.bytes.resize(5 * PAGE_SIZE, 0);
    assert_eq!(Image::from_snapshot(bad, limits()), Err(Error::TooLarge));
    let mut bad = good.clone();
    bad.bytes.pop();
    assert_eq!(Image::from_snapshot(bad, limits()), Err(Error::Malformed));
    let mut bad = good.clone();
    bad.head.revision = 0;
    assert_eq!(Image::from_snapshot(bad, limits()), Err(Error::Head));
    for offset in [0, 16] {
        let mut bad = good.clone();
        bad.bytes[offset] ^= 1;
        bad.head.image_digest = digest(&bad.bytes);
        assert_eq!(
            Image::from_snapshot(bad, limits()),
            Err(Error::SqliteHeader)
        );
    }
    let mut bad = good.clone();
    bad.head.image_digest[0] ^= 1;
    assert_eq!(Image::from_snapshot(bad, limits()), Err(Error::Integrity));
    let mut bad = empty().snapshot();
    bad.head.image_digest[0] ^= 1;
    assert_eq!(Image::from_snapshot(bad, limits()), Err(Error::Integrity));
    assert_eq!(Image::from_snapshot(good, limits()).unwrap(), committed());
}

#[test]
fn replay_from_a_snapshot_keeps_the_exact_receipt_and_image_chain() {
    let image = committed();
    let staged = image
        .prepare(
            ticket(&image),
            PageBatch {
                size_after: 2,
                pages: vec![page(2, 41)],
            },
        )
        .unwrap();
    let accepted = receipt(&staged);
    let restored = Image::from_snapshot(image.snapshot(), limits()).unwrap();
    assert_eq!(
        restored
            .replay(&accepted, &staged.write().physical_changes)
            .unwrap(),
        staged.accepted(&accepted).unwrap()
    );
}
