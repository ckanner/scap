use super::*;

fn header() -> Vec<u8> {
    let mut page = vec![0; PAGE_SIZE];
    page[..16].copy_from_slice(b"SQLite format 3\0");
    page[16] = 0x10;
    page
}

fn page(number: u32) -> PageChange {
    PageChange {
        number,
        bytes: header(),
    }
}

#[test]
fn headers_fail_closed_before_streaming_or_publication() {
    assert!(image::validate_header(&header()).is_ok());
    for bytes in [vec![0; PAGE_SIZE], {
        let mut bytes = header();
        bytes[17] = 1;
        bytes
    }] {
        assert!(matches!(
            image::validate_header(&bytes),
            Err(Error::InvalidImage)
        ));
    }
}

#[test]
fn page_deltas_require_complete_growth_and_unique_ordered_pages() {
    let mut bounded = limits();
    bounded.max_database_pages = 3;
    bounded.max_changed_pages = 2;
    let invalid = [
        PageBatch {
            size_after: 4,
            pages: vec![],
        },
        PageBatch {
            size_after: 3,
            pages: vec![page(1), page(2), page(3)],
        },
        PageBatch {
            size_after: 1,
            pages: vec![],
        },
        PageBatch {
            size_after: 1,
            pages: vec![page(0)],
        },
        PageBatch {
            size_after: 1,
            pages: vec![page(2)],
        },
        PageBatch {
            size_after: 1,
            pages: vec![PageChange {
                number: 1,
                bytes: vec![1],
            }],
        },
        PageBatch {
            size_after: 1,
            pages: vec![page(1), page(1)],
        },
        PageBatch {
            size_after: 2,
            pages: vec![page(2)],
        },
        PageBatch {
            size_after: 2,
            pages: vec![page(1)],
        },
        PageBatch {
            size_after: 1,
            pages: vec![PageChange {
                number: 1,
                bytes: vec![0; PAGE_SIZE],
            }],
        },
    ];
    for batch in invalid {
        assert!(
            matches!(
                image::validate_batch(0, &batch, bounded),
                Err(Error::InvalidImage)
            ),
            "{batch:?}"
        );
    }
    image::validate_batch(
        0,
        &PageBatch {
            size_after: 2,
            pages: vec![page(1), page(2)],
        },
        bounded,
    )
    .unwrap();
    image::validate_batch(
        2,
        &PageBatch {
            size_after: 2,
            pages: vec![],
        },
        bounded,
    )
    .unwrap();
    image::validate_batch(
        2,
        &PageBatch {
            size_after: 1,
            pages: vec![page(1)],
        },
        bounded,
    )
    .unwrap();
    image::validate_batch(
        2,
        &PageBatch {
            size_after: 3,
            pages: vec![page(3)],
        },
        bounded,
    )
    .unwrap();
    image::validate_batch(
        0,
        &PageBatch {
            size_after: 0,
            pages: vec![],
        },
        bounded,
    )
    .unwrap();

    let mut physical = limits();
    physical.max_database_pages = MAX_DATABASE_PAGES;
    image::validate_batch(
        MAX_DATABASE_PAGES - 1,
        &PageBatch {
            size_after: MAX_DATABASE_PAGES,
            pages: vec![page(MAX_DATABASE_PAGES)],
        },
        physical,
    )
    .unwrap();
    image::validate_batch(
        MAX_DATABASE_PAGES,
        &PageBatch {
            size_after: MAX_DATABASE_PAGES,
            pages: vec![],
        },
        physical,
    )
    .unwrap();
}

#[test]
fn only_new_lock_byte_extent_is_materialized_and_counted_in_the_dirty_budget() {
    let lock = image::LOCK_BYTE_PAGE;
    assert_eq!(lock, 262_145);
    let mut bounded = limits();
    bounded.max_database_pages = lock + 8;
    bounded.max_changed_pages = 4;
    let mut crossing = PageBatch {
        size_after: lock + 1,
        pages: vec![page(1), page(lock - 1), page(lock + 1)],
    };
    image::normalize_growth(lock - 2, &mut crossing, bounded).unwrap();
    assert_eq!(
        crossing.pages.iter().map(|p| p.number).collect::<Vec<_>>(),
        [1, lock - 1, lock, lock + 1]
    );
    assert_eq!(crossing.pages[2].bytes, vec![0; PAGE_SIZE]);
    let unchanged = crossing.clone();
    image::normalize_growth(lock - 2, &mut crossing, bounded).unwrap();
    assert_eq!(
        crossing, unchanged,
        "normalization must not duplicate a reserved frame"
    );

    // A previously existing reserved extent belongs to the authenticated base;
    // it is not zeroed or copied again during later growth or truncation.
    for (before, after, pages) in [
        (lock, lock + 1, vec![page(lock + 1)]),
        (lock + 1, lock + 2, vec![page(lock + 2)]),
        (lock + 2, lock + 1, vec![page(1)]),
        (lock - 1, lock - 1, vec![]),
    ] {
        let mut batch = PageBatch {
            size_after: after,
            pages,
        };
        let unchanged = batch.clone();
        image::normalize_growth(before, &mut batch, bounded).unwrap();
        assert_eq!(batch, unchanged);
    }
    let mut explicit = PageBatch {
        size_after: lock + 1,
        pages: vec![
            PageChange {
                number: lock,
                bytes: vec![7; PAGE_SIZE],
            },
            page(lock + 1),
        ],
    };
    image::normalize_growth(lock - 1, &mut explicit, bounded).unwrap();
    assert_eq!(
        explicit.pages[0].bytes,
        vec![7; PAGE_SIZE],
        "never overwrite explicitly supplied bytes"
    );

    let mut crossing = PageBatch {
        size_after: lock + 1,
        pages: vec![page(lock + 1)],
    };
    bounded.max_changed_pages = 1;
    assert!(matches!(
        image::normalize_growth(lock - 1, &mut crossing, bounded),
        Err(Error::InvalidImage)
    ));
    assert_eq!(
        crossing.pages.len(),
        1,
        "check the budget before allocating the reserved page"
    );
    bounded.max_changed_pages = 2;
    image::normalize_growth(lock - 1, &mut crossing, bounded).unwrap();
    assert_eq!(crossing.pages.len(), 2);
}

#[test]
fn lock_byte_normalization_never_repairs_an_ordinary_missing_growth_page() {
    let lock = image::LOCK_BYTE_PAGE;
    let mut bounded = limits();
    bounded.max_database_pages = lock + 8;
    for (before, after, pages) in [
        (lock - 3, lock + 1, vec![page(lock - 2), page(lock + 1)]),
        (lock - 1, lock + 2, vec![page(lock + 2)]),
        (lock - 1, lock + 1, vec![]),
        (lock - 1, lock, vec![]),
        (lock, lock + 2, vec![page(lock + 2)]),
    ] {
        let mut batch = PageBatch {
            size_after: after,
            pages,
        };
        assert!(matches!(
            image::normalize_growth(before, &mut batch, bounded),
            Err(Error::InvalidImage)
        ));
    }
}
