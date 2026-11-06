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
fn restored_geometry_and_headers_fail_closed() {
    assert!(image::validate(&[], 0).is_ok());
    assert!(image::validate(&header(), 1).is_ok());
    for bytes in [vec![1], vec![0; PAGE_SIZE], {
        let mut bytes = header();
        bytes[17] = 1;
        bytes
    }] {
        assert!(matches!(
            image::validate(&bytes, 1),
            Err(Error::InvalidImage)
        ));
    }
    assert!(matches!(
        image::validate(&header(), 0),
        Err(Error::InvalidImage)
    ));
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
            matches!(image::apply(&[], &batch, bounded), Err(Error::InvalidImage)),
            "{batch:?}"
        );
    }
    let base = image::apply(
        &[],
        &PageBatch {
            size_after: 2,
            pages: vec![page(1), page(2)],
        },
        bounded,
    )
    .unwrap();
    assert_eq!(base.len(), 2 * PAGE_SIZE);
    let same = image::apply(
        &base,
        &PageBatch {
            size_after: 2,
            pages: vec![],
        },
        bounded,
    )
    .unwrap();
    assert_eq!(base, same);
    let truncated = image::apply(
        &base,
        &PageBatch {
            size_after: 1,
            pages: vec![page(1)],
        },
        bounded,
    )
    .unwrap();
    assert_eq!(truncated, header());
    let grown = image::apply(
        &base,
        &PageBatch {
            size_after: 3,
            pages: vec![page(3)],
        },
        bounded,
    )
    .unwrap();
    assert_eq!(grown.len(), 3 * PAGE_SIZE);
    let empty = image::apply(
        &[],
        &PageBatch {
            size_after: 0,
            pages: vec![],
        },
        bounded,
    )
    .unwrap();
    assert!(empty.is_empty());
}
