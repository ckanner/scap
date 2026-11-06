use crate::{Error, PageBatch, PageChange, WriterLimits, PAGE_SIZE};

// The pinned core's os.h/global.c place PENDING_BYTE at 0x40000000.
// btreeInt.h and btree.c exclude its whole page from database allocation.
pub(crate) const LOCK_BYTE_PAGE: u32 = 0x4000_0000 / PAGE_SIZE as u32 + 1;

/// SQLite never emits a WAL frame for its lock-byte page. When a fresh private
/// file first grows past that page, Unix file extension leaves those bytes zero
/// (the core/VFS never write database content there). Materialize that one new
/// reserved extent in the authoritative batch before enforcing full growth.
/// Existing authoritative bytes and explicit frames are never overwritten;
/// this is not a rule for filling arbitrary missing pages or sparse restores.
pub(crate) fn normalize_growth(
    old_pages: u32,
    batch: &mut PageBatch,
    limits: WriterLimits,
) -> Result<(), Error> {
    if old_pages < LOCK_BYTE_PAGE && batch.size_after > LOCK_BYTE_PAGE {
        if let Err(position) = batch
            .pages
            .binary_search_by_key(&LOCK_BYTE_PAGE, |page| page.number)
        {
            if batch.pages.len() >= limits.max_changed_pages as usize {
                return Err(Error::InvalidImage);
            }
            batch.pages.insert(
                position,
                PageChange {
                    number: LOCK_BYTE_PAGE,
                    bytes: vec![0; PAGE_SIZE],
                },
            );
        }
    }
    validate_batch(old_pages, batch, limits)
}

pub(crate) fn validate_header(page: &[u8]) -> Result<(), Error> {
    if &page[..16] != b"SQLite format 3\0" || page[16..18] != [0x10, 0] {
        return Err(Error::InvalidImage);
    }
    Ok(())
}

/// Validate changed-page geometry without cloning or reconstructing the base.
/// Newly allocated pages must all be present; truncation may discard old pages.
/// The authenticated base was streamed and structurally checked during open.
pub(crate) fn validate_batch(
    old_pages: u32,
    batch: &PageBatch,
    limits: WriterLimits,
) -> Result<(), Error> {
    if batch.size_after > limits.max_database_pages
        || batch.pages.len() > limits.max_changed_pages as usize
    {
        return Err(Error::InvalidImage);
    }
    if batch.pages.is_empty() && batch.size_after != old_pages {
        return Err(Error::InvalidImage);
    }
    let mut previous = 0;
    let mut next_new = u64::from(old_pages) + 1;
    for page in &batch.pages {
        if page.number == 0 || page.number > batch.size_after || page.bytes.len() != PAGE_SIZE {
            return Err(Error::InvalidImage);
        }
        if page.number <= previous {
            return Err(Error::InvalidImage);
        }
        previous = page.number;
        if page.number == 1 {
            validate_header(&page.bytes)?;
        }
        if page.number > old_pages {
            if u64::from(page.number) != next_new {
                return Err(Error::InvalidImage);
            }
            next_new += 1;
        }
    }
    if batch.size_after > old_pages && next_new != u64::from(batch.size_after) + 1 {
        return Err(Error::InvalidImage);
    }
    Ok(())
}
