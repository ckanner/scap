use crate::{Error, PageBatch, WriterLimits, PAGE_SIZE};

pub(crate) fn validate(bytes: &[u8], max_pages: u32) -> Result<(), Error> {
    if !bytes.len().is_multiple_of(PAGE_SIZE) || bytes.len() / PAGE_SIZE > max_pages as usize {
        return Err(Error::InvalidImage);
    }
    if !bytes.is_empty() && (&bytes[..16] != b"SQLite format 3\0" || bytes[16..18] != [0x10, 0]) {
        return Err(Error::InvalidImage);
    }
    Ok(())
}

/// Validate the complete changed-page geometry before allocating or publishing.
/// Newly allocated pages must all be present; truncation may discard old pages.
pub(crate) fn apply(
    base: &[u8],
    batch: &PageBatch,
    limits: WriterLimits,
) -> Result<Vec<u8>, Error> {
    if batch.size_after > limits.max_database_pages
        || batch.pages.len() > limits.max_changed_pages as usize
    {
        return Err(Error::InvalidImage);
    }
    let old_pages = base.len() / PAGE_SIZE;
    if batch.pages.is_empty() && batch.size_after as usize != old_pages {
        return Err(Error::InvalidImage);
    }
    let mut previous = 0;
    let mut next_new = old_pages + 1;
    for page in &batch.pages {
        if page.number == 0 || page.number > batch.size_after || page.bytes.len() != PAGE_SIZE {
            return Err(Error::InvalidImage);
        }
        if page.number <= previous {
            return Err(Error::InvalidImage);
        }
        previous = page.number;
        if page.number as usize > old_pages {
            if page.number as usize != next_new {
                return Err(Error::InvalidImage);
            }
            next_new += 1;
        }
    }
    if batch.size_after as usize > old_pages && next_new != batch.size_after as usize + 1 {
        return Err(Error::InvalidImage);
    }
    let mut bytes = base.to_vec();
    bytes.resize(batch.size_after as usize * PAGE_SIZE, 0);
    for page in &batch.pages {
        let offset = (page.number as usize - 1) * PAGE_SIZE;
        bytes[offset..offset + PAGE_SIZE].copy_from_slice(&page.bytes);
    }
    validate(&bytes, limits.max_database_pages)?;
    Ok(bytes)
}
