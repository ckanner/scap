//! Shared bounded SQLite page encoding, validation and deterministic replay.
//!
//! No Raft, storage, authentication or native SQLite dependency is present.
//! Both cell compaction and trusted worker recovery use this exact algorithm.
//! The caller binds snapshots to authoritative identities, commit hashes and
//! applied positions before using them as recovery sources.

use crate::{CellIdentity, CommitReceipt, CommitTicket, DatabaseIdentity, PreparedWrite};
use sha2::{Digest, Sha256};

pub const PAGE_SIZE: usize = 4096;
pub const HEADER_SIZE: usize = 152;
pub const MAX_DATABASE_PAGES: u32 = 262_144;
const MAGIC: &[u8; 8] = b"SCAPIMG!";
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineIdentity {
    pub cell: CellIdentity,
    pub database: DatabaseIdentity,
}

/// Limits apply before copying pages or allocating a candidate database image.
/// The implementation keeps complete images; the cap is a format bound, not a
/// measured throughput, memory-budget, or production-size recommendation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_database_pages: u32,
    pub max_changed_pages: u32,
    pub max_transaction_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub identity: EngineIdentity,
    pub revision: u64,
    pub image_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageChange {
    pub number: u32,
    pub bytes: Vec<u8>,
}

/// Pages must be strictly ordered and unique. Empty changes are valid only for
/// an unchanged file size; they still require a durable cell transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageBatch {
    pub size_after: u32,
    pub pages: Vec<PageChange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Limits,
    Identity,
    Ticket,
    Receipt,
    Exhausted,
    TooLarge,
    Malformed,
    PageOrder,
    MissingPage,
    SqliteHeader,
    Head,
    Integrity,
}

/// An immutable physical image built from an empty baseline, validated page
/// transitions, or a byte-validated snapshot. Its caller supplies authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    head: Head,
    bytes: Vec<u8>,
    limits: Limits,
}

/// Physical bytes and their complete-image digest at an exact revision.
/// The enclosing cell/archival format additionally binds the durable commit
/// hash and source position. A public Snapshot value alone proves no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub head: Head,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    write: PreparedWrite,
    image: Image,
}

impl Image {
    pub fn empty(identity: EngineIdentity, limits: Limits) -> Result<Self, Error> {
        if limits.max_database_pages == 0
            || limits.max_database_pages > MAX_DATABASE_PAGES
            || limits.max_changed_pages == 0
            || limits.max_changed_pages > limits.max_database_pages
            || limits.max_transaction_bytes < HEADER_SIZE as u32
        {
            return Err(Error::Limits);
        }
        if identity.cell.cell_id == 0
            || identity.cell.cell_incarnation == 0
            || identity.database.database_id == 0
            || identity.database.incarnation == 0
            || identity.database.placement_generation == 0
        {
            return Err(Error::Identity);
        }
        Ok(Self {
            head: Head {
                identity,
                revision: 0,
                image_digest: digest(&[]),
            },
            bytes: Vec::new(),
            limits,
        })
    }

    pub fn head(&self) -> Head {
        self.head
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// `payload_digest` must be the zero placeholder. All other immutable
    /// ticket fields are validated; the encoded physical digest is then bound.
    pub fn prepare(&self, mut ticket: CommitTicket, batch: PageBatch) -> Result<Prepared, Error> {
        self.validate_ticket(&ticket)?;
        if ticket.payload_digest != [0; 32] {
            return Err(Error::Ticket);
        }
        let image = self.apply_batch(&batch)?;
        let physical_changes = self.encode(&batch, image.head.image_digest);
        ticket.payload_digest = digest(&physical_changes);
        Ok(Prepared {
            write: PreparedWrite {
                ticket,
                physical_changes,
            },
            image,
        })
    }

    /// Import a bounded physical baseline after its authority and commit-hash
    /// anchor have been checked by the caller. This validates the image bytes,
    /// identity, page geometry and digest; it does not grant cell authority.
    pub fn from_snapshot(snapshot: Snapshot, limits: Limits) -> Result<Self, Error> {
        let mut image = Self::empty(snapshot.head.identity, limits)?;
        if snapshot.bytes.len() / PAGE_SIZE > limits.max_database_pages as usize {
            return Err(Error::TooLarge);
        }
        if !snapshot.bytes.len().is_multiple_of(PAGE_SIZE) {
            return Err(Error::Malformed);
        }
        if snapshot.head.revision == 0 && !snapshot.bytes.is_empty() {
            return Err(Error::Head);
        }
        if !snapshot.bytes.is_empty()
            && (&snapshot.bytes[..16] != SQLITE_MAGIC || snapshot.bytes[16..18] != [0x10, 0])
        {
            return Err(Error::SqliteHeader);
        }
        if digest(&snapshot.bytes) != snapshot.head.image_digest {
            return Err(Error::Integrity);
        }
        image.head = snapshot.head;
        image.bytes = snapshot.bytes;
        Ok(image)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            head: self.head,
            bytes: self.bytes.clone(),
        }
    }

    fn validate_ticket(&self, ticket: &CommitTicket) -> Result<(), Error> {
        let identity = self.head.identity;
        if ticket.cell_id != identity.cell.cell_id
            || ticket.cell_incarnation != identity.cell.cell_incarnation
            || ticket.database_id != identity.database.database_id
            || ticket.incarnation != identity.database.incarnation
            || ticket.placement_generation != identity.database.placement_generation
            || ticket.predecessor != self.head.revision
            || ticket.owner_epoch == 0
            || ticket.worker_instance_id == 0
            || ticket.auth_epoch == 0
            || ticket.request_id == 0
        {
            return Err(Error::Ticket);
        }
        Ok(())
    }

    fn apply_batch(&self, batch: &PageBatch) -> Result<Self, Error> {
        let count = batch.pages.len();
        if batch.size_after > self.limits.max_database_pages
            || count > self.limits.max_changed_pages as usize
            || HEADER_SIZE + count * (4 + PAGE_SIZE) > self.limits.max_transaction_bytes as usize
        {
            return Err(Error::TooLarge);
        }
        let base_pages = self.bytes.len() / PAGE_SIZE;
        if count == 0 && batch.size_after as usize != base_pages {
            return Err(Error::MissingPage);
        }
        let mut previous = 0;
        let mut next_new = base_pages + 1;
        for page in &batch.pages {
            if page.number == 0 || page.number > batch.size_after || page.bytes.len() != PAGE_SIZE {
                return Err(Error::Malformed);
            }
            if page.number <= previous {
                return Err(Error::PageOrder);
            }
            previous = page.number;
            if page.number as usize > base_pages {
                if page.number as usize != next_new {
                    return Err(Error::MissingPage);
                }
                next_new += 1;
            }
        }
        if batch.size_after as usize > base_pages && next_new != batch.size_after as usize + 1 {
            return Err(Error::MissingPage);
        }
        let revision = self.head.revision.checked_add(1).ok_or(Error::Exhausted)?;
        let mut bytes = self.bytes.clone();
        bytes.resize(batch.size_after as usize * PAGE_SIZE, 0);
        for page in &batch.pages {
            let offset = (page.number as usize - 1) * PAGE_SIZE;
            bytes[offset..offset + PAGE_SIZE].copy_from_slice(&page.bytes);
        }
        if !bytes.is_empty() && (&bytes[..16] != SQLITE_MAGIC || bytes[16..18] != [0x10, 0]) {
            return Err(Error::SqliteHeader);
        }
        Ok(Self {
            head: Head {
                identity: self.head.identity,
                revision,
                image_digest: digest(&bytes),
            },
            bytes,
            limits: self.limits,
        })
    }

    fn encode(&self, batch: &PageBatch, image_digest: [u8; 32]) -> Vec<u8> {
        let identity = self.head.identity;
        let mut bytes = Vec::with_capacity(HEADER_SIZE + batch.pages.len() * (4 + PAGE_SIZE));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        bytes.extend_from_slice(&identity.cell.cell_id.to_le_bytes());
        bytes.extend_from_slice(&identity.cell.cell_incarnation.to_le_bytes());
        bytes.extend_from_slice(&identity.database.database_id.to_le_bytes());
        bytes.extend_from_slice(&identity.database.incarnation.to_le_bytes());
        bytes.extend_from_slice(&identity.database.placement_generation.to_le_bytes());
        bytes.extend_from_slice(&self.head.revision.to_le_bytes());
        bytes.extend_from_slice(&self.head.image_digest);
        bytes.extend_from_slice(&image_digest);
        bytes.extend_from_slice(&batch.size_after.to_le_bytes());
        bytes.extend_from_slice(&(batch.pages.len() as u32).to_le_bytes());
        for page in &batch.pages {
            bytes.extend_from_slice(&page.number.to_le_bytes());
            bytes.extend_from_slice(&page.bytes);
        }
        bytes
    }

    pub fn replay(&self, receipt: &CommitReceipt, changes: &[u8]) -> Result<Self, Error> {
        self.validate_ticket(&receipt.ticket)?;
        if self.head.revision.checked_add(1) != Some(receipt.sequence) {
            return Err(Error::Receipt);
        }
        if changes.len() < HEADER_SIZE || changes.len() > self.limits.max_transaction_bytes as usize
        {
            return Err(Error::TooLarge);
        }
        if digest(changes) != receipt.ticket.payload_digest {
            return Err(Error::Integrity);
        }
        if &changes[..8] != MAGIC
            || changes[8..12] != 1_u32.to_le_bytes()
            || changes[12..16] != (PAGE_SIZE as u32).to_le_bytes()
        {
            return Err(Error::Malformed);
        }
        let identity = self.head.identity;
        if changes[16..32] != identity.cell.cell_id.to_le_bytes()
            || changes[32..40] != identity.cell.cell_incarnation.to_le_bytes()
            || changes[40..56] != identity.database.database_id.to_le_bytes()
            || changes[56..64] != identity.database.incarnation.to_le_bytes()
            || changes[64..72] != identity.database.placement_generation.to_le_bytes()
            || changes[72..80] != self.head.revision.to_le_bytes()
            || changes[80..112] != self.head.image_digest
        {
            return Err(Error::Head);
        }
        let size_after = u32::from_le_bytes(changes[144..148].try_into().unwrap());
        let count = u32::from_le_bytes(changes[148..152].try_into().unwrap()) as usize;
        if count > self.limits.max_changed_pages as usize
            || changes.len() != HEADER_SIZE + count * (4 + PAGE_SIZE)
        {
            return Err(Error::Malformed);
        }
        let pages = changes[HEADER_SIZE..]
            .chunks_exact(4 + PAGE_SIZE)
            .map(|record| PageChange {
                number: u32::from_le_bytes(record[..4].try_into().unwrap()),
                bytes: record[4..].to_vec(),
            })
            .collect();
        let image = self.apply_batch(&PageBatch { size_after, pages })?;
        if changes[112..144] != image.head.image_digest {
            return Err(Error::Integrity);
        }
        Ok(image)
    }
}

impl Prepared {
    pub fn write(&self) -> &PreparedWrite {
        &self.write
    }

    /// Validates an exact NEW acceptance and consumes the staged image. The
    /// native owner may install it as its local head only after final SQLite
    /// COMMIT success. A historical dedup hit must discard the entire Prepared.
    pub fn accepted(self, receipt: &CommitReceipt) -> Result<Image, Error> {
        if receipt.ticket != self.write.ticket || receipt.sequence != self.image.head.revision {
            return Err(Error::Receipt);
        }
        Ok(self.image)
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests;
