//! Bounded, immutable object archives and ordered cold lifecycle operations.
//!
//! Run on a trusted blocking worker thread. There is no automatic GC: every
//! uploaded object is retained, including uncommitted uploads. Only a fresh cell
//! view selects a recovery object; listing a bucket never advances a database.

use scap_cell::{
    AdminResult, ArchiveRef, CellState, CommandKind, DatabaseIdentity, DatabaseView, Outcome,
    Reject,
};
use scap_cell_client::{CellPort, Client, RequestContext};
use scap_raft_store::Identity;

mod s3;
pub use s3::{S3Config, S3};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unknown,
    Object,
    Integrity,
    TooLarge,
    Rejected(Reject),
}

/// Immutable-create and bounded-read boundary. Implementations preserve the
/// original deadline and never overwrite an existing object. A create result
/// alone is not proof of readable data: Controller always reads it back.
pub trait Objects {
    fn put(&mut self, key: &str, bytes: &[u8], context: &RequestContext) -> Result<(), Error>;
    fn get(
        &mut self,
        key: &str,
        max_bytes: u32,
        context: &RequestContext,
    ) -> Result<Vec<u8>, Error>;
}

pub struct Controller<P, S> {
    client: Client<P>,
    objects: S,
}

impl<P: CellPort, S: Objects> Controller<P, S> {
    pub fn new(client: Client<P>, objects: S) -> Self {
        Self { client, objects }
    }

    pub fn suspend(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        let epoch = if view.suspended || view.owner.epoch == 0 {
            view.owner.epoch
        } else {
            view.owner
                .epoch
                .checked_add(1)
                .ok_or(Error::Rejected(Reject::Exhausted))?
        };
        let result = self
            .client
            .submit(
                context,
                database,
                CommandKind::SuspendDb {
                    operation_id: operation,
                    token: view.owner,
                    expected_revision: view.revision,
                },
            )
            .map_err(|_| Error::Unknown)?;
        accepted(result.outcome, AdminResult::Suspended(epoch))
    }

    /// Upload a complete physical-history object, verify exact readable bytes,
    /// then publish the pointer through the same authoritative cell. Failure or
    /// UNKNOWN leaves every pre-existing recovery source protected.
    pub fn publish(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<ArchiveRef, Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        self.publish_view(context, state, view, operation)
    }

    /// Queued maintenance keeps its original owner, head, policy epoch and
    /// previous archive. A fresh view cannot silently refresh a stale job.
    pub fn publish_bound(
        &mut self,
        context: &RequestContext,
        expected: DatabaseView,
        operation: u128,
    ) -> Result<ArchiveRef, Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let current = state
            .archive_status(expected.identity, context.admission)
            .map_err(Error::Rejected)?;
        if current != expected {
            return Err(Error::Rejected(Reject::Fenced));
        }
        self.publish_view(context, state, expected, operation)
    }

    fn publish_view(
        &mut self,
        context: &RequestContext,
        state: CellState,
        view: DatabaseView,
        operation: u128,
    ) -> Result<ArchiveRef, Error> {
        if !view.suspended {
            return Err(Error::Rejected(Reject::Fenced));
        }
        let database = view.identity;
        let (archive, bytes) = state
            .archive_snapshot(database, context.admission)
            .map_err(Error::Rejected)?;
        let key = object_key(self.client.identity(), database, archive.object_digest);
        self.objects.put(&key, &bytes, context)?;
        let readback = self.objects.get(&key, archive.object_bytes, context)?;
        verify(&readback, archive)?;
        let result = self
            .client
            .submit(
                context,
                database,
                CommandKind::PublishArchive {
                    operation_id: operation,
                    expected_owner: view.owner,
                    expected_previous: view.archive.map(|value| value.object_digest),
                    archive,
                },
            )
            .map_err(|_| Error::Unknown)?;
        accepted(
            result.outcome,
            AdminResult::ArchivePublished(archive.object_digest),
        )?;
        Ok(archive)
    }

    /// Removes only physical transaction bytes from replicated application
    /// state. Shared Raft log truncation still requires its own durable snapshot.
    pub fn prune(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        let archive = view.archive.ok_or(Error::Rejected(Reject::NotFound))?;
        self.prune_view(context, view, archive, operation)
    }

    /// A published reference is usable only with the same queued owner/head.
    /// Final acceptance repeats the owner fence after this fresh read.
    pub fn prune_bound(
        &mut self,
        context: &RequestContext,
        mut expected: DatabaseView,
        archive: ArchiveRef,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let current = state
            .archive_status(expected.identity, context.admission)
            .map_err(Error::Rejected)?;
        expected.archive = Some(archive);
        if current != expected {
            return Err(Error::Rejected(Reject::Fenced));
        }
        self.prune_view(context, expected, archive, operation)
    }

    fn prune_view(
        &mut self,
        context: &RequestContext,
        view: DatabaseView,
        archive: ArchiveRef,
        operation: u128,
    ) -> Result<(), Error> {
        let result = self
            .client
            .submit(
                context,
                view.identity,
                CommandKind::PruneArchive {
                    operation_id: operation,
                    expected_owner: view.owner,
                    archive_digest: archive.object_digest,
                },
            )
            .map_err(|_| Error::Unknown)?;
        accepted(
            result.outcome,
            AdminResult::ArchivePruned(archive.object_digest),
        )
    }

    /// Rehydrates the exact published object before ClaimOwner/Writer::recover.
    /// The cell checks every retained receipt, result, hash and physical payload;
    /// object bytes cannot replace permissions, fences or request metadata.
    pub fn hydrate(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        if !view.cold {
            return Ok(());
        }
        // CellState has a private, validated representation: cold implies a
        // published reference covering the current head and retained metadata.
        let archive = view.archive.unwrap();
        let key = object_key(self.client.identity(), database, archive.object_digest);
        let bytes = self.objects.get(&key, archive.object_bytes, context)?;
        verify(&bytes, archive)?;
        let result = self
            .client
            .submit(
                context,
                database,
                CommandKind::HydrateArchive {
                    operation_id: operation,
                    archive: bytes,
                },
            )
            .map_err(|_| Error::Unknown)?;
        accepted(
            result.outcome,
            AdminResult::ArchiveHydrated(archive.object_digest),
        )
    }
}

pub fn object_key(identity: Identity, database: DatabaseIdentity, digest: [u8; 32]) -> String {
    let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "scap/v1/{:032x}/{:032x}/{}/{:032x}/{}/{}/{digest}",
        identity.cluster_id,
        identity.cell_id,
        identity.cell_incarnation,
        database.database_id,
        database.incarnation,
        database.placement_generation
    )
}

fn verify(bytes: &[u8], archive: ArchiveRef) -> Result<(), Error> {
    if bytes.len() != archive.object_bytes as usize
        || scap_cell::payload_digest(bytes) != archive.object_digest
    {
        return Err(Error::Integrity);
    }
    Ok(())
}

fn accepted(outcome: Outcome, expected: AdminResult) -> Result<(), Error> {
    match outcome {
        Outcome::Administrative(result) | Outcome::AlreadyApplied(result) if result == expected => {
            Ok(())
        }
        Outcome::Rejected(reason) => Err(Error::Rejected(reason)),
        _ => Err(Error::Unknown),
    }
}

#[cfg(test)]
mod tests;
