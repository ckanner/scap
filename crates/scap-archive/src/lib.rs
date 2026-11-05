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

/// Exact confirmed publication, tied to the immutable view that was queued.
/// Only Controller constructs this receipt; pruning cannot infer successful
/// publication by reading a newer control revision after an UNKNOWN result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedArchive {
    archive: ArchiveRef,
    control_revision: Option<u64>,
    source: DatabaseView,
}

impl PublishedArchive {
    pub fn archive(&self) -> ArchiveRef {
        self.archive
    }

    pub fn control_revision(&self) -> Option<u64> {
        self.control_revision
    }
}

pub struct Controller<P, S> {
    client: Client<P>,
    objects: S,
}

impl<P: CellPort, S: Objects> Controller<P, S> {
    pub fn new(client: Client<P>, objects: S) -> Self {
        Self { client, objects }
    }

    /// Historical convenience API. Once control receipts are enabled, callers
    /// must capture a view before the first attempt and use suspend_bound.
    pub fn suspend(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.legacy(context)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        self.suspend_view(context, view, operation)
    }

    pub fn suspend_bound(
        &mut self,
        context: &RequestContext,
        expected: DatabaseView,
        operation: u128,
    ) -> Result<(), Error> {
        self.bound(context, &expected)?;
        self.suspend_view(context, expected, operation)
    }

    fn suspend_view(
        &mut self,
        context: &RequestContext,
        view: DatabaseView,
        operation: u128,
    ) -> Result<(), Error> {
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
            .submit_control(
                context,
                view.identity,
                view.control_revision,
                CommandKind::SuspendDb {
                    operation_id: operation,
                    token: view.owner,
                    expected_revision: view.revision,
                },
            )
            .map_err(|_| Error::Unknown)?;
        accepted(
            result.outcome,
            AdminResult::Suspended(epoch),
            view.control_revision,
        )
        .map(|_| ())
    }

    /// Historical convenience API. Upload a complete readable object before
    /// publishing its pointer. Enabled control receipts require publish_bound.
    pub fn publish(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<ArchiveRef, Error> {
        let state = self.legacy(context)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        self.publish_view(context, state, view, operation)
            .map(|published| published.archive)
    }

    /// Queued maintenance keeps its original owner, head, policy epoch,
    /// previous archive and control revision, including after UNKNOWN.
    pub fn publish_bound(
        &mut self,
        context: &RequestContext,
        expected: DatabaseView,
        operation: u128,
    ) -> Result<PublishedArchive, Error> {
        let state = self.bound(context, &expected)?;
        self.publish_view(context, state, expected, operation)
    }

    fn publish_view(
        &mut self,
        context: &RequestContext,
        state: CellState,
        view: DatabaseView,
        operation: u128,
    ) -> Result<PublishedArchive, Error> {
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
            .submit_control(
                context,
                database,
                view.control_revision,
                CommandKind::PublishArchive {
                    operation_id: operation,
                    expected_owner: view.owner,
                    expected_previous: view.archive.map(|value| value.object_digest),
                    archive,
                },
            )
            .map_err(|_| Error::Unknown)?;
        let control_revision = accepted(
            result.outcome,
            AdminResult::ArchivePublished(archive.object_digest),
            view.control_revision,
        )?;
        Ok(PublishedArchive {
            archive,
            control_revision,
            source: view,
        })
    }

    /// Historical convenience API. Removes only bytes covered by the current
    /// archive. Enabled control receipts require prune_bound's publication.
    pub fn prune(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.legacy(context)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        let archive = view.archive.ok_or(Error::Rejected(Reject::NotFound))?;
        self.prune_view(context, view, archive, operation)
    }

    /// Consume the exact confirmed publication for this queued view. The
    /// receipt, rather than a refreshed read, advances the control revision.
    pub fn prune_bound(
        &mut self,
        context: &RequestContext,
        mut expected: DatabaseView,
        published: PublishedArchive,
        operation: u128,
    ) -> Result<(), Error> {
        if published.source != expected {
            return Err(Error::Invalid);
        }
        expected.archive = Some(published.archive);
        expected.control_revision = published.control_revision;
        self.bound(context, &expected)?;
        self.prune_view(context, expected, published.archive, operation)
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
            .submit_control(
                context,
                view.identity,
                view.control_revision,
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
            view.control_revision,
        )
        .map(|_| ())
    }

    /// Historical convenience API. Enabled control receipts require the view
    /// captured by hydrate_bound's caller before the first attempt.
    pub fn hydrate(
        &mut self,
        context: &RequestContext,
        database: DatabaseIdentity,
        operation: u128,
    ) -> Result<(), Error> {
        let state = self.legacy(context)?;
        let view = state
            .archive_status(database, context.admission)
            .map_err(Error::Rejected)?;
        self.hydrate_view(context, view, operation)
    }

    /// Object bytes restore only covered physical history. The current cell
    /// retains its permissions, owner, request and control receipt metadata.
    pub fn hydrate_bound(
        &mut self,
        context: &RequestContext,
        expected: DatabaseView,
        operation: u128,
    ) -> Result<(), Error> {
        self.bound(context, &expected)?;
        self.hydrate_view(context, expected, operation)
    }

    fn hydrate_view(
        &mut self,
        context: &RequestContext,
        view: DatabaseView,
        operation: u128,
    ) -> Result<(), Error> {
        if !view.cold {
            return Ok(());
        }
        // Both entry points obtain a private, validated state view. Cold
        // implies a published reference covering the current logical head.
        let archive = view.archive.unwrap();
        let key = object_key(self.client.identity(), view.identity, archive.object_digest);
        let bytes = self.objects.get(&key, archive.object_bytes, context)?;
        verify(&bytes, archive)?;
        let result = self
            .client
            .submit_control(
                context,
                view.identity,
                view.control_revision,
                CommandKind::HydrateArchive {
                    operation_id: operation,
                    archive: bytes,
                },
            )
            .map_err(|_| Error::Unknown)?;
        accepted(
            result.outcome,
            AdminResult::ArchiveHydrated(archive.object_digest),
            view.control_revision,
        )
        .map(|_| ())
    }

    fn legacy(&mut self, context: &RequestContext) -> Result<CellState, Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        if state.control_enabled() {
            return Err(Error::Invalid);
        }
        Ok(state)
    }

    fn bound(
        &mut self,
        context: &RequestContext,
        expected: &DatabaseView,
    ) -> Result<CellState, Error> {
        let state = self.client.read(context).map_err(|_| Error::Unknown)?;
        let current = state
            .archive_status(expected.identity, context.admission)
            .map_err(Error::Rejected)?;
        if &current != expected {
            return Err(Error::Rejected(Reject::Fenced));
        }
        Ok(state)
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

fn accepted(
    outcome: Outcome,
    expected: AdminResult,
    expected_revision: Option<u64>,
) -> Result<Option<u64>, Error> {
    match outcome {
        Outcome::Administrative(result) | Outcome::AlreadyApplied(result)
            if expected_revision.is_none() && result == expected =>
        {
            Ok(None)
        }
        Outcome::ControlApplied(result) | Outcome::ControlAlreadyApplied(result)
            if expected_revision.and_then(|revision| revision.checked_add(1))
                == Some(result.revision)
                && result.result == expected =>
        {
            Ok(Some(result.revision))
        }
        Outcome::Rejected(reason) => Err(Error::Rejected(reason)),
        _ => Err(Error::Unknown),
    }
}

#[cfg(test)]
mod tests;
