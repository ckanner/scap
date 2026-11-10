//! Current ADMIN plus an exact, durable original deletion source.
//! Only this module can produce the capability consumed by terminal sealing.

use super::*;

pub(crate) struct VerifiedDeletionSource {
    base: Snapshot,
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;

impl VerifiedDeletionSource {
    pub(crate) fn into_snapshot(self) -> Snapshot {
        self.base
    }
}

impl Catalogue {
    fn terminal_source(
        &self,
        caller: Caller,
        creation: &Creation,
        deadline: Instant,
    ) -> Result<(Database, VerifiedDeletionSource), CatalogueError> {
        Self::caller(caller)?;
        self.creation(creation)?;
        let source = authority(self.descriptor(creation, deadline))?;
        // view preserves proof-before-HEAD and exact stable-name double reads.
        let view = self.view(&source, deadline)?;
        let base = Self::admin(&source, &view, caller.principal)?;
        if base.head.lifecycle != Lifecycle::Deleted {
            return Err(CatalogueError::Conflict);
        }
        // This checks the actual original control/proof, including OwnDeleted
        // before/after name release and a legitimately reused name. A mark in
        // HEAD alone is insufficient; missing records are never recreated.
        self.metadata_state(&source, &view, deadline)?;
        Ok((
            self.database(&source),
            VerifiedDeletionSource { base: base.clone() },
        ))
    }

    pub fn storage_status(
        &self,
        caller: Caller,
        creation: &Creation,
        deadline: Instant,
    ) -> Result<Head, CatalogueError> {
        let deadline = self.options.deadline(deadline, false);
        let (_, source) = self.terminal_source(caller, creation, deadline)?;
        Ok(source.base.head)
    }

    pub fn retire_storage(
        &self,
        caller: Caller,
        input: &RetireNamedStorage,
        deadline: Instant,
    ) -> Result<Head, CatalogueError> {
        records::valid(input.expected_head_serial != 0)?;
        let deadline = self.options.deadline(deadline, false);
        let (database, source) = self.terminal_source(caller, &input.creation, deadline)?;
        database
            .retire_named_storage(source, input.expected_head_serial, deadline)
            .map_err(core_error)
    }
}
