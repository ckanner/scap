//! Catalogue calls use the formal object runtime on their own worker pool.

use std::sync::Arc;
use std::time::Instant;

use scap_object::{catalogue as core, Options};
use scap_object_store::Objects;
use serde_json::Value;

use crate::{
    auth::Principal,
    catalogue_wire::{self as wire, Call, NativeAction},
    Failure,
};

pub struct Worker {
    objects: Arc<dyn Objects>,
    worker: u64,
    options: Options,
}

impl Worker {
    pub fn new(objects: Arc<dyn Objects>, worker: u64, options: Options) -> Self {
        Self {
            objects,
            worker,
            options,
        }
    }

    pub fn execute(
        &self,
        principal: &Principal,
        call: Call,
        deadline: Instant,
    ) -> Result<Value, Failure> {
        let action = call.action.native();
        let Ok(action) = action else {
            return Err(action.err().expect("native action validation failed"));
        };
        let authorization = call.action.authorize(principal);
        let Ok(()) = authorization else {
            return Err(authorization.expect_err("catalogue authorization failed"));
        };
        let catalogue = core::Catalogue::new(
            self.objects.clone(),
            principal.deployment,
            principal.tenant,
            self.worker,
            self.options.clone(),
        );
        if let Err(error) = catalogue {
            return Err(error.into());
        }
        let catalogue = catalogue.expect("catalogue configuration validation succeeded");
        let caller = core::Caller {
            principal: principal.principal,
            provision: principal.provision,
        };
        if let NativeAction::Prepare(input) = action {
            return project(catalogue.prepare(caller, &input, deadline), wire::prepared);
        }
        if let NativeAction::Resume(creation) = action {
            return project(
                catalogue.resume_create(caller, &creation, deadline),
                wire::progress,
            );
        }
        if let NativeAction::Abort(input) = action {
            return project(
                catalogue.abort_create(caller, &input, deadline),
                wire::aborted,
            );
        }
        if let NativeAction::Inspect(operation) = action {
            return project(
                catalogue.inspect_create_operation(caller, operation, deadline),
                wire::progress,
            );
        }
        if let NativeAction::PrepareRestore(input) = action {
            return project(
                catalogue.prepare_restore(caller, &input, deadline),
                |value| crate::restore_wire::prepared(&value),
            );
        }
        if let NativeAction::InspectRestore { creator, operation } = action {
            return project(
                catalogue.inspect_restore(caller, creator, operation, deadline),
                |value| crate::restore_wire::progress(&value),
            );
        }
        if let NativeAction::AbortRestore { reference, input } = action {
            return project(
                catalogue.abort_restore(caller, &reference, &input, deadline),
                wire::aborted,
            );
        }
        if let NativeAction::Resolve(name) = action {
            return project(catalogue.resolve(caller, &name, deadline), wire::named);
        }
        if let NativeAction::Delete(input) = action {
            return project(catalogue.delete(caller, &input, deadline), wire::deleted);
        }
        if let NativeAction::StorageStatus(creation) = action {
            return project(
                catalogue.storage_status(caller, &creation, deadline),
                |value| crate::wire::status(&value),
            );
        }
        if let NativeAction::RetireStorage(input) = action {
            return project(
                catalogue.retire_storage(caller, &input, deadline),
                |value| crate::wire::status(&value),
            );
        }
        // ResumeRestore belongs to the separately bounded native recovery
        // worker. The catalogue control pool must never run its copy stage.
        Err(Failure::new("INVALID"))
    }
}

fn project<T>(
    result: Result<T, core::CatalogueError>,
    encode: impl FnOnce(T) -> Value,
) -> Result<Value, Failure> {
    if let Err(error) = result {
        return Err(error.into());
    }
    Ok(encode(result.expect("catalogue operation succeeded")))
}

impl From<core::CatalogueError> for Failure {
    fn from(error: core::CatalogueError) -> Self {
        let code = if error == core::CatalogueError::Invalid {
            "INVALID"
        } else if error == core::CatalogueError::Denied {
            "DENIED"
        } else if error == core::CatalogueError::NotFound {
            "NOT_FOUND"
        } else if error == core::CatalogueError::Conflict {
            "CONFLICT"
        } else if error == core::CatalogueError::IdentityConflict {
            "IDENTITY_CONFLICT"
        } else if error == core::CatalogueError::Corrupt {
            "CORRUPT"
        } else if error == core::CatalogueError::SnapshotExpired {
            "SNAPSHOT_EXPIRED"
        } else if error == core::CatalogueError::Limit {
            "LIMIT"
        } else {
            "UNKNOWN"
        };
        Self::new(code)
    }
}

#[cfg(test)]
mod tests;
