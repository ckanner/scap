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
        let action = call.action.native()?;
        call.action.authorize(principal)?;
        let catalogue = core::Catalogue::new(
            self.objects.clone(),
            principal.deployment,
            principal.tenant,
            self.worker,
            self.options.clone(),
        )?;
        let caller = core::Caller {
            principal: principal.principal,
            provision: principal.provision,
        };
        Ok(match action {
            NativeAction::Prepare(input) => {
                wire::prepared(catalogue.prepare(caller, &input, deadline)?)
            }
            NativeAction::Resume(creation) => {
                wire::progress(catalogue.resume_create(caller, &creation, deadline)?)
            }
            NativeAction::Abort(input) => {
                wire::aborted(catalogue.abort_create(caller, &input, deadline)?)
            }
            NativeAction::Inspect(operation) => {
                wire::progress(catalogue.inspect_create_operation(caller, operation, deadline)?)
            }
            NativeAction::Resolve(name) => wire::named(catalogue.resolve(caller, &name, deadline)?),
            NativeAction::Delete(input) => {
                wire::deleted(catalogue.delete(caller, &input, deadline)?)
            }
        })
    }
}

impl From<core::CatalogueError> for Failure {
    fn from(error: core::CatalogueError) -> Self {
        Self::new(match error {
            core::CatalogueError::Invalid => "INVALID",
            core::CatalogueError::Denied => "DENIED",
            core::CatalogueError::NotFound => "NOT_FOUND",
            core::CatalogueError::Conflict => "CONFLICT",
            core::CatalogueError::IdentityConflict => "IDENTITY_CONFLICT",
            core::CatalogueError::Corrupt => "CORRUPT",
            core::CatalogueError::Limit => "LIMIT",
            core::CatalogueError::Unknown => "UNKNOWN",
        })
    }
}

#[cfg(test)]
mod tests;
