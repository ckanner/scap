//! Explicit one-step restoration into a newly reserved catalogue identity.
//! Immutable completion proves a complete authorized copy, never a past ACK.

use std::path::Path;

use super::inspect::CreateStep;
use super::records::BindingState;
use super::restore_records::{Completion, Recipe};
use super::*;
use crate::format::{RestoreCopyPhase, RestoreOrigin};
use crate::head_publication::PreparedHead;

pub(crate) struct VerifiedRestoreTransition {
    base: Snapshot,
    next: Head,
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;

impl VerifiedRestoreTransition {
    pub(crate) fn into_parts(self) -> (Snapshot, Head) {
        (self.base, self.next)
    }
}

impl Catalogue {
    pub(crate) fn verify_database_restore(
        database: &Database,
        head: &Head,
        deadline: Instant,
    ) -> Result<(), Error> {
        if head
            .restore_origin
            .as_ref()
            .and_then(Option::as_ref)
            .is_none()
        {
            return Ok(());
        }
        let catalogue = Self {
            objects: database.objects.clone(),
            deployment: database.scope.deployment,
            tenant: database.scope.tenant,
            worker: database.worker,
            options: database.options.clone(),
        };
        let result = (|| {
            let origin = head.creation.as_ref().ok_or(CatalogueError::Corrupt)?;
            let source =
                authority(catalogue.read_descriptor(origin.creator, origin.operation, deadline))?;
            require(source.creation.scope == head.scope && source.origin() == *origin)?;
            catalogue.verify_restore_origin(&source, head, deadline)
        })();
        result.map_err(|error| match error {
            CatalogueError::Unknown => Error::Unknown,
            CatalogueError::Limit => Error::Limit,
            _ => Error::Corrupt,
        })
    }

    pub fn prepare_restore(
        &self,
        caller: Caller,
        input: &PrepareRestore,
        deadline: Instant,
    ) -> Result<PreparedRestore, CatalogueError> {
        Self::creator(caller, caller.principal)?;
        input.validate()?;
        records::valid(
            input.source_scope.deployment == self.deployment
                && input.source_scope.tenant == self.tenant,
        )?;
        let deadline = self.options.deadline(deadline, false);
        if let Some(record) = self.read::<Descriptor>(
            &self.descriptor_key(caller.principal, input.operation),
            deadline,
        )? {
            let stored = self.restore_existing(caller.principal, input.operation, record.body)?;
            if stored.input != *input {
                return Err(CatalogueError::Conflict);
            }
            return Ok(stored);
        }
        let creation = Creation {
            creator: caller.principal,
            operation: input.operation,
            name: input.name.clone(),
            expected_name_revision: input.expected_name_revision,
            scope: records::derive_scope(
                self.deployment,
                self.tenant,
                caller.principal,
                input.operation,
            )?,
        };
        records::valid(creation.scope != input.source_scope)?;
        let database = self.restore_source_database(&input.source_scope)?;
        let (_, _, observation) = database
            .snapshot_view(caller.principal, &input.snapshot.identity(), true, deadline)
            .map_err(core_error)?;
        if observation.prepared.reference != input.snapshot
            || observation.state != crate::snapshot::SnapshotState::Retained
        {
            return Err(CatalogueError::Conflict);
        }
        let initial_quota = input.options.effective_quota(&self.options.quota);
        let maximum = initial_quota
            .max_pages()
            .map_err(|_| CatalogueError::Invalid)?;
        if observation.prepared.point.page_count > maximum {
            return Err(CatalogueError::Limit);
        }
        let candidate = Canonical::new(Descriptor {
            format: 2,
            creation,
            options: input.options.clone(),
            initial_quota,
            retention: self.options.retention.clone(),
            recipe: Some(Recipe::SnapshotRestore {
                source_scope: input.source_scope.clone(),
                snapshot: input.snapshot.clone(),
                point: observation.prepared.point,
                rewrap_version: 1,
                native_format: 1,
                snapshot_limits: self.options.snapshot_limits.clone(),
            }),
        })?;
        let key = self.descriptor_key(caller.principal, input.operation);
        match self
            .objects
            .put(&key, candidate.bytes(), Condition::Absent, deadline)
        {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(store_error(error)),
        }
        let durable = authority(self.read_descriptor(caller.principal, input.operation, deadline))?;
        let prepared = durable.prepared_restore()?;
        if prepared.input != *input {
            return Err(CatalogueError::Conflict);
        }
        Ok(prepared)
    }

    fn restore_existing(
        &self,
        creator: u64,
        operation: u64,
        source: Source,
    ) -> Result<PreparedRestore, CatalogueError> {
        require(
            source.creation.creator == creator
                && source.creation.operation == operation
                && source.creation.scope.deployment == self.deployment
                && source.creation.scope.tenant == self.tenant,
        )?;
        source.prepared_restore()
    }

    pub(super) fn restore_source_database(
        &self,
        scope: &Scope,
    ) -> Result<Database, CatalogueError> {
        records::valid(scope.deployment == self.deployment && scope.tenant == self.tenant)?;
        Database::with_options(
            self.objects.clone(),
            scope.clone(),
            self.worker,
            self.options.clone(),
        )
        .map_err(core_error)
    }

    fn restore_descriptor(
        &self,
        reference: &RestoreRef,
        deadline: Instant,
    ) -> Result<Source, CatalogueError> {
        reference.validate()?;
        let source = self.descriptor(&reference.creation, deadline)?;
        if source.hash() != reference.descriptor_hash || source.recipe.is_none() {
            return Err(CatalogueError::Conflict);
        }
        Ok(source)
    }

    pub fn inspect_restore(
        &self,
        caller: Caller,
        creator: u64,
        operation: u64,
        deadline: Instant,
    ) -> Result<RestoreProgress, CatalogueError> {
        Self::creator(caller, creator)?;
        records::valid(operation != 0)?;
        let deadline = self.options.deadline(deadline, false);
        let source = self.read_descriptor(creator, operation, deadline)?;
        source.prepared_restore()?;
        self.restore_progress(&source, deadline)
    }

    fn restore_progress(
        &self,
        source: &Source,
        deadline: Instant,
    ) -> Result<RestoreProgress, CatalogueError> {
        let view = self.view(source, deadline)?;
        let plan = self.creation_plan(source, &view, deadline)?;
        let phase = match plan.phase {
            CreationPhase::NotReserved => RestorePhase::NotReserved,
            CreationPhase::Reserved => RestorePhase::Reserved,
            CreationPhase::Provisioning => {
                let head = &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head;
                match &head.restore_origin {
                    Some(Some(RestoreOrigin {
                        phase: RestoreCopyPhase::Copying {},
                        ..
                    })) => RestorePhase::Copying,
                    Some(Some(RestoreOrigin {
                        phase: RestoreCopyPhase::Copied { .. },
                        ..
                    })) => RestorePhase::Copied,
                    _ => return Err(CatalogueError::Corrupt),
                }
            }
            CreationPhase::Bound => RestorePhase::Bound,
            CreationPhase::Ready => RestorePhase::Ready,
            CreationPhase::Aborting => RestorePhase::Aborting,
            CreationPhase::Aborted => RestorePhase::Aborted,
            CreationPhase::Deleting => RestorePhase::Deleting,
            CreationPhase::Deleted => RestorePhase::Deleted,
            CreationPhase::NameConflict => RestorePhase::NameConflict,
            CreationPhase::IdentityConflict => RestorePhase::IdentityConflict,
        };
        let (binding_revision, head_revision) = Self::revisions(source, &view);
        Ok(RestoreProgress {
            prepared: source.prepared_restore()?,
            phase,
            binding_revision,
            head_revision,
        })
    }

    pub fn resume_restore(
        &self,
        caller: Caller,
        reference: &RestoreRef,
        directory: &Path,
        budget: RestoreBudget,
        deadline: Instant,
    ) -> Result<RestoreProgress, CatalogueError> {
        Self::creator(caller, reference.creation.creator)?;
        budget.validate()?;
        let deadline = self.options.deadline(deadline, true);
        let source = self.restore_descriptor(reference, deadline)?;
        let view = self.view(&source, deadline)?;
        let plan = self.creation_plan(&source, &view, deadline)?;
        match plan.step {
            CreateStep::None => {}
            CreateStep::Reserve(previous) => {
                let binding = Binding {
                    format: 1,
                    creation: source.creation.clone(),
                    origin: source.origin(),
                    revision: source.creation.expected_name_revision.unwrap_or(0) + 1,
                    state: BindingState::Reserved,
                    control: None,
                    proof: None,
                };
                self.write_binding(
                    &binding,
                    previous.map(|binding| binding.etag.as_str()),
                    deadline,
                )?;
            }
            CreateStep::Provision => {
                let database = self.database(&source);
                let mut head = database
                    .initial_head(source.creation.creator, source.creation.operation, deadline)
                    .map_err(core_error)?;
                head.lifecycle = Lifecycle::Provisioning;
                head.creation = Some(source.origin());
                Self::initial_restore_origin(&source, &mut head);
                database.create_head(&head, deadline).map_err(core_error)?;
            }
            CreateStep::RestoreCopy(base) => {
                let mut copying = self.clone();
                copying.objects =
                    super::restore_budget::Meter::target(self.objects.clone(), budget, deadline);
                let completion = match copying.read_completion(&source, deadline)? {
                    Some(record) => {
                        copying.validate_completed_copy(
                            &source,
                            base,
                            record.raw(),
                            directory,
                            budget,
                            deadline,
                        )?;
                        record
                    }
                    None => {
                        let complete = copying.copy_restore_point(
                            caller,
                            &source,
                            base,
                            super::restore_copy::CopyResources {
                                source_objects: self.objects.clone(),
                                directory,
                                budget,
                            },
                            deadline,
                        )?;
                        copying.immutable(
                            &copying.completion_key(&source),
                            &complete.into_record(),
                            deadline,
                        )?
                    }
                };
                copying.install_copied(&source, &view, base, &completion, deadline)?;
            }
            CreateStep::Bind(binding) => {
                let mut next = binding.body.raw().clone();
                next.state = BindingState::Bound;
                next.revision += 1;
                self.write_binding(&next, Some(&binding.etag), deadline)?;
            }
            CreateStep::Complete(binding, base) => {
                self.complete(&source, binding, base, deadline)?
            }
        }
        self.restore_progress(&source, deadline)
    }

    pub fn abort_restore(
        &self,
        caller: Caller,
        reference: &RestoreRef,
        input: &AbortCreate,
        deadline: Instant,
    ) -> Result<AbortProgress, CatalogueError> {
        Self::creator(caller, reference.creation.creator)?;
        let deadline = self.options.deadline(deadline, false);
        self.restore_descriptor(reference, deadline)?;
        if input.creation != reference.creation {
            return Err(CatalogueError::Conflict);
        }
        // abort_create deliberately uses one step for a restore recipe. It
        // shares the original name/HEAD proof machinery and needs no source ACL.
        self.abort_create(caller, input, deadline)
    }

    pub(super) fn initial_restore_origin(source: &Source, head: &mut Head) {
        if let Some(Recipe::SnapshotRestore {
            snapshot_limits, ..
        }) = &source.recipe
        {
            head.format = 9;
            head.snapshots = Some(Vec::new());
            head.snapshot_limits = Some(snapshot_limits.clone());
            head.restore_origin = Some(Some(RestoreOrigin {
                descriptor_hash: source.hash().into(),
                phase: RestoreCopyPhase::Copying {},
            }));
        }
    }

    fn completion_key(&self, source: &Source) -> String {
        format!(
            "{}/restore-completion/{}/{}",
            self.prefix(),
            source.creation.creator,
            source.creation.operation
        )
    }

    fn read_completion(
        &self,
        source: &Source,
        deadline: Instant,
    ) -> Result<Option<Canonical<Completion>>, CatalogueError> {
        let record = self.read::<Completion>(&self.completion_key(source), deadline)?;
        if let Some(record) = &record {
            require(record.body.matches(source))?;
        }
        Ok(record.map(|record| record.body))
    }

    pub(super) fn verify_absent_restore_head(
        &self,
        source: &Source,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        if source.recipe.is_some() && self.read_completion(source, deadline)?.is_some() {
            // A completion was formed only after an own Provisioning HEAD and
            // a complete authorized copy. Its permanent HEAD cannot be rebuilt
            // from absence. A legal concurrent provision/copy can appear after
            // our first missing observation; recheck without adopting its ETag.
            if self.read_slot(&source.creation.scope, deadline)?.is_some() {
                return Err(CatalogueError::Conflict);
            }
            return Err(CatalogueError::Corrupt);
        }
        Ok(())
    }

    pub(super) fn verify_restore_origin(
        &self,
        source: &Source,
        head: &Head,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let origin = head.restore_origin.as_ref().and_then(Option::as_ref);
        let Some(_) = &source.recipe else {
            return require(origin.is_none());
        };
        let origin = origin.ok_or(CatalogueError::Corrupt)?;
        require(origin.descriptor_hash == source.hash())?;
        let completion = self.read_completion(source, deadline)?;
        match &origin.phase {
            RestoreCopyPhase::Copying {} => Ok(()),
            RestoreCopyPhase::Copied {
                completion_hash,
                data_root,
                page_count,
            } => {
                let completion = completion.ok_or(CatalogueError::Corrupt)?;
                require(
                    completion.hash() == completion_hash
                        && completion.data_root == *data_root
                        && completion.page_count == *page_count,
                )?;
                if head.lifecycle == Lifecycle::Provisioning {
                    require(completion.request_root == head.windows[0].root)?;
                }
                Ok(())
            }
        }
    }

    fn install_copied(
        &self,
        source: &Source,
        original_view: &View,
        base: &Snapshot,
        completion: &Canonical<Completion>,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let current = self.view(source, deadline)?;
        if current.binding != original_view.binding
            || current
                .head
                .as_ref()
                .is_none_or(|head| head.head != base.head || head.etag != base.etag)
        {
            return Err(CatalogueError::Conflict);
        }
        let mut next = base.head.clone();
        next.head_serial = next
            .head_serial
            .checked_add(1)
            .ok_or(CatalogueError::Limit)?;
        next.data_root = completion.data_root.clone();
        next.restore_origin = Some(Some(RestoreOrigin {
            descriptor_hash: source.hash().into(),
            phase: RestoreCopyPhase::Copied {
                completion_hash: completion.hash().into(),
                data_root: completion.data_root.clone(),
                page_count: completion.page_count,
            },
        }));
        let database = self.database(source);
        let candidate = VerifiedRestoreTransition {
            base: base.clone(),
            next,
        };
        let publication =
            PreparedHead::restore(&database, candidate, deadline).map_err(core_error)?;
        database.publish_healthy(publication).map_err(core_error)
    }
}
