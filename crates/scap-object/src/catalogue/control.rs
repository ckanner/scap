use super::*;
use records::BindingState;

struct ControlInput<'a> {
    creation: &'a Creation,
    kind: NamedDeletionKind,
    principal: u64,
    operation: u64,
    expected_name_revision: u64,
    expected_head_revision: Option<u64>,
    nonce: u64,
}

enum AbortStep<'a> {
    Done(AbortPhase),
    Accept(&'a Name),
    FenceAbsent,
    Fence(&'a Snapshot),
    Prove(Barrier),
    Release(&'a Name, &'a str),
}

impl AbortStep<'_> {
    /// Report only a durably accepted cancellation as in progress. A remaining
    /// reservation is not an accepted abort, even when its control was admitted.
    fn phase(&self) -> Result<AbortPhase, CatalogueError> {
        match self {
            Self::Done(phase) => Ok(phase.clone()),
            Self::Accept(_) => Err(CatalogueError::Conflict),
            _ => Ok(AbortPhase::Aborting),
        }
    }
}

enum DeleteStep<'a> {
    Blocked,
    Publish(&'a Snapshot),
    Release(&'a Name),
    Done,
}

impl DeleteStep<'_> {
    fn phase(&self) -> DeletionPhase {
        match self {
            Self::Blocked | Self::Publish(_) => DeletionPhase::NotDeleted,
            Self::Release(_) => DeletionPhase::Deleting,
            Self::Done => DeletionPhase::Deleted,
        }
    }
}

impl Catalogue {
    fn precheck_control(
        &self,
        input: &ControlInput<'_>,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        self.creation(input.creation)?;
        records::valid(
            input.operation != 0 && input.expected_name_revision != 0 && input.nonce != 0,
        )?;
        records::valid(input.expected_head_revision != Some(0))?;
        let key = self.control_address(input.principal, &input.kind, input.operation);
        if let Some(stored) = self.read::<Control>(&key, deadline)? {
            require(
                stored.body.principal == input.principal
                    && stored.body.kind == input.kind
                    && stored.body.operation == input.operation,
            )?;
            require(
                stored.body.creation.scope.deployment == self.deployment
                    && stored.body.creation.scope.tenant == self.tenant,
            )?;
            if stored.body.creation != *input.creation
                || stored.body.expected_name_revision != input.expected_name_revision
                || stored.body.expected_head_revision != input.expected_head_revision
                || stored.body.nonce != input.nonce
            {
                return Err(CatalogueError::Conflict);
            }
        }
        Ok(())
    }

    pub fn abort_create(
        &self,
        caller: Caller,
        input: &AbortCreate,
        deadline: Instant,
    ) -> Result<AbortProgress, CatalogueError> {
        Self::creator(caller, input.creation.creator)?;
        let deadline = self.options.deadline(deadline, false);
        self.precheck_control(
            &ControlInput {
                creation: &input.creation,
                kind: NamedDeletionKind::Abort,
                principal: caller.principal,
                operation: input.operation,
                expected_name_revision: input.expected_name_revision,
                expected_head_revision: None,
                nonce: input.nonce,
            },
            deadline,
        )?;
        let source = self.descriptor(&input.creation, deadline)?;
        let candidate = Control {
            format: 1,
            creation: input.creation.clone(),
            origin: source.origin(),
            kind: NamedDeletionKind::Abort,
            principal: caller.principal,
            operation: input.operation,
            expected_name_revision: input.expected_name_revision,
            expected_head_revision: None,
            nonce: input.nonce,
        };
        let control = self.immutable(&self.control_key(&candidate), &candidate, deadline)?;
        for _ in 0..4 {
            let view = self.view(&source, deadline)?;
            match self.abort_plan(&source, &control, &view, deadline)? {
                AbortStep::Done(phase) => {
                    return Self::abort_progress(&source, &control, &view, AbortStep::Done(phase))
                }
                AbortStep::Accept(binding) => {
                    let mut next = binding.body.raw().clone();
                    next.state = BindingState::Aborting;
                    next.revision += 1;
                    next.control = Some(control.raw().clone());
                    self.write_binding(&next, Some(&binding.etag), deadline)?;
                }
                AbortStep::FenceAbsent => {
                    let database = self.database(&source);
                    let mut head = database
                        .initial_head(control.principal, control.nonce, deadline)
                        .map_err(core_error)?;
                    head.lifecycle = Lifecycle::Deleted;
                    head.creation = Some(source.origin());
                    head.deletion = Some(control.mark());
                    database.create_head(&head, deadline).map_err(core_error)?;
                }
                AbortStep::Fence(base) => {
                    let mut head = Database::next(&base.head, control.nonce).map_err(core_error)?;
                    // The plan checked the unique initial Provisioning state.
                    head.owner_epoch = 2;
                    head.active = false;
                    head.lifecycle = Lifecycle::Deleted;
                    head.deletion = Some(control.mark());
                    self.database(&source)
                        .publish(base, &head, deadline)
                        .map_err(core_error)?;
                }
                AbortStep::Prove(barrier) => {
                    self.immutable(
                        &self.proof_key(&input.creation),
                        &AbortProof {
                            format: 1,
                            control: control.raw().clone(),
                            barrier,
                        },
                        deadline,
                    )?;
                }
                AbortStep::Release(binding, hash) => {
                    let mut next = binding.body.raw().clone();
                    next.state = BindingState::Tombstone;
                    next.revision += 1;
                    next.proof = Some(hash.into());
                    self.write_binding(&next, Some(&binding.etag), deadline)?;
                }
            }
        }
        let view = self.view(&source, deadline)?;
        let step = self.abort_plan(&source, &control, &view, deadline)?;
        Self::abort_progress(&source, &control, &view, step)
    }

    fn abort_plan<'a>(
        &self,
        source: &Source,
        control: &Admitted,
        view: &'a View,
        deadline: Instant,
    ) -> Result<AbortStep<'a>, CatalogueError> {
        let own = view.head.as_ref().filter(|h| Self::own(source, &h.head));
        let Some(binding) = &view.binding else {
            require(own.is_none() && view.proof.is_none())?;
            return Ok(AbortStep::Done(AbortPhase::NotReserved));
        };
        if binding.body.creation != source.creation {
            if let Some(proof) = &view.proof {
                if proof.control != *control {
                    return Err(CatalogueError::Conflict);
                }
                require(
                    binding.body.revision > source.creation.expected_name_revision.unwrap_or(0) + 3,
                )?;
                Self::barrier(
                    &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                    proof,
                )?;
                return Ok(AbortStep::Done(AbortPhase::Aborted));
            }
            if let Some(head) = own {
                require(
                    binding.body.revision > source.creation.expected_name_revision.unwrap_or(0) + 3,
                )?;
                self.delete_source(source, &head.head, deadline)?;
                Database::permission(&head.head, source.creation.creator, true, false, false)
                    .map_err(core_error)?;
                return Ok(AbortStep::Done(AbortPhase::CannotAbortBound));
            }
            return Ok(AbortStep::Done(AbortPhase::NotReserved));
        }
        match &binding.stage {
            NameStage::Reserved => {
                require(view.proof.is_none())?;
                if let Some(head) = own {
                    Self::provisioning(source, &head.head)?;
                }
                if binding.body.revision != control.expected_name_revision {
                    return Err(CatalogueError::Conflict);
                }
                Ok(AbortStep::Accept(binding))
            }
            NameStage::Bound => {
                require(view.proof.is_none())?;
                let head = &own.ok_or(CatalogueError::Corrupt)?.head;
                match head.lifecycle {
                    Lifecycle::Provisioning => Self::provisioning(source, head)?,
                    Lifecycle::Ready | Lifecycle::Maintenance => {
                        Database::permission(head, source.creation.creator, true, false, false)
                            .map_err(core_error)?;
                    }
                    Lifecycle::Deleted => {
                        self.delete_source(source, head, deadline)?;
                        Database::permission(head, source.creation.creator, true, false, false)
                            .map_err(core_error)?;
                    }
                }
                Ok(AbortStep::Done(AbortPhase::CannotAbortBound))
            }
            NameStage::Deleted(_) => {
                let head = Self::tombstone_view(binding, view)?;
                Database::permission(head, source.creation.creator, true, false, false)
                    .map_err(core_error)?;
                Ok(AbortStep::Done(AbortPhase::CannotAbortBound))
            }
            NameStage::Aborted {
                control: accepted, ..
            } => {
                if accepted != control {
                    return Err(CatalogueError::Conflict);
                }
                Self::tombstone_view(binding, view)?;
                Ok(AbortStep::Done(AbortPhase::Aborted))
            }
            NameStage::Aborting(accepted) => {
                if accepted != control {
                    return Err(CatalogueError::Conflict);
                }
                Self::aborting(source, control, view)?;
                let Some(head) = &view.head else {
                    return Ok(AbortStep::FenceAbsent);
                };
                if let Some(proof) = &view.proof {
                    return Ok(AbortStep::Release(binding, proof.body.hash()));
                }
                if Self::own(source, &head.head) {
                    if head.head.lifecycle == Lifecycle::Provisioning {
                        return Ok(AbortStep::Fence(head));
                    }
                    Ok(AbortStep::Prove(Barrier::OwnDeleted {
                        transition: head.head.transition.clone(),
                    }))
                } else {
                    Ok(AbortStep::Prove(Barrier::ForeignOccupied {
                        scope: head.head.scope.clone(),
                        creation: head.head.creation.clone(),
                    }))
                }
            }
        }
    }

    fn abort_progress(
        source: &Source,
        control: &Admitted,
        view: &View,
        step: AbortStep<'_>,
    ) -> Result<AbortProgress, CatalogueError> {
        let phase = step.phase()?;
        let (binding_revision, head_revision) = Self::revisions(source, view);
        Ok(AbortProgress {
            creation: source.creation.clone(),
            operation: control.operation,
            nonce: control.nonce,
            phase,
            binding_revision,
            head_revision,
        })
    }

    pub fn delete(
        &self,
        caller: Caller,
        input: &DeleteNamed,
        deadline: Instant,
    ) -> Result<DeletionProgress, CatalogueError> {
        Self::caller(caller)?;
        let deadline = self.options.deadline(deadline, false);
        self.precheck_control(
            &ControlInput {
                creation: &input.creation,
                kind: NamedDeletionKind::Delete,
                principal: caller.principal,
                operation: input.operation,
                expected_name_revision: input.expected_name_revision,
                expected_head_revision: Some(input.expected_head_revision),
                nonce: input.nonce,
            },
            deadline,
        )?;
        let source = self.descriptor(&input.creation, deadline)?;
        // New admission and old-operation reentry both require current ADMIN.
        let initial = self.view(&source, deadline)?;
        let base = Self::admin(&source, &initial, caller.principal)?;
        // A published delete already references a durable control descriptor.
        // Validate it before immutable admission: recreating a missing record
        // from the request would conceal a broken authority dependency.
        if base
            .head
            .deletion
            .as_ref()
            .is_some_and(|mark| mark.kind == NamedDeletionKind::Delete)
        {
            self.delete_source(&source, &base.head, deadline)?;
        }
        let candidate = Control {
            format: 1,
            creation: input.creation.clone(),
            origin: source.origin(),
            kind: NamedDeletionKind::Delete,
            principal: caller.principal,
            operation: input.operation,
            expected_name_revision: input.expected_name_revision,
            expected_head_revision: Some(input.expected_head_revision),
            nonce: input.nonce,
        };
        let control = self.immutable(&self.control_key(&candidate), &candidate, deadline)?;
        for _ in 0..2 {
            let view = self.view(&source, deadline)?;
            let plan = self.delete_plan(&source, &control, &view)?;
            match plan {
                DeleteStep::Blocked | DeleteStep::Done => {
                    return Ok(Self::deletion_progress(
                        &source,
                        &control,
                        &view,
                        plan.phase(),
                    ))
                }
                DeleteStep::Publish(base) => {
                    let mut head = Database::next(&base.head, input.nonce).map_err(core_error)?;
                    head.owner_epoch = head
                        .owner_epoch
                        .checked_add(1)
                        .ok_or(CatalogueError::Limit)?;
                    head.active = false;
                    head.lifecycle = Lifecycle::Deleted;
                    head.deletion = Some(control.mark());
                    self.database(&source)
                        .publish(base, &head, deadline)
                        .map_err(core_error)?;
                }
                DeleteStep::Release(binding) => {
                    let mut next = binding.body.raw().clone();
                    next.state = BindingState::Tombstone;
                    next.revision += 1;
                    next.control = Some(control.raw().clone());
                    self.write_binding(&next, Some(&binding.etag), deadline)?;
                }
            }
        }
        let view = self.view(&source, deadline)?;
        let plan = self.delete_plan(&source, &control, &view)?;
        Ok(Self::deletion_progress(
            &source,
            &control,
            &view,
            plan.phase(),
        ))
    }

    fn admin<'a>(
        source: &Source,
        view: &'a View,
        principal: u64,
    ) -> Result<&'a Snapshot, CatalogueError> {
        let binding = view
            .binding
            .as_ref()
            .filter(|b| b.body.creation == source.creation);
        let must_exist = binding.is_some_and(|b| {
            matches!(
                b.stage,
                NameStage::Bound | NameStage::Aborted { .. } | NameStage::Deleted(_)
            )
        }) || view.proof.is_some();
        let head = view.head.as_ref().ok_or(if must_exist {
            CatalogueError::Corrupt
        } else {
            CatalogueError::NotFound
        })?;
        if let Some(binding) = binding {
            if matches!(
                binding.stage,
                NameStage::Aborted { .. } | NameStage::Deleted(_)
            ) {
                Self::tombstone_view(binding, view)?;
            }
        }
        if let Some(proof) = &view.proof {
            Self::barrier(&head.head, proof)?;
        }
        if !Self::own(source, &head.head) {
            if binding.is_some_and(|b| b.stage == NameStage::Bound) {
                return Err(CatalogueError::Corrupt);
            }
            return Err(CatalogueError::IdentityConflict);
        }
        Database::permission(&head.head, principal, false, false, true).map_err(core_error)?;
        Ok(head)
    }

    fn delete_plan<'a>(
        &self,
        source: &Source,
        control: &Admitted,
        view: &'a View,
    ) -> Result<DeleteStep<'a>, CatalogueError> {
        let base = Self::admin(source, view, control.principal)?;
        let binding = view.binding.as_ref().ok_or(CatalogueError::Corrupt)?;
        if base.head.lifecycle != Lifecycle::Deleted {
            // admin verified any proof against this same own HEAD. An abort
            // proof certifies Deleted, so none can coexist with this state.
            require(binding.body.creation == source.creation)?;
            if base.head.lifecycle == Lifecycle::Provisioning {
                Self::provisioning(source, &base.head)?;
                return Ok(DeleteStep::Blocked);
            }
            require(binding.stage == NameStage::Bound)?;
            if binding.body.revision != control.expected_name_revision
                || Some(base.head.revision) != control.expected_head_revision
            {
                return Err(CatalogueError::Conflict);
            }
            return Ok(DeleteStep::Publish(base));
        }
        if base.head.deletion.as_ref() != Some(&control.mark()) {
            return Err(CatalogueError::Conflict);
        }
        Self::deleted(&base.head, control)?;
        // The exact normal-delete mark excludes an abort proof, whose barrier
        // admin already verified before returning the own HEAD.
        if binding.body.creation != source.creation {
            require(
                binding.body.revision > source.creation.expected_name_revision.unwrap_or(0) + 3,
            )?;
            return Ok(DeleteStep::Done);
        }
        match &binding.stage {
            // A canonical Bound has creation.expected_name_revision + 2;
            // deleted() verified that same revision in the admitted control.
            NameStage::Bound => Ok(DeleteStep::Release(binding)),
            // admin verified the tombstone's source against this exact HEAD,
            // whose deletion mark was just matched to the caller's control.
            NameStage::Deleted(_) => Ok(DeleteStep::Done),
            _ => Err(CatalogueError::Corrupt),
        }
    }

    fn deletion_progress(
        source: &Source,
        control: &Admitted,
        view: &View,
        phase: DeletionPhase,
    ) -> DeletionProgress {
        let (binding_revision, head_revision) = Self::revisions(source, view);
        DeletionProgress {
            creation: source.creation.clone(),
            operation: control.operation,
            nonce: control.nonce,
            phase,
            binding_revision,
            head_revision,
        }
    }
}

#[cfg(test)]
#[path = "control_boundary_tests.rs"]
mod tests;
