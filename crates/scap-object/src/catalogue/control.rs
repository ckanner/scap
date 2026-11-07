use super::*;
use records::BindingState;

impl Catalogue {
    /// Cancellation competes only with binding Reserved to Bound. It never
    /// turns a completed/Bound database into an aborted creation.
    pub fn abort_create(
        &self,
        caller: Caller,
        input: &AbortCreate,
        deadline: Instant,
    ) -> Result<AbortProgress, CatalogueError> {
        Self::creator(caller, input.creation.creator)?;
        let deadline = self.options.deadline(deadline, false);
        let descriptor = self.descriptor(&input.creation, deadline)?;
        let control = Control {
            format: 1,
            creation: input.creation.clone(),
            origin: descriptor.origin()?,
            kind: NamedDeletionKind::Abort,
            principal: caller.principal,
            operation: input.operation,
            expected_name_revision: input.expected_name_revision,
            expected_head_revision: None,
            nonce: input.nonce,
        };
        self.immutable(&self.control_key(&control), &control, deadline)?;
        let mut view = self.view(&descriptor, deadline)?;
        if let Some(binding) = &view.binding {
            if binding.body.creation == input.creation
                && binding.body.state == BindingState::Reserved
            {
                if binding.body.revision != input.expected_name_revision {
                    return Err(CatalogueError::Conflict);
                }
                let mut aborting = binding.body.clone();
                aborting.state = BindingState::Aborting;
                aborting.revision += 1;
                aborting.control = Some(control.clone());
                self.write_binding(&aborting, Some(&binding.etag), deadline)?;
                view = self.view(&descriptor, deadline)?;
            }
        }
        let phase = self.abort_phase(&descriptor, &control, &view, deadline)?;
        if phase != AbortPhase::Aborting {
            return self.abort_progress(&descriptor, &control, &view, phase);
        }
        self.fence_abort(&descriptor, &control, &view, deadline)?;
        view = self.view(&descriptor, deadline)?;
        let phase = self.abort_phase(&descriptor, &control, &view, deadline)?;
        if phase != AbortPhase::Aborting {
            return self.abort_progress(&descriptor, &control, &view, phase);
        }
        let head = &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head;
        let barrier = if Self::own(&descriptor, head)? {
            Self::deleted(head, &control)?;
            Barrier::OwnDeleted {
                transition: head.transition.clone(),
            }
        } else {
            Barrier::ForeignOccupied {
                scope: head.scope.clone(),
                creation: head.creation.clone(),
            }
        };
        let proof = AbortProof {
            format: 1,
            control: control.clone(),
            barrier,
        };
        self.immutable(&self.proof_key(&input.creation), &proof, deadline)?;
        view = self.view(&descriptor, deadline)?;
        let phase = self.abort_phase(&descriptor, &control, &view, deadline)?;
        if phase != AbortPhase::Aborting {
            return self.abort_progress(&descriptor, &control, &view, phase);
        }
        let binding = view.binding.as_ref().ok_or(CatalogueError::Corrupt)?;
        let mut tombstone = binding.body.clone();
        tombstone.state = BindingState::Tombstone;
        tombstone.revision += 1;
        tombstone.proof = Some(format::digest(&records::encode(&proof)?));
        self.write_binding(&tombstone, Some(&binding.etag), deadline)?;
        view = self.view(&descriptor, deadline)?;
        let phase = self.abort_phase(&descriptor, &control, &view, deadline)?;
        require(phase == AbortPhase::Aborted)?;
        self.abort_progress(&descriptor, &control, &view, phase)
    }

    fn fence_abort(
        &self,
        descriptor: &Descriptor,
        control: &Control,
        view: &View,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let database = self.database(descriptor)?;
        let Some(base) = &view.head else {
            let mut head = database
                .initial_head(control.principal, control.nonce, deadline)
                .map_err(core_error)?;
            head.lifecycle = Lifecycle::Deleted;
            head.creation = Some(descriptor.origin()?);
            head.deletion = Some(control.mark()?);
            return database.create_head(&head, deadline).map_err(core_error);
        };
        if !Self::own(descriptor, &base.head)? {
            return Ok(());
        }
        if base.head.lifecycle == Lifecycle::Deleted {
            return Self::deleted(&base.head, control);
        }
        Self::provisioning(descriptor, &base.head)?;
        let mut head = Database::next(&base.head, control.nonce).map_err(core_error)?;
        head.owner_epoch = head
            .owner_epoch
            .checked_add(1)
            .ok_or(CatalogueError::Limit)?;
        head.active = false;
        head.lifecycle = Lifecycle::Deleted;
        head.deletion = Some(control.mark()?);
        database.publish(base, &head, deadline).map_err(core_error)
    }

    fn abort_phase(
        &self,
        descriptor: &Descriptor,
        control: &Control,
        view: &View,
        deadline: Instant,
    ) -> Result<AbortPhase, CatalogueError> {
        let own_head = match &view.head {
            Some(head) if Self::own(descriptor, &head.head)? => Some(&head.head),
            _ => None,
        };
        let Some(binding) = &view.binding else {
            require(own_head.is_none() && view.proof.is_none())?;
            return Ok(AbortPhase::NotReserved);
        };
        if binding.body.creation != descriptor.creation {
            if let Some(proof) = &view.proof {
                if proof.body.control != *control {
                    return Err(CatalogueError::Conflict);
                }
                require(
                    binding.body.revision
                        > descriptor.creation.expected_name_revision.unwrap_or(0) + 3,
                )?;
                Self::barrier(
                    &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                    &proof.body,
                )?;
                return Ok(AbortPhase::Aborted);
            }
            if let Some(head) = own_head {
                self.deleted_control(descriptor, head, deadline)?;
                return Ok(AbortPhase::CannotAbortBound);
            }
            return Ok(AbortPhase::NotReserved);
        }
        match binding.body.state {
            BindingState::Reserved => Err(CatalogueError::Conflict),
            BindingState::Bound => {
                require(view.proof.is_none())?;
                let head = own_head.ok_or(CatalogueError::Corrupt)?;
                match head.lifecycle {
                    Lifecycle::Provisioning => Self::provisioning(descriptor, head)?,
                    Lifecycle::Ready | Lifecycle::Maintenance => {
                        Database::permission(head, descriptor.creation.creator, true, false, false)
                            .map_err(core_error)?;
                    }
                    Lifecycle::Deleted => {
                        self.deleted_control(descriptor, head, deadline)?;
                    }
                }
                Ok(AbortPhase::CannotAbortBound)
            }
            BindingState::Aborting | BindingState::Tombstone => {
                let accepted = binding
                    .body
                    .control
                    .as_ref()
                    .ok_or(CatalogueError::Corrupt)?;
                if accepted.kind == NamedDeletionKind::Delete {
                    self.verify_tombstone(&binding.body, deadline)?;
                    self.deleted_control(
                        descriptor,
                        own_head.ok_or(CatalogueError::Corrupt)?,
                        deadline,
                    )?;
                    return Ok(AbortPhase::CannotAbortBound);
                }
                if accepted != control {
                    return Err(CatalogueError::Conflict);
                }
                if let Some(head) = own_head {
                    match head.lifecycle {
                        Lifecycle::Provisioning => Self::provisioning(descriptor, head)?,
                        Lifecycle::Deleted => Self::deleted(head, control)?,
                        _ => return Err(CatalogueError::Corrupt),
                    }
                }
                if let Some(proof) = &view.proof {
                    require(proof.body.control == *control)?;
                    Self::barrier(
                        &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                        &proof.body,
                    )?;
                }
                if binding.body.state == BindingState::Tombstone {
                    require(view.proof.is_some())?;
                    self.verify_tombstone(&binding.body, deadline)?;
                    Ok(AbortPhase::Aborted)
                } else {
                    Ok(AbortPhase::Aborting)
                }
            }
        }
    }

    fn revisions(
        descriptor: &Descriptor,
        view: &View,
    ) -> Result<(Option<u64>, Option<u64>), CatalogueError> {
        let binding = view
            .binding
            .as_ref()
            .filter(|binding| binding.body.creation == descriptor.creation)
            .map(|binding| binding.body.revision);
        let head = match &view.head {
            Some(head) if Self::own(descriptor, &head.head)? => Some(head.head.revision),
            _ => None,
        };
        Ok((binding, head))
    }

    fn abort_progress(
        &self,
        descriptor: &Descriptor,
        control: &Control,
        view: &View,
        phase: AbortPhase,
    ) -> Result<AbortProgress, CatalogueError> {
        let (binding_revision, head_revision) = Self::revisions(descriptor, view)?;
        Ok(AbortProgress {
            creation: descriptor.creation.clone(),
            operation: control.operation,
            nonce: control.nonce,
            phase,
            binding_revision,
            head_revision,
        })
    }

    /// A normal deletion may be admitted by a different current ADMIN. Its
    /// original binding/HEAD revisions remain fixed for the entire operation.
    pub fn delete(
        &self,
        caller: Caller,
        input: &DeleteNamed,
        deadline: Instant,
    ) -> Result<DeletionProgress, CatalogueError> {
        Self::caller(caller)?;
        let deadline = self.options.deadline(deadline, false);
        let descriptor = self.descriptor(&input.creation, deadline)?;
        let control = Control {
            format: 1,
            creation: input.creation.clone(),
            origin: descriptor.origin()?,
            kind: NamedDeletionKind::Delete,
            principal: caller.principal,
            operation: input.operation,
            expected_name_revision: input.expected_name_revision,
            expected_head_revision: Some(input.expected_head_revision),
            nonce: input.nonce,
        };
        control.validate()?;
        let view = self.view(&descriptor, deadline)?;
        Self::admin(&descriptor, &view, caller.principal)?;
        self.immutable(&self.control_key(&control), &control, deadline)?;
        let mut view = self.view(&descriptor, deadline)?;
        let mut phase = self.deletion_phase(&descriptor, &control, &view)?;
        if phase == DeletionPhase::NotDeleted {
            let base = Self::admin(&descriptor, &view, caller.principal)?;
            let binding = view.binding.as_ref().ok_or(CatalogueError::Corrupt)?;
            if binding.body.state != BindingState::Bound
                || base.head.lifecycle == Lifecycle::Provisioning
            {
                return self.deletion_progress(&descriptor, &control, &view, phase);
            }
            if binding.body.revision != input.expected_name_revision
                || base.head.revision != input.expected_head_revision
            {
                return Err(CatalogueError::Conflict);
            }
            let database = self.database(&descriptor)?;
            let mut head = Database::next(&base.head, input.nonce).map_err(core_error)?;
            head.owner_epoch = head
                .owner_epoch
                .checked_add(1)
                .ok_or(CatalogueError::Limit)?;
            head.active = false;
            head.lifecycle = Lifecycle::Deleted;
            head.deletion = Some(control.mark()?);
            database
                .publish(base, &head, deadline)
                .map_err(core_error)?;
            view = self.view(&descriptor, deadline)?;
            phase = self.deletion_phase(&descriptor, &control, &view)?;
        }
        if phase == DeletionPhase::Deleting {
            let binding = view.binding.as_ref().ok_or(CatalogueError::Corrupt)?;
            let mut tombstone = binding.body.clone();
            tombstone.state = BindingState::Tombstone;
            tombstone.revision += 1;
            tombstone.control = Some(control.clone());
            self.write_binding(&tombstone, Some(&binding.etag), deadline)?;
            view = self.view(&descriptor, deadline)?;
            phase = self.deletion_phase(&descriptor, &control, &view)?;
        }
        self.deletion_progress(&descriptor, &control, &view, phase)
    }

    fn admin<'a>(
        descriptor: &Descriptor,
        view: &'a View,
        principal: u64,
    ) -> Result<&'a Snapshot, CatalogueError> {
        let binding = view
            .binding
            .as_ref()
            .filter(|binding| binding.body.creation == descriptor.creation);
        let must_exist = binding.is_some_and(|binding| {
            matches!(
                binding.body.state,
                BindingState::Bound | BindingState::Tombstone
            )
        }) || view.proof.is_some();
        let head = view.head.as_ref().ok_or(if must_exist {
            CatalogueError::Corrupt
        } else {
            CatalogueError::NotFound
        })?;
        if let Some(binding) = binding {
            if binding.body.state == BindingState::Tombstone {
                Self::tombstone_view(&binding.body, view)?;
            }
        }
        if let Some(proof) = &view.proof {
            Self::barrier(&head.head, &proof.body)?;
        }
        if !Self::own(descriptor, &head.head)? {
            if binding.is_some_and(|binding| binding.body.state == BindingState::Bound) {
                return Err(CatalogueError::Corrupt);
            }
            return Err(CatalogueError::IdentityConflict);
        }
        Database::permission(&head.head, principal, false, false, true).map_err(core_error)?;
        Ok(head)
    }

    fn deletion_phase(
        &self,
        descriptor: &Descriptor,
        control: &Control,
        view: &View,
    ) -> Result<DeletionPhase, CatalogueError> {
        let head = &Self::admin(descriptor, view, control.principal)?.head;
        let binding = &view.binding.as_ref().ok_or(CatalogueError::Corrupt)?.body;
        if head.lifecycle != Lifecycle::Deleted {
            require(view.proof.is_none())?;
            require(binding.creation == descriptor.creation)?;
            if head.lifecycle == Lifecycle::Provisioning {
                Self::provisioning(descriptor, head)?;
            } else {
                require(binding.state == BindingState::Bound)?;
            }
            return Ok(DeletionPhase::NotDeleted);
        }
        if head.deletion.as_ref() != Some(&control.mark()?) {
            return Err(CatalogueError::Conflict);
        }
        Self::deleted(head, control)?;
        require(view.proof.is_none())?;
        if binding.creation != descriptor.creation {
            require(
                binding.revision > descriptor.creation.expected_name_revision.unwrap_or(0) + 3,
            )?;
            return Ok(DeletionPhase::Deleted);
        }
        match binding.state {
            BindingState::Bound => {
                require(binding.revision == control.expected_name_revision)?;
                Ok(DeletionPhase::Deleting)
            }
            BindingState::Tombstone => {
                require(binding.control.as_ref() == Some(control))?;
                Ok(DeletionPhase::Deleted)
            }
            _ => Err(CatalogueError::Corrupt),
        }
    }

    fn deletion_progress(
        &self,
        descriptor: &Descriptor,
        control: &Control,
        view: &View,
        phase: DeletionPhase,
    ) -> Result<DeletionProgress, CatalogueError> {
        let (binding_revision, head_revision) = Self::revisions(descriptor, view)?;
        Ok(DeletionProgress {
            creation: descriptor.creation.clone(),
            operation: control.operation,
            nonce: control.nonce,
            phase,
            binding_revision,
            head_revision,
        })
    }
}
