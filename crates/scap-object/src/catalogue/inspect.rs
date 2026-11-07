use super::*;
use records::BindingState;

impl Catalogue {
    /// An exact create-operation lookup. This performs no writes and does not
    /// recover a different caller's control operation.
    pub fn inspect_create_operation(
        &self,
        caller: Caller,
        create_operation: u64,
        deadline: Instant,
    ) -> Result<CreationProgress, CatalogueError> {
        Self::creator(caller, caller.principal)?;
        records::valid(create_operation != 0)?;
        let deadline = self.options.deadline(deadline, false);
        let descriptor = self.read_descriptor(caller.principal, create_operation, deadline)?;
        let view = self.view(&descriptor, deadline)?;
        self.progress(&descriptor, &view, deadline)
    }

    /// A name alone never grants access. A successful result requires a Bound
    /// binding, the matching fresh Ready HEAD, and its current READ permission.
    pub fn resolve(
        &self,
        caller: Caller,
        name: &str,
        deadline: Instant,
    ) -> Result<Named, CatalogueError> {
        Self::caller(caller)?;
        records::name_valid(name)?;
        let deadline = self.options.deadline(deadline, false);
        let binding = self
            .read_binding(name, deadline)?
            .ok_or(CatalogueError::NotFound)?;
        let descriptor = authority(self.descriptor(&binding.body.creation, deadline))?;
        let view = self.view(&descriptor, deadline)?;
        if view.binding.as_ref() != Some(&binding) {
            return Err(CatalogueError::Conflict);
        }
        if binding.body.state != BindingState::Bound {
            return Err(CatalogueError::NotFound);
        }
        require(view.proof.is_none())?;
        let head = view.head.ok_or(CatalogueError::Corrupt)?.head;
        require(Self::own(&descriptor, &head)?)?;
        if head.lifecycle != Lifecycle::Ready {
            return Err(CatalogueError::NotFound);
        }
        Database::permission(&head, caller.principal, true, false, false).map_err(core_error)?;
        Ok(Named {
            creation: descriptor.creation,
            binding_revision: binding.body.revision,
            head,
        })
    }

    pub(super) fn progress(
        &self,
        descriptor: &Descriptor,
        view: &View,
        deadline: Instant,
    ) -> Result<CreationProgress, CatalogueError> {
        let phase = self.phase(descriptor, view, deadline)?;
        let binding_revision = view
            .binding
            .as_ref()
            .filter(|binding| binding.body.creation == descriptor.creation)
            .map(|binding| binding.body.revision);
        let head_revision = match &view.head {
            Some(head) if Self::own(descriptor, &head.head)? => Some(head.head.revision),
            _ => None,
        };
        Ok(CreationProgress {
            creation: descriptor.creation.clone(),
            phase,
            binding_revision,
            head_revision,
            initial_quota: descriptor.initial_quota.clone(),
            retention: descriptor.retention.clone(),
        })
    }

    pub(super) fn phase(
        &self,
        descriptor: &Descriptor,
        view: &View,
        deadline: Instant,
    ) -> Result<CreationPhase, CatalogueError> {
        let own_head = match &view.head {
            Some(head) if Self::own(descriptor, &head.head)? => Some(&head.head),
            _ => None,
        };
        let Some(binding) = &view.binding else {
            require(own_head.is_none() && view.proof.is_none())?;
            return Ok(if descriptor.creation.expected_name_revision.is_some() {
                CreationPhase::NameConflict
            } else {
                CreationPhase::NotReserved
            });
        };
        if binding.body.creation != descriptor.creation {
            return self.other_binding(descriptor, view, own_head, deadline);
        }
        require(binding.body.origin == descriptor.origin()?)?;
        match binding.body.state {
            BindingState::Reserved => {
                require(view.proof.is_none())?;
                match (&view.head, own_head) {
                    (None, _) => Ok(CreationPhase::Reserved),
                    (_, None) => Ok(CreationPhase::IdentityConflict),
                    (_, Some(head)) => {
                        Self::provisioning(descriptor, head)?;
                        Ok(CreationPhase::Provisioning)
                    }
                }
            }
            BindingState::Bound => {
                require(view.proof.is_none())?;
                let head = own_head.ok_or(CatalogueError::Corrupt)?;
                match head.lifecycle {
                    Lifecycle::Provisioning => {
                        Self::provisioning(descriptor, head)?;
                        Ok(CreationPhase::Bound)
                    }
                    Lifecycle::Ready => {
                        Database::permission(head, descriptor.creation.creator, true, false, false)
                            .map_err(core_error)?;
                        Ok(CreationPhase::Ready)
                    }
                    Lifecycle::Maintenance => Err(CatalogueError::Conflict),
                    Lifecycle::Deleted => {
                        self.deleted_control(descriptor, head, deadline)?;
                        Ok(CreationPhase::Deleting)
                    }
                }
            }
            BindingState::Aborting => {
                let control = binding
                    .body
                    .control
                    .as_ref()
                    .ok_or(CatalogueError::Corrupt)?;
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
                Ok(CreationPhase::Aborting)
            }
            BindingState::Tombstone => {
                self.verify_tombstone(&binding.body, deadline)?;
                match binding
                    .body
                    .control
                    .as_ref()
                    .ok_or(CatalogueError::Corrupt)?
                    .kind
                {
                    NamedDeletionKind::Abort => {
                        require(view.proof.is_some())?;
                        Ok(CreationPhase::Aborted)
                    }
                    NamedDeletionKind::Delete => {
                        Database::permission(
                            own_head.ok_or(CatalogueError::Corrupt)?,
                            descriptor.creation.creator,
                            true,
                            false,
                            false,
                        )
                        .map_err(core_error)?;
                        Ok(CreationPhase::Deleted)
                    }
                }
            }
        }
    }

    pub(super) fn deleted_control(
        &self,
        descriptor: &Descriptor,
        head: &Head,
        deadline: Instant,
    ) -> Result<Control, CatalogueError> {
        let mark = head.deletion.as_ref().ok_or(CatalogueError::Corrupt)?;
        require(mark.kind == NamedDeletionKind::Delete)?;
        let control = Control {
            format: 1,
            creation: descriptor.creation.clone(),
            origin: descriptor.origin()?,
            kind: mark.kind.clone(),
            principal: mark.principal,
            operation: mark.operation,
            expected_name_revision: mark.expected_name_revision,
            expected_head_revision: mark.expected_head_revision,
            nonce: mark.nonce,
        };
        self.control_exists(&control, deadline)?;
        Self::deleted(head, &control)?;
        Database::permission(head, descriptor.creation.creator, true, false, false)
            .map_err(core_error)?;
        Ok(control)
    }

    fn other_binding(
        &self,
        descriptor: &Descriptor,
        view: &View,
        own_head: Option<&Head>,
        deadline: Instant,
    ) -> Result<CreationPhase, CatalogueError> {
        let binding = &view.binding.as_ref().ok_or(CatalogueError::Corrupt)?.body;
        let terminal_revision = descriptor.creation.expected_name_revision.unwrap_or(0) + 3;
        if let Some(proof) = &view.proof {
            require(binding.revision > terminal_revision)?;
            Self::barrier(
                &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                &proof.body,
            )?;
            return Ok(CreationPhase::Aborted);
        }
        if let Some(head) = own_head {
            require(binding.revision > terminal_revision)?;
            self.deleted_control(descriptor, head, deadline)?;
            return Ok(CreationPhase::Deleted);
        }
        if binding.state == BindingState::Tombstone
            && descriptor.creation.expected_name_revision == Some(binding.revision)
        {
            self.verify_tombstone(binding, deadline)?;
            if binding.creation.scope.database == descriptor.creation.scope.database {
                return Ok(CreationPhase::IdentityConflict);
            }
            return Ok(CreationPhase::NotReserved);
        }
        Ok(CreationPhase::NameConflict)
    }
}
