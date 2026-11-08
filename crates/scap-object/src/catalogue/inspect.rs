use super::*;

pub(super) enum CreateStep<'a> {
    None,
    Reserve(Option<&'a Name>),
    Provision,
    Bind(&'a Name),
    Complete(&'a Name, &'a Snapshot),
}

pub(super) struct CreationPlan<'a> {
    pub(super) phase: CreationPhase,
    pub(super) step: CreateStep<'a>,
}

impl CreationPlan<'_> {
    fn idle(phase: CreationPhase) -> Self {
        Self {
            phase,
            step: CreateStep::None,
        }
    }
}

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
        let source = self.read_descriptor(caller.principal, create_operation, deadline)?;
        let view = self.view(&source, deadline)?;
        let plan = self.creation_plan(&source, &view, deadline)?;
        Ok(Self::progress(&source, &view, plan.phase))
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
        let source = authority(self.descriptor(&binding.body.creation, deadline))?;
        let view = self.view(&source, deadline)?;
        if view.binding.as_ref() != Some(&binding) {
            return Err(CatalogueError::Conflict);
        }
        match &binding.stage {
            NameStage::Aborted { .. } | NameStage::Deleted(_) => {
                Self::tombstone_view(&binding, &view)?;
                Err(CatalogueError::NotFound)
            }
            NameStage::Aborting(control) => {
                Self::aborting(&source, control, &view)?;
                Err(CatalogueError::NotFound)
            }
            NameStage::Reserved => {
                require(view.proof.is_none())?;
                if let Some(head) = &view.head {
                    if Self::own(&source, &head.head) {
                        Self::provisioning(&source, &head.head)?;
                    }
                }
                Err(CatalogueError::NotFound)
            }
            NameStage::Bound => {
                require(view.proof.is_none())?;
                let head = &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head;
                require(Self::own(&source, head))?;
                match head.lifecycle {
                    Lifecycle::Provisioning => {
                        Self::provisioning(&source, head)?;
                        Err(CatalogueError::NotFound)
                    }
                    Lifecycle::Deleted => {
                        self.delete_source(&source, head, deadline)?;
                        Err(CatalogueError::NotFound)
                    }
                    Lifecycle::Maintenance => Err(CatalogueError::NotFound),
                    Lifecycle::Ready => {
                        Database::permission(head, caller.principal, true, false, false)
                            .map_err(core_error)?;
                        Ok(Named {
                            creation: source.creation.clone(),
                            binding_revision: binding.body.revision,
                            head: head.clone(),
                        })
                    }
                }
            }
        }
    }

    pub(super) fn progress(source: &Source, view: &View, phase: CreationPhase) -> CreationProgress {
        let (binding_revision, head_revision) = Self::revisions(source, view);
        CreationProgress {
            creation: source.creation.clone(),
            phase,
            binding_revision,
            head_revision,
            initial_quota: source.initial_quota.clone(),
            retention: source.retention.clone(),
        }
    }

    pub(super) fn revisions(source: &Source, view: &View) -> (Option<u64>, Option<u64>) {
        let binding = view
            .binding
            .as_ref()
            .filter(|binding| binding.body.creation == source.creation)
            .map(|binding| binding.body.revision);
        let head = view
            .head
            .as_ref()
            .filter(|head| Self::own(source, &head.head))
            .map(|head| head.head.revision);
        (binding, head)
    }

    pub(super) fn creation_plan<'a>(
        &self,
        source: &Source,
        view: &'a View,
        deadline: Instant,
    ) -> Result<CreationPlan<'a>, CatalogueError> {
        let own = view
            .head
            .as_ref()
            .filter(|head| Self::own(source, &head.head));
        let Some(binding) = &view.binding else {
            require(own.is_none() && view.proof.is_none())?;
            return Ok(if source.creation.expected_name_revision.is_some() {
                CreationPlan::idle(CreationPhase::NameConflict)
            } else {
                CreationPlan {
                    phase: CreationPhase::NotReserved,
                    step: CreateStep::Reserve(None),
                }
            });
        };
        if binding.body.creation != source.creation {
            return self.other_binding(source, binding, view, own, deadline);
        }
        match &binding.stage {
            NameStage::Reserved => {
                require(view.proof.is_none())?;
                match (&view.head, own) {
                    (None, _) => Ok(CreationPlan {
                        phase: CreationPhase::Reserved,
                        step: CreateStep::Provision,
                    }),
                    (_, None) => Ok(CreationPlan::idle(CreationPhase::IdentityConflict)),
                    (_, Some(head)) => {
                        Self::provisioning(source, &head.head)?;
                        Ok(CreationPlan {
                            phase: CreationPhase::Provisioning,
                            step: CreateStep::Bind(binding),
                        })
                    }
                }
            }
            NameStage::Bound => {
                require(view.proof.is_none())?;
                let head = own.ok_or(CatalogueError::Corrupt)?;
                match head.head.lifecycle {
                    Lifecycle::Provisioning => {
                        Self::provisioning(source, &head.head)?;
                        Ok(CreationPlan {
                            phase: CreationPhase::Bound,
                            step: CreateStep::Complete(binding, head),
                        })
                    }
                    Lifecycle::Ready => {
                        Database::permission(
                            &head.head,
                            source.creation.creator,
                            true,
                            false,
                            false,
                        )
                        .map_err(core_error)?;
                        Ok(CreationPlan::idle(CreationPhase::Ready))
                    }
                    Lifecycle::Maintenance => Err(CatalogueError::Conflict),
                    Lifecycle::Deleted => {
                        self.delete_source(source, &head.head, deadline)?;
                        Database::permission(
                            &head.head,
                            source.creation.creator,
                            true,
                            false,
                            false,
                        )
                        .map_err(core_error)?;
                        Ok(CreationPlan::idle(CreationPhase::Deleting))
                    }
                }
            }
            NameStage::Aborting(control) => {
                Self::aborting(source, control, view)?;
                Ok(CreationPlan::idle(CreationPhase::Aborting))
            }
            NameStage::Aborted { .. } => {
                Self::tombstone_view(binding, view)?;
                Ok(CreationPlan::idle(CreationPhase::Aborted))
            }
            NameStage::Deleted(_) => {
                let head = Self::tombstone_view(binding, view)?;
                Database::permission(head, source.creation.creator, true, false, false)
                    .map_err(core_error)?;
                Ok(CreationPlan::idle(CreationPhase::Deleted))
            }
        }
    }

    pub(super) fn aborting(
        source: &Source,
        control: &Admitted,
        view: &View,
    ) -> Result<(), CatalogueError> {
        if let Some(head) = view
            .head
            .as_ref()
            .filter(|head| Self::own(source, &head.head))
        {
            match head.head.lifecycle {
                Lifecycle::Provisioning => Self::provisioning(source, &head.head)?,
                Lifecycle::Deleted => Self::deleted(&head.head, control)?,
                Lifecycle::Ready | Lifecycle::Maintenance => return Err(CatalogueError::Corrupt),
            }
        }
        if let Some(proof) = &view.proof {
            require(proof.control == *control)?;
            Self::barrier(
                &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                proof,
            )?;
        }
        Ok(())
    }

    /// Check the durable deletion source independently of caller permission.
    /// Each public entry point applies its own current READ or ADMIN contract.
    pub(super) fn delete_source(
        &self,
        source: &Source,
        head: &Head,
        deadline: Instant,
    ) -> Result<Admitted, CatalogueError> {
        let mark = head.deletion.as_ref().ok_or(CatalogueError::Corrupt)?;
        require(mark.kind == NamedDeletionKind::Delete)?;
        let expected = Control {
            format: 1,
            creation: source.creation.clone(),
            origin: source.origin(),
            kind: mark.kind.clone(),
            principal: mark.principal,
            operation: mark.operation,
            expected_name_revision: mark.expected_name_revision,
            expected_head_revision: mark.expected_head_revision,
            nonce: mark.nonce,
        };
        let control = self.control_exists(&expected, deadline)?;
        Self::deleted(head, &control)?;
        Ok(control)
    }

    fn other_binding<'a>(
        &self,
        source: &Source,
        binding: &'a Name,
        view: &'a View,
        own: Option<&'a Snapshot>,
        deadline: Instant,
    ) -> Result<CreationPlan<'a>, CatalogueError> {
        let terminal_revision = source.creation.expected_name_revision.unwrap_or(0) + 3;
        if let Some(proof) = &view.proof {
            require(binding.body.revision > terminal_revision)?;
            Self::barrier(
                &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                proof,
            )?;
            return Ok(CreationPlan::idle(CreationPhase::Aborted));
        }
        if let Some(head) = own {
            require(binding.body.revision > terminal_revision)?;
            self.delete_source(source, &head.head, deadline)?;
            Database::permission(&head.head, source.creation.creator, true, false, false)
                .map_err(core_error)?;
            return Ok(CreationPlan::idle(CreationPhase::Deleted));
        }
        if matches!(
            binding.stage,
            NameStage::Aborted { .. } | NameStage::Deleted(_)
        ) && source.creation.expected_name_revision == Some(binding.body.revision)
        {
            self.verify_tombstone(binding, deadline)?;
            return Ok(Self::reuse_plan(&source.creation.scope, binding));
        }
        Ok(CreationPlan::idle(CreationPhase::NameConflict))
    }

    /// A verified terminal name may be reused, but its permanent physical HEAD
    /// slot may not. Compare the physical key component, not just full Scope.
    fn reuse_plan<'a>(scope: &Scope, previous: &'a Name) -> CreationPlan<'a> {
        if previous.body.creation.scope.database == scope.database {
            CreationPlan::idle(CreationPhase::IdentityConflict)
        } else {
            CreationPlan {
                phase: CreationPhase::NotReserved,
                step: CreateStep::Reserve(Some(previous)),
            }
        }
    }
}

#[cfg(test)]
#[path = "inspect_boundary_tests.rs"]
mod tests;
