use super::inspect::CreateStep;
use super::*;
use crate::object_context::ObjectContext;
use records::BindingState;

impl Catalogue {
    /// Freeze the complete create operation and effective defaults before any
    /// mutable name/HEAD write. Reusing its ID with other inputs is a conflict.
    pub fn prepare(
        &self,
        caller: Caller,
        input: &PrepareCreate,
        deadline: Instant,
    ) -> Result<PreparedCreate, CatalogueError> {
        Self::creator(caller, caller.principal)?;
        records::name_valid(&input.name)?;
        let creation = Creation {
            creator: caller.principal,
            operation: input.operation,
            name: input.name.clone(),
            scope: records::derive_scope(
                self.deployment,
                self.tenant,
                caller.principal,
                input.operation,
            )?,
            expected_name_revision: input.expected_name_revision,
        };
        let candidate = Canonical::new(Descriptor {
            format: 1,
            creation,
            options: input.options.clone(),
            initial_quota: input.options.effective_quota(&self.options.quota),
            retention: self.options.retention.clone(),
        })?;
        let deadline = self.options.deadline(deadline, false);
        let key = self.descriptor_key(caller.principal, input.operation);
        match self
            .objects
            .put(&key, candidate.bytes(), Condition::Absent, deadline)
        {
            Ok(_) | Err(StoreError::Conflict) => {}
            Err(error) => return Err(store_error(error)),
        }
        let durable = authority(self.read_descriptor(caller.principal, input.operation, deadline))?;
        // A concurrent first admission may have used earlier server defaults.
        // The raw request must match; the first persisted effective defaults win.
        if durable.creation != candidate.creation || durable.options != candidate.options {
            return Err(CatalogueError::Conflict);
        }
        Ok(durable.prepared())
    }

    pub fn resume_create(
        &self,
        caller: Caller,
        creation: &Creation,
        deadline: Instant,
    ) -> Result<CreationProgress, CatalogueError> {
        Self::creator(caller, creation.creator)?;
        let deadline = self.options.deadline(deadline, false);
        let source = self.descriptor(creation, deadline)?;
        for _ in 0..4 {
            let view = self.view(&source, deadline)?;
            let plan = self.creation_plan(&source, &view, deadline)?;
            match plan.step {
                CreateStep::None => return Ok(Self::progress(&source, &view, plan.phase)),
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
                    // The plan verified the previous tombstone and permanent
                    // barrier. Use that original ETag once, without rebasing.
                    self.write_binding(
                        &binding,
                        previous.map(|name| name.etag.as_str()),
                        deadline,
                    )?;
                }
                CreateStep::Provision => {
                    let database = self.database(&source);
                    let mut head = database
                        .initial_head(creation.creator, creation.operation, deadline)
                        .map_err(core_error)?;
                    head.lifecycle = Lifecycle::Provisioning;
                    head.creation = Some(source.origin());
                    database.create_head(&head, deadline).map_err(core_error)?;
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
        }
        let view = self.view(&source, deadline)?;
        let plan = self.creation_plan(&source, &view, deadline)?;
        Ok(Self::progress(&source, &view, plan.phase))
    }

    fn complete(
        &self,
        source: &Source,
        binding: &Name,
        base: &Snapshot,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        require(binding.body.creation == source.creation && binding.stage == NameStage::Bound)?;
        Self::provisioning(source, &base.head)?;
        let database = self.database(source);
        let objects = ObjectContext::capture(&database, &base.head);
        database
            .verify_closure(&objects, &base.head, deadline)
            .map_err(core_error)?;
        let current = database.read_head(deadline).map_err(core_error)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(CatalogueError::Conflict);
        }
        // A verified Provisioning HEAD is always its first revision. Completing
        // it preserves the initial owner, policy and inactive state.
        let mut head = base.head.clone();
        head.revision = 2;
        head.transition = format::Transition {
            revision: 2,
            nonce: source.creation.operation,
        };
        head.lifecycle = Lifecycle::Ready;
        database
            .publish_in(&objects, base, &head, deadline)
            .map_err(core_error)
    }
}

#[cfg(test)]
#[path = "create_boundary_tests.rs"]
mod tests;
