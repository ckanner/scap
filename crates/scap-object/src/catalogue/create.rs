use super::*;
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
        self.creation(&creation)?;
        let initial_quota = input.options.effective_quota(&self.options.quota);
        let candidate = Descriptor {
            format: 1,
            creation,
            options: input.options.clone(),
            initial_quota,
            retention: self.options.retention.clone(),
        };
        let bytes = records::encode(&candidate)?;
        let deadline = self.options.deadline(deadline, false);
        let key = self.descriptor_key(caller.principal, input.operation);
        match self.objects.put(&key, &bytes, Condition::Absent, deadline) {
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
        let descriptor = self.descriptor(creation, deadline)?;
        let mut view = self.view(&descriptor, deadline)?;
        if self.phase(&descriptor, &view, deadline)? == CreationPhase::NotReserved {
            self.reserve(&descriptor, &view, deadline)?;
            view = self.view(&descriptor, deadline)?;
        }
        if self.phase(&descriptor, &view, deadline)? == CreationPhase::Reserved {
            let database = self.database(&descriptor)?;
            let mut head = database
                .initial_head(creation.creator, creation.operation, deadline)
                .map_err(core_error)?;
            head.lifecycle = Lifecycle::Provisioning;
            head.creation = Some(descriptor.origin()?);
            database.create_head(&head, deadline).map_err(core_error)?;
            view = self.view(&descriptor, deadline)?;
        }
        if self.phase(&descriptor, &view, deadline)? == CreationPhase::Provisioning {
            let binding = view.binding.as_ref().ok_or(CatalogueError::Corrupt)?;
            let mut bound = binding.body.clone();
            bound.state = BindingState::Bound;
            bound.revision += 1;
            self.write_binding(&bound, Some(&binding.etag), deadline)?;
            view = self.view(&descriptor, deadline)?;
        }
        if self.phase(&descriptor, &view, deadline)? == CreationPhase::Bound {
            self.complete(&descriptor, &view, deadline)?;
            view = self.view(&descriptor, deadline)?;
        }
        self.progress(&descriptor, &view, deadline)
    }

    fn reserve(
        &self,
        descriptor: &Descriptor,
        view: &View,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let original = view.binding.as_ref().map(|binding| binding.etag.as_str());
        let binding = Binding {
            format: 1,
            creation: descriptor.creation.clone(),
            origin: descriptor.origin()?,
            revision: descriptor.creation.expected_name_revision.unwrap_or(0) + 1,
            state: BindingState::Reserved,
            control: None,
            proof: None,
        };
        // `phase` already verified any preceding tombstone and its permanent
        // barrier. This is its original ETag, never a refreshed failed candidate.
        self.write_binding(&binding, original, deadline)
    }

    fn complete(
        &self,
        descriptor: &Descriptor,
        view: &View,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let binding = &view.binding.as_ref().ok_or(CatalogueError::Corrupt)?.body;
        require(binding.creation == descriptor.creation && binding.state == BindingState::Bound)?;
        let base = view.head.as_ref().ok_or(CatalogueError::Corrupt)?;
        Self::provisioning(descriptor, &base.head)?;
        let database = self.database(descriptor)?;
        database
            .verify_closure(&base.head, deadline)
            .map_err(core_error)?;
        let current = database.read_head(deadline).map_err(core_error)?;
        if current.etag != base.etag || current.head != base.head {
            return Err(CatalogueError::Conflict);
        }
        let mut head =
            Database::next(&base.head, descriptor.creation.operation).map_err(core_error)?;
        head.lifecycle = Lifecycle::Ready;
        database.publish(base, &head, deadline).map_err(core_error)
    }
}
