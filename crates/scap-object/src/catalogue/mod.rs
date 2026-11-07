//! Exact-name catalogue over the same object authority as database HEADs.
//!
//! Mutation primitives stay private to this crate. A client-supplied identity
//! is never a proof that a binding, control intent or deletion barrier exists.

mod control;
mod create;
mod inspect;
mod records;
mod types;

pub use types::*;

use std::sync::Arc;
use std::time::Instant;

use scap_object_store::{Condition, Objects, StoreError};

use crate::format::{self, Head, Lifecycle, NamedDeletionKind, Permission, Scope};
use crate::{Database, Error, Options, Snapshot};
use records::{AbortProof, Barrier, Binding, Control, Descriptor, Record};

#[derive(Clone)]
pub struct Catalogue {
    objects: Arc<dyn Objects>,
    deployment: u64,
    tenant: u64,
    worker: u64,
    options: Options,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Version<T> {
    body: T,
    etag: String,
}

struct View {
    binding: Option<Version<Binding>>,
    head: Option<Snapshot>,
    proof: Option<Version<AbortProof>>,
}

fn store_error(error: StoreError) -> CatalogueError {
    match error {
        StoreError::Missing => CatalogueError::NotFound,
        StoreError::Conflict => CatalogueError::Conflict,
        StoreError::Unknown => CatalogueError::Unknown,
        StoreError::Invalid => CatalogueError::Invalid,
        StoreError::Limit | StoreError::Corrupt => CatalogueError::Corrupt,
    }
}

fn core_error(error: Error) -> CatalogueError {
    match error {
        Error::Store(StoreError::Unknown) | Error::Unknown => CatalogueError::Unknown,
        Error::Denied => CatalogueError::Denied,
        Error::Conflict | Error::Store(StoreError::Conflict) => CatalogueError::Conflict,
        Error::Limit => CatalogueError::Limit,
        _ => CatalogueError::Corrupt,
    }
}

fn authority<T>(value: Result<T, CatalogueError>) -> Result<T, CatalogueError> {
    value.map_err(|error| match error {
        CatalogueError::NotFound | CatalogueError::Invalid => CatalogueError::Corrupt,
        other => other,
    })
}

fn require(condition: bool) -> Result<(), CatalogueError> {
    if condition {
        Ok(())
    } else {
        Err(CatalogueError::Corrupt)
    }
}

impl Catalogue {
    pub fn new(
        objects: Arc<dyn Objects>,
        deployment: u64,
        tenant: u64,
        worker: u64,
        options: Options,
    ) -> Result<Self, CatalogueError> {
        records::valid(deployment != 0 && tenant != 0 && worker != 0)?;
        options.validate().map_err(|_| CatalogueError::Invalid)?;
        Ok(Self {
            objects,
            deployment,
            tenant,
            worker,
            options,
        })
    }

    fn caller(caller: Caller) -> Result<(), CatalogueError> {
        records::valid(caller.principal != 0)
    }

    fn creator(caller: Caller, creator: u64) -> Result<(), CatalogueError> {
        Self::caller(caller)?;
        if !caller.provision || caller.principal != creator {
            return Err(CatalogueError::Denied);
        }
        Ok(())
    }

    fn creation(&self, creation: &Creation) -> Result<(), CatalogueError> {
        records::creation_valid(creation)?;
        records::valid(
            creation.scope.deployment == self.deployment && creation.scope.tenant == self.tenant,
        )
    }

    fn prefix(&self) -> String {
        format!(
            "scap-object/v1/{}/{}/catalogue/v1",
            self.deployment, self.tenant
        )
    }

    fn descriptor_key(&self, creator: u64, operation: u64) -> String {
        format!("{}/create/{creator}/{operation}", self.prefix())
    }

    fn binding_key(&self, name: &str) -> String {
        format!("{}/name/{}", self.prefix(), format::digest(name.as_bytes()))
    }

    fn control_key(&self, control: &Control) -> String {
        let kind = match control.kind {
            NamedDeletionKind::Abort => "abort",
            NamedDeletionKind::Delete => "delete",
        };
        format!(
            "{}/control/{}/{kind}/{}",
            self.prefix(),
            control.principal,
            control.operation
        )
    }

    fn proof_key(&self, creation: &Creation) -> String {
        format!(
            "{}/abort-proof/{}/{}",
            self.prefix(),
            creation.creator,
            creation.operation
        )
    }

    fn read<R: Record>(
        &self,
        key: &str,
        deadline: Instant,
    ) -> Result<Option<Version<R>>, CatalogueError> {
        let stored = match self.objects.get(key, records::MAX_RECORD_BYTES, deadline) {
            Ok(stored) => stored,
            Err(StoreError::Missing) => return Ok(None),
            Err(error) => return Err(store_error(error)),
        };
        require(!stored.etag.is_empty())?;
        Ok(Some(Version {
            body: records::decode(&stored.bytes)?,
            etag: stored.etag,
        }))
    }

    fn immutable<R: Record + PartialEq>(
        &self,
        key: &str,
        record: &R,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let bytes = records::encode(record)?;
        let stored = match self.read::<R>(key, deadline)? {
            Some(stored) => stored,
            None => {
                match self.objects.put(key, &bytes, Condition::Absent, deadline) {
                    Ok(_) | Err(StoreError::Conflict) => {}
                    Err(error) => return Err(store_error(error)),
                }
                self.read::<R>(key, deadline)?
                    .ok_or(CatalogueError::Corrupt)?
            }
        };
        if stored.body != *record {
            return Err(CatalogueError::Conflict);
        }
        Ok(())
    }

    fn write_binding(
        &self,
        binding: &Binding,
        original: Option<&str>,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let bytes = records::encode(binding)?;
        let condition = original.map_or(Condition::Absent, Condition::Match);
        self.objects
            .put(
                &self.binding_key(&binding.creation.name),
                &bytes,
                condition,
                deadline,
            )
            .map_err(store_error)?;
        Ok(())
    }

    fn read_descriptor(
        &self,
        creator: u64,
        operation: u64,
        deadline: Instant,
    ) -> Result<Descriptor, CatalogueError> {
        let descriptor = self
            .read::<Descriptor>(&self.descriptor_key(creator, operation), deadline)?
            .ok_or(CatalogueError::NotFound)?
            .body;
        require(
            descriptor.creation.creator == creator && descriptor.creation.operation == operation,
        )?;
        authority(self.creation(&descriptor.creation))?;
        Ok(descriptor)
    }

    fn descriptor(
        &self,
        creation: &Creation,
        deadline: Instant,
    ) -> Result<Descriptor, CatalogueError> {
        self.creation(creation)?;
        let descriptor = self.read_descriptor(creation.creator, creation.operation, deadline)?;
        if descriptor.creation != *creation {
            return Err(CatalogueError::Conflict);
        }
        Ok(descriptor)
    }

    fn control_exists(&self, control: &Control, deadline: Instant) -> Result<(), CatalogueError> {
        let stored = self
            .read::<Control>(&self.control_key(control), deadline)?
            .ok_or(CatalogueError::Corrupt)?;
        require(stored.body == *control)
    }

    fn read_binding(
        &self,
        name: &str,
        deadline: Instant,
    ) -> Result<Option<Version<Binding>>, CatalogueError> {
        let binding = self.read::<Binding>(&self.binding_key(name), deadline)?;
        if let Some(value) = &binding {
            require(value.body.creation.name == name)?;
            let descriptor = authority(self.read_descriptor(
                value.body.creation.creator,
                value.body.creation.operation,
                deadline,
            ))?;
            require(
                value.body.creation == descriptor.creation
                    && value.body.origin == descriptor.origin()?,
            )?;
            if let Some(control) = &value.body.control {
                self.control_exists(control, deadline)?;
            }
        }
        Ok(binding)
    }

    fn read_slot(
        &self,
        scope: &Scope,
        deadline: Instant,
    ) -> Result<Option<Snapshot>, CatalogueError> {
        let stored =
            match self
                .objects
                .get(&format::head_key(scope), format::MAX_HEAD_BYTES, deadline)
            {
                Ok(stored) => stored,
                Err(StoreError::Missing) => return Ok(None),
                Err(error) => return Err(store_error(error)),
            };
        require(!stored.etag.is_empty())?;
        let head =
            format::decode_head_slot(&stored.bytes, scope).map_err(|_| CatalogueError::Corrupt)?;
        if let Some(origin) = &head.creation {
            let source =
                authority(self.read_descriptor(origin.creator, origin.operation, deadline))?;
            require(source.creation.scope == head.scope && source.origin()? == *origin)?;
        }
        Ok(Some(Snapshot {
            head,
            etag: stored.etag,
        }))
    }

    fn read_proof(
        &self,
        descriptor: &Descriptor,
        deadline: Instant,
    ) -> Result<Option<Version<AbortProof>>, CatalogueError> {
        let proof = self.read::<AbortProof>(&self.proof_key(&descriptor.creation), deadline)?;
        if let Some(value) = &proof {
            require(
                value.body.control.creation == descriptor.creation
                    && value.body.control.origin == descriptor.origin()?,
            )?;
            self.control_exists(&value.body.control, deadline)?;
        }
        Ok(proof)
    }

    fn view(&self, descriptor: &Descriptor, deadline: Instant) -> Result<View, CatalogueError> {
        let binding = self.read_binding(&descriptor.creation.name, deadline)?;
        let head = self.read_slot(&descriptor.creation.scope, deadline)?;
        let proof = self.read_proof(descriptor, deadline)?;
        // Records across keys are not an atomic snapshot. A monotonic name
        // revision and this second exact GET distinguish a changing name from
        // a corrupt stable relationship; no failed candidate is rebased here.
        let current =
            self.read::<Binding>(&self.binding_key(&descriptor.creation.name), deadline)?;
        if current != binding {
            return Err(CatalogueError::Conflict);
        }
        Ok(View {
            binding,
            head,
            proof,
        })
    }

    fn database(&self, descriptor: &Descriptor) -> Result<Database, CatalogueError> {
        let mut options = self.options.clone();
        options.quota = descriptor.initial_quota.clone();
        options.retention = descriptor.retention.clone();
        Database::with_options(
            self.objects.clone(),
            descriptor.creation.scope.clone(),
            self.worker,
            options,
        )
        .map_err(core_error)
    }

    fn own(descriptor: &Descriptor, head: &Head) -> Result<bool, CatalogueError> {
        Ok(head.scope == descriptor.creation.scope
            && head.creation.as_ref() == Some(&descriptor.origin()?))
    }

    fn provisioning(descriptor: &Descriptor, head: &Head) -> Result<(), CatalogueError> {
        require(Self::own(descriptor, head)? && head.lifecycle == Lifecycle::Provisioning)?;
        require(head.revision == 1 && head.owner_epoch == 1 && head.auth_epoch == 1)?;
        require(head.quota == descriptor.initial_quota && head.retention == descriptor.retention)?;
        require(
            head.policy
                == vec![Permission {
                    principal: descriptor.creation.creator,
                    read: true,
                    write: true,
                    admin: true,
                }],
        )
    }

    fn deleted(head: &Head, control: &Control) -> Result<(), CatalogueError> {
        let ordinal = match control.kind {
            NamedDeletionKind::Abort => 1,
            NamedDeletionKind::Delete => 2,
        };
        require(
            control.expected_name_revision
                == control.creation.expected_name_revision.unwrap_or(0) + ordinal,
        )?;
        require(
            head.scope == control.creation.scope && head.creation.as_ref() == Some(&control.origin),
        )?;
        require(
            head.lifecycle == Lifecycle::Deleted
                && head.deletion.as_ref() == Some(&control.mark()?),
        )
    }

    fn barrier(head: &Head, proof: &AbortProof) -> Result<(), CatalogueError> {
        match &proof.barrier {
            Barrier::OwnDeleted { transition } => {
                Self::deleted(head, &proof.control)?;
                require(head.transition == *transition)
            }
            Barrier::ForeignOccupied { scope, creation } => {
                require(head.scope == *scope && head.creation == *creation)
            }
        }
    }

    fn tombstone_view(binding: &Binding, view: &View) -> Result<(), CatalogueError> {
        let control = binding.control.as_ref().ok_or(CatalogueError::Corrupt)?;
        let head = &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head;
        match control.kind {
            NamedDeletionKind::Abort => {
                let proof = view.proof.as_ref().ok_or(CatalogueError::Corrupt)?;
                require(
                    proof.body.control == *control
                        && binding.proof.as_ref()
                            == Some(&format::digest(&records::encode(&proof.body)?)),
                )?;
                Self::barrier(head, &proof.body)
            }
            NamedDeletionKind::Delete => Self::deleted(head, control),
        }
    }

    fn verify_tombstone(&self, binding: &Binding, deadline: Instant) -> Result<(), CatalogueError> {
        let control = binding.control.as_ref().ok_or(CatalogueError::Corrupt)?;
        let head = self
            .read_slot(&binding.creation.scope, deadline)?
            .ok_or(CatalogueError::Corrupt)?;
        match control.kind {
            NamedDeletionKind::Abort => {
                let descriptor = authority(self.descriptor(&binding.creation, deadline))?;
                let proof = self
                    .read_proof(&descriptor, deadline)?
                    .ok_or(CatalogueError::Corrupt)?;
                require(
                    proof.body.control == *control
                        && binding.proof.as_ref()
                            == Some(&format::digest(&records::encode(&proof.body)?)),
                )?;
                Self::barrier(&head.head, &proof.body)
            }
            NamedDeletionKind::Delete => Self::deleted(&head.head, control),
        }
    }
}

#[cfg(test)]
mod tests;
