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
use records::{AbortProof, Barrier, Binding, BindingShape, Canonical, Control, Descriptor, Record};

type Source = Canonical<Descriptor>;
type Admitted = Canonical<Control>;

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

#[derive(Clone, Debug, PartialEq, Eq)]
enum NameStage {
    Reserved,
    Bound,
    Aborting(Admitted),
    Aborted { control: Admitted, proof: String },
    Deleted(Admitted),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Name {
    record: Version<Canonical<Binding>>,
    stage: NameStage,
}

impl std::ops::Deref for Name {
    type Target = Version<Canonical<Binding>>;
    fn deref(&self) -> &Self::Target { &self.record }
}

struct Proof {
    record: Version<Canonical<AbortProof>>,
    control: Admitted,
}

impl std::ops::Deref for Proof {
    type Target = Version<Canonical<AbortProof>>;
    fn deref(&self) -> &Self::Target { &self.record }
}

struct View {
    binding: Option<Name>,
    head: Option<Snapshot>,
    proof: Option<Proof>,
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

    fn control_address(&self, principal: u64, kind: &NamedDeletionKind, operation: u64) -> String {
        let kind = match kind {
            NamedDeletionKind::Abort => "abort",
            NamedDeletionKind::Delete => "delete",
        };
        format!("{}/control/{principal}/{kind}/{operation}", self.prefix())
    }

    fn control_key(&self, control: &Control) -> String {
        self.control_address(control.principal, &control.kind, control.operation)
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
    ) -> Result<Option<Version<Canonical<R>>>, CatalogueError> {
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

    fn immutable<R: Record>(
        &self,
        key: &str,
        record: &R,
        deadline: Instant,
    ) -> Result<Canonical<R>, CatalogueError> {
        let candidate = Canonical::new(record.clone())?;
        let stored = match self.read::<R>(key, deadline)? {
            Some(stored) => stored,
            None => {
                match self.objects.put(key, candidate.bytes(), Condition::Absent, deadline) {
                    Ok(_) | Err(StoreError::Conflict) => {}
                    Err(error) => return Err(store_error(error)),
                }
                self.read::<R>(key, deadline)?.ok_or(CatalogueError::Corrupt)?
            }
        };
        if stored.body.raw() != record {
            return Err(CatalogueError::Conflict);
        }
        Ok(stored.body)
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
    ) -> Result<Source, CatalogueError> {
        let source = self
            .read::<Descriptor>(&self.descriptor_key(creator, operation), deadline)?
            .ok_or(CatalogueError::NotFound)?.body;
        require(source.creation.creator == creator && source.creation.operation == operation)?;
        require(source.creation.scope.deployment == self.deployment
            && source.creation.scope.tenant == self.tenant)?;
        Ok(source)
    }

    fn descriptor(&self, creation: &Creation, deadline: Instant) -> Result<Source, CatalogueError> {
        self.creation(creation)?;
        let source = self.read_descriptor(creation.creator, creation.operation, deadline)?;
        if source.creation != *creation { return Err(CatalogueError::Conflict); }
        Ok(source)
    }

    fn control_exists(&self, control: &Control, deadline: Instant) -> Result<Admitted, CatalogueError> {
        let stored = self.read::<Control>(&self.control_key(control), deadline)?
            .ok_or(CatalogueError::Corrupt)?;
        require(stored.body.raw() == control)?;
        Ok(stored.body)
    }

    fn read_binding(&self, name: &str, deadline: Instant) -> Result<Option<Name>, CatalogueError> {
        let Some(record) = self.read::<Binding>(&self.binding_key(name), deadline)? else { return Ok(None); };
        require(record.body.creation.name == name)?;
        let source = authority(self.read_descriptor(record.body.creation.creator,
            record.body.creation.operation, deadline))?;
        require(record.body.creation == source.creation && record.body.origin == source.origin())?;
        let stage = match record.body.shape() {
            BindingShape::Reserved => NameStage::Reserved,
            BindingShape::Bound => NameStage::Bound,
            BindingShape::Aborting(control) => NameStage::Aborting(self.control_exists(control, deadline)?),
            BindingShape::Aborted { control, proof } => NameStage::Aborted {
                control: self.control_exists(control, deadline)?, proof: proof.clone(),
            },
            BindingShape::Deleted(control) => NameStage::Deleted(self.control_exists(control, deadline)?),
        };
        Ok(Some(Name { record, stage }))
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
            require(source.creation.scope == head.scope && source.origin() == *origin)?;
        }
        Ok(Some(Snapshot {
            head,
            etag: stored.etag,
        }))
    }

    fn read_proof(&self, source: &Source, deadline: Instant) -> Result<Option<Proof>, CatalogueError> {
        let Some(record) = self.read::<AbortProof>(&self.proof_key(&source.creation), deadline)?
            else { return Ok(None); };
        require(record.body.control.creation == source.creation
            && record.body.control.origin == source.origin())?;
        let control = self.control_exists(&record.body.control, deadline)?;
        Ok(Some(Proof { record, control }))
    }

    fn view(&self, source: &Source, deadline: Instant) -> Result<View, CatalogueError> {
        let binding = self.read_binding(&source.creation.name, deadline)?;
        // A proof can appear while an Aborting name stays unchanged. Read the
        // permanent proof before the HEAD barrier it certifies, so a new proof
        // cannot be paired with a previously observed absent/Provisioning HEAD.
        let proof = self.read_proof(source, deadline)?;
        let head = self.read_slot(&source.creation.scope, deadline)?;
        // Records across keys are not an atomic snapshot. A monotonic name
        // revision and this second exact GET distinguish a changing name from
        // a corrupt stable relationship; no failed candidate is rebased here.
        let current = self.read::<Binding>(&self.binding_key(&source.creation.name), deadline)?;
        if current.as_ref() != binding.as_ref().map(|name| &name.record) {
            return Err(CatalogueError::Conflict);
        }
        Ok(View { binding, head, proof })
    }

    fn database(&self, source: &Source) -> Database {
        let mut options = self.options.clone();
        options.quota = source.initial_quota.clone();
        options.retention = source.retention.clone();
        // Catalogue::new validated worker and runtime options; Source validated
        // the immutable scope, effective quota and retention. No cross-field
        // option validation depends on those two replaced values.
        Database {
            objects: self.objects.clone(),
            scope: source.creation.scope.clone(),
            worker: self.worker,
            options,
            quarantined: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn own(source: &Source, head: &Head) -> bool {
        head.scope == source.creation.scope && head.creation.as_ref() == Some(&source.origin())
    }

    fn provisioning(source: &Source, head: &Head) -> Result<(), CatalogueError> {
        require(Self::own(source, head) && head.lifecycle == Lifecycle::Provisioning)?;
        require(head.revision == 1 && head.owner_epoch == 1 && head.auth_epoch == 1)?;
        require(head.quota == source.initial_quota && head.retention == source.retention)?;
        require(head.policy == vec![Permission {
            principal: source.creation.creator,
            read: true,
            write: true,
            admin: true,
        }])
    }

    fn deleted(head: &Head, control: &Admitted) -> Result<(), CatalogueError> {
        let ordinal = match control.kind {
            NamedDeletionKind::Abort => 1,
            NamedDeletionKind::Delete => 2,
        };
        require(control.expected_name_revision
            == control.creation.expected_name_revision.unwrap_or(0) + ordinal)?;
        require(head.scope == control.creation.scope
            && head.creation.as_ref() == Some(&control.origin))?;
        require(head.lifecycle == Lifecycle::Deleted
            && head.deletion.as_ref() == Some(&control.mark()))
    }

    fn barrier(head: &Head, proof: &Proof) -> Result<(), CatalogueError> {
        match &proof.body.barrier {
            Barrier::OwnDeleted { transition } => {
                Self::deleted(head, &proof.control)?;
                require(head.transition == *transition)
            }
            Barrier::ForeignOccupied { scope, creation } => {
                require(head.scope == *scope && head.creation == *creation)
            }
        }
    }

    fn tombstone_view<'a>(binding: &Name, view: &'a View) -> Result<&'a Head, CatalogueError> {
        let head = &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head;
        match &binding.stage {
            NameStage::Aborted { control, proof: expected } => {
                let proof = view.proof.as_ref().ok_or(CatalogueError::Corrupt)?;
                require(proof.control == *control && proof.body.hash() == expected)?;
                Self::barrier(head, proof)?;
            }
            NameStage::Deleted(control) => {
                require(view.proof.is_none())?;
                Self::deleted(head, control)?;
            }
            _ => return Err(CatalogueError::Corrupt),
        }
        Ok(head)
    }

    fn verify_tombstone(&self, binding: &Name, deadline: Instant) -> Result<(), CatalogueError> {
        let source = authority(self.descriptor(&binding.body.creation, deadline))?;
        let view = View {
            binding: None,
            head: self.read_slot(&binding.body.creation.scope, deadline)?,
            proof: self.read_proof(&source, deadline)?,
        };
        Self::tombstone_view(binding, &view).map(|_| ())
    }
}

#[cfg(test)]
mod tests;
