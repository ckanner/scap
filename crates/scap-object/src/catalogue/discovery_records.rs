//! Metadata classification reuses canonical records and the stable catalogue
//! view. It never impersonates a creator or resumes a control operation.

use scap_object_store::{ListEntry, ListKind};

use super::discovery::{
    component, DiscoveredRecord, DiscoveryError, MetadataState, Phase, RecordKind,
};
use super::*;

impl Catalogue {
    pub(super) fn discover_record(
        &self,
        phase: Phase,
        entry: &ListEntry,
        deadline: Instant,
    ) -> Result<Option<DiscoveredRecord>, DiscoveryError> {
        if phase != Phase::Slots && entry.kind != ListKind::Object {
            return Err(DiscoveryError::Corrupt);
        }
        let (kind, source, admitted, listed_proof) = match phase {
            Phase::Names => {
                let (source, _, view) = self.discovery_name_view(entry, deadline)?;
                let state = self.metadata_state(&source, &view, deadline)?;
                return Ok(Some(record(
                    &entry.key,
                    RecordKind::Name,
                    state,
                    &source,
                    &view,
                )));
            }
            Phase::Creates => {
                let (creator, operation) = pair(&entry.key, &format!("{}/create/", self.prefix()))?;
                (
                    RecordKind::Create,
                    authority(self.read_descriptor(creator, operation, deadline))?,
                    None,
                    None,
                )
            }
            Phase::Controls => {
                let control = self
                    .read::<Control>(&entry.key, deadline)?
                    .ok_or(DiscoveryError::Corrupt)?
                    .body;
                require(entry.key == self.control_key(&control))?;
                let source = authority(self.descriptor(&control.creation, deadline))?;
                require(control.origin == source.origin())?;
                (RecordKind::Control, source, Some(control), None)
            }
            Phase::Proofs => {
                let (creator, operation) =
                    pair(&entry.key, &format!("{}/abort-proof/", self.prefix()))?;
                let source = authority(self.read_descriptor(creator, operation, deadline))?;
                let proof = self
                    .read_proof(&source, deadline)?
                    .ok_or(DiscoveryError::Corrupt)?;
                (RecordKind::AbortProof, source, None, Some(proof.record))
            }
            Phase::Slots => return self.discover_slot(entry, deadline),
        };
        let observed_control = admitted.as_ref().map(|control| ObservedControl {
            kind: control.kind.clone(),
            principal: control.principal,
            operation: control.operation,
            expected_name_revision: control.expected_name_revision,
            expected_head_revision: control.expected_head_revision,
            nonce: control.nonce,
        });
        let view = self.view(&source, deadline)?;
        let mut state = self.metadata_state(&source, &view, deadline)?;
        if let Some(proof) = listed_proof {
            require(view.proof.as_ref().map(|value| &value.record) == Some(&proof))?;
        }
        if let Some(control) = admitted {
            let accepted = match control.kind {
                NamedDeletionKind::Abort => {
                    view.proof.as_ref().is_some_and(|proof| proof.control == control)
                        || view.binding.as_ref().is_some_and(|binding| {
                            matches!(&binding.stage, NameStage::Aborting(current) if *current == control)
                        })
                }
                NamedDeletionKind::Delete => view.head.as_ref().is_some_and(|head| {
                    Self::own(&source, &head.head) && head.head.deletion.as_ref() == Some(&control.mark())
                }),
            };
            if !accepted {
                state = MetadataState::ControlAdmitted;
            }
        }
        let mut value = record(&entry.key, kind, state, &source, &view);
        value.control = observed_control;
        Ok(Some(value))
    }

    fn discovery_name_view(
        &self,
        entry: &ListEntry,
        deadline: Instant,
    ) -> Result<(Source, u64, View), DiscoveryError> {
        let binding = self
            .read::<Binding>(&entry.key, deadline)?
            .ok_or(DiscoveryError::Corrupt)?;
        require(entry.key == self.binding_key(&binding.body.creation.name))?;
        let source = authority(self.descriptor(&binding.body.creation, deadline))?;
        require(binding.body.origin == source.origin())?;
        let view = self.view(&source, deadline)?;
        let current = view.binding.as_ref().ok_or(DiscoveryError::Corrupt)?;
        if current.record != binding {
            return Err(DiscoveryError::Conflict);
        }
        Ok((source, binding.body.revision, view))
    }

    pub(super) fn visible_candidate(
        &self,
        caller: Caller,
        entry: &ListEntry,
        deadline: Instant,
    ) -> Result<Option<VisibleName>, DiscoveryError> {
        let (source, binding_revision, view) = self.discovery_name_view(entry, deadline)?;
        let state = self.metadata_state(&source, &view, deadline)?;
        let Some(snapshot) = view.head.as_ref().filter(|_| state == MetadataState::Ready) else {
            return Ok(None);
        };
        let head = &snapshot.head;
        // This is the same permission primitive and fresh HEAD observation as
        // ordinary resolve. The stable view already proved Bound + own Ready;
        // its authority must not be replaced by an old inventory observation.
        Database::permission(head, caller.principal, true, false, false).map_err(core_error)?;
        Ok(Some(VisibleName {
            creation: source.creation.clone(),
            binding_revision,
            head_revision: head.revision,
        }))
    }

    fn discover_slot(
        &self,
        entry: &ListEntry,
        deadline: Instant,
    ) -> Result<Option<DiscoveredRecord>, DiscoveryError> {
        if entry.kind != ListKind::Prefix {
            return Err(DiscoveryError::Corrupt);
        }
        let prefix = format!("scap-object/v1/{}/{}/", self.deployment, self.tenant);
        if entry.key == format!("{prefix}catalogue/") {
            return Ok(None);
        }
        let database = component(&entry.key, &prefix, true)?;
        let key = format!("{}head", entry.key);
        let stored = match self.objects.get(&key, format::MAX_HEAD_BYTES, deadline) {
            Ok(stored) => stored,
            Err(StoreError::Missing) => {
                return Ok(Some(DiscoveredRecord {
                    key: entry.key.clone(),
                    kind: RecordKind::OrphanPrefix,
                    state: MetadataState::Orphan,
                    creation: None,
                    scope: None,
                    binding_revision: None,
                    head_revision: None,
                    control: None,
                }));
            }
            Err(error) => return Err(store_error(error).into()),
        };
        require(!stored.etag.is_empty())?;
        // Read the actual Scope before strict decoding, never fabricate an
        // incarnation/generation to address the permanent physical slot.
        let untrusted: Head =
            serde_json::from_slice(&stored.bytes).map_err(|_| DiscoveryError::Corrupt)?;
        let head = format::decode_head(&stored.bytes, &untrusted.scope)
            .map_err(|_| DiscoveryError::Corrupt)?;
        require(
            head.scope.deployment == self.deployment
                && head.scope.tenant == self.tenant
                && head.scope.database == database,
        )?;
        if let Some(origin) = &head.creation {
            let source =
                authority(self.read_descriptor(origin.creator, origin.operation, deadline))?;
            require(source.creation.scope == head.scope && source.origin() == *origin)?;
            let view = self.view(&source, deadline)?;
            self.metadata_state(&source, &view, deadline)?;
            let current = &view.head.as_ref().ok_or(DiscoveryError::Corrupt)?.head;
            require(Self::own(&source, current))?;
            let state = lifecycle(current.lifecycle.clone());
            return Ok(Some(record(&key, RecordKind::Head, state, &source, &view)));
        }
        Ok(Some(DiscoveredRecord {
            key,
            kind: RecordKind::Head,
            state: lifecycle(head.lifecycle),
            creation: None,
            scope: Some(head.scope),
            binding_revision: None,
            head_revision: Some(head.revision),
            control: None,
        }))
    }

    fn metadata_state(
        &self,
        source: &Source,
        view: &View,
        deadline: Instant,
    ) -> Result<MetadataState, CatalogueError> {
        let own = view
            .head
            .as_ref()
            .filter(|head| Self::own(source, &head.head));
        let Some(binding) = &view.binding else {
            require(own.is_none() && view.proof.is_none())?;
            return Ok(if source.creation.expected_name_revision.is_some() {
                MetadataState::NameConflict
            } else {
                MetadataState::DescriptorOnly
            });
        };
        if binding.body.creation != source.creation {
            return self.metadata_other(source, view, binding, own, deadline);
        }
        match &binding.stage {
            NameStage::Reserved => {
                require(view.proof.is_none())?;
                match (&view.head, own) {
                    (None, _) => Ok(MetadataState::Reserved),
                    (_, None) => Ok(MetadataState::IdentityConflict),
                    (_, Some(head)) => {
                        Self::provisioning(source, &head.head)?;
                        Ok(MetadataState::Provisioning)
                    }
                }
            }
            NameStage::Bound => {
                require(view.proof.is_none())?;
                let head = &own.ok_or(CatalogueError::Corrupt)?.head;
                match head.lifecycle {
                    Lifecycle::Provisioning => {
                        Self::provisioning(source, head)?;
                        Ok(MetadataState::Bound)
                    }
                    Lifecycle::Ready => Ok(MetadataState::Ready),
                    Lifecycle::Maintenance => Ok(MetadataState::Maintenance),
                    Lifecycle::Deleted => {
                        self.delete_source(source, head, deadline)?;
                        Ok(MetadataState::Deleting)
                    }
                }
            }
            NameStage::Aborting(control) => {
                Self::aborting(source, control, view)?;
                Ok(MetadataState::Aborting)
            }
            NameStage::Aborted { .. } => {
                Self::tombstone_view(binding, view)?;
                Ok(MetadataState::Aborted)
            }
            NameStage::Deleted(_) => {
                Self::tombstone_view(binding, view)?;
                Ok(MetadataState::Deleted)
            }
        }
    }

    fn metadata_other(
        &self,
        source: &Source,
        view: &View,
        binding: &Name,
        own: Option<&Snapshot>,
        deadline: Instant,
    ) -> Result<MetadataState, CatalogueError> {
        let terminal = source.creation.expected_name_revision.unwrap_or(0) + 3;
        if let Some(proof) = &view.proof {
            require(binding.body.revision > terminal)?;
            Self::barrier(
                &view.head.as_ref().ok_or(CatalogueError::Corrupt)?.head,
                proof,
            )?;
            return Ok(MetadataState::Aborted);
        }
        if let Some(head) = own {
            require(binding.body.revision > terminal)?;
            self.delete_source(source, &head.head, deadline)?;
            return Ok(MetadataState::Deleted);
        }
        if matches!(
            binding.stage,
            NameStage::Aborted { .. } | NameStage::Deleted(_)
        ) && source.creation.expected_name_revision == Some(binding.body.revision)
        {
            self.verify_tombstone(binding, deadline)?;
            return Ok(reuse_state(source.creation.scope.database, binding));
        }
        Ok(MetadataState::NameConflict)
    }
}

fn reuse_state(database: u64, previous: &Name) -> MetadataState {
    if previous.body.creation.scope.database == database {
        MetadataState::IdentityConflict
    } else {
        MetadataState::DescriptorOnly
    }
}

fn pair(key: &str, prefix: &str) -> Result<(u64, u64), DiscoveryError> {
    let suffix = key.strip_prefix(prefix).ok_or(DiscoveryError::Corrupt)?;
    let (principal, operation) = suffix.split_once('/').ok_or(DiscoveryError::Corrupt)?;
    Ok((
        component(principal, "", false)?,
        component(operation, "", false)?,
    ))
}

fn lifecycle(value: Lifecycle) -> MetadataState {
    match value {
        Lifecycle::Provisioning => MetadataState::Provisioning,
        Lifecycle::Ready => MetadataState::Ready,
        Lifecycle::Maintenance => MetadataState::Maintenance,
        Lifecycle::Deleted => MetadataState::Deleted,
    }
}

fn record(
    key: &str,
    kind: RecordKind,
    state: MetadataState,
    source: &Source,
    view: &View,
) -> DiscoveredRecord {
    let (binding_revision, head_revision) = Catalogue::revisions(source, view);
    DiscoveredRecord {
        key: key.into(),
        kind,
        state,
        creation: Some(source.creation.clone()),
        scope: Some(source.creation.scope.clone()),
        binding_revision,
        head_revision,
        control: None,
    }
}

#[cfg(test)]
#[path = "discovery_record_tests.rs"]
mod tests;
