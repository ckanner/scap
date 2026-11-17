//! Permanent restore recipe and completion records share the original create
//! identity slot. Only the copying module constructs a completion capability.

use serde::{Deserialize, Serialize};

use super::records::{valid, Canonical, Descriptor, Record};
use super::{CatalogueError, PrepareRestore, PreparedRestore, RestoreRef};
use crate::format::{self, Scope, SnapshotLimits, SnapshotPoint, SnapshotRef};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Recipe {
    SnapshotRestore {
        source_scope: Scope,
        snapshot: SnapshotRef,
        point: SnapshotPoint,
        rewrap_version: u32,
        native_format: u32,
        snapshot_limits: SnapshotLimits,
    },
}

impl Recipe {
    pub fn validate(&self, target: &Scope) -> Result<(), CatalogueError> {
        let Self::SnapshotRestore {
            source_scope,
            snapshot,
            point,
            rewrap_version,
            native_format,
            snapshot_limits,
        } = self;
        source_scope
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        snapshot.validate().map_err(|_| CatalogueError::Invalid)?;
        point.validate().map_err(|_| CatalogueError::Invalid)?;
        snapshot_limits
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        valid(
            source_scope.deployment == target.deployment && source_scope.tenant == target.tenant,
        )?;
        valid(source_scope != target && point.source_revision < snapshot.capture_serial)?;
        valid(*rewrap_version == 1 && *native_format == 1)
    }

    pub fn point(&self) -> &SnapshotPoint {
        let Self::SnapshotRestore { point, .. } = self;
        point
    }

    pub fn source(&self) -> (&Scope, &SnapshotRef) {
        let Self::SnapshotRestore {
            source_scope,
            snapshot,
            ..
        } = self;
        (source_scope, snapshot)
    }
}

impl Canonical<Descriptor> {
    pub fn prepared_restore(&self) -> Result<PreparedRestore, CatalogueError> {
        let recipe = self.recipe.as_ref().ok_or(CatalogueError::Conflict)?;
        let (source_scope, snapshot) = recipe.source();
        Ok(PreparedRestore {
            reference: RestoreRef {
                creation: self.creation.clone(),
                descriptor_hash: self.hash().into(),
            },
            input: PrepareRestore {
                name: self.creation.name.clone(),
                operation: self.creation.operation,
                expected_name_revision: self.creation.expected_name_revision,
                options: self.options.clone(),
                source_scope: source_scope.clone(),
                snapshot: snapshot.clone(),
            },
            initial_quota: self.initial_quota.clone(),
            retention: self.retention.clone(),
            point: recipe.point().clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Completion {
    pub format: u32,
    pub descriptor_hash: String,
    pub source_scope: Scope,
    pub snapshot: SnapshotRef,
    pub point: SnapshotPoint,
    pub target_scope: Scope,
    pub data_root: String,
    pub page_count: u32,
    pub request_root: String,
    pub rewrap_version: u32,
    pub native_format: u32,
}

impl Record for Completion {
    type Shape = ();

    fn validate(&self) -> Result<(), CatalogueError> {
        valid(self.format == 1 && self.rewrap_version == 1 && self.native_format == 1)?;
        self.source_scope
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        self.target_scope
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        self.snapshot
            .validate()
            .map_err(|_| CatalogueError::Invalid)?;
        self.point.validate().map_err(|_| CatalogueError::Invalid)?;
        valid(
            self.source_scope != self.target_scope
                && self.source_scope.deployment == self.target_scope.deployment
                && self.source_scope.tenant == self.target_scope.tenant,
        )?;
        valid(
            format::hash_valid(&self.descriptor_hash)
                && format::hash_valid(&self.data_root)
                && format::hash_valid(&self.request_root),
        )?;
        valid(
            self.page_count == self.point.page_count
                && self.point.source_revision < self.snapshot.capture_serial,
        )
    }
}

impl Completion {
    pub fn matches(&self, source: &Canonical<Descriptor>) -> bool {
        let Some(recipe) = &source.recipe else {
            return false;
        };
        let (scope, snapshot) = recipe.source();
        self.descriptor_hash == source.hash()
            && self.source_scope == *scope
            && self.snapshot == *snapshot
            && self.point == *recipe.point()
            && self.target_scope == source.creation.scope
    }
}
