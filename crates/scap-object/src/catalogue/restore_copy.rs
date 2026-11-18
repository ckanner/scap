//! Bounded postorder transcoding into a new Scope. No source object hash or
//! frame is imported. One native image is owned and discarded per attempt.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use scap_object_sqlite::{
    GateDecision, ImageBuilder, PreparedImage, ReadInterrupt, SqliteWriter, WriterLimits,
};

use super::restore_records::{Completion, Recipe, Restoring};
use super::*;
use crate::data_tree::{self, DataObjects};
use crate::format::{Manifest, Payload};
use crate::object_context::ObjectContext;

#[cfg(test)]
#[path = "restore_copy_tests.rs"]
mod tests;

pub(super) struct CompleteCopy(Completion);

pub(super) struct CopyResources<'a> {
    pub source_objects: Arc<dyn Objects>,
    pub directory: &'a Path,
    pub budget: RestoreBudget,
}

/// The initial fresh READ barrier and its exact immutable-object context travel
/// together. The database retains the same metered backend for the final fresh
/// barrier; neither phase can silently switch to another source generation.
struct RestoreSource {
    database: Database,
    objects: ObjectContext,
}

impl CompleteCopy {
    pub fn into_record(self) -> Completion {
        self.0
    }
}

fn native_error(error: scap_object_sqlite::Error) -> CatalogueError {
    match error {
        scap_object_sqlite::Error::InvalidImage => CatalogueError::Corrupt,
        scap_object_sqlite::Error::ResourceExhausted | scap_object_sqlite::Error::ResultLimit => {
            CatalogueError::Limit
        }
        _ => CatalogueError::Unknown,
    }
}

fn copy_error(error: Error) -> CatalogueError {
    match error {
        // The data-tree visitor uses the core error type, but a failed local
        // image write is not evidence of corrupt authoritative source bytes.
        Error::Engine(error) => native_error(error),
        other => core_error(other),
    }
}

fn target_error(error: Error) -> Error {
    // An aborted/retired target is not an expired source snapshot. Source
    // diagnostics remain bound to their own context and original generation.
    if matches!(error, Error::SnapshotExpired) {
        Error::Conflict
    } else {
        error
    }
}

fn validate_native(
    mut limits: WriterLimits,
    image: PreparedImage,
    interrupt: ReadInterrupt,
) -> Result<(), CatalogueError> {
    // Validation never invokes execute. Even an accidental commit cannot pass
    // the rejecting gate; its changed-page allowance is independently bounded.
    limits.max_changed_pages = 1;
    let writer = SqliteWriter::open(
        image,
        limits,
        |_: &scap_object_sqlite::PageBatch, _: &[u8]| GateDecision::Rejected,
        interrupt.clone(),
    )
    .map_err(native_error)?;
    drop(writer);
    if interrupt() {
        return Err(CatalogueError::Unknown);
    }
    Ok(())
}

struct Transcode<'a> {
    source: &'a ObjectContext,
    target: &'a ObjectContext,
    image: &'a mut ImageBuilder,
    pages: u32,
    deadline: Instant,
}

impl Transcode<'_> {
    fn node(&mut self, hash: &str, level: u8, first: u32) -> Result<String, Error> {
        let Payload::Node {
            level: actual_level,
            first_chunk,
            children,
        } = self.source.load(hash, self.deadline)?
        else {
            return Err(self.source.observe(Error::Corrupt));
        };
        data_tree::check_node(
            actual_level,
            first_chunk,
            children.len(),
            level,
            first,
            self.pages,
        )
        .map_err(|error| self.source.observe(error))?;
        // At most TREE_FANOUT hashes per level; maximum tree depth derives
        // from the persisted MAX_PAGES geometry, never untrusted recursion.
        let mut rewritten = Vec::with_capacity(children.len());
        for (index, child) in children.iter().enumerate() {
            let start = data_tree::child_first(level, first, index);
            let hash = if level == 0 {
                let Payload::Chunk { first_page, bytes } =
                    self.source.load(child, self.deadline)?
                else {
                    return Err(self.source.observe(Error::Corrupt));
                };
                data_tree::check_chunk(first_page, bytes.len(), start, self.pages)
                    .map_err(|error| self.source.observe(error))?;
                self.image
                    .append_pages(first_page, &bytes)
                    .map_err(Error::Engine)?;
                self.target
                    .save(Payload::Chunk { first_page, bytes }, self.deadline)
                    .map_err(target_error)?
            } else {
                self.node(child, level - 1, start)?
            };
            rewritten.push(hash);
        }
        self.target
            .save(
                Payload::Node {
                    level,
                    first_chunk: first,
                    children: rewritten,
                },
                self.deadline,
            )
            .map_err(target_error)
    }
}

impl Catalogue {
    fn restore_writer_limits(&self, source: &Source) -> WriterLimits {
        // Catalogue construction validates the runtime options; the immutable
        // descriptor retains its validated quota bound. No new admission or
        // mutable default can change native limits midway through this copy.
        WriterLimits {
            sql: self.options.sql,
            max_vm_steps: self.options.max_vm_steps,
            max_database_pages: source.maximum_pages(),
            max_changed_pages: 1,
            cache_bytes: self.options.cache_bytes,
            result_memory_bytes: self.options.result_memory_bytes,
        }
    }

    fn restore_source(
        &self,
        caller: Caller,
        recipe: &Recipe,
        source_objects: Arc<dyn Objects>,
        budget: RestoreBudget,
        deadline: Instant,
    ) -> Result<RestoreSource, CatalogueError> {
        let (scope, reference) = recipe.source();
        let mut database = self.restore_source_database(scope)?;
        database.objects = super::restore_budget::Meter::source(source_objects, budget, deadline);
        let (base, _, observation) = database
            .snapshot_view(caller.principal, &reference.identity(), true, deadline)
            .map_err(core_error)?;
        require(
            observation.prepared.reference == *reference
                && observation.prepared.point == *recipe.point(),
        )?;
        if observation.state != crate::snapshot::SnapshotState::Retained {
            return Err(CatalogueError::Conflict);
        }
        // snapshot_view supplied strict nonterminal authority; this database
        // owns a new, unshared Knowledge. Keep context admission in the same
        // constructor instead of reconstructing either invariant in copying.
        ObjectContext::from_snapshot(&database, &base, deadline)
            .map_err(core_error)
            .map(|objects| RestoreSource { database, objects })
    }

    pub(super) fn copy_restore_point(
        &self,
        caller: Caller,
        source: Restoring<'_>,
        target_base: &Snapshot,
        resources: CopyResources<'_>,
        deadline: Instant,
    ) -> Result<CompleteCopy, CatalogueError> {
        let CopyResources {
            source_objects,
            directory,
            budget,
        } = resources;
        let recipe = source.recipe();
        let (scope, reference) = recipe.source();
        let original = self.restore_source(caller, recipe, source_objects, budget, deadline)?;
        let manifest = data_tree::manifest(&original.objects, &recipe.point().data_root, deadline)
            .map_err(core_error)?;
        require(manifest.page_count == recipe.point().page_count)?;
        let database = self.database(&source);
        let target =
            ObjectContext::from_snapshot(&database, target_base, deadline).map_err(core_error)?;
        let mut image = self.restore_image(source, directory, budget)?;
        let root = match &manifest.root {
            Some(root) => Some(
                Transcode {
                    source: &original.objects,
                    target: &target,
                    image: &mut image,
                    pages: manifest.page_count,
                    deadline,
                }
                .node(root, data_tree::level_for(manifest.page_count), 0)
                .map_err(copy_error)?,
            ),
            None => None,
        };
        let data_root = target
            .save(
                Payload::Manifest(Manifest {
                    page_count: manifest.page_count,
                    root,
                }),
                deadline,
            )
            .map_err(|error| core_error(target_error(error)))?;
        validate_native(
            self.restore_writer_limits(&source),
            image.finish().map_err(native_error)?,
            Arc::new(move || Instant::now() >= deadline),
        )?;
        self.verify_restore_closure(
            &source,
            target_base,
            &data_root,
            manifest.page_count,
            &target,
            deadline,
        )?;
        // Every payload operation is finished before this stable authorization
        // barrier. A failed attempt cannot retain an image/cursor for later use.
        let (_, _, final_observation) = original
            .database
            .snapshot_view(caller.principal, &reference.identity(), true, deadline)
            .map_err(core_error)?;
        require(
            final_observation.prepared.reference == *reference
                && final_observation.prepared.point == *recipe.point(),
        )?;
        require(matches!(
            final_observation.state,
            crate::snapshot::SnapshotState::Retained
                | crate::snapshot::SnapshotState::ReleasedObserved
        ))?;
        Ok(CompleteCopy(Completion {
            format: 1,
            descriptor_hash: source.hash().into(),
            source_scope: scope.clone(),
            snapshot: reference.clone(),
            point: recipe.point().clone(),
            target_scope: source.creation.scope.clone(),
            data_root,
            page_count: manifest.page_count,
            request_root: target_base.head.windows[0].root.clone(),
            rewrap_version: 1,
            native_format: 1,
        }))
    }

    pub(super) fn restore_image(
        &self,
        source: Restoring<'_>,
        directory: &Path,
        budget: RestoreBudget,
    ) -> Result<ImageBuilder, CatalogueError> {
        let prepared = source.prepared();
        if prepared.image_bytes() > budget.max_image_bytes {
            return Err(CatalogueError::Limit);
        }
        let pages = source.maximum_pages();
        ImageBuilder::create_new(directory, prepared.point.page_count, pages).map_err(native_error)
    }

    fn verify_restore_closure(
        &self,
        source: &Source,
        base: &Snapshot,
        root: &str,
        pages: u32,
        objects: &ObjectContext,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        let manifest = data_tree::manifest(objects, root, deadline)
            .map_err(|error| core_error(target_error(error)))?;
        require(manifest.page_count == pages)?;
        data_tree::walk(objects, &manifest, deadline, |_, _| Ok(()))
            .map_err(|error| core_error(target_error(error)))?;
        self.database(source)
            .verify_results(objects, &base.head, deadline)
            .map_err(|error| core_error(target_error(error)))
    }

    pub(super) fn validate_completed_copy(
        &self,
        source: Restoring<'_>,
        base: &Snapshot,
        record: &Completion,
        directory: &Path,
        budget: RestoreBudget,
        deadline: Instant,
    ) -> Result<(), CatalogueError> {
        require(record.matches(&source) && record.request_root == base.head.windows[0].root)?;
        let database = self.database(&source);
        let target = ObjectContext::from_snapshot(&database, base, deadline).map_err(core_error)?;
        self.verify_restore_closure(
            &source,
            base,
            &record.data_root,
            record.page_count,
            &target,
            deadline,
        )?;
        let manifest = data_tree::manifest(&target, &record.data_root, deadline)
            .map_err(|error| core_error(target_error(error)))?;
        let mut image = self.restore_image(source, directory, budget)?;
        data_tree::walk(&target, &manifest, deadline, |first, bytes| {
            image.append_pages(first, bytes).map_err(Error::Engine)
        })
        .map_err(|error| copy_error(target_error(error)))?;
        validate_native(
            self.restore_writer_limits(&source),
            image.finish().map_err(native_error)?,
            Arc::new(move || Instant::now() >= deadline),
        )
    }
}
