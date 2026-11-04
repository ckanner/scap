use super::*;
use rocksdb::Env;
use std::cell::{Cell, RefCell};

// A private memory Env is injected only at the external DB::open boundary. The
// production constructors, option wiring, cursor and write functions are not
// replaced by cfg code. This tests one adapter's arguments/results, not fsync or
// disk recovery; those remain in the independent real-dependency harness.
// The Rust wrapper creates a directory before invoking the native Env. Each
// test uses a private TempDir for that metadata, never for database payloads.
fn memory_backend(env: &Env, path: &Path, create: bool) -> Result<RocksBackend, Error> {
    memory_backend_prepared(env, path, create, Ok(()))
}

fn memory_backend_prepared(
    env: &Env,
    path: &Path,
    create: bool,
    prepared: Result<(), Error>,
) -> Result<RocksBackend, Error> {
    let mut backend = RocksBackend::open_with(
        path,
        create,
        |actual_path, mode| {
            assert_eq!(actual_path, path);
            assert_eq!(mode, create);
            prepared
        },
        |options, path| {
            assert!(options.get_use_fsync());
            let mut options = options.clone();
            options.set_env(env);
            DB::open(&options, path)
        },
    )?;
    backend.load(usize::MAX)?;
    Ok(backend)
}

#[test]
fn memory_native_delegates_preserve_one_image_and_owned_copy_limit() {
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut backend = memory_backend(&env, directory.path(), true).unwrap();
    assert!(matches!(backend.load(0).unwrap(), LoadState::Empty));
    backend.replace_sync(b"old").unwrap();
    assert!(matches!(backend.load(3).unwrap(), LoadState::Image(v) if v == b"old"));
    assert!(matches!(backend.load(2), Err(Error::Invalid(_))));
    assert!(backend
        .replace_sync(b"must not overwrite an unreadable image")
        .is_err());
    backend.load(3).unwrap();
    backend.replace_sync(b"replacement").unwrap();
    assert!(matches!(backend.load(11).unwrap(), LoadState::Image(v) if v == b"replacement"));
    backend.replace_sync(b"").unwrap();
    assert!(matches!(backend.load(0).unwrap(), LoadState::Image(v) if v.is_empty()));
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn memory_native_configuration_disallows_recreate_and_missing_open() {
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        memory_backend(&env, directory.path(), false),
        Err(Error::Native(_))
    ));
    let backend = memory_backend(&env, directory.path(), true).unwrap();
    // The DB handle is never exposed by the public backend API. A second open
    // exercises the native exclusive lock while the original handle is alive.
    assert!(matches!(
        memory_backend(&env, directory.path(), false),
        Err(Error::Native(_))
    ));
    drop(backend);
    assert!(matches!(
        memory_backend(&env, directory.path(), true),
        Err(Error::Native(_))
    ));
    assert!(memory_backend(&env, directory.path(), false).is_ok());
}

#[test]
fn memory_native_namespace_rejects_foreign_and_additional_keys() {
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut backend = memory_backend(&env, directory.path(), true).unwrap();
    backend.db.put(b"foreign", b"value").unwrap();
    assert!(matches!(
        backend.load(100).unwrap(),
        LoadState::Unrecognized
    ));
    backend.db.delete(b"foreign").unwrap();
    backend.load(usize::MAX).unwrap();
    backend.replace_sync(b"image").unwrap();
    backend.db.put(b"z-extra", b"value").unwrap();
    assert!(matches!(
        backend.load(100).unwrap(),
        LoadState::Unrecognized
    ));
}

#[test]
fn memory_native_write_error_is_returned_without_repair() {
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut backend = memory_backend(&env, directory.path(), true).unwrap();
    backend.replace_sync(b"original").unwrap();
    drop(backend);
    let mut options = Options::default();
    options.set_env(&env);
    let db = DB::open_for_read_only(&options, directory.path(), false).unwrap();
    let mut backend = RocksBackend {
        db,
        layout: None,
        stopped: false,
    };
    backend.load(usize::MAX).unwrap();
    assert!(matches!(
        backend.replace_sync(b"new"),
        Err(Error::Native(_))
    ));
    assert!(matches!(
        backend.replace_sync(b"retry must not run"),
        Err(Error::Invalid("backend stopped after uncertain write"))
    ));
    assert!(matches!(backend.load(8).unwrap(), LoadState::Image(v) if v == b"original"));
}

#[test]
fn write_requires_a_recognized_loaded_namespace_and_migrates_legacy_atomically() {
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut backend = memory_backend(&env, directory.path(), true).unwrap();
    backend.layout = None;
    assert!(matches!(
        backend.replace_sync(b"no load"),
        Err(Error::Invalid(_))
    ));
    backend.db.put(IMAGE_KEY, b"legacy").unwrap();
    assert!(matches!(backend.load(6).unwrap(), LoadState::Image(v) if v == b"legacy"));
    assert!(backend.layout.as_ref().unwrap().legacy);
    // Read-only open did not migrate the representation.
    assert!(backend.db.get(layout::MANIFEST_KEY).unwrap().is_none());
    backend.replace_sync(b"updated").unwrap();
    assert!(backend.db.get(IMAGE_KEY).unwrap().is_none());
    assert!(backend.db.get(layout::MANIFEST_KEY).unwrap().is_some());
    assert!(matches!(backend.load(7).unwrap(), LoadState::Image(v) if v == b"updated"));
    backend.replace_sync(b"updated").unwrap();
    assert!(matches!(backend.load(7).unwrap(), LoadState::Image(v) if v == b"updated"));
    backend.db.put(b"unknown", b"keep").unwrap();
    assert!(matches!(backend.load(7).unwrap(), LoadState::Unrecognized));
    assert!(backend.replace_sync(b"overwrite unknown").is_err());
    assert_eq!(backend.db.get(b"unknown").unwrap().unwrap(), b"keep");
}

struct Operations(Vec<(bool, Vec<u8>, usize)>);

impl rocksdb::WriteBatchIterator for Operations {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.0.push((true, key.to_vec(), value.len()));
    }
    fn delete(&mut self, key: &[u8]) {
        self.0.push((false, key.to_vec(), 0));
    }
}

#[test]
fn incremental_batch_reuses_unchanged_blocks_and_deletes_only_unreferenced_ones() {
    let old_image = vec![0; layout::MAX_CHUNK * 3];
    let old = layout::plan(&old_image);
    let previous = LoadedLayout {
        legacy: false,
        chunks: old.chunks.keys().copied().collect(),
    };
    let mut changed = old_image.clone();
    changed.extend_from_slice(b"tail");
    let next = layout::plan(&changed);
    let mut operations = Operations(Vec::new());
    write_batch(&previous, &next).iterate(&mut operations);
    // One manifest and one four-byte tail; unchanged repeated pages are not
    // rewritten even though the complete logical image is nearly 100 KiB.
    assert_eq!(operations.0.len(), 2);
    assert!(operations.0.iter().all(|op| op.0));
    assert_eq!(operations.0[1].2, 4);
    let previous = LoadedLayout {
        legacy: false,
        chunks: next.chunks.keys().copied().collect(),
    };
    let mut operations = Operations(Vec::new());
    write_batch(&previous, &old).iterate(&mut operations);
    assert_eq!(operations.0.len(), 2);
    assert!(!operations.0[1].0);
    assert_eq!(operations.0[1].1, layout::chunk_key(&layout::hash(b"tail")));
    let mut operations = Operations(Vec::new());
    write_batch(
        &LoadedLayout {
            legacy: true,
            chunks: BTreeSet::new(),
        },
        &old,
    )
    .iterate(&mut operations);
    assert!(operations.0.iter().any(|op| !op.0 && op.1 == IMAGE_KEY));
}

#[test]
fn public_constructors_reject_existing_missing_and_non_directory_paths() {
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        RocksBackend::create_new(temp.path()),
        Err(Error::Directory(_))
    ));
    let missing = temp.path().join("missing");
    assert!(matches!(
        RocksBackend::open_existing(&missing),
        Err(Error::Directory(_))
    ));
    assert!(!missing.exists());
    let file = temp.path().join("file");
    fs::write(&file, b"preserved").unwrap();
    assert!(matches!(
        RocksBackend::open_existing(&file),
        Err(Error::Invalid(_))
    ));
    assert_eq!(fs::read(&file).unwrap(), b"preserved");
    assert!(matches!(
        RocksBackend::create_new(&file),
        Err(Error::Directory(_))
    ));
}

#[test]
fn directory_preparation_claims_once_and_syncs_only_the_parent() {
    // Filesystem operations here are confined to directory metadata. No real
    // database or persisted payload is used in this unit profile.
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("owned");
    prepare_directory(&directory, true).unwrap();
    assert!(directory.is_dir());
    assert!(fs::read_dir(&directory).unwrap().next().is_none());
    prepare_directory(&directory, false).unwrap();
    assert!(matches!(
        prepare_directory(&directory, true),
        Err(Error::Directory(_))
    ));
    assert!(sync_parent(&temp.path().join("missing")).is_err());
}

#[test]
fn preparation_failure_prevents_native_open_and_preserves_error() {
    let opened = Cell::new(false);
    let result = RocksBackend::open_with(
        Path::new("/unused"),
        true,
        |_, _| Err(Error::Invalid("injected preparation failure")),
        |_, _| {
            opened.set(true);
            unreachable!("native open must not run after a preparation error")
        },
    );
    assert!(matches!(
        result,
        Err(Error::Invalid("injected preparation failure"))
    ));
    assert!(!opened.get());

    // Exercise success and failure through the same external opener type, and
    // confirm a rejected preparation did not create a native database at all.
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let error = memory_backend_prepared(
        &env,
        directory.path(),
        true,
        Err(Error::Invalid("preparation rejected")),
    );
    assert!(matches!(error, Err(Error::Invalid("preparation rejected"))));
    assert!(memory_backend(&env, directory.path(), true).is_ok());
}

#[test]
fn native_open_failure_keeps_the_claimed_directory() {
    let env = Env::mem_env().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("retained");
    let result = RocksBackend::open_with(&path, true, prepare_directory, |_, native_path| {
        let mut options = Options::default();
        options.set_env(&env);
        // No database exists inside this private memory Env.
        DB::open(&options, native_path)
    });
    assert!(matches!(result, Err(Error::Native(_))));
    assert!(path.is_dir());
    assert!(matches!(
        RocksBackend::create_new(&path),
        Err(Error::Directory(_))
    ));
}

#[test]
fn diagnostics_keep_native_directory_and_policy_categories() {
    let env = Env::mem_env().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let native = memory_backend(&env, directory.path(), false).err().unwrap();
    assert!(native.to_string().starts_with("Native("));
    let directory = Error::Directory(io::Error::from(io::ErrorKind::PermissionDenied));
    assert!(directory.to_string().starts_with("Directory("));
    let invalid = Error::Invalid("bound");
    assert_eq!(invalid.to_string(), "Invalid(\"bound\")");
    let as_error: &dyn std::error::Error = &invalid;
    assert!(as_error.source().is_none());
}

struct ScriptCursor {
    entries: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    offset: usize,
    error_at: Option<usize>,
    events: RefCell<Vec<&'static str>>,
}

impl ScriptCursor {
    fn new(entries: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Self {
        Self {
            entries,
            offset: 0,
            error_at: None,
            events: RefCell::new(Vec::new()),
        }
    }
}

impl Cursor for ScriptCursor {
    fn first(&mut self) {
        self.events.borrow_mut().push("first");
        self.offset = 0;
    }

    fn next(&mut self) {
        self.events.borrow_mut().push("next");
        self.offset += 1;
    }

    fn key(&self) -> Option<&[u8]> {
        self.events.borrow_mut().push("key");
        self.entries
            .get(self.offset)
            .map(|entry| entry.0.as_slice())
    }

    fn value(&self) -> Option<&[u8]> {
        self.events.borrow_mut().push("value");
        self.entries
            .get(self.offset)
            .and_then(|entry| entry.1.as_deref())
    }

    fn status(&self) -> Result<(), Error> {
        self.events.borrow_mut().push("status");
        if self.error_at == Some(self.offset) {
            Err(Error::Native("injected iterator error".into()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn cursor_policy_distinguishes_empty_foreign_and_exact_namespace() {
    let mut empty = ScriptCursor::new(Vec::new());
    assert!(matches!(
        read_image(&mut empty, 0).unwrap().state,
        LoadState::Empty
    ));
    assert_eq!(*empty.events.borrow(), ["first", "key", "status"]);
    let mut foreign = ScriptCursor::new(vec![(b"other".to_vec(), Some(vec![0; 100]))]);
    assert!(matches!(
        read_image(&mut foreign, 0).unwrap().state,
        LoadState::Unrecognized
    ));
    assert!(!foreign.events.borrow().contains(&"value"));
    let mut exact = ScriptCursor::new(vec![(IMAGE_KEY.to_vec(), Some(b"abc".to_vec()))]);
    assert!(matches!(read_image(&mut exact, 3).unwrap().state, LoadState::Image(v) if v == b"abc"));
    assert_eq!(
        *exact.events.borrow(),
        ["first", "key", "value", "next", "status", "key"]
    );
    exact.entries.push((b"second".to_vec(), Some(vec![])));
    assert!(matches!(
        read_image(&mut exact, 3).unwrap().state,
        LoadState::Unrecognized
    ));
}

#[test]
fn cursor_policy_rejects_missing_values_and_oversized_images() {
    let mut missing = ScriptCursor::new(vec![(IMAGE_KEY.to_vec(), None)]);
    assert!(matches!(
        read_image(&mut missing, 3),
        Err(Error::Invalid(_))
    ));
    assert!(!missing.events.borrow().contains(&"next"));
    let mut large = ScriptCursor::new(vec![(IMAGE_KEY.to_vec(), Some(vec![0; 4]))]);
    assert!(matches!(read_image(&mut large, 3), Err(Error::Invalid(_))));
    assert!(!large.events.borrow().contains(&"next"));
}

#[test]
fn cursor_status_errors_are_never_interpreted_as_empty_or_complete() {
    let mut failed_first = ScriptCursor::new(Vec::new());
    failed_first.error_at = Some(0);
    assert!(matches!(
        read_image(&mut failed_first, 100),
        Err(Error::Native(_))
    ));
    let mut failed_next = ScriptCursor::new(vec![(IMAGE_KEY.to_vec(), Some(b"abc".to_vec()))]);
    failed_next.error_at = Some(1);
    assert!(matches!(
        read_image(&mut failed_next, 3),
        Err(Error::Native(_))
    ));
}

fn block_cursor(bytes: &[u8]) -> ScriptCursor {
    let plan = layout::plan(bytes);
    let mut entries = vec![(layout::MANIFEST_KEY.to_vec(), Some(plan.manifest))];
    entries.extend(
        plan.chunks
            .into_iter()
            .map(|(digest, bytes)| (layout::chunk_key(&digest), Some(bytes.to_vec()))),
    );
    ScriptCursor::new(entries)
}

#[test]
fn block_reader_checks_all_references_content_order_and_complete_namespace() {
    let bytes = vec![42; layout::MAX_CHUNK * 2 + 7];
    let mut cursor = block_cursor(&bytes);
    let loaded = read_image(&mut cursor, bytes.len()).unwrap();
    assert!(matches!(loaded.state, LoadState::Image(v) if v == bytes));
    assert!(!loaded.layout.unwrap().legacy);
    let mut empty = block_cursor(&[]);
    assert!(
        matches!(read_image(&mut empty, 0).unwrap().state, LoadState::Image(v) if v.is_empty())
    );
    let mut oversized = block_cursor(&bytes);
    assert!(read_image(&mut oversized, bytes.len() - 1).is_err());
    assert!(!oversized.events.borrow().contains(&"next"));

    let mut no_manifest = block_cursor(&bytes);
    no_manifest.entries[0].1 = None;
    assert!(matches!(
        read_image(&mut no_manifest, bytes.len()),
        Err(Error::Invalid("manifest has no readable value"))
    ));
    let mut missing = block_cursor(&bytes);
    missing.entries.pop();
    assert!(matches!(
        read_image(&mut missing, bytes.len()),
        Err(Error::Invalid("manifest block is missing"))
    ));
    let mut foreign = block_cursor(&bytes);
    foreign.entries[1].0 = b"unexpected".to_vec();
    assert!(matches!(
        read_image(&mut foreign, bytes.len()).unwrap().state,
        LoadState::Unrecognized
    ));
    let mut unreadable = block_cursor(&bytes);
    unreadable.entries[1].1 = None;
    assert!(matches!(
        read_image(&mut unreadable, bytes.len()),
        Err(Error::Invalid("block has no readable value"))
    ));
    let mut bad_length = block_cursor(&bytes);
    bad_length.entries[1].1.as_mut().unwrap().pop();
    assert!(matches!(
        read_image(&mut bad_length, bytes.len()),
        Err(Error::Invalid("block content mismatch"))
    ));
    let mut bad_digest = block_cursor(&bytes);
    bad_digest.entries[1].1.as_mut().unwrap()[0] ^= 1;
    assert!(matches!(
        read_image(&mut bad_digest, bytes.len()),
        Err(Error::Invalid("block content mismatch"))
    ));
    let mut extra = block_cursor(&bytes);
    extra.entries.push((b"z-foreign".to_vec(), Some(vec![])));
    assert!(matches!(
        read_image(&mut extra, bytes.len()).unwrap().state,
        LoadState::Unrecognized
    ));
    let mut bad_image = block_cursor(&bytes);
    let manifest = bad_image.entries[0].1.as_mut().unwrap();
    manifest[24] ^= 1;
    let end = manifest.len() - 32;
    let digest = layout::hash(&manifest[..end]);
    manifest[end..].copy_from_slice(&digest);
    assert!(matches!(
        read_image(&mut bad_image, bytes.len()),
        Err(Error::Invalid("reconstructed image checksum mismatch"))
    ));

    let mut failed_next = block_cursor(&bytes);
    failed_next.error_at = Some(1);
    assert!(matches!(
        read_image(&mut failed_next, bytes.len()),
        Err(Error::Native(_))
    ));
    let mut failed_end = block_cursor(&bytes);
    failed_end.error_at = Some(failed_end.entries.len());
    assert!(matches!(
        read_image(&mut failed_end, bytes.len()),
        Err(Error::Native(_))
    ));
}
