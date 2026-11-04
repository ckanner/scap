//! Independent on-disk contracts for the production incremental adapter.
//! No second block codec or alternative recovery algorithm exists in this test.

use raft::eraftpb::{ConfState, Entry, HardState};
use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use scap_raft_rocks::RocksBackend;
use scap_raft_store::{AtomicBackend, Identity, Limits, LoadState, Store};
use std::path::Path;
use std::process::Command;

const CHILD_PATH: &str = "SCAP_NATIVE_BLOCK_CHILD";
const IMAGE_KEY: &[u8] = b"scap/g0/atomic-image";
const MANIFEST_KEY: &[u8] = b"scap/g1/0-manifest";

fn limits() -> Limits {
    Limits {
        max_image_bytes: 2 * 1024 * 1024,
        max_entry_bytes: 64 * 1024,
        max_entries: 128,
        max_application_bytes: 512 * 1024,
    }
}

fn identity() -> Identity {
    Identity {
        cluster_id: 11,
        cell_id: 22,
        cell_incarnation: 1,
        node_id: 1,
    }
}

fn configuration() -> ConfState {
    ConfState {
        voters: vec![1, 2, 3],
        ..Default::default()
    }
}

fn open(path: &Path) -> Store<RocksBackend> {
    Store::open_existing(
        RocksBackend::open_existing(path).unwrap(),
        identity(),
        limits(),
    )
    .unwrap()
}

fn create(path: &Path) -> Store<RocksBackend> {
    Store::create_new_with_application(
        RocksBackend::create_new(path).unwrap(),
        identity(),
        configuration(),
        limits(),
        vec![0x35; 256 * 1024],
    )
    .unwrap()
}

fn write(path: &Path) -> Store<RocksBackend> {
    let mut store = open(path);
    let entry = Entry {
        index: 2,
        term: 2,
        data: vec![9; 16 * 1024].into(),
        ..Default::default()
    };
    store
        .persist_ready(
            std::slice::from_ref(&entry),
            Some(&HardState {
                term: 2,
                vote: 1,
                commit: 2,
                ..Default::default()
            }),
            None,
        )
        .unwrap();
    let mut application = store.view().unwrap().application.clone();
    application[100..104].copy_from_slice(b"next");
    store
        .apply_committed(2, &[entry], &application, &configuration())
        .unwrap();
    store.checkpoint_and_compact().unwrap();
    store
}

fn raw(path: &Path) -> DB {
    let mut options = Options::default();
    options.create_if_missing(false);
    DB::open(&options, path).unwrap()
}

fn sync(db: &DB, batch: WriteBatch) {
    let mut options = WriteOptions::default();
    options.disable_wal(false);
    options.set_sync(true);
    db.write_opt(batch, &options).unwrap();
}

fn convert_to_legacy(path: &Path) {
    let mut backend = RocksBackend::open_existing(path).unwrap();
    let LoadState::Image(image) = backend.load(limits().max_image_bytes).unwrap() else {
        panic!("expected image")
    };
    drop(backend);
    let db = raw(path);
    let mut batch = WriteBatch::default();
    let mut cursor = db.raw_iterator();
    cursor.seek_to_first();
    while cursor.valid() {
        batch.delete(cursor.key().unwrap());
        cursor.next();
    }
    cursor.status().unwrap();
    batch.put(IMAGE_KEY, &image);
    sync(&db, batch);
}

#[test]
fn native_updates_reopen_and_compaction_preserve_the_exact_logical_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replica");
    drop(create(&path));
    write(&path);
    let store = open(&path);
    let expected = store.view().unwrap().clone();
    assert_eq!(expected.applied, 2);
    assert_eq!(expected.snapshot.get_metadata().index, 2);
    assert!(expected.entries.is_empty());
    assert_eq!(&expected.application[100..104], b"next");
    drop(store);
    assert_eq!(open(&path).view().unwrap(), &expected);
}

#[test]
fn legacy_open_is_read_only_and_migration_survives_process_exit_after_sync() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replica");
    let initial = create(&path).view().unwrap().clone();
    convert_to_legacy(&path);
    assert_eq!(open(&path).view().unwrap(), &initial);
    {
        let db = raw(&path);
        assert!(db.get(IMAGE_KEY).unwrap().is_some());
        assert!(db.get(MANIFEST_KEY).unwrap().is_none());
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_child", "--test-threads=1"])
        .env(CHILD_PATH, &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let store = open(&path);
    assert_eq!(store.view().unwrap().applied, 2);
    assert_eq!(&store.view().unwrap().application[100..104], b"next");
    drop(store);
    let db = raw(&path);
    assert!(db.get(IMAGE_KEY).unwrap().is_none());
    assert!(db.get(MANIFEST_KEY).unwrap().is_some());
}

#[test]
fn native_child() {
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        return;
    };
    // Every transition uses the formal Store and native synchronous adapter.
    // process::exit skips all Rust destructors, including RocksDB close/flush.
    let _store = write(Path::new(&path));
    std::process::exit(73);
}

#[test]
fn missing_corrupt_extra_or_unrecognized_blocks_never_reinitialize_a_replica() {
    for mode in 0..4 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replica");
        drop(create(&path));
        {
            let db = raw(&path);
            let mut cursor = db.raw_iterator();
            cursor.seek_to_first();
            assert_eq!(cursor.key(), Some(MANIFEST_KEY));
            cursor.next();
            let key = cursor.key().unwrap().to_vec();
            let mut bytes = cursor.value().unwrap().to_vec();
            let mut batch = WriteBatch::default();
            match mode {
                0 => batch.delete(key),
                1 => {
                    bytes[0] ^= 1;
                    batch.put(key, bytes);
                }
                2 => batch.put(b"z-unreferenced-block", b"must be rejected"),
                _ => batch.delete(MANIFEST_KEY),
            }
            sync(&db, batch);
        }
        let backend = RocksBackend::open_existing(&path).unwrap();
        assert!(Store::open_existing(backend, identity(), limits()).is_err());
        let backend = RocksBackend::open_existing(&path).unwrap();
        assert!(Store::create_new(backend, identity(), configuration(), limits()).is_err());
    }
}
