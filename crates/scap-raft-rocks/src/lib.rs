//! Exclusive, incremental RocksDB backend for the bounded Raft image format.
//!
//! This synchronous adapter belongs on a dedicated blocking executor. Creation
//! reserves a previously nonexistent directory; failed initialization leaves its
//! contents for explicit inspection. Opening an existing directory never enables
//! database creation. The caller must prevent concurrent directory replacement.
//! A successful write uses WAL and a synchronous, atomic WriteBatch. An error is
//! not evidence of rollback: Store must stop and reopen to determine its state.
//! WAL recovery is strict: detected corruption rejects opening the replica,
//! rather than silently recovering an earlier image or vote.
//! The logical Store image is preserved byte for byte. Versioned manifests and
//! content-addressed blocks avoid rewriting unchanged history. Legacy images
//! migrate atomically on the first write; opening never changes stored bytes.

use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io;
use std::path::Path;

use rocksdb::{DBRawIterator, DBRecoveryMode, Options, WriteBatch, WriteOptions, DB};
use scap_raft_store::{AtomicBackend, LoadState};

mod layout;

const IMAGE_KEY: &[u8] = b"scap/g0/atomic-image";

#[derive(Debug)]
pub enum Error {
    Directory(io::Error),
    Native(String),
    Invalid(&'static str),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// One exclusively owned database. Its native handle and options are private:
/// callers cannot add keys, disable WAL, or replace the durability options.
pub struct RocksBackend {
    db: DB,
    layout: Option<LoadedLayout>,
    stopped: bool,
}

#[derive(Default)]
struct LoadedLayout {
    legacy: bool,
    chunks: BTreeSet<layout::Hash>,
}

struct Loaded {
    state: LoadState,
    layout: Option<LoadedLayout>,
}

impl RocksBackend {
    /// The parent directory must already exist. Any existing final path is an
    /// error, including an empty directory or a leftover failed initialization.
    pub fn create_new(path: &Path) -> Result<Self, Error> {
        Self::open_with(path, true, prepare_directory, DB::open)
    }

    /// Missing paths and non-directories are rejected before invoking RocksDB.
    /// Native create_if_missing remains disabled even for an empty directory.
    pub fn open_existing(path: &Path) -> Result<Self, Error> {
        Self::open_with(path, false, prepare_directory, DB::open)
    }

    fn open_with<'path>(
        path: &'path Path,
        create: bool,
        prepare: impl FnOnce(&Path, bool) -> Result<(), Error>,
        open: impl FnOnce(&Options, &'path Path) -> Result<DB, rocksdb::Error>,
    ) -> Result<Self, Error> {
        prepare(path, create)?;
        let mut options = Options::default();
        options.create_if_missing(create);
        options.set_error_if_exists(create);
        options.set_use_fsync(true);
        options.set_paranoid_checks(true);
        options.set_wal_recovery_mode(DBRecoveryMode::AbsoluteConsistency);
        let db = open(&options, path).map_err(native_error)?;
        Ok(Self {
            db,
            layout: None,
            stopped: false,
        })
    }
}

fn native_error(error: rocksdb::Error) -> Error {
    Error::Native(error.into_string())
}

fn prepare_directory(path: &Path, create: bool) -> Result<(), Error> {
    if create {
        fs::create_dir(path).map_err(Error::Directory)?;
        sync_parent(path).map_err(Error::Directory)
    } else {
        let metadata = fs::metadata(path).map_err(Error::Directory)?;
        if !metadata.is_dir() {
            return Err(Error::Invalid("existing database path is not a directory"));
        }
        Ok(())
    }
}

fn sync_parent(created_directory: &Path) -> io::Result<()> {
    // Resolving '..' after creation also supports a simple relative child path.
    // The caller owns the parent namespace and forbids concurrent replacement.
    File::open(created_directory.join(".."))?.sync_all()
}

/// A borrowed cursor is the read I/O boundary. Policy tests control invalidation
/// and errors without manufacturing corrupted native iterator objects.
trait Cursor {
    fn first(&mut self);
    fn next(&mut self);
    fn key(&self) -> Option<&[u8]>;
    fn value(&self) -> Option<&[u8]>;
    fn status(&self) -> Result<(), Error>;
}

impl Cursor for DBRawIterator<'_> {
    fn first(&mut self) {
        self.seek_to_first();
    }

    fn next(&mut self) {
        DBRawIterator::next(self);
    }

    fn key(&self) -> Option<&[u8]> {
        DBRawIterator::key(self)
    }

    fn value(&self) -> Option<&[u8]> {
        DBRawIterator::value(self)
    }

    fn status(&self) -> Result<(), Error> {
        DBRawIterator::status(self).map_err(native_error)
    }
}

fn read_image(cursor: &mut impl Cursor, max_image_bytes: usize) -> Result<Loaded, Error> {
    cursor.first();
    match cursor.key() {
        None => {
            cursor.status()?;
            return Ok(Loaded {
                state: LoadState::Empty,
                layout: Some(LoadedLayout::default()),
            });
        }
        Some(IMAGE_KEY) => {}
        Some(layout::MANIFEST_KEY) => return read_blocks(cursor, max_image_bytes),
        Some(_) => return Ok(unrecognized()),
    }
    let value = cursor
        .value()
        .ok_or(Error::Invalid("image has no readable value"))?;
    if value.len() > max_image_bytes {
        return Err(Error::Invalid(
            "image exceeds the configured owned-copy bound",
        ));
    }
    // The borrowed native value may use native cache memory, but no owned image
    // is allocated until its complete length has passed the admission bound.
    let image = value.to_vec();
    cursor.next();
    cursor.status()?;
    if cursor.key().is_some() {
        return Ok(unrecognized());
    }
    Ok(Loaded {
        state: LoadState::Image(image),
        layout: Some(LoadedLayout {
            legacy: true,
            chunks: BTreeSet::new(),
        }),
    })
}

fn unrecognized() -> Loaded {
    Loaded {
        state: LoadState::Unrecognized,
        layout: None,
    }
}

fn read_blocks(cursor: &mut impl Cursor, max_image_bytes: usize) -> Result<Loaded, Error> {
    let bytes = cursor
        .value()
        .ok_or(Error::Invalid("manifest has no readable value"))?;
    let manifest = layout::decode(bytes, max_image_bytes)?;
    // Admission precedes the only owned image allocation. Native block-cache
    // memory remains a separate resource budget, as in the legacy adapter.
    let mut image = vec![0u8; manifest.length];
    for (digest, chunk) in &manifest.chunks {
        cursor.next();
        cursor.status()?;
        let key = cursor
            .key()
            .ok_or(Error::Invalid("manifest block is missing"))?;
        if key != layout::chunk_key(digest) {
            return Ok(unrecognized());
        }
        let bytes = cursor
            .value()
            .ok_or(Error::Invalid("block has no readable value"))?;
        if bytes.len() != chunk.length || layout::hash(bytes) != *digest {
            return Err(Error::Invalid("block content mismatch"));
        }
        for offset in &chunk.offsets {
            image[*offset..*offset + chunk.length].copy_from_slice(bytes);
        }
    }
    cursor.next();
    cursor.status()?;
    if cursor.key().is_some() {
        return Ok(unrecognized());
    }
    if layout::hash(&image) != manifest.digest {
        return Err(Error::Invalid("reconstructed image checksum mismatch"));
    }
    Ok(Loaded {
        state: LoadState::Image(image),
        layout: Some(LoadedLayout {
            legacy: false,
            chunks: manifest.chunks.into_keys().collect(),
        }),
    })
}

fn write_batch(previous: &LoadedLayout, plan: &layout::Plan<'_>) -> WriteBatch {
    let mut batch = WriteBatch::default();
    batch.put(layout::MANIFEST_KEY, &plan.manifest);
    if previous.legacy {
        batch.delete(IMAGE_KEY);
    }
    for (digest, bytes) in &plan.chunks {
        if !previous.chunks.contains(digest) {
            batch.put(layout::chunk_key(digest), bytes);
        }
    }
    for digest in &previous.chunks {
        if !plan.chunks.contains_key(digest) {
            batch.delete(layout::chunk_key(digest));
        }
    }
    batch
}

impl AtomicBackend for RocksBackend {
    type Error = Error;

    fn load(&mut self, max_image_bytes: usize) -> Result<LoadState, Error> {
        self.layout = None;
        let loaded = read_image(&mut self.db.raw_iterator(), max_image_bytes)?;
        self.layout = loaded.layout;
        Ok(loaded.state)
    }

    fn replace_sync(&mut self, image: &[u8]) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Invalid("backend stopped after uncertain write"));
        }
        // The Store always calls bounded load first. Direct adapter users must
        // obey the same rule; overwriting unknown/corrupt namespaces is refused.
        let previous = self
            .layout
            .as_ref()
            .ok_or(Error::Invalid("backend must be loaded before replacement"))?;
        let plan = layout::plan(image);
        let batch = write_batch(previous, &plan);
        let mut options = WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(true);
        self.stopped = true;
        self.db.write_opt(batch, &options).map_err(native_error)?;
        self.layout = Some(LoadedLayout {
            legacy: false,
            chunks: plan.chunks.into_keys().collect(),
        });
        self.stopped = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
