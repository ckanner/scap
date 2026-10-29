//! Exclusive RocksDB backend for the bounded Raft image format.
//!
//! This synchronous adapter belongs on a dedicated blocking executor. Creation
//! reserves a previously nonexistent directory; failed initialization leaves its
//! contents for explicit inspection. Opening an existing directory never enables
//! database creation. The caller must prevent concurrent directory replacement.
//! A successful write uses WAL and a synchronous, atomic WriteBatch. An error is
//! not evidence of rollback: Store must stop and reopen to determine its state.
//! WAL recovery is strict: detected corruption rejects opening the replica,
//! rather than silently recovering an earlier image or vote.

use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io;
use std::path::Path;

use rocksdb::{DBRawIterator, DBRecoveryMode, Options, WriteBatch, WriteOptions, DB};
use scap_raft_store::{AtomicBackend, LoadState};

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
        Ok(Self { db })
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

fn read_image(cursor: &mut impl Cursor, max_image_bytes: usize) -> Result<LoadState, Error> {
    cursor.first();
    match cursor.key() {
        None => {
            cursor.status()?;
            return Ok(LoadState::Empty);
        }
        Some(IMAGE_KEY) => {}
        Some(_) => return Ok(LoadState::Unrecognized),
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
        return Ok(LoadState::Unrecognized);
    }
    Ok(LoadState::Image(image))
}

impl AtomicBackend for RocksBackend {
    type Error = Error;

    fn load(&mut self, max_image_bytes: usize) -> Result<LoadState, Error> {
        read_image(&mut self.db.raw_iterator(), max_image_bytes)
    }

    fn replace_sync(&mut self, image: &[u8]) -> Result<(), Error> {
        let mut batch = WriteBatch::default();
        batch.put(IMAGE_KEY, image);
        let mut options = WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(true);
        self.db.write_opt(batch, &options).map_err(native_error)
    }
}

#[cfg(test)]
mod tests;
