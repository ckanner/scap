use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::{image, Error, MAX_DATABASE_PAGES, PAGE_SIZE};

/// Sequentially materializes already authenticated pages in a fresh private
/// directory. No database-sized allocation, inherited file or sidecar is used.
/// The caller owns authentication and the original restoration deadline.
pub struct ImageBuilder(Builder<NativeFiles>);

impl ImageBuilder {
    pub fn create_new(
        directory: &Path,
        expected_pages: u32,
        max_database_pages: u32,
    ) -> Result<Self, Error> {
        Builder::create_new(NativeFiles, directory, expected_pages, max_database_pages).map(Self)
    }

    /// Pages must be consecutive, nonempty and aligned to 4096 bytes. A failed
    /// append permanently invalidates this builder, including short I/O writes.
    pub fn append_pages(&mut self, first_page: u32, bytes: &[u8]) -> Result<(), Error> {
        self.0.append_pages(first_page, bytes)
    }

    pub fn finish(self) -> Result<PreparedImage, Error> {
        self.0.finish().map(PreparedImage)
    }
}

/// A fully written and synced private image. Only ImageBuilder can construct
/// one. Dropping it, or the writer that owns it, removes its private directory.
/// Structural SQLite validation happens once, under the deadline, during open.
pub struct PreparedImage(Prepared<NativeFiles>);

impl PreparedImage {
    pub(crate) fn path(&self) -> PathBuf {
        self.0.directory.path.join("database.sqlite")
    }

    pub(crate) fn page_count(&self) -> u32 {
        self.0.pages
    }
}

/// Only filesystem effects vary; ordering and failure decisions are shared by
/// real storage and deterministic unit faults.
pub(crate) trait Files {
    type Output: Write;
    fn validate_directory(&mut self, path: &Path) -> io::Result<()>;
    fn create_directory(&mut self, path: &Path) -> io::Result<()>;
    fn create_file(&mut self, path: &Path) -> io::Result<Self::Output>;
    fn sync_file(&mut self, file: &Self::Output) -> io::Result<()>;
    fn sync_directory(&mut self, path: &Path) -> io::Result<()>;
    fn remove_directory(&mut self, path: &Path) -> io::Result<()>;
}

pub(crate) struct NativeFiles;

impl Files for NativeFiles {
    type Output = File;

    fn validate_directory(&mut self, path: &Path) -> io::Result<()> {
        crate::validate_cache_directory(path)
    }

    fn create_directory(&mut self, path: &Path) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(path)
    }

    fn create_file(&mut self, path: &Path) -> io::Result<Self::Output> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    fn sync_file(&mut self, file: &Self::Output) -> io::Result<()> {
        file.sync_all()
    }

    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        File::open(path).and_then(|directory| directory.sync_all())
    }

    fn remove_directory(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}

struct Directory<F: Files> {
    files: F,
    path: PathBuf,
}

impl<F: Files> Drop for Directory<F> {
    fn drop(&mut self) {
        // Cleanup failure is an orphaned cache, never a durable authority or a
        // reason to reinterpret a completed remote commit as a rollback.
        let _ = self.files.remove_directory(&self.path);
    }
}

pub(crate) struct Builder<F: Files> {
    // Close the file before Directory removes it, including failed builders.
    output: F::Output,
    directory: Directory<F>,
    expected_pages: u32,
    written_pages: u32,
    failed: bool,
}

pub(crate) struct Prepared<F: Files> {
    directory: Directory<F>,
    pages: u32,
}

impl<F: Files> Builder<F> {
    pub(crate) fn create_new(
        mut files: F,
        directory: &Path,
        expected_pages: u32,
        max_database_pages: u32,
    ) -> Result<Self, Error> {
        if max_database_pages == 0 || max_database_pages > MAX_DATABASE_PAGES {
            return Err(Error::InvalidLimits);
        }
        if expected_pages > max_database_pages {
            return Err(Error::InvalidImage);
        }
        let parent = directory.parent().ok_or_else(invalid_parent)?;
        if parent.as_os_str().is_empty() {
            return Err(invalid_parent());
        }
        files.validate_directory(parent).map_err(Error::Io)?;
        files.create_directory(directory).map_err(Error::Io)?;
        let mut directory = Directory {
            files,
            path: directory.to_owned(),
        };
        // Recheck the actual owned directory before creating any SQLite file.
        // Once creation succeeds, every failure removes only this private dir.
        directory
            .files
            .validate_directory(&directory.path)
            .map_err(Error::Io)?;
        let output = directory
            .files
            .create_file(&directory.path.join("database.sqlite"))
            .map_err(Error::Io)?;
        Ok(Self {
            output,
            directory,
            expected_pages,
            written_pages: 0,
            failed: false,
        })
    }

    pub(crate) fn append_pages(&mut self, first_page: u32, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Stopped);
        }
        self.failed = true;
        if u64::from(first_page) != u64::from(self.written_pages) + 1
            || bytes.is_empty()
            || !bytes.len().is_multiple_of(PAGE_SIZE)
            || bytes.len() / PAGE_SIZE > (self.expected_pages - self.written_pages) as usize
        {
            return Err(Error::InvalidImage);
        }
        if self.written_pages == 0 {
            image::validate_header(&bytes[..PAGE_SIZE])?;
        }
        self.output.write_all(bytes).map_err(Error::Io)?;
        self.written_pages += (bytes.len() / PAGE_SIZE) as u32;
        self.failed = false;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Prepared<F>, Error> {
        if self.failed {
            return Err(Error::Stopped);
        }
        if self.written_pages != self.expected_pages {
            return Err(Error::InvalidImage);
        }
        let directory = &mut self.directory;
        directory.files.sync_file(&self.output).map_err(Error::Io)?;
        directory
            .files
            .sync_directory(&directory.path)
            .map_err(Error::Io)?;
        // create_new already established that this explicit parent exists.
        directory
            .files
            .sync_directory(directory.path.parent().unwrap())
            .map_err(Error::Io)?;
        drop(self.output);
        Ok(Prepared {
            directory: self.directory,
            pages: self.written_pages,
        })
    }
}

fn invalid_parent() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "worker directory requires an explicit parent",
    ))
}
