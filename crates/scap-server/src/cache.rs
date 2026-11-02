//! Disposable writer directories are owned by this process only. The caller
//! holds the node's exclusive RocksDB lock and never uses them for authority.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use scap_service::ServiceError;

use crate::failure;

trait Files: Send + Sync {
    fn vacant(&self, path: &Path) -> io::Result<bool>;
    fn remove(&self, path: &Path) -> io::Result<()>;
}

struct Native;
impl Files for Native {
    fn vacant(&self, path: &Path) -> io::Result<bool> {
        vacant(fs::symlink_metadata(path))
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}

struct Entry {
    name: OsString,
    directory: io::Result<bool>,
}

trait Namespace {
    fn prepare(&self, path: &Path) -> io::Result<bool>;
    fn entries(&self, path: &Path, limit: usize) -> io::Result<Vec<Entry>>;
    fn remove(&self, path: &Path) -> io::Result<()>;
}

impl Namespace for Native {
    fn prepare(&self, path: &Path) -> io::Result<bool> {
        // The namespace itself must also be a directory, never a symlink into
        // another tree. Entry validation alone would not protect that case.
        fs::create_dir_all(path)
            .and_then(|()| fs::symlink_metadata(path))
            .map(|metadata| metadata.is_dir())
    }
    fn entries(&self, path: &Path, limit: usize) -> io::Result<Vec<Entry>> {
        fs::read_dir(path)?
            .take(limit)
            .map(|entry| {
                entry.map(|entry| Entry {
                    name: entry.file_name(),
                    directory: entry.file_type().map(|kind| kind.is_dir()),
                })
            })
            .collect()
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}

fn vacant(metadata: io::Result<fs::Metadata>) -> io::Result<bool> {
    match metadata {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

pub(crate) struct Cache {
    path: PathBuf,
    failed: Arc<AtomicBool>,
    files: Arc<dyn Files>,
}

impl Cache {
    pub(crate) fn reserve(path: PathBuf, failed: Arc<AtomicBool>) -> Result<Self, ServiceError> {
        Self::with_files(path, failed, Arc::new(Native))
    }

    fn with_files(
        path: PathBuf,
        failed: Arc<AtomicBool>,
        files: Arc<dyn Files>,
    ) -> Result<Self, ServiceError> {
        if !files.vacant(&path).map_err(|_| failure("CACHE_IO"))? {
            return Err(failure("CACHE_EXISTS"));
        }
        Ok(Self {
            path,
            failed,
            files,
        })
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        if let Err(error) = self.files.remove(&self.path) {
            if error.kind() != io::ErrorKind::NotFound {
                self.failed.store(true, Ordering::Release);
            }
        }
    }
}

/// Call only after acquiring the exclusive store lock and before starting any
/// SQL thread. Unknown names/symlinks require operator inspection; this routine
/// never follows them or deletes files outside the reserved writer namespace.
pub(crate) fn clean_namespace(path: &Path) -> Result<(), ServiceError> {
    clean_with(path, &Native)
}

fn clean_with(path: &Path, files: &dyn Namespace) -> Result<(), ServiceError> {
    if !files
        .prepare(path)
        .map_err(|_| failure("CACHE_DIRECTORY"))?
    {
        return Err(failure("CACHE_NAMESPACE"));
    }
    let entries = files
        .entries(path, 1025)
        .map_err(|_| failure("CACHE_DIRECTORY"))?;
    if entries.len() > 1024 {
        return Err(failure("CACHE_LIMIT"));
    }
    for entry in &entries {
        let text = entry
            .name
            .to_str()
            .ok_or_else(|| failure("CACHE_NAMESPACE"))?;
        if text.len() != 32
            || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !*entry.directory.as_ref().map_err(|_| failure("CACHE_IO"))?
        {
            return Err(failure("CACHE_NAMESPACE"));
        }
    }
    for entry in entries {
        files
            .remove(&path.join(entry.name))
            .map_err(|_| failure("CACHE_IO"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
