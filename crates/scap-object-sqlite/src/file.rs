use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::Error;

/// The parent directory belongs exclusively to the runtime. Creating a whole
/// new directory prevents inherited SQLite sidecars from changing the baseline.
/// Partial failures deliberately leave the directory unusable for this API.
pub(crate) fn materialize(directory: &Path, image: &[u8]) -> Result<PathBuf, Error> {
    materialize_with(&mut NativeFiles, directory, image)
}

/// Only filesystem effects vary; ordering and failure decisions stay in the
/// same implementation for real storage and controlled unit faults.
pub(crate) trait Files {
    type Output: Write;
    fn create_directory(&mut self, path: &Path) -> io::Result<()>;
    fn create_file(&mut self, path: &Path) -> io::Result<Self::Output>;
    fn sync_file(&mut self, file: &Self::Output) -> io::Result<()>;
    fn sync_directory(&mut self, path: &Path) -> io::Result<()>;
}

pub(crate) struct NativeFiles;

impl Files for NativeFiles {
    type Output = File;

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
}

pub(crate) fn materialize_with(
    files: &mut impl Files,
    directory: &Path,
    image: &[u8],
) -> Result<PathBuf, Error> {
    // Validate before creating anything. The runtime supplies a private parent;
    // neither this directory nor any SQLite sidecars may be inherited.
    let parent = directory.parent().ok_or_else(invalid_parent)?;
    if parent.as_os_str().is_empty() {
        return Err(invalid_parent());
    }
    files.create_directory(directory).map_err(Error::Io)?;
    let path = directory.join("database.sqlite");
    let mut file = files.create_file(&path).map_err(Error::Io)?;
    file.write_all(image).map_err(Error::Io)?;
    files.sync_file(&file).map_err(Error::Io)?;
    files.sync_directory(directory).map_err(Error::Io)?;
    files.sync_directory(parent).map_err(Error::Io)?;
    Ok(path)
}

fn invalid_parent() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "worker directory requires an explicit parent",
    ))
}
