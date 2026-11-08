//! Admission for private SQLite execution directories, never commit authority.
//!
//! Object durability does not make arbitrary local I/O safe: SQLite must still
//! read and write a coherent private image before producing authoritative pages.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

/// Checks the filesystem of an opened directory, following any path symlinks.
///
/// Supported execution storage is an explicitly allowed Linux filesystem.
/// Network, FUSE and unknown types fail closed. The directory namespace and
/// mount stack must still be controlled by the operator: an allowed overlay
/// does not prove the properties of its backing filesystem, and a preflight
/// does not prevent a privileged process from changing mounts afterwards.
///
/// This check covers the database and its adjacent WAL/SHM. Native connection
/// admission separately checks every possible temporary-file directory below.
/// No storage error may turn a local cache into a fallback durable authority.
pub fn validate_cache_directory(path: &Path) -> io::Result<()> {
    validate_with(&NativeProbe, path)
}

/// Check all existing Unix temporary-directory candidates before native open.
///
/// The pinned SQLite VFS considers SQLITE_TMPDIR, TMPDIR, /var/tmp, /usr/tmp,
/// /tmp and the current directory, in that order. Checking every candidate
/// prevents an inaccessible preferred directory from hiding an unsafe fallback.
/// Missing directories are not created; all other probe failures fail closed.
///
/// SCAP never changes the process environment or sqlite3_temp_directory. The
/// pinned VFS caches environment pointers during its first initialization:
/// environment, working directory, VFS registration, directory namespace and
/// mounts must remain unchanged from before that initialization for the entire
/// process lifetime. Configuration separately rejects any global override.
pub(crate) fn validate_temporary_directories() -> io::Result<()> {
    validate_temporary_with(&NativeProbe, &temporary_candidates(&NativeEnvironment))
}

pub(crate) trait TemporaryEnvironment {
    fn directory(&self, variable: &str) -> Option<OsString>;
}

struct NativeEnvironment;

impl TemporaryEnvironment for NativeEnvironment {
    fn directory(&self, variable: &str) -> Option<OsString> {
        std::env::var_os(variable)
    }
}

pub(crate) fn temporary_candidates(environment: &impl TemporaryEnvironment) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(6);
    for variable in ["SQLITE_TMPDIR", "TMPDIR"] {
        if let Some(value) = environment.directory(variable) {
            if !value.is_empty() {
                candidates.push(PathBuf::from(value));
            }
        }
    }
    candidates.extend(["/var/tmp", "/usr/tmp", "/tmp", "."].map(PathBuf::from));
    candidates
}

pub(crate) fn validate_temporary_with(
    probe: &impl DirectoryProbe,
    candidates: &[PathBuf],
) -> io::Result<()> {
    let mut found = false;
    for path in candidates {
        let directory = match probe.open_directory(path) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        validate_opened(probe, &directory)?;
        found = true;
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no supported SQLite temporary-file directory is available",
        ));
    }
    Ok(())
}

/// The filesystem probe is the only effect boundary. Native and controlled
/// probes use the same allowlist and ordering; tests cannot change admission.
pub(crate) trait DirectoryProbe {
    type Handle;

    fn open_directory(&self, path: &Path) -> io::Result<Self::Handle>;
    fn filesystem(&self, directory: &Self::Handle) -> io::Result<u32>;
}

struct NativeProbe;

impl DirectoryProbe for NativeProbe {
    type Handle = OwnedFd;

    fn open_directory(&self, path: &Path) -> io::Result<Self::Handle> {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)
    }

    #[cfg(target_os = "linux")]
    fn filesystem(&self, directory: &Self::Handle) -> io::Result<u32> {
        // Linux filesystem magic values are 32-bit even where fsword_t is
        // signed or wider. Normalize without sign-extending the identifier.
        rustix::fs::fstatfs(directory)
            .map(|status| status.f_type as u32)
            .map_err(io::Error::from)
    }

    #[cfg(not(target_os = "linux"))]
    fn filesystem(&self, _: &Self::Handle) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SCAP private SQLite execution storage is supported only on Linux",
        ))
    }
}

pub(crate) fn validate_with(probe: &impl DirectoryProbe, path: &Path) -> io::Result<()> {
    let directory = probe.open_directory(path)?;
    validate_opened(probe, &directory)
}

fn validate_opened<P: DirectoryProbe>(probe: &P, directory: &P::Handle) -> io::Result<()> {
    let filesystem = probe.filesystem(directory)?;
    // Linux UAPI magic values: ext2/ext3/ext4, XFS, Btrfs, tmpfs and overlayfs.
    // An overlay requires an operator-verified supported local backing store.
    // A positive list rejects unrecognized shared filesystems by default.
    if !matches!(
        filesystem,
        0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0x794c_7630
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "unsupported SQLite execution filesystem 0x{filesystem:x}; use supported local storage"
            ),
        ));
    }
    Ok(())
}
