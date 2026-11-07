//! Admission for private SQLite execution directories, never commit authority.
//!
//! Object durability does not make arbitrary local I/O safe: SQLite must still
//! read and write a coherent private image before producing authoritative pages.

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{Mode, OFlags};

/// Checks the filesystem of an opened directory, following any path symlinks.
///
/// Supported execution storage is an explicitly allowed Linux filesystem.
/// Network, FUSE and unknown types fail closed. The directory namespace and
/// mount stack must still be controlled by the operator: an allowed overlay
/// does not prove the properties of its backing filesystem, and a preflight
/// does not prevent a privileged process from changing mounts afterwards.
///
/// This check covers the database and its adjacent WAL/SHM, not SQLite's separate
/// temporary-file directory. No storage error may turn a local cache into a
/// fallback durable authority.
pub fn validate_cache_directory(path: &Path) -> io::Result<()> {
    validate_with(&NativeProbe, path)
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
    let filesystem = probe.filesystem(&directory)?;
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
