//! Admission against kernel-enforced deployment limits. This module observes
//! an operator-owned cgroup and private temporary mounts; it never changes the
//! host's limits, moves processes, or substitutes logical budgets for them.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Failure;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MEMBERSHIP: &str = "/proc/self/cgroup";
const CGROUP2: u32 = 0x6367_7270;
const TMPFS: u32 = 0x0102_1994;
const SYSFS: u32 = 0x6265_6572;
const SCHED_EXT: &str = "/sys/kernel/sched_ext";

/// Optional, explicit deployment contract. Missing configuration preserves the
/// ordinary logical admission budgets and makes no kernel-isolation claim.
/// Each maximum is an upper bound on the actual configured kernel limit.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub memory_bytes: u64,
    pub swap_bytes: u64,
    pub cpu_millis_per_second: u64,
    pub tasks: u64,
    pub temporary_bytes: u64,
    pub temporary_inodes: u64,
}

impl Profile {
    pub fn checked(&self) -> Result<(), Failure> {
        if self.version != 1
            || self.memory_bytes == 0
            || self.cpu_millis_per_second == 0
            || self.tasks == 0
            || self.temporary_bytes == 0
            || self.temporary_inodes == 0
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }
}

/// Validate before a permanent worker identity is consumed or any listener is
/// opened. The operator must keep mounts, cgroup membership/limits, environment
/// working directory and directory namespace fixed for the process lifetime.
/// All tasks must retain ordinary fair-class scheduling, with no BPF scheduler.
/// Privileged mutation is outside this contract, as for filesystem admission.
pub fn admit(profile: Option<&Profile>, cache: &Path) -> Result<(), Failure> {
    match profile {
        Some(profile) => admit_with(profile, cache, &Native),
        None => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mount {
    kind: u32,
    device: u64,
    bytes: Option<u64>,
    inodes: u64,
}

/// Only operating-system effects vary in unit tests. Parsing, membership,
/// finite limits, device deduplication and rejection ordering are shared.
trait Probe {
    fn read(&self, path: &Path, limit: usize) -> Result<String, Failure>;
    fn mount(&self, path: &Path) -> Result<Option<Mount>, Failure>;
    fn temporary_directories(&self) -> Vec<PathBuf>;
    fn pid(&self) -> u32;
}

struct Native;

impl Probe for Native {
    fn read(&self, path: &Path, limit: usize) -> Result<String, Failure> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(unavailable)?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() > limit {
            return Err(Failure::new("RESOURCE_ENVELOPE"));
        }
        String::from_utf8(bytes).map_err(unavailable)
    }

    fn mount(&self, path: &Path) -> Result<Option<Mount>, Failure> {
        let directory = match rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        inspect_mount(&directory, &|fd| rustix::fs::fstatfs(fd), &|fd| {
            rustix::fs::fstat(fd)
        })
        .map(Some)
    }

    fn temporary_directories(&self) -> Vec<PathBuf> {
        scap_object_sqlite::temporary_directories()
    }

    fn pid(&self) -> u32 {
        std::process::id()
    }
}

/// The two descriptor syscalls are explicit effects so deterministic I/O
/// faults use the same propagation as native admission, without invalid FDs.
fn inspect_mount(
    directory: &std::os::fd::OwnedFd,
    filesystem: &dyn Fn(&std::os::fd::OwnedFd) -> rustix::io::Result<rustix::fs::StatFs>,
    metadata: &dyn Fn(&std::os::fd::OwnedFd) -> rustix::io::Result<rustix::fs::Stat>,
) -> Result<Mount, Failure> {
    let fs = filesystem(directory).map_err(unavailable)?;
    let stat = metadata(directory).map_err(unavailable)?;
    Ok(Mount {
        kind: fs.f_type as u32,
        device: stat.st_dev,
        bytes: u64::try_from(fs.f_bsize)
            .ok()
            .and_then(|block_size| fs.f_blocks.checked_mul(block_size)),
        inodes: fs.f_files,
    })
}

fn unavailable<T>(_: T) -> Failure {
    Failure::new("RESOURCE_ENVELOPE")
}

fn decimal(text: &str) -> Result<u64, Failure> {
    let value = text.parse::<u64>().map_err(unavailable)?;
    if value.to_string() != text {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    Ok(value)
}

fn line(text: &str) -> Result<&str, Failure> {
    let value = text.strip_suffix('\n').unwrap_or(text);
    if value.is_empty() || value.contains(['\n', '\r', '\0']) {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    Ok(value)
}

fn group(membership: &str) -> Result<PathBuf, Failure> {
    let relative = line(membership)?
        .strip_prefix("0::/")
        .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
    if !relative.is_empty()
        && relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    Ok(Path::new(CGROUP_ROOT).join(relative))
}

fn finite(probe: &dyn Probe, directory: &Path, name: &str) -> Result<u64, Failure> {
    decimal(line(&probe.read(&directory.join(name), 1024)?)?)
}

fn cpu_scheduling(probe: &dyn Probe) -> Result<(), Failure> {
    // comm may contain spaces and parentheses. The fields after its final ') '
    // begin at field 3; scheduling policy is field 41 in the stable proc ABI.
    let stat = probe.read(Path::new("/proc/thread-self/stat"), 8192)?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
    let policy = fields
        .split_ascii_whitespace()
        .nth(38)
        .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
    if decimal(policy)? != 0 {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    // SCHED_NORMAL alone is insufficient: a full-switch BPF scheduler can
    // take over ordinary tasks without implementing cgroup bandwidth control.
    if let Some(filesystem) = probe.mount(Path::new(SCHED_EXT))? {
        if filesystem.kind != SYSFS
            || line(&probe.read(&Path::new(SCHED_EXT).join("state"), 1024)?)? != "disabled"
        {
            return Err(Failure::new("RESOURCE_ENVELOPE"));
        }
    }
    Ok(())
}

fn admit_with(profile: &Profile, cache: &Path, probe: &dyn Probe) -> Result<(), Failure> {
    profile.checked()?;
    let original = probe.read(Path::new(MEMBERSHIP), 8192)?;
    let directory = group(&original)?;
    let filesystem = probe
        .mount(&directory)?
        .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
    if filesystem.kind != CGROUP2
        || line(&probe.read(&directory.join("cgroup.type"), 1024)?)? != "domain"
    {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    let mut own_process = false;
    let processes = probe.read(&directory.join("cgroup.procs"), 256 * 1024)?;
    for process in processes.lines() {
        own_process |= decimal(process)? == u64::from(probe.pid());
    }
    if !own_process {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    // An OOM-immune worker would survive a group OOM event. The deployer must
    // also prevent privileged changes or immune neighbours after admission.
    let adjustment = probe.read(Path::new("/proc/self/oom_score_adj"), 1024)?;
    let adjustment = line(&adjustment)?.parse::<i16>().map_err(unavailable)?;
    if !(-999..=1000).contains(&adjustment) {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    let memory = finite(probe, &directory, "memory.max")?;
    let swap = finite(probe, &directory, "memory.swap.max")?;
    let tasks = finite(probe, &directory, "pids.max")?;
    if memory == 0
        || memory > profile.memory_bytes
        || swap > profile.swap_bytes
        || tasks == 0
        || tasks > profile.tasks
        || finite(probe, &directory, "memory.oom.group")? != 1
    {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    let cpu = probe.read(&directory.join("cpu.max"), 1024)?;
    let fields: Vec<_> = line(&cpu)?.split(' ').collect();
    if fields.len() != 2 {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    let quota = decimal(fields[0])?;
    let period = decimal(fields[1])?;
    if quota == 0
        || period == 0
        || u128::from(quota) * 1000 > u128::from(period) * u128::from(profile.cpu_millis_per_second)
        || finite(probe, &directory, "cpu.max.burst")? != 0
    {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    cpu_scheduling(probe)?;
    storage(profile, cache, probe)?;
    if probe.read(Path::new(MEMBERSHIP), 8192)? != original {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    Ok(())
}

fn storage(profile: &Profile, cache: &Path, probe: &dyn Probe) -> Result<(), Failure> {
    let cache_mount = probe
        .mount(cache)?
        .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
    let mut mounts = BTreeMap::new();
    include_mount(&mut mounts, cache_mount)?;
    for path in probe.temporary_directories() {
        if let Some(mount) = probe.mount(&path)? {
            include_mount(&mut mounts, mount)?;
        }
    }
    let mut bytes = 0u64;
    let mut inodes = 0u64;
    for mount in mounts.values() {
        bytes = bytes
            .checked_add(mount.bytes.expect("checked finite mount"))
            .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
        inodes = inodes
            .checked_add(mount.inodes)
            .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))?;
    }
    if bytes > profile.temporary_bytes || inodes > profile.temporary_inodes {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    Ok(())
}

fn include_mount(mounts: &mut BTreeMap<u64, Mount>, mount: Mount) -> Result<(), Failure> {
    if mount.kind != TMPFS || mount.bytes.is_none() || mount.bytes == Some(0) || mount.inodes == 0 {
        return Err(Failure::new("RESOURCE_ENVELOPE"));
    }
    if let Some(previous) = mounts.insert(mount.device, mount) {
        if previous != mount {
            return Err(Failure::new("RESOURCE_ENVELOPE"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
