use super::*;
use std::cell::RefCell;

pub(crate) fn profile() -> Profile {
    Profile {
        version: 1,
        memory_bytes: 1024 * 1024 * 1024,
        swap_bytes: 0,
        cpu_millis_per_second: 2000,
        tasks: 256,
        temporary_bytes: 128 * 1024 * 1024,
        temporary_inodes: 8192,
    }
}

#[derive(Clone)]
struct Fake {
    files: BTreeMap<PathBuf, String>,
    mounts: BTreeMap<PathBuf, Mount>,
    missing: Vec<PathBuf>,
    unreadable: Vec<PathBuf>,
    membership_after: Option<String>,
    membership_read_fails_after: bool,
    reads: RefCell<Vec<PathBuf>>,
}

impl Fake {
    fn new() -> Self {
        let directory = Path::new(CGROUP_ROOT).join("scap");
        let mut files = BTreeMap::new();
        files.insert(PathBuf::from(MEMBERSHIP), "0::/scap\n".into());
        files.insert(PathBuf::from("/proc/self/oom_score_adj"), "0\n".into());
        files.insert(PathBuf::from("/proc/thread-self/stat"), task_stat("0"));
        for (name, value) in [
            ("cgroup.type", "domain\n"),
            ("cgroup.procs", "3\n41\n"),
            ("memory.max", "1073741824\n"),
            ("memory.swap.max", "0\n"),
            ("pids.max", "256\n"),
            ("memory.oom.group", "1\n"),
            ("cpu.max", "200000 100000\n"),
            ("cpu.max.burst", "0\n"),
        ] {
            files.insert(directory.join(name), value.into());
        }
        let mut mounts = BTreeMap::new();
        mounts.insert(
            directory,
            Mount {
                kind: CGROUP2,
                device: 1,
                bytes: Some(0),
                inodes: 0,
            },
        );
        for path in ["/cache", "/tmp", "/var/tmp", "."] {
            mounts.insert(
                PathBuf::from(path),
                Mount {
                    kind: TMPFS,
                    device: 2,
                    bytes: Some(128 * 1024 * 1024),
                    inodes: 8192,
                },
            );
        }
        Self {
            files,
            mounts,
            missing: vec![PathBuf::from("/usr/tmp")],
            unreadable: Vec::new(),
            membership_after: None,
            membership_read_fails_after: false,
            reads: RefCell::new(Vec::new()),
        }
    }

    fn set(&mut self, name: &str, value: &str) {
        self.files
            .insert(Path::new(CGROUP_ROOT).join("scap").join(name), value.into());
    }

    fn admit(&self) -> Result<(), Failure> {
        admit_with(&profile(), Path::new("/cache"), self)
    }
}

impl Probe for Fake {
    fn read(&self, path: &Path, _: usize) -> Result<String, Failure> {
        let mut reads = self.reads.borrow_mut();
        let second = reads.contains(&path.to_path_buf());
        reads.push(path.to_path_buf());
        if self.unreadable.contains(&path.to_path_buf()) {
            return Err(Failure::new("RESOURCE_ENVELOPE"));
        }
        if path == Path::new(MEMBERSHIP) && second {
            if self.membership_read_fails_after {
                return Err(Failure::new("RESOURCE_ENVELOPE"));
            }
            if let Some(value) = &self.membership_after {
                return Ok(value.clone());
            }
        }
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| Failure::new("RESOURCE_ENVELOPE"))
    }

    fn mount(&self, path: &Path) -> Result<Option<Mount>, Failure> {
        if self.unreadable.contains(&path.to_path_buf()) {
            return Err(Failure::new("RESOURCE_ENVELOPE"));
        }
        if self.missing.contains(&path.to_path_buf()) {
            return Ok(None);
        }
        Ok(self.mounts.get(path).copied())
    }

    fn temporary_directories(&self) -> Vec<PathBuf> {
        ["/tmp", "/var/tmp", "/usr/tmp", "."]
            .map(PathBuf::from)
            .to_vec()
    }

    fn pid(&self) -> u32 {
        41
    }
}

#[test]
fn optional_contract_preserves_ordinary_admission_and_profile_is_strict() {
    admit(None, Path::new("/not-opened")).unwrap();
    profile().checked().unwrap();
    let mut value = profile();
    for index in 0..6 {
        match index {
            0 => value.version = 2,
            1 => value.memory_bytes = 0,
            2 => value.cpu_millis_per_second = 0,
            3 => value.tasks = 0,
            4 => value.temporary_bytes = 0,
            _ => value.temporary_inodes = 0,
        }
        assert_eq!(value.checked().unwrap_err().code, "CONFIG");
        assert_eq!(
            admit(Some(&value), Path::new("/not-opened"))
                .unwrap_err()
                .code,
            "CONFIG"
        );
        value = profile();
    }
    // Zero swap is an intentional hard limit, unlike the other resources.
    assert_eq!(profile().swap_bytes, 0);
}

#[test]
fn exact_domain_membership_and_all_finite_limits_are_required() {
    Fake::new().admit().unwrap();
    for (name, value) in [
        ("cgroup.type", "threaded\n"),
        ("cgroup.procs", "3\n"),
        ("cgroup.procs", "41\nbad\n"),
        ("memory.max", "max\n"),
        ("memory.max", "\n"),
        ("memory.max", "0\n"),
        ("memory.max", "1073741825\n"),
        ("memory.swap.max", "1\n"),
        ("pids.max", "0\n"),
        ("pids.max", "257\n"),
        ("pids.max", "max\n"),
        ("memory.oom.group", "0\n"),
        ("cpu.max", "max 100000\n"),
        ("cpu.max", "\n"),
        ("cpu.max", "200000\n"),
        ("cpu.max", "200000  100000\n"),
        ("cpu.max", "0 100000\n"),
        ("cpu.max", "200000 0\n"),
        ("cpu.max", "200001 100000\n"),
        ("cpu.max", "1 bad\n"),
        ("cpu.max.burst", "1\n"),
        ("cpu.max.burst", "max\n"),
    ] {
        let mut fake = Fake::new();
        fake.set(name, value);
        assert_eq!(
            fake.admit().unwrap_err().code,
            "RESOURCE_ENVELOPE",
            "{name}={value}"
        );
    }
    let mut fake = Fake::new();
    fake.set("cpu.max", "10000 10000\n");
    fake.set("memory.max", "536870912\n");
    fake.set("pids.max", "128\n");
    fake.admit().unwrap();
}

fn task_stat(policy: &str) -> String {
    let mut fields = vec!["0"; 42];
    fields[0] = "R";
    fields[38] = policy;
    format!("41 (scap ) name) {}\n", fields.join(" "))
}

#[test]
fn cpu_bandwidth_requires_ordinary_policy_and_no_extended_scheduler() {
    cpu_scheduling(&Fake::new()).unwrap();
    for value in [
        "bad".into(),
        "41 (scap) R 0".into(),
        task_stat("no"),
        task_stat("1"),
        task_stat("2"),
        task_stat("6"),
    ] {
        let mut fake = Fake::new();
        fake.files
            .insert(PathBuf::from("/proc/thread-self/stat"), value);
        assert!(fake.admit().is_err());
    }
    let directory = PathBuf::from(SCHED_EXT);
    let mut fake = Fake::new();
    fake.unreadable.push(directory.clone());
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.mounts.insert(
        directory.clone(),
        Mount {
            kind: SYSFS,
            device: 99,
            bytes: Some(0),
            inodes: 0,
        },
    );
    assert!(fake.admit().is_err());
    for state in ["enabled\n", "enabling\n", "\n"] {
        fake.files.insert(directory.join("state"), state.into());
        assert!(fake.admit().is_err());
    }
    fake.files
        .insert(directory.join("state"), "disabled\n".into());
    fake.admit().unwrap();
    fake.mounts.get_mut(&directory).unwrap().kind = TMPFS;
    assert!(fake.admit().is_err());
    // Exercise the actual per-thread proc ABI without mutating scheduling.
    let actual = Native
        .read(Path::new("/proc/thread-self/stat"), 8192)
        .unwrap();
    let fields = actual.rsplit_once(") ").unwrap().1;
    assert_eq!(fields.split_ascii_whitespace().nth(38).unwrap(), "0");
}

#[test]
fn membership_cannot_escape_the_cgroup_mount_or_change_during_admission() {
    assert_eq!(group("0::/\n").unwrap(), Path::new(CGROUP_ROOT));
    assert_eq!(
        group("0::/a/b").unwrap(),
        Path::new(CGROUP_ROOT).join("a/b")
    );
    for value in [
        "",
        "0::",
        "1:memory:/a\n",
        "0::/../outside\n",
        "0::/a/./b\n",
        "0:://a\n",
        "0::/a/\n",
        "0::/a\n0::/b\n",
        "0::/a\r\n",
        "0::/a\0\n",
    ] {
        assert!(group(value).is_err(), "{value:?}");
    }
    for value in ["", "max", "01", "+1", "-1", "18446744073709551616", " 1"] {
        assert!(decimal(value).is_err(), "{value}");
    }
    assert_eq!(decimal("18446744073709551615").unwrap(), u64::MAX);
    let mut fake = Fake::new();
    fake.membership_after = Some("0::/other\n".into());
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.membership_read_fails_after = true;
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.files.insert(PathBuf::from(MEMBERSHIP), "bad".into());
    assert!(fake.admit().is_err());
}

#[test]
fn missing_unreadable_and_counterfeit_kernel_metadata_fail_closed() {
    let directory = Path::new(CGROUP_ROOT).join("scap");
    let baseline = Fake::new();
    for path in baseline.files.keys().chain(baseline.mounts.keys()) {
        let mut fake = Fake::new();
        fake.unreadable.push(path.clone());
        assert!(fake.admit().is_err(), "{path:?}");
    }
    let mut fake = Fake::new();
    fake.missing.push(directory.clone());
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.mounts.get_mut(&directory).unwrap().kind = TMPFS;
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.missing.push(PathBuf::from("/cache"));
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.mounts.get_mut(Path::new("/cache")).unwrap().kind = 0xef53;
    assert!(fake.admit().is_err());
    let mut fake = Fake::new();
    fake.files
        .insert(directory.join("cgroup.type"), "\n".into());
    assert!(fake.admit().is_err());
}

#[test]
fn an_oom_immune_worker_or_invalid_kernel_adjustment_is_rejected() {
    for value in ["-1000\n", "1001\n", "no\n", "\n"] {
        let mut fake = Fake::new();
        fake.files
            .insert(PathBuf::from("/proc/self/oom_score_adj"), value.into());
        assert!(fake.admit().is_err(), "{value}");
    }
    for value in ["-999\n", "1000\n"] {
        let mut fake = Fake::new();
        fake.files
            .insert(PathBuf::from("/proc/self/oom_score_adj"), value.into());
        fake.admit().unwrap();
    }
}

#[test]
fn every_native_temporary_fallback_is_bounded_and_mounts_are_deduplicated() {
    let baseline = Fake::new();
    baseline.admit().unwrap();
    // Four bind paths for one backing mount count once; a second mount counts
    // in full, even when it is only the last native fallback.
    let mut fake = Fake::new();
    fake.mounts.get_mut(Path::new(".")).unwrap().device = 3;
    assert!(fake.admit().is_err());
    let mut doubled = profile();
    doubled.temporary_bytes *= 2;
    doubled.temporary_inodes *= 2;
    admit_with(&doubled, Path::new("/cache"), &fake).unwrap();
    doubled.temporary_inodes -= 1;
    assert!(admit_with(&doubled, Path::new("/cache"), &fake).is_err());
    for change in 0..5 {
        let mut fake = Fake::new();
        let mount = fake.mounts.get_mut(Path::new("/tmp")).unwrap();
        match change {
            0 => mount.kind = 0xef53,
            1 => mount.bytes = None,
            2 => mount.bytes = Some(0),
            3 => mount.inodes = 0,
            _ => mount.bytes = Some(4096),
        }
        assert!(fake.admit().is_err());
    }
    for inode_overflow in [false, true] {
        let mut fake = Fake::new();
        for (index, path) in ["/cache", "/tmp", "/var/tmp", "."].iter().enumerate() {
            let mount = fake.mounts.get_mut(Path::new(path)).unwrap();
            mount.device = index as u64 + 10;
            if inode_overflow {
                mount.inodes = u64::MAX;
            } else {
                mount.bytes = Some(u64::MAX);
            }
        }
        assert!(fake.admit().is_err());
    }
}

#[test]
fn native_effects_read_bounded_utf8_and_use_opened_directory_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("sample");
    std::fs::write(&file, b"abc").unwrap();
    assert_eq!(Native.read(&file, 3).unwrap(), "abc");
    assert!(Native.read(&file, 2).is_err());
    assert!(Native.read(directory.path(), 4).is_err());
    assert!(Native.read(&directory.path().join("missing"), 4).is_err());
    std::fs::write(&file, [255]).unwrap();
    assert!(Native.read(&file, 4).is_err());
    assert!(Native.mount(directory.path()).unwrap().is_some());
    assert!(Native
        .mount(&directory.path().join("missing"))
        .unwrap()
        .is_none());
    assert!(Native.mount(&file).is_err());
    assert_eq!(Native.pid(), std::process::id());
    assert_eq!(
        Native.temporary_directories(),
        scap_object_sqlite::temporary_directories()
    );
}

#[test]
fn descriptor_stat_failures_and_unrepresentable_capacity_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let fd = rustix::fs::open(
        directory.path(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    assert!(inspect_mount(&fd, &|_| Err(rustix::io::Errno::IO), &|fd| {
        rustix::fs::fstat(fd)
    })
    .is_err());
    assert!(inspect_mount(&fd, &|fd| rustix::fs::fstatfs(fd), &|_| Err(
        rustix::io::Errno::IO
    ))
    .is_err());
    for block_size in [-1, 4096] {
        let mount = inspect_mount(
            &fd,
            &|fd| {
                let mut fs = rustix::fs::fstatfs(fd)?;
                fs.f_bsize = block_size;
                fs.f_blocks = u64::MAX;
                Ok(fs)
            },
            &|fd| rustix::fs::fstat(fd),
        )
        .unwrap();
        assert!(mount.bytes.is_none());
    }
}
