use crate::file::{Builder, Files, NativeFiles};
use crate::storage::{validate_with, DirectoryProbe};
use crate::{Error, ImageBuilder, MAX_DATABASE_PAGES, PAGE_SIZE};
use std::cell::RefCell;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::rc::Rc;

#[derive(Default)]
struct Trace {
    fail_at: Option<&'static str>,
    events: Vec<&'static str>,
    bytes: Vec<u8>,
}

impl Trace {
    fn event(&mut self, event: &'static str) -> io::Result<()> {
        self.events.push(event);
        if self.fail_at == Some(event) {
            return Err(io::Error::other("injected filesystem failure"));
        }
        Ok(())
    }
}

struct MemoryFile(Rc<RefCell<Trace>>);

impl Write for MemoryFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut trace = self.0.borrow_mut();
        let (event, length) = if trace.bytes.is_empty() {
            ("write", 2)
        } else {
            ("write_tail", bytes.len())
        };
        trace.event(event)?;
        trace.bytes.extend_from_slice(&bytes[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("flush must not substitute for sync_all");
    }
}

struct ControlledFiles(Rc<RefCell<Trace>>);

impl Files for ControlledFiles {
    type Output = MemoryFile;

    fn validate_directory(&mut self, path: &Path) -> io::Result<()> {
        let event = if path == Path::new("/owned") {
            "validate_parent"
        } else {
            assert_eq!(path, Path::new("/owned/new-worker"));
            "validate_directory"
        };
        self.0.borrow_mut().event(event)
    }

    fn create_directory(&mut self, path: &Path) -> io::Result<()> {
        assert_eq!(path, Path::new("/owned/new-worker"));
        self.0.borrow_mut().event("directory")
    }

    fn create_file(&mut self, path: &Path) -> io::Result<Self::Output> {
        assert_eq!(path, Path::new("/owned/new-worker/database.sqlite"));
        self.0.borrow_mut().event("file")?;
        Ok(MemoryFile(self.0.clone()))
    }

    fn sync_file(&mut self, _: &Self::Output) -> io::Result<()> {
        self.0.borrow_mut().event("sync_file")
    }

    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        let event = if path == Path::new("/owned/new-worker") {
            "sync_directory"
        } else {
            assert_eq!(path, Path::new("/owned"));
            "sync_parent"
        };
        self.0.borrow_mut().event(event)
    }

    fn remove_directory(&mut self, path: &Path) -> io::Result<()> {
        assert_eq!(path, Path::new("/owned/new-worker"));
        self.0.borrow_mut().event("remove")
    }
}

fn header() -> [u8; PAGE_SIZE] {
    let mut bytes = [0; PAGE_SIZE];
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    bytes[16] = 0x10;
    bytes
}

#[test]
fn all_streaming_filesystem_faults_stop_before_a_prepared_image_can_escape() {
    let order = [
        "validate_parent",
        "directory",
        "validate_directory",
        "file",
        "write",
        "write_tail",
        "sync_file",
        "sync_directory",
        "sync_parent",
    ];
    for (index, fail_at) in order.iter().enumerate() {
        let trace = Rc::new(RefCell::new(Trace {
            fail_at: Some(fail_at),
            ..Trace::default()
        }));
        let result = (|| {
            let mut builder = Builder::create_new(
                ControlledFiles(trace.clone()),
                Path::new("/owned/new-worker"),
                1,
                1,
            )?;
            builder.append_pages(1, &header())?;
            builder.finish()
        })();
        assert!(matches!(result, Err(Error::Io(_))));
        let mut expected = order[..=index].to_vec();
        if index >= 2 {
            expected.push("remove");
        }
        assert_eq!(trace.borrow().events, expected);
        if *fail_at == "write_tail" {
            assert_eq!(trace.borrow().bytes, &header()[..2]);
            assert!(!trace.borrow().events.contains(&"sync_file"));
        }
    }
    for cleanup_fails in [false, true] {
        let trace = Rc::new(RefCell::new(Trace {
            fail_at: cleanup_fails.then_some("remove"),
            ..Trace::default()
        }));
        let mut builder = Builder::create_new(
            ControlledFiles(trace.clone()),
            Path::new("/owned/new-worker"),
            1,
            1,
        )
        .unwrap();
        builder.append_pages(1, &header()).unwrap();
        let prepared = builder.finish().unwrap();
        assert_eq!(trace.borrow().events, order);
        assert_eq!(trace.borrow().bytes, header());
        drop(prepared);
        assert_eq!(trace.borrow().events.last(), Some(&"remove"));
    }
}

#[test]
fn invalid_parent_and_capacity_are_rejected_before_any_effect() {
    let trace = Rc::new(RefCell::new(Trace::default()));
    for path in ["/", "worker", ""] {
        assert!(matches!(
            Builder::create_new(ControlledFiles(trace.clone()), Path::new(path), 0, 1),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }
    for max in [0, u32::MAX] {
        assert!(matches!(
            Builder::create_new(
                ControlledFiles(trace.clone()),
                Path::new("/owned/new-worker"),
                0,
                max
            ),
            Err(Error::InvalidLimits)
        ));
    }
    assert!(matches!(
        Builder::create_new(
            ControlledFiles(trace.clone()),
            Path::new("/owned/new-worker"),
            2,
            1
        ),
        Err(Error::InvalidImage)
    ));
    assert!(trace.borrow().events.is_empty());
}

#[test]
fn streaming_rejects_gaps_overlap_short_extra_and_invalid_header_pages() {
    let root = tempfile::tempdir().unwrap();
    for (index, first, bytes) in [
        (0, 0, header().to_vec()),
        (1, 2, header().to_vec()),
        (2, 1, vec![]),
        (3, 1, vec![0]),
        (4, 1, vec![0; PAGE_SIZE * 2]),
        (5, 1, vec![0; PAGE_SIZE]),
        (6, 1, {
            let mut h = header();
            h[17] = 1;
            h.to_vec()
        }),
    ] {
        let path = root.path().join(index.to_string());
        let mut builder = ImageBuilder::create_new(&path, 1, 1).unwrap();
        assert!(matches!(
            builder.append_pages(first, &bytes),
            Err(Error::InvalidImage)
        ));
        assert!(matches!(
            builder.append_pages(1, &header()),
            Err(Error::Stopped)
        ));
        assert!(matches!(builder.finish(), Err(Error::Stopped)));
        assert!(!path.exists());
    }
    let path = root.path().join("missing");
    let mut builder = ImageBuilder::create_new(&path, 2, 2).unwrap();
    builder.append_pages(1, &header()).unwrap();
    assert!(matches!(builder.finish(), Err(Error::InvalidImage)));
    assert!(!path.exists());
    let path = root.path().join("extra");
    let mut builder = ImageBuilder::create_new(&path, 1, 1).unwrap();
    builder.append_pages(1, &header()).unwrap();
    assert!(matches!(
        builder.append_pages(2, &[0; PAGE_SIZE]),
        Err(Error::InvalidImage)
    ));
    drop(builder);
    assert!(!path.exists());
    // A format-sized reservation does not allocate or create a sparse image.
    let path = root.path().join("large-reservation");
    let mut builder =
        ImageBuilder::create_new(&path, MAX_DATABASE_PAGES, MAX_DATABASE_PAGES).unwrap();
    builder.append_pages(1, &header()).unwrap();
    assert_eq!(
        fs::metadata(path.join("database.sqlite")).unwrap().len(),
        PAGE_SIZE as u64
    );
    drop(builder);
    assert!(!path.exists());
}

#[test]
fn partial_writes_poison_the_builder_and_never_sync_a_partial_snapshot() {
    let trace = Rc::new(RefCell::new(Trace {
        fail_at: Some("write_tail"),
        ..Trace::default()
    }));
    let mut builder = Builder::create_new(
        ControlledFiles(trace.clone()),
        Path::new("/owned/new-worker"),
        1,
        1,
    )
    .unwrap();
    assert!(matches!(
        builder.append_pages(1, &header()),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        builder.append_pages(1, &header()),
        Err(Error::Stopped)
    ));
    assert!(matches!(builder.finish(), Err(Error::Stopped)));
    assert_eq!(
        trace.borrow().events,
        [
            "validate_parent",
            "directory",
            "validate_directory",
            "file",
            "write",
            "write_tail",
            "remove"
        ]
    );
}

#[test]
fn controlled_streams_validate_before_writing_and_require_all_pages() {
    for invalid in [vec![], vec![0; PAGE_SIZE]] {
        let trace = Rc::new(RefCell::new(Trace::default()));
        let mut builder = Builder::create_new(
            ControlledFiles(trace.clone()),
            Path::new("/owned/new-worker"),
            1,
            1,
        )
        .unwrap();
        assert!(matches!(
            builder.append_pages(1, &invalid),
            Err(Error::InvalidImage)
        ));
        assert!(trace.borrow().bytes.is_empty());
    }
    for complete in [false, true] {
        let trace = Rc::new(RefCell::new(Trace::default()));
        let mut builder = Builder::create_new(
            ControlledFiles(trace.clone()),
            Path::new("/owned/new-worker"),
            2,
            2,
        )
        .unwrap();
        builder.append_pages(1, &header()).unwrap();
        if complete {
            builder.append_pages(2, &[3; PAGE_SIZE]).unwrap();
            drop(builder.finish().unwrap());
            assert_eq!(trace.borrow().bytes.len(), 2 * PAGE_SIZE);
            assert!(trace.borrow().events.contains(&"sync_parent"));
        } else {
            assert!(matches!(builder.finish(), Err(Error::InvalidImage)));
            assert!(!trace.borrow().events.contains(&"sync_file"));
        }
    }
}

#[test]
fn native_streaming_is_exclusive_private_and_cleans_owned_sidecars() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("worker");
    let mut builder = ImageBuilder::create_new(&directory, 3, 3).unwrap();
    builder.append_pages(1, &header()).unwrap();
    builder.append_pages(2, &[7; PAGE_SIZE * 2]).unwrap();
    let prepared = builder.finish().unwrap();
    let path = prepared.path();
    assert_eq!(prepared.page_count(), 3);
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(&fs::read(&path).unwrap()[..PAGE_SIZE], &header());
    assert_eq!(&fs::read(&path).unwrap()[PAGE_SIZE..], &[7; PAGE_SIZE * 2]);
    fs::write(directory.join("database.sqlite-wal"), b"old sidecar").unwrap();
    assert!(
        matches!(ImageBuilder::create_new(&directory, 0, 1), Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(
        fs::read(directory.join("database.sqlite-wal")).unwrap(),
        b"old sidecar"
    );
    assert!(NativeFiles.create_file(&path).is_err());
    assert!(NativeFiles
        .sync_directory(&root.path().join("absent"))
        .is_err());
    drop(prepared);
    assert!(!directory.exists());
    assert!(NativeFiles.remove_directory(&directory).is_err());
    let empty_directory = root.path().join("empty");
    let empty = ImageBuilder::create_new(&empty_directory, 0, 1)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(fs::metadata(empty.path()).unwrap().len(), 0);
    assert_eq!(empty.page_count(), 0);
    drop(empty);
    assert!(!empty_directory.exists());
}

struct Probe {
    filesystem: u32,
    fail_at: Option<&'static str>,
    events: RefCell<Vec<&'static str>>,
}

impl DirectoryProbe for Probe {
    type Handle = u64;

    fn open_directory(&self, path: &Path) -> io::Result<Self::Handle> {
        assert_eq!(path, Path::new("/cache"));
        self.events.borrow_mut().push("open");
        if self.fail_at == Some("open") {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "open"));
        }
        Ok(41)
    }

    fn filesystem(&self, directory: &Self::Handle) -> io::Result<u32> {
        assert_eq!(*directory, 41);
        self.events.borrow_mut().push("fstatfs");
        if self.fail_at == Some("fstatfs") {
            return Err(io::Error::other("fstatfs"));
        }
        Ok(self.filesystem)
    }
}

#[test]
fn execution_filesystems_require_explicit_support_and_successful_directory_probe() {
    for filesystem in [0xef53, 0x5846_5342, 0x9123_683e, 0x0102_1994, 0x794c_7630] {
        let probe = Probe {
            filesystem,
            fail_at: None,
            events: RefCell::new(Vec::new()),
        };
        validate_with(&probe, Path::new("/cache")).unwrap();
        assert_eq!(*probe.events.borrow(), ["open", "fstatfs"]);
    }
    for filesystem in [
        0x6969,      // NFS, including EFS mounts
        0xff53_4d42, // CIFS
        0xfe53_4d42, // SMB2
        0x6573_5546, // FUSE, including object-store mounts
        0x0102_1997, // 9p
        0x00c3_6400, // Ceph
        0x5346_414f, // AFS
        0x9fa0,      // procfs
        0,          // unknown
        u32::MAX,   // unknown
    ] {
        let probe = Probe {
            filesystem,
            fail_at: None,
            events: RefCell::new(Vec::new()),
        };
        let error = validate_with(&probe, Path::new("/cache")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains(&format!("0x{filesystem:x}")));
        assert_eq!(*probe.events.borrow(), ["open", "fstatfs"]);
    }
    for fail_at in ["open", "fstatfs"] {
        let probe = Probe {
            filesystem: 0xef53,
            fail_at: Some(fail_at),
            events: RefCell::new(Vec::new()),
        };
        let error = validate_with(&probe, Path::new("/cache")).unwrap_err();
        assert_eq!(error.to_string(), fail_at);
        let expected = if fail_at == "open" {
            vec!["open"]
        } else {
            vec!["open", "fstatfs"]
        };
        assert_eq!(*probe.events.borrow(), expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_execution_storage_checks_actual_directory_and_rejects_symlink_bypass() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    crate::validate_cache_directory(root.path()).unwrap();
    let local_alias = root.path().join("local-alias");
    symlink(root.path(), &local_alias).unwrap();
    crate::validate_cache_directory(&local_alias).unwrap();
    let missing = root.path().join("missing");
    assert_eq!(
        crate::validate_cache_directory(&missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let file = root.path().join("file");
    fs::write(&file, b"").unwrap();
    assert!(crate::validate_cache_directory(&file).is_err());

    // procfs is a real rejected Linux filesystem accessible without mounting a
    // test NFS server or requiring mount privileges. A symlink must inspect it,
    // not infer eligibility from the path's location inside the local tempdir.
    let unsupported_alias = root.path().join("unsupported-alias");
    symlink("/proc", &unsupported_alias).unwrap();
    assert_eq!(
        crate::validate_cache_directory(&unsupported_alias)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert!(matches!(
        ImageBuilder::create_new(&unsupported_alias.join("must-not-create"), 0, 1),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::Unsupported
    ));
    assert!(!unsupported_alias.join("must-not-create").exists());
}
