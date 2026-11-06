use crate::file::{materialize, materialize_with, Files, NativeFiles};
use crate::Error;
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
        let event = if trace.bytes.is_empty() {
            "write"
        } else {
            "write_tail"
        };
        trace.event(event)?;
        let length = bytes.len().min(2);
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
}

#[test]
fn all_materialization_faults_stop_before_a_path_can_be_used() {
    let order = [
        "directory",
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
        let result = materialize_with(
            &mut ControlledFiles(trace.clone()),
            Path::new("/owned/new-worker"),
            b"data",
        );
        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(trace.borrow().events, order[..=index]);
        if index == 3 {
            assert_eq!(trace.borrow().bytes, b"da");
            assert!(!trace.borrow().events.contains(&"sync_file"));
        }
    }
    let trace = Rc::new(RefCell::new(Trace::default()));
    let path = materialize_with(
        &mut ControlledFiles(trace.clone()),
        Path::new("/owned/new-worker"),
        b"data",
    )
    .unwrap();
    assert_eq!(path, Path::new("/owned/new-worker/database.sqlite"));
    assert_eq!(trace.borrow().events, order);
    assert_eq!(trace.borrow().bytes, b"data");
}

#[test]
fn invalid_parent_is_rejected_before_any_effect() {
    let trace = Rc::new(RefCell::new(Trace::default()));
    for path in ["/", "worker", ""] {
        assert!(matches!(
            materialize_with(&mut ControlledFiles(trace.clone()), Path::new(path), b"data"),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }
    assert!(trace.borrow().events.is_empty());
}

#[test]
fn native_materialization_is_exclusive_and_never_reuses_sidecars() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("worker");
    let path = materialize(&directory, b"exact logical image").unwrap();
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&path).unwrap(), b"exact logical image");
    fs::write(directory.join("database.sqlite-wal"), b"old sidecar").unwrap();
    assert!(
        matches!(materialize(&directory, b"replace"), Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read(&path).unwrap(), b"exact logical image");
    assert_eq!(
        fs::read(directory.join("database.sqlite-wal")).unwrap(),
        b"old sidecar"
    );
    assert!(NativeFiles.create_file(&path).is_err());
    assert!(NativeFiles
        .sync_directory(&root.path().join("absent"))
        .is_err());
    let empty = materialize(&root.path().join("empty"), &[]).unwrap();
    assert_eq!(fs::metadata(empty).unwrap().len(), 0);
}
