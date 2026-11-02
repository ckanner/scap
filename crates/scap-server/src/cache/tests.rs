use super::*;

struct Faults {
    vacant: io::Result<bool>,
    remove: io::ErrorKind,
}
impl Files for Faults {
    fn vacant(&self, _: &Path) -> io::Result<bool> {
        self.vacant
            .as_ref()
            .copied()
            .map_err(|error| io::Error::new(error.kind(), "injected"))
    }
    fn remove(&self, _: &Path) -> io::Result<()> {
        Err(io::Error::new(self.remove, "injected"))
    }
}

#[test]
fn disposable_cache_cleanup_owns_only_new_paths_and_blocks_after_io_failure() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("new");
    let failed = Arc::new(AtomicBool::new(false));
    let cache = Cache::reserve(path.clone(), failed.clone()).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("database.sqlite"), b"only a cache").unwrap();
    assert_eq!(
        Cache::reserve(path.clone(), failed.clone())
            .err()
            .unwrap()
            .code,
        "CACHE_EXISTS"
    );
    drop(cache);
    assert!(!path.exists());
    drop(Cache::reserve(path.clone(), failed.clone()).unwrap());
    assert!(!failed.load(Ordering::Acquire));
    let bad = Arc::new(Faults {
        vacant: Err(io::Error::other("metadata")),
        remove: io::ErrorKind::PermissionDenied,
    });
    assert_eq!(
        Cache::with_files(path.clone(), failed.clone(), bad)
            .err()
            .unwrap()
            .code,
        "CACHE_IO"
    );
    drop(
        Cache::with_files(
            path,
            failed.clone(),
            Arc::new(Faults {
                vacant: Ok(true),
                remove: io::ErrorKind::PermissionDenied,
            }),
        )
        .unwrap(),
    );
    assert!(failed.load(Ordering::Acquire));
    assert!(vacant(Err(io::Error::other("injected metadata"))).is_err());
}

#[test]
fn restart_cleanup_validates_the_entire_owned_namespace_before_deleting() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("writers");
    clean_namespace(&path).unwrap();
    let valid = path.join(format!("{:032x}", 1));
    fs::create_dir(&valid).unwrap();
    let unknown = path.join("not-a-cache");
    fs::create_dir(&unknown).unwrap();
    assert_eq!(clean_namespace(&path).unwrap_err().code, "CACHE_NAMESPACE");
    assert!(valid.exists());
    fs::remove_dir(&unknown).unwrap();
    let invalid = path.join(std::ffi::OsString::from_vec(vec![255]));
    fs::create_dir(&invalid).unwrap();
    assert!(clean_namespace(&path).is_err());
    fs::remove_dir(invalid).unwrap();
    let non_hex = path.join("z".repeat(32));
    fs::create_dir(&non_hex).unwrap();
    assert!(clean_namespace(&path).is_err());
    fs::remove_dir(non_hex).unwrap();
    let regular = path.join(format!("{:032x}", 2));
    fs::write(&regular, b"not a directory").unwrap();
    assert!(clean_namespace(&path).is_err());
    fs::remove_file(regular).unwrap();
    clean_namespace(&path).unwrap();
    assert!(!valid.exists());
    for n in 0..1025 {
        fs::create_dir(path.join(format!("{n:032x}"))).unwrap();
    }
    assert_eq!(clean_namespace(&path).unwrap_err().code, "CACHE_LIMIT");
    let file = temp.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert_eq!(clean_namespace(&file).unwrap_err().code, "CACHE_DIRECTORY");
}

#[test]
fn namespace_errors_do_not_delete_before_complete_validation() {
    let directory = tempfile::tempdir().unwrap();
    assert!(Native
        .entries(&directory.path().join("missing"), 1025)
        .is_err());
    struct FailingNamespace {
        stage: u8,
        removed: std::cell::RefCell<Vec<PathBuf>>,
    }
    impl Namespace for FailingNamespace {
        fn prepare(&self, _: &Path) -> io::Result<bool> {
            if self.stage == 0 {
                Err(io::Error::other("create"))
            } else {
                Ok(true)
            }
        }
        fn entries(&self, _: &Path, limit: usize) -> io::Result<Vec<Entry>> {
            assert_eq!(limit, 1025);
            if self.stage == 1 {
                return Err(io::Error::other("read directory entry"));
            }
            Ok(vec![
                Entry {
                    name: format!("{:032x}", 1).into(),
                    directory: Ok(true),
                },
                Entry {
                    name: format!("{:032x}", 2).into(),
                    directory: if self.stage == 2 {
                        Err(io::Error::other("file type"))
                    } else {
                        Ok(true)
                    },
                },
            ])
        }
        fn remove(&self, path: &Path) -> io::Result<()> {
            self.removed.borrow_mut().push(path.to_owned());
            Err(io::Error::other("remove"))
        }
    }
    for (stage, code) in [
        (0, "CACHE_DIRECTORY"),
        (1, "CACHE_DIRECTORY"),
        (2, "CACHE_IO"),
        (3, "CACHE_IO"),
    ] {
        let files = FailingNamespace {
            stage,
            removed: Default::default(),
        };
        assert_eq!(
            clean_with(Path::new("/node/writers"), &files)
                .unwrap_err()
                .code,
            code
        );
        assert_eq!(files.removed.borrow().len(), usize::from(stage == 3));
    }
}

#[test]
fn symlinks_including_the_namespace_root_are_never_followed() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("other-owned-data");
    fs::create_dir(&outside).unwrap();
    let outside_file = outside.join(format!("{:032x}", 4));
    fs::create_dir(&outside_file).unwrap();
    let namespace = temp.path().join("writers");
    symlink(&outside, &namespace).unwrap();
    assert_eq!(
        clean_namespace(&namespace).unwrap_err().code,
        "CACHE_NAMESPACE"
    );
    assert!(outside_file.is_dir());
    fs::remove_file(&namespace).unwrap();
    fs::create_dir(&namespace).unwrap();
    let inside = namespace.join(format!("{:032x}", 5));
    symlink(&outside, &inside).unwrap();
    assert_eq!(
        clean_namespace(&namespace).unwrap_err().code,
        "CACHE_NAMESPACE"
    );
    assert!(outside_file.is_dir());
    assert!(inside.is_symlink());
    assert_eq!(
        Cache::reserve(inside, Arc::new(AtomicBool::new(false)))
            .err()
            .unwrap()
            .code,
        "CACHE_EXISTS"
    );
}
