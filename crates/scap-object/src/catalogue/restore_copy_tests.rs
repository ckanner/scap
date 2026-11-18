use super::*;

#[test]
fn local_image_failures_do_not_claim_authoritative_corruption_or_source_expiry() {
    use scap_object_sqlite::Error as NativeError;
    for error in [
        NativeError::Io(std::io::Error::from_raw_os_error(28)),
        NativeError::Io(std::io::Error::from_raw_os_error(5)),
        NativeError::Interrupted,
        NativeError::Stopped,
    ] {
        assert_eq!(copy_error(Error::Engine(error)), CatalogueError::Unknown);
    }
    for error in [NativeError::ResourceExhausted, NativeError::ResultLimit] {
        assert_eq!(copy_error(Error::Engine(error)), CatalogueError::Limit);
    }
    assert_eq!(
        copy_error(Error::Engine(NativeError::InvalidImage)),
        CatalogueError::Corrupt
    );
    assert_eq!(
        copy_error(Error::SnapshotExpired),
        CatalogueError::SnapshotExpired
    );
    assert_eq!(
        copy_error(target_error(Error::SnapshotExpired)),
        CatalogueError::Conflict
    );
    assert_eq!(
        copy_error(target_error(Error::Unknown)),
        CatalogueError::Unknown
    );
}

#[test]
fn native_validation_checks_the_original_interrupt_after_actual_writer_cleanup() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-validation");
    let image = ImageBuilder::create_new(&path, 0, 1)
        .unwrap()
        .finish()
        .unwrap();
    let limits = crate::tests::test_options()
        .writer(&crate::format::DatabaseQuota {
            max_bytes: Some(4096),
        })
        .unwrap();
    let during = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let watched = path.clone();
    let before_count = during.clone();
    let after_count = after.clone();
    // The same interrupt provider is queried inside the real native open and
    // again after its actual connection/image destructor has removed the dir.
    // A deadline/cancellation becoming true during cleanup must not escape as
    // validated success. No sleep, dummy writer or successful native bypass.
    let interrupt = Arc::new(move || {
        if watched.exists() {
            before_count.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            after_count.fetch_add(1, Ordering::Relaxed);
            true
        }
    });
    assert_eq!(
        validate_native(limits, image, interrupt),
        Err(CatalogueError::Unknown)
    );
    assert!(!path.exists());
    assert!(during.load(Ordering::Relaxed) > 0);
    assert_eq!(after.load(Ordering::Relaxed), 1);
}
