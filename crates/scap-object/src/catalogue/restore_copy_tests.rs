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
