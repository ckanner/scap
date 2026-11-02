use super::*;

fn environment(mode: u8) -> impl Fn(&str) -> Option<String> {
    move |name| match mode {
        0 => panic!("disabled storage must not inspect environment"),
        1 => None,
        2 if name != "SCAP_TEST_KEY" => None,
        _ => Some("synthetic-test-only".into()),
    }
}

#[test]
fn missing_archive_and_explicit_credentials_are_never_ambient_fallbacks() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert!(connect(None, runtime.handle().clone(), environment(0))
        .unwrap()
        .is_none());
    let archive = ArchiveConfig {
        endpoint: "http://127.0.0.1:1".into(),
        region: "test".into(),
        bucket: "test".into(),
        access_key_env: "SCAP_TEST_KEY".into(),
        secret_key_env: "SCAP_TEST_SECRET".into(),
        allow_http: true,
    };
    assert_eq!(
        connect(Some(&archive), runtime.handle().clone(), environment(1))
            .err()
            .unwrap()
            .code,
        "ARCHIVE_CREDENTIAL"
    );
    assert_eq!(
        connect(Some(&archive), runtime.handle().clone(), environment(2))
            .err()
            .unwrap()
            .code,
        "ARCHIVE_CREDENTIAL"
    );
    assert!(
        connect(Some(&archive), runtime.handle().clone(), environment(3))
            .unwrap()
            .is_some()
    );
    let mut invalid = archive;
    invalid.endpoint = "not a URL".into();
    assert_eq!(
        connect(Some(&invalid), runtime.handle().clone(), environment(3))
            .err()
            .unwrap()
            .code,
        "ARCHIVE_CONFIG"
    );
}
