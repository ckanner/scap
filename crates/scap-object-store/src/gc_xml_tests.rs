use super::*;

fn versioning(body: &str) -> String {
    format!("<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{body}</VersioningConfiguration>")
}

#[test]
fn only_an_explicit_never_versioned_configuration_is_accepted() {
    for document in [versioning(""), versioning(" \n\t\r"), "<?xml version=\"1.0\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>".into(), format!(" \n<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}\t",versioning(""))] {
        assert_eq!(unversioned(document.as_bytes()), Ok(()));
    }
    for fields in [
        "<Status>Enabled</Status>",
        "<Status>Suspended</Status>",
        "<Status/>",
        "<MFADelete>Enabled</MFADelete>",
        "<MFADelete>Disabled</MFADelete>",
        "<Status>FutureState</Status><MFADelete>Disabled</MFADelete>",
    ] {
        assert_eq!(
            unversioned(versioning(fields).as_bytes()),
            Err(GcError::Unsupported)
        );
    }
}

#[test]
fn ambiguous_and_malformed_capability_documents_fail_closed() {
    let invalid = [
        String::new(),
        "<VersioningConfiguration/>".into(),
        "<Wrong/>".into(),
        "<VersioningConfiguration xmlns=\"wrong\"/>".into(),
        "<VersioningConfiguration other=\"x\"/>".into(),
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\" other=\"x\"/>"
            .into(),
        "<VersioningConfiguration xmlns/>".into(),
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"".into(),
        versioning("<Unknown/>"),
        versioning("<Status>Enabled</Status><Status>Suspended</Status>"),
        versioning("<Status x=\"x\">Enabled</Status>"),
        versioning("<Status><Child/></Status>"),
        versioning("<Status><![CDATA[Enabled]]></Status>"),
        versioning("<Status>&unknown;</Status>"),
        versioning("<Status>&#0;</Status>"),
        versioning("<Status>&#xD800;</Status>"),
        versioning("<Status>Enabled</Other>"),
        versioning("text"),
        versioning("<!-- comment -->"),
        versioning("<?instruction x?>"),
        versioning("<?xml version=\"1.0\"?>"),
        format!("{}<Error/>", versioning("")),
        format!("{}text", versioning("")),
        format!("{}<!-- trailing -->", versioning("")),
        format!("<?xml version=\"1.1\"?>{}", versioning("")),
        format!(
            "<?xml version=\"1.0\"?><?xml version=\"1.0\"?>{}",
            versioning("")
        ),
        format!("<!DOCTYPE x>{}", versioning("")),
        versioning("<Status>\0</Status>"),
        versioning("<Status>\u{fffe}</Status>"),
    ];
    for value in invalid {
        assert_eq!(
            unversioned(value.as_bytes()),
            Err(GcError::Corrupt),
            "{value:?}"
        );
    }
    assert_eq!(unversioned(&[0xff]), Err(GcError::Corrupt));
    assert_eq!(
        unversioned(&vec![b' '; MAX_GC_RESPONSE_BYTES + 1]),
        Err(GcError::Limit)
    );
}

#[test]
fn error_codes_are_exact_and_bucket_absence_is_distinct() {
    for code in [
        "NoSuchKey",
        "NoSuchBucket",
        "ObjectLockConfigurationNotFoundError",
    ] {
        assert_eq!(error_code(format!("<Error><Code>{code}</Code><Message>a &amp; b &lt; c &#x1F600;</Message><RequestId>r</RequestId><HostId>h</HostId><Resource>/x</Resource><BucketName>b</BucketName><Key>k</Key></Error>").as_bytes()),Ok(code.into()));
    }
    assert_eq!(error_code(b"<Error xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Code>NoSuchKey</Code></Error>"),Ok("NoSuchKey".into()));
    for doc in [
        "<Error/>",
        "<Error><Code/></Error>",
        "<Error><Code>NoSuchKey</Code><Code>NoSuchBucket</Code></Error>",
        "<Error><Code>NoSuchKey",
        "<Error><Code>NoSuchKey</Code>",
        "<Error><Code>NoSuchKey</Code></Error>",
        "<Error xmlns='wrong'><Code>NoSuchKey</Code></Error>",
    ] {
        // Keep the one complete positive control alongside truncated variants.
        if doc == "<Error><Code>NoSuchKey</Code></Error>" {
            assert!(error_code(doc.as_bytes()).is_ok());
        } else {
            assert_eq!(error_code(doc.as_bytes()), Err(GcError::Corrupt), "{doc}");
        }
    }
}

#[test]
fn every_accepted_envelope_component_has_its_own_byte_validation() {
    let valid = versioning("");
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(valid.as_bytes());
    assert_eq!(unversioned(&bom), Ok(()));
    for prefix in [
        b"\xff\xfe".as_slice(),
        b"\xfe\xff",
        b"\xff\xfe\0\0",
        b"\0\0\xfe\xff",
        b"\xef\xbb\xbf\xef\xbb\xbf",
        b" \xef\xbb\xbf",
    ] {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(valid.as_bytes());
        assert_eq!(unversioned(&bytes), Err(GcError::Corrupt), "{prefix:?}");
    }
    for bytes in [
        b"\xff<Error><Code>NoSuchKey</Code></Error>".as_slice(),
        b"<Error xmlns=\"\xff\"><Code>NoSuchKey</Code></Error>",
        b"<Error><Co\xffde>NoSuchKey</Co\xffde></Error>",
        b"<Error><Code>NoSuch\xffKey</Code></Error>",
        b"<Error><Code>NoSuchKey</Code></Error>\xff",
        b"<Error><Code>NoSuchKey</Code></Error>\xef\xbb\xbf",
        b"<Error><",
        b"<Error></Other>",
        b"<Error><Code>NoSuchKey</Code></Error><",
        b"<Error><Code>NoSuchKey</Code><Message>]]></Message></Error>",
        b"<Error><Code>NoSuchKey</Code><Message>\0</Message></Error>",
        b"<Error><Code>NoSuchKey</Code><Message>&#xFFFE;</Message></Error>",
    ] {
        assert_eq!(error_code(bytes), Err(GcError::Corrupt), "{bytes:?}");
    }
    assert_eq!(
        error_code(b"<Error><Code>NoSuchKey</Code><Message>]]&gt;</Message></Error>"),
        Ok("NoSuchKey".into())
    );
}
