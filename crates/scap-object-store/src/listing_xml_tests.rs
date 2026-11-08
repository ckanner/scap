use super::*;

pub(crate) fn context(mode: ListMode, after: Option<&str>) -> Context {
    Context {
        bucket: "scap-unit".into(),
        prefix: "scope/".into(),
        mode,
        after: after.map(str::to_owned),
    }
}

pub(crate) fn object(key: &str) -> String {
    format!(
        "<Contents><Key>{}</Key><Size>4</Size><LastModified>2026-11-08T01:02:03.000Z</LastModified><ETag>&#34;token&#34;</ETag><StorageClass>STANDARD</StorageClass></Contents>",
        quick_xml::escape::escape(key)
    )
}

pub(crate) fn prefix(key: &str) -> String {
    format!(
        "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
        quick_xml::escape::escape(key)
    )
}

pub(crate) fn xml(inner: &str, count: usize, truncated: bool, context: &Context) -> Vec<u8> {
    let mut controls = String::new();
    if context.mode == ListMode::Children {
        controls.push_str("<Delimiter>/</Delimiter>");
    }
    if let Some(after) = &context.after {
        controls.push_str(&format!(
            "<StartAfter>{}</StartAfter>",
            quick_xml::escape::escape(after)
        ));
    }
    if truncated {
        controls.push_str("<NextContinuationToken>bounded-token</NextContinuationToken>");
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>32</MaxKeys><IsTruncated>{truncated}</IsTruncated><KeyCount>{count}</KeyCount>{controls}{inner}</ListBucketResult>\n",
        quick_xml::escape::escape(&context.bucket),
        quick_xml::escape::escape(&context.prefix)
    )
    .into_bytes()
}

fn change(bytes: &[u8], before: &str, after: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.contains(before), "{before:?}");
    text.replacen(before, after, 1).into_bytes()
}

#[test]
fn explicit_empty_and_full_pages_preserve_raw_candidates_and_proof() {
    let context = context(ListMode::Keys, None);
    let empty = xml("", 0, false, &context);
    let proof = validate(&empty, &context).unwrap();
    assert_eq!(proof.context, context);
    assert!(proof.objects.is_empty());
    assert!(proof.prefixes.is_empty());
    assert!(proof.token.is_none());
    assert_eq!(proof.page.end, ListEnd::Exhausted);
    assert_eq!(proof.page.response_bytes, empty.len());
    let keys: Vec<_> = (0..32).map(|index| format!("scope/{index:02}")).collect();
    let body = keys.iter().map(|key| object(key)).collect::<String>();
    let full = validate(&xml(&body, 32, true, &context), &context).unwrap();
    assert_eq!(full.objects, keys);
    assert_eq!(full.token.as_deref(), Some("bounded-token"));
    assert_eq!(
        full.page.end,
        ListEnd::More {
            after: "scope/31".into()
        }
    );
    assert!(full
        .page
        .entries
        .iter()
        .all(|entry| entry.kind == ListKind::Object));
    let metadata = object("scope/meta").replace(
        "</Contents>",
        "<ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumType>FULL_OBJECT</ChecksumType></Contents>",
    );
    assert!(validate(&xml(&metadata, 1, false, &context), &context).is_ok());
}

#[test]
fn children_merge_separate_sequences_and_use_utf8_bytes_after_the_frontier() {
    let context = context(ListMode::Children, Some("scope/a"));
    let body = format!(
        "{}{}{}{}",
        object("scope/z"),
        object("scope/é"),
        prefix("scope/b/"),
        prefix("scope/中/")
    );
    let proof = validate(&xml(&body, 4, true, &context), &context).unwrap();
    assert_eq!(proof.objects, ["scope/z", "scope/é"]);
    assert_eq!(proof.prefixes, ["scope/b/", "scope/中/"]);
    assert_eq!(
        proof
            .page
            .entries
            .iter()
            .map(|item| item.key.as_str())
            .collect::<Vec<_>>(),
        ["scope/b/", "scope/z", "scope/é", "scope/中/"]
    );
    assert_eq!(
        proof.page.end,
        ListEnd::More {
            after: "scope/中/".into()
        }
    );
    let same_stem = format!("{}{}", object("scope/b"), prefix("scope/b/"));
    assert!(validate(&xml(&same_stem, 2, false, &context), &context).is_ok());
}

#[test]
fn control_echoes_counts_and_truncation_must_be_complete_and_unambiguous() {
    let keys = context(ListMode::Keys, None);
    let original = xml(&object("scope/a"), 1, false, &keys);
    for (before, after) in [
        ("<Name>scap-unit</Name>", ""),
        ("<Name>scap-unit</Name>", "<Name>other-bucket</Name>"),
        ("<Prefix>scope/</Prefix>", ""),
        ("<Prefix>scope/</Prefix>", "<Prefix>scope</Prefix>"),
        ("<MaxKeys>32</MaxKeys>", ""),
        ("<MaxKeys>32</MaxKeys>", "<MaxKeys>1000</MaxKeys>"),
        ("<KeyCount>1</KeyCount>", ""),
        ("<KeyCount>1</KeyCount>", "<KeyCount>0</KeyCount>"),
        ("<IsTruncated>false</IsTruncated>", ""),
        (
            "<IsTruncated>false</IsTruncated>",
            "<IsTruncated>0</IsTruncated>",
        ),
        (
            "<IsTruncated>false</IsTruncated>",
            "<IsTruncated>true</IsTruncated>",
        ),
        (
            "<KeyCount>1</KeyCount>",
            "<KeyCount>1</KeyCount><KeyCount>1</KeyCount>",
        ),
        (
            "<Name>scap-unit</Name>",
            "<Name><Nested>scap-unit</Nested></Name>",
        ),
        (
            "</ListBucketResult>",
            "<Delimiter>/</Delimiter></ListBucketResult>",
        ),
        (
            "</ListBucketResult>",
            "<StartAfter>scope/a</StartAfter></ListBucketResult>",
        ),
        (
            "</ListBucketResult>",
            "<ContinuationToken>unexpected</ContinuationToken></ListBucketResult>",
        ),
        (
            "</ListBucketResult>",
            "<EncodingType>url</EncodingType></ListBucketResult>",
        ),
        (
            "</ListBucketResult>",
            "<NextContinuationToken>unexpected</NextContinuationToken></ListBucketResult>",
        ),
        (
            "</ListBucketResult>",
            "<Other>ignored-by-sdk</Other></ListBucketResult>",
        ),
    ] {
        assert_eq!(
            validate(&change(&original, before, after), &keys),
            Err(ListError::Corrupt),
            "{before} => {after}"
        );
    }
    let children = context(ListMode::Children, Some("scope/a"));
    let original = xml(&prefix("scope/b/"), 1, false, &children);
    for (before, after) in [
        ("<StartAfter>scope/a</StartAfter>", ""),
        (
            "<StartAfter>scope/a</StartAfter>",
            "<StartAfter>scope/b</StartAfter>",
        ),
        ("<Delimiter>/</Delimiter>", ""),
        ("<Delimiter>/</Delimiter>", "<Delimiter>-</Delimiter>"),
    ] {
        assert_eq!(
            validate(&change(&original, before, after), &children),
            Err(ListError::Corrupt)
        );
    }
    let more = xml(&object("scope/a"), 1, true, &keys);
    for (before, after) in [
        ("bounded-token", ""),
        (
            "<NextContinuationToken>bounded-token</NextContinuationToken>",
            "",
        ),
        (
            "<IsTruncated>true</IsTruncated>",
            "<IsTruncated>false</IsTruncated>",
        ),
    ] {
        assert_eq!(
            validate(&change(&more, before, after), &keys),
            Err(ListError::Corrupt)
        );
    }
    assert_eq!(
        validate(
            &change(
                &more,
                "bounded-token",
                &"t".repeat(MAX_LIST_TOKEN_BYTES + 1)
            ),
            &keys
        ),
        Err(ListError::Corrupt)
    );
    assert!(validate(
        &change(&more, "bounded-token", &"t".repeat(MAX_LIST_TOKEN_BYTES)),
        &keys
    )
    .is_ok());
    assert_eq!(
        validate(&xml("", 0, true, &keys), &keys),
        Err(ListError::Corrupt)
    );
}

#[test]
fn malformed_metadata_raw_keys_duplicates_and_order_are_not_normalized_away() {
    let keys = context(ListMode::Keys, Some("scope/a"));
    for key in [
        "scope/a",
        "scope/0",
        "other/b",
        "/scope/b",
        "scope/b/",
        "scope/../b",
        "scope//b",
        "scope/",
    ] {
        assert_eq!(
            validate(&xml(&object(key), 1, false, &keys), &keys),
            Err(ListError::Corrupt),
            "{key:?}"
        );
    }
    let children = context(ListMode::Children, None);
    for key in ["scope/a/child", "scope/a/"] {
        assert_eq!(
            validate(&xml(&object(key), 1, false, &children), &children),
            Err(ListError::Corrupt)
        );
    }
    for key in [
        "scope/b",
        "scope/a/b/",
        "scope/",
        "other/a/",
        "/scope/a/",
        "scope/../",
        "scope//",
    ] {
        assert_eq!(
            validate(&xml(&prefix(key), 1, false, &children), &children),
            Err(ListError::Corrupt),
            "{key:?}"
        );
    }
    assert_eq!(
        validate(&xml(&prefix("scope/b/"), 1, false, &keys), &keys),
        Err(ListError::Corrupt)
    );
    for body in [
        format!("{}{}", object("scope/b"), object("scope/b")),
        format!("{}{}", object("scope/c"), object("scope/b")),
        format!("{}{}", prefix("scope/b/"), prefix("scope/b/")),
        format!("{}{}", prefix("scope/c/"), prefix("scope/b/")),
    ] {
        assert_eq!(
            validate(&xml(&body, 2, false, &children), &children),
            Err(ListError::Corrupt)
        );
    }
    let full = xml(&object("scope/b"), 1, false, &keys);
    for (before, after) in [
        ("<Key>scope/b</Key>", ""),
        ("<Size>4</Size>", ""),
        ("<Size>4</Size>", "<Size>-1</Size>"),
        ("<Size>4</Size>", "<Size>18446744073709551616</Size>"),
        ("<LastModified>2026-11-08T01:02:03.000Z</LastModified>", ""),
        (
            "<LastModified>2026-11-08T01:02:03.000Z</LastModified>",
            "<LastModified/>",
        ),
        ("<Key>scope/b</Key>", "<Key>scope/b</Key><Key>scope/c</Key>"),
        ("</Contents>", "<Unknown>no</Unknown></Contents>"),
        (
            "</Contents>",
            "<Owner><ID>unrequested</ID></Owner></Contents>",
        ),
    ] {
        assert_eq!(
            validate(&change(&full, before, after), &keys),
            Err(ListError::Corrupt),
            "{before} => {after}"
        );
    }
}

#[test]
fn xml_is_bounded_without_accepting_partial_or_ambiguous_documents() {
    let context = context(ListMode::Keys, None);
    let original = xml(&object("scope/a"), 1, false, &context);
    for (before, after) in [
        (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<?xml version=\"1.1\"?>",
        ),
        (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<?xml version=\"1.0\"?><?xml version=\"1.0\"?>",
        ),
        (
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<Wrong xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        ),
        (" xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"", ""),
        ("xmlns=", "other="),
        ("http://s3.amazonaws.com/doc/2006-03-01/", "wrong-namespace"),
        ("<Name>", "<Name xmlns=\"other\">"),
        ("<Name>", "<Name unwanted=\"attribute\">"),
        ("<Name>", "<Name>text<Nested/>"),
        ("<Key>scope/a</Key>", "<Key>scope/<![CDATA[a]]></Key>"),
        ("<Key>scope/a</Key>", "<Key>scope/&unknown;</Key>"),
        ("<Key>scope/a</Key>", "<Key>scope/&#x0;</Key>"),
        ("<Key>scope/a</Key>", "<Key>scope/&#xnothex;</Key>"),
        ("</ListBucketResult>", "<!-- no --></ListBucketResult>"),
        (
            "</ListBucketResult>",
            "<?control invalid?></ListBucketResult>",
        ),
        (
            "</ListBucketResult>",
            "<?xml version=\"1.0\"?></ListBucketResult>",
        ),
        ("</ListBucketResult>", ""),
        ("</ListBucketResult>", "</ListBucketResult>unexpected"),
        ("</ListBucketResult>", "</ListBucketResult><Other/>"),
        ("<Key>scope/a</Key>", "<Key>scope/a</Wrong>"),
    ] {
        assert_eq!(
            validate(&change(&original, before, after), &context),
            Err(ListError::Corrupt),
            "{before} => {after}"
        );
    }
    for bytes in [
        b"".as_slice(),
        b"not xml",
        b"<!-- comment -->",
        b"<!DOCTYPE x><x/>",
        b"<unclosed",
        b"<",
        b"</bad>",
    ] {
        assert_eq!(validate(bytes, &context), Err(ListError::Corrupt));
    }
    let namespace = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
    for invalid in [
        "xmlns",
        "xmlns='unclosed",
        "xmlns=unquoted",
        &format!("{namespace} xmlns=\"other\""),
    ] {
        assert_eq!(
            validate(&change(&original, namespace, invalid), &context),
            Err(ListError::Corrupt)
        );
    }
    for bytes in [
        change(&original, "<Key>scope/a</Key>", "<Key>scope/INVALID</Key>"),
        change(
            &original,
            "<Key>scope/a</Key>",
            "<INVALID>scope/a</INVALID>",
        ),
        change(&original, "<Key>scope/a</Key>", "<Key>&INVALID;</Key>"),
    ] {
        let mut invalid = bytes;
        let offset = invalid
            .windows(7)
            .position(|part| part == b"INVALID")
            .unwrap();
        invalid[offset] = 0xff;
        assert_eq!(validate(&invalid, &context), Err(ListError::Corrupt));
    }
    assert_eq!(
        validate(&vec![b' '; MAX_LIST_RESPONSE_BYTES + 1], &context),
        Err(ListError::Limit)
    );
    let deep = change(
        &original,
        "<Key>scope/a</Key>",
        "<Key><A><B>deep</B></A></Key>",
    );
    assert_eq!(validate(&deep, &context), Err(ListError::Limit));
    let nodes = change(
        &original,
        "</ListBucketResult>",
        &format!("{}</ListBucketResult>", "<X/>".repeat(MAX_XML_NODES)),
    );
    assert_eq!(validate(&nodes, &context), Err(ListError::Limit));
    let oversized_text = change(&original, "scope/a", &"x".repeat(MAX_XML_TEXT_BYTES + 1));
    assert_eq!(validate(&oversized_text, &context), Err(ListError::Limit));
    let too_many = (0..33)
        .map(|index| object(&format!("scope/{index:02}")))
        .collect::<String>();
    assert_eq!(
        validate(&xml(&too_many, 33, false, &context), &context),
        Err(ListError::Limit)
    );
}

#[test]
fn allowed_xml_entities_whitespace_and_unicode_keep_exact_scalar_values() {
    let context = context(ListMode::Keys, None);
    let xml = xml(&object("scope/&<>\"'中\u{10000}"), 1, false, &context);
    let proof = validate(&xml, &context).unwrap();
    assert_eq!(proof.objects, ["scope/&<>\"'中\u{10000}"]);
    let simple = change(
        &xml,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<?xml version=\"1.0\"?>",
    );
    assert_eq!(validate(&simple, &context).unwrap().objects, proof.objects);
    let no_decl = change(&simple, "<?xml version=\"1.0\"?>", " \t\r\n");
    assert_eq!(validate(&no_decl, &context).unwrap().objects, proof.objects);
    let with_spaces = change(&xml, "<Name>", " \t\r\n<Name>");
    assert_eq!(
        validate(&with_spaces, &context).unwrap().objects,
        proof.objects
    );
    let mut text = String::new();
    append(
        &mut text,
        "\t\r\n \u{d7ff}\u{e000}\u{fffd}\u{10000}\u{10ffff}",
    )
    .unwrap();
    for bad in ["\0", "\u{1}", "\u{b}", "\u{fffe}", "\u{ffff}"] {
        assert_eq!(append(&mut text, bad), Err(ListError::Corrupt));
    }
    let mut exact = String::new();
    append(&mut exact, &"x".repeat(MAX_XML_TEXT_BYTES)).unwrap();
    assert_eq!(append(&mut exact, "x"), Err(ListError::Limit));
}

#[test]
fn malformed_child_prefixes_trailing_markup_and_decoded_controls_fail_closed() {
    let context = context(ListMode::Children, None);
    for body in [
        "<CommonPrefixes/>",
        "<CommonPrefixes><Other>scope/a/</Other></CommonPrefixes>",
        "<CommonPrefixes><Prefix>scope/&#1;/</Prefix></CommonPrefixes>",
    ] {
        assert_eq!(
            validate(&xml(body, 1, false, &context), &context),
            Err(ListError::Corrupt)
        );
    }
    let mut trailing = xml("", 0, false, &context);
    trailing.extend_from_slice(b"<unclosed");
    assert_eq!(validate(&trailing, &context), Err(ListError::Corrupt));
}
