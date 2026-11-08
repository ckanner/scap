//! Strict, bounded ListObjectsV2 envelope validation before SDK normalization.

use std::collections::BTreeMap;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::listing::{
    Context, ListEnd, ListEntry, ListError, ListKind, ListMode, ListPage, Proof, MAX_LIST_ENTRIES,
    MAX_LIST_RESPONSE_BYTES, MAX_LIST_TOKEN_BYTES,
};

const NAMESPACE: &[u8] = b"http://s3.amazonaws.com/doc/2006-03-01/";
const MAX_XML_NODES: usize = 512;
const MAX_XML_TEXT_BYTES: usize = 16 * 1024;
const ROOT_FIELDS: &[&str] = &[
    "Name",
    "Prefix",
    "MaxKeys",
    "Delimiter",
    "StartAfter",
    "IsTruncated",
    "NextContinuationToken",
    "KeyCount",
];
const OBJECT_FIELDS: &[&str] = &[
    "Key",
    "LastModified",
    "Size",
    "ETag",
    "StorageClass",
    "ChecksumAlgorithm",
    "ChecksumType",
];

#[derive(Debug)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

pub(super) fn validate(bytes: &[u8], context: &Context) -> Result<Proof, ListError> {
    if bytes.len() > MAX_LIST_RESPONSE_BYTES {
        return Err(ListError::Limit);
    }
    let root = document(bytes)?;
    let mut objects = Vec::new();
    let mut prefixes = Vec::new();
    let mut controls = Vec::new();
    for child in root.children {
        match child.name.as_str() {
            "Contents" => {
                let fields = fields(child.children, OBJECT_FIELDS)?;
                let key = required(&fields, "Key")?;
                required(&fields, "Size")?
                    .parse::<u64>()
                    .map_err(|_| ListError::Corrupt)?;
                if required(&fields, "LastModified")?.is_empty() {
                    return Err(ListError::Corrupt);
                }
                push_key(&mut objects, key, ListKind::Object, context)?;
            }
            "CommonPrefixes" => {
                let fields = fields(child.children, &["Prefix"])?;
                push_key(
                    &mut prefixes,
                    required(&fields, "Prefix")?,
                    ListKind::Prefix,
                    context,
                )?;
            }
            _ => controls.push(child),
        }
        if objects.len() + prefixes.len() > MAX_LIST_ENTRIES {
            return Err(ListError::Limit);
        }
    }
    let fields = fields(controls, ROOT_FIELDS)?;
    if required(&fields, "Name")? != context.bucket
        || required(&fields, "Prefix")? != context.prefix
        || required(&fields, "MaxKeys")? != MAX_LIST_ENTRIES.to_string()
        || fields.get("StartAfter") != context.after.as_ref()
        || fields.get("Delimiter").map(String::as_str)
            != match context.mode {
                ListMode::Keys => None,
                ListMode::Children => Some("/"),
            }
        || required(&fields, "KeyCount")? != (objects.len() + prefixes.len()).to_string()
    {
        return Err(ListError::Corrupt);
    }
    let truncated = match required(&fields, "IsTruncated")? {
        "true" => true,
        "false" => false,
        _ => return Err(ListError::Corrupt),
    };
    let token = fields.get("NextContinuationToken").cloned();
    if truncated != token.is_some() {
        return Err(ListError::Corrupt);
    }
    if let Some(token) = &token {
        if token.is_empty() || token.len() > MAX_LIST_TOKEN_BYTES {
            return Err(ListError::Corrupt);
        }
    }
    let mut entries: Vec<_> = objects
        .iter()
        .map(|key| ListEntry {
            key: key.clone(),
            kind: ListKind::Object,
        })
        .chain(prefixes.iter().map(|key| ListEntry {
            key: key.clone(),
            kind: ListKind::Prefix,
        }))
        .collect();
    // AWS may serialize all Contents before all CommonPrefixes. Each separate
    // sequence must be ordered; merge their raw UTF-8 byte order for the caller.
    entries.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    let end = if truncated {
        ListEnd::More {
            after: entries.last().ok_or(ListError::Corrupt)?.key.clone(),
        }
    } else {
        ListEnd::Exhausted
    };
    Ok(Proof {
        context: context.clone(),
        objects,
        prefixes,
        token,
        page: ListPage {
            entries,
            end,
            response_bytes: bytes.len(),
        },
    })
}

fn push_key(
    keys: &mut Vec<String>,
    key: &str,
    kind: ListKind,
    context: &Context,
) -> Result<(), ListError> {
    context
        .check_entry(key, kind)
        .map_err(|_| ListError::Corrupt)?;
    let lower = keys.last().or(context.after.as_ref());
    if lower.is_some_and(|lower| key.as_bytes() <= lower.as_bytes()) {
        return Err(ListError::Corrupt);
    }
    keys.push(key.into());
    Ok(())
}

fn fields(nodes: Vec<Node>, allowed: &[&str]) -> Result<BTreeMap<String, String>, ListError> {
    let mut result = BTreeMap::new();
    for node in nodes {
        if !allowed.contains(&node.name.as_str())
            || !node.children.is_empty()
            || result.insert(node.name, node.text).is_some()
        {
            return Err(ListError::Corrupt);
        }
    }
    Ok(result)
}

fn required<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, ListError> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or(ListError::Corrupt)
}

fn document(bytes: &[u8]) -> Result<Node, ListError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().expand_empty_elements = true;
    let mut declaration = false;
    let mut remaining = MAX_XML_NODES;
    let root = loop {
        match reader.read_event().map_err(|_| ListError::Corrupt)? {
            Event::Decl(value) => {
                if declaration
                    || !matches!(
                        value.as_ref(),
                        b"xml version=\"1.0\" encoding=\"UTF-8\"" | b"xml version=\"1.0\""
                    )
                {
                    return Err(ListError::Corrupt);
                }
                declaration = true;
            }
            Event::Text(text) if whitespace(&text) => {}
            Event::Start(start) => {
                if start.name().as_ref() != b"ListBucketResult" {
                    return Err(ListError::Corrupt);
                }
                break node(&mut reader, start, 0, &mut remaining)?;
            }
            _ => return Err(ListError::Corrupt),
        }
    };
    loop {
        match reader.read_event().map_err(|_| ListError::Corrupt)? {
            Event::Text(text) if whitespace(&text) => {}
            Event::Eof => return Ok(root),
            _ => return Err(ListError::Corrupt),
        }
    }
}

fn node(
    reader: &mut Reader<&[u8]>,
    start: BytesStart<'_>,
    depth: usize,
    remaining: &mut usize,
) -> Result<Node, ListError> {
    if depth == 4 || *remaining == 0 {
        return Err(ListError::Limit);
    }
    *remaining -= 1;
    let mut attributes = start.attributes();
    if depth == 0 {
        let namespace = attributes
            .next()
            .ok_or(ListError::Corrupt)?
            .map_err(|_| ListError::Corrupt)?;
        if namespace.key.as_ref() != b"xmlns" || namespace.value.as_ref() != NAMESPACE {
            return Err(ListError::Corrupt);
        }
    }
    if attributes.next().is_some() {
        return Err(ListError::Corrupt);
    }
    let mut value = Node {
        name: std::str::from_utf8(start.name().as_ref())
            .map_err(|_| ListError::Corrupt)?
            .into(),
        text: String::new(),
        children: Vec::new(),
    };
    loop {
        match reader.read_event().map_err(|_| ListError::Corrupt)? {
            Event::Start(child) => {
                value
                    .children
                    .push(node(reader, child, depth + 1, remaining)?);
            }
            Event::Text(text) => append(
                &mut value.text,
                &text.xml10_content().map_err(|_| ListError::Corrupt)?,
            )?,
            Event::GeneralRef(reference) => {
                let decoded = reference.decode().map_err(|_| ListError::Corrupt)?;
                let escaped = format!("&{decoded};");
                append(
                    &mut value.text,
                    &quick_xml::escape::unescape(&escaped).map_err(|_| ListError::Corrupt)?,
                )?;
            }
            Event::End(_) => break,
            // Comments, CDATA, DTDs, processing instructions and document
            // declarations inside the result are outside this strict profile.
            _ => return Err(ListError::Corrupt),
        }
    }
    if !value.children.is_empty() && !whitespace(value.text.as_bytes()) {
        return Err(ListError::Corrupt);
    }
    Ok(value)
}

fn append(text: &mut String, addition: &str) -> Result<(), ListError> {
    if addition.len() > MAX_XML_TEXT_BYTES - text.len() {
        return Err(ListError::Limit);
    }
    if addition
        .chars()
        .any(|value| !matches!(value, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'))
    {
        return Err(ListError::Corrupt);
    }
    text.push_str(addition);
    Ok(())
}

fn whitespace(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|value| matches!(value, b' ' | b'\t' | b'\n' | b'\r'))
}

#[cfg(test)]
#[path = "listing_xml_tests.rs"]
pub(crate) mod tests;
