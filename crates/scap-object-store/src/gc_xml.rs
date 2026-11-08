//! Strict flat metadata envelopes. Malformed or ambiguous capability responses
//! never authorize DELETE; error parsing never aliases a missing bucket to key.

use crate::{GcError, MAX_GC_RESPONSE_BYTES};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

const NAMESPACE: &[u8] = b"http://s3.amazonaws.com/doc/2006-03-01/";

pub(super) fn unversioned(bytes: &[u8]) -> Result<(), GcError> {
    let fields = flat(
        bytes,
        b"VersioningConfiguration",
        &["Status", "MFADelete"],
        true,
    )?;
    if !fields.is_empty() {
        return Err(GcError::Unsupported);
    }
    Ok(())
}

pub(super) fn error_code(bytes: &[u8]) -> Result<String, GcError> {
    let mut fields = flat(
        bytes,
        b"Error",
        &[
            "Code",
            "Message",
            "RequestId",
            "HostId",
            "Resource",
            "BucketName",
            "Key",
        ],
        false,
    )?;
    fields
        .remove("Code")
        .filter(|value| !value.is_empty())
        .ok_or(GcError::Corrupt)
}

fn flat(
    bytes: &[u8],
    root: &[u8],
    allowed: &[&str],
    namespace_required: bool,
) -> Result<BTreeMap<String, String>, GcError> {
    if bytes.len() > MAX_GC_RESPONSE_BYTES {
        return Err(GcError::Limit);
    }
    let raw = std::str::from_utf8(bytes).map_err(|_| GcError::Corrupt)?;
    valid_chars(raw)?;
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().expand_empty_elements = true;
    let mut declaration = false;
    loop {
        match reader.read_event().map_err(|_| GcError::Corrupt)? {
            Event::Decl(value) => {
                if declaration
                    || !matches!(
                        value.as_ref(),
                        b"xml version=\"1.0\" encoding=\"UTF-8\"" | b"xml version=\"1.0\""
                    )
                {
                    return Err(GcError::Corrupt);
                }
                declaration = true;
            }
            Event::Text(text) if whitespace(&text) => {}
            Event::Start(start) if start.name().as_ref() == root => {
                attributes(&start, namespace_required)?;
                break;
            }
            _ => return Err(GcError::Corrupt),
        }
    }
    let mut fields = BTreeMap::new();
    loop {
        match reader.read_event().map_err(|_| GcError::Corrupt)? {
            Event::Start(start) => {
                if start.attributes().next().is_some() {
                    return Err(GcError::Corrupt);
                }
                let name = std::str::from_utf8(start.name().as_ref())
                    .map_err(|_| GcError::Corrupt)?
                    .to_owned();
                if !allowed.contains(&name.as_str()) || fields.contains_key(&name) {
                    return Err(GcError::Corrupt);
                }
                let text = reader
                    .read_text(start.name())
                    .map_err(|_| GcError::Corrupt)?;
                let text = text.xml10_content().map_err(|_| GcError::Corrupt)?;
                if text.contains('<') {
                    return Err(GcError::Corrupt);
                }
                let decoded = quick_xml::escape::unescape(&text).map_err(|_| GcError::Corrupt)?;
                valid_chars(&decoded)?;
                fields.insert(name, decoded.into_owned());
            }
            Event::Text(text) if whitespace(&text) => {}
            Event::End(end) if end.name().as_ref() == root => break,
            _ => return Err(GcError::Corrupt),
        }
    }
    loop {
        match reader.read_event().map_err(|_| GcError::Corrupt)? {
            Event::Text(text) if whitespace(&text) => {}
            Event::Eof => return Ok(fields),
            _ => return Err(GcError::Corrupt),
        }
    }
}

fn attributes(start: &BytesStart<'_>, required: bool) -> Result<(), GcError> {
    let mut attrs = start.attributes();
    if let Some(attribute) = attrs.next() {
        let attribute = attribute.map_err(|_| GcError::Corrupt)?;
        if attribute.key.as_ref() != b"xmlns"
            || attribute.value.as_ref() != NAMESPACE
            || attrs.next().is_some()
        {
            return Err(GcError::Corrupt);
        }
    } else if required {
        return Err(GcError::Corrupt);
    }
    Ok(())
}

fn valid_chars(text: &str) -> Result<(), GcError> {
    if text.chars().any(|value| !matches!(value, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')) { return Err(GcError::Corrupt); }
    Ok(())
}

fn whitespace(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
}

#[cfg(test)]
#[path = "gc_xml_tests.rs"]
mod tests;
