//! Bounded parent/child observation protocol. Raft payload delivery never uses
//! this control channel; only test proposals and observations do.
use std::io::{self, BufRead, Read};

pub const PREFIX: &str = "SCAP_SQL_NETWORK_V1";
pub const REQUEST_BYTES: usize = 256 * 1024;
pub const RESPONSE_BYTES: usize = 5 * 1024 * 1024;

pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

pub fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub fn line(reader: &mut impl BufRead, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let count = reader
        .by_ref()
        .take(maximum as u64 + 1)
        .read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if count > maximum || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame limit",
        ));
    }
    Ok(Some(bytes))
}

#[derive(Debug)]
pub struct Reply {
    pub sequence: u64,
    pub kind: String,
    pub fields: Vec<String>,
}

impl Reply {
    pub fn parse(text: &str) -> Option<Self> {
        let start = text.find(PREFIX)?;
        let fields: Vec<_> = text[start..].split_whitespace().collect();
        assert!(fields.len() >= 4);
        assert_eq!(fields.last(), Some(&"END"));
        Some(Self {
            sequence: fields[1].parse().unwrap(),
            kind: fields[2].into(),
            fields: fields[3..fields.len() - 1]
                .iter()
                .map(|field| (*field).into())
                .collect(),
        })
    }

    pub fn error(&self) -> Option<String> {
        (self.kind == "error").then(|| String::from_utf8(unhex(&self.fields[0])).unwrap())
    }
}
