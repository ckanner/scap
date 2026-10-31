//! Private, bounded test IPC. No product API or transport is provided here.
use std::io::{self, Read, Write};
use std::time::Duration;

pub const PAGE_SIZE: usize = 4096;
pub const MAX_PAGES: usize = 64;
pub const MAX_PHYSICAL: usize = 16 + MAX_PAGES * (4 + PAGE_SIZE);
pub const MAX_RESULT: usize = 1024;
pub const MAX_FRAME: usize = MAX_PHYSICAL + MAX_RESULT + 32;
pub const TIMEOUT: Duration = Duration::from_secs(20);
pub const SQL: &str = "UPDATE items SET payload=randomblob(32) WHERE id=0 RETURNING payload";
pub const INIT_SCHEMA: &str = "BEGIN IMMEDIATE; \
    CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL); \
    CREATE TABLE cache_meta(revision INTEGER NOT NULL); \
    CREATE TRIGGER bump_revision AFTER UPDATE ON items BEGIN \
    UPDATE cache_meta SET revision=revision+1; END;";

#[derive(Debug, PartialEq, Eq)]
pub enum Wire {
    Ready,
    Start(u64),
    Gate { changes: Vec<u8>, result: Vec<u8> },
    Publish,
    Reject,
    Ack(Vec<u8>),
    Rejected(i32),
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid bounded fixture frame")
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take_bytes(input: &mut &[u8], limit: usize) -> io::Result<Vec<u8>> {
    if input.len() < 4 {
        return Err(invalid());
    }
    let length = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    *input = &input[4..];
    if length > limit || input.len() < length {
        return Err(invalid());
    }
    let value = input[..length].to_vec();
    *input = &input[length..];
    Ok(value)
}

pub fn write_frame(writer: &mut impl Write, message: &Wire) -> io::Result<()> {
    let mut body = Vec::new();
    match message {
        Wire::Ready => body.push(1),
        Wire::Start(revision) => {
            body.push(2);
            body.extend_from_slice(&revision.to_le_bytes());
        }
        Wire::Gate { changes, result } => {
            if changes.len() > MAX_PHYSICAL || result.len() > MAX_RESULT {
                return Err(invalid());
            }
            body.push(3);
            push_bytes(&mut body, changes);
            push_bytes(&mut body, result);
        }
        Wire::Publish => body.push(4),
        Wire::Reject => body.push(5),
        Wire::Ack(result) => {
            if result.len() > MAX_RESULT {
                return Err(invalid());
            }
            body.push(6);
            push_bytes(&mut body, result);
        }
        Wire::Rejected(code) => {
            body.push(7);
            body.extend_from_slice(&code.to_le_bytes());
        }
    }
    if body.len() > MAX_FRAME {
        return Err(invalid());
    }
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Wire> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let mut rest = &bytes[1..];
    let message = match bytes[0] {
        1 => Wire::Ready,
        2 if rest.len() == 8 => {
            let revision = u64::from_le_bytes(rest.try_into().unwrap());
            rest = &[];
            Wire::Start(revision)
        }
        3 => Wire::Gate {
            changes: take_bytes(&mut rest, MAX_PHYSICAL)?,
            result: take_bytes(&mut rest, MAX_RESULT)?,
        },
        4 => Wire::Publish,
        5 => Wire::Reject,
        6 => Wire::Ack(take_bytes(&mut rest, MAX_RESULT)?),
        7 if rest.len() == 4 => {
            let code = i32::from_le_bytes(rest.try_into().unwrap());
            rest = &[];
            Wire::Rejected(code)
        }
        _ => return Err(invalid()),
    };
    if !rest.is_empty() {
        return Err(invalid());
    }
    Ok(message)
}
