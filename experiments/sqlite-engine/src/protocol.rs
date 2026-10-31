//! Length-bounded private test IPC, not a product SDK or peer transport.
use std::io::{self, Read, Write};
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CHANGES: usize = 300 * 1024;
const MAX_RESULT: usize = 16 * 1024;
const MAX_FRAME: usize = MAX_CHANGES + MAX_RESULT + 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Wire {
    Lookup,
    NotFound,
    Proposal { changes: Vec<u8>, result: Vec<u8> },
    Accept,
    AcceptedHeld,
    Proceed,
    Ack(Vec<u8>),
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid private fixture frame")
}

fn append(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> io::Result<()> {
    if bytes.len() > limit {
        return Err(invalid());
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take(input: &mut &[u8], limit: usize) -> io::Result<Vec<u8>> {
    if input.len() < 4 {
        return Err(invalid());
    }
    let count = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    *input = &input[4..];
    if count > limit || count > input.len() {
        return Err(invalid());
    }
    let bytes = input[..count].to_vec();
    *input = &input[count..];
    Ok(bytes)
}

pub fn write_frame(writer: &mut impl Write, message: &Wire) -> io::Result<()> {
    let mut bytes = Vec::new();
    match message {
        Wire::Lookup => bytes.push(1),
        Wire::NotFound => bytes.push(2),
        Wire::Proposal { changes, result } => {
            bytes.push(3);
            append(&mut bytes, changes, MAX_CHANGES)?;
            append(&mut bytes, result, MAX_RESULT)?;
        }
        Wire::Accept => bytes.push(4),
        Wire::AcceptedHeld => bytes.push(5),
        Wire::Proceed => bytes.push(6),
        Wire::Ack(result) => {
            bytes.push(7);
            append(&mut bytes, result, MAX_RESULT)?;
        }
    }
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Wire> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let count = u32::from_le_bytes(header) as usize;
    if count == 0 || count > MAX_FRAME {
        return Err(invalid());
    }
    let mut bytes = vec![0; count];
    reader.read_exact(&mut bytes)?;
    let mut rest = &bytes[1..];
    let message = match bytes[0] {
        1 => Wire::Lookup,
        2 => Wire::NotFound,
        3 => Wire::Proposal {
            changes: take(&mut rest, MAX_CHANGES)?,
            result: take(&mut rest, MAX_RESULT)?,
        },
        4 => Wire::Accept,
        5 => Wire::AcceptedHeld,
        6 => Wire::Proceed,
        7 => Wire::Ack(take(&mut rest, MAX_RESULT)?),
        _ => return Err(invalid()),
    };
    if !rest.is_empty() {
        return Err(invalid());
    }
    Ok(message)
}
