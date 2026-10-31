//! Test-only SQLite writer. The parent owns every path and authorizes publication
//! only after observing the real replicated cell's decision. No public service.
#[path = "../../wal-gate/src/probe.rs"]
mod probe;
mod protocol;

use libsql_sys::{ffi, wal};
use protocol::{
    read_frame, write_frame, Wire, INIT_SCHEMA, MAX_PAGES, MAX_RESULT, PAGE_SIZE, SQL, TIMEOUT,
};
use std::io;
use std::sync::{mpsc, Arc, Mutex};

fn physical(batch: &probe::CommitBatch) -> wal::Result<Vec<u8>> {
    if batch.pages.len() > MAX_PAGES || batch.size_after as usize > MAX_PAGES {
        return Err(wal::Error::new(ffi::SQLITE_TOOBIG));
    }
    let mut bytes = b"SCAPPG01".to_vec();
    bytes.extend_from_slice(&batch.size_after.to_le_bytes());
    bytes.extend_from_slice(&(batch.pages.len() as u32).to_le_bytes());
    for page in &batch.pages {
        bytes.extend_from_slice(&page.number.to_le_bytes());
        bytes.extend_from_slice(&page.bytes);
    }
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let initialize = args.len() == 3 && args[1] == "--initialize";
    if (args.len() != 2 && !initialize) || !std::fs::metadata(args.last().unwrap())?.is_file() {
        return Err("expected one existing, parent-owned SQLite fixture path".into());
    }
    assert_eq!(PAGE_SIZE, probe::PAGE_SIZE);
    let (input_tx, input_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        loop {
            let result = read_frame(&mut input).map_err(|error| error.to_string());
            let done = result.is_err();
            if input_tx.send(result).is_err() || done {
                break;
            }
        }
    });
    let input = Arc::new(Mutex::new(input_rx));
    let saved_result = Arc::new(Mutex::new(Vec::<u8>::new()));
    let gate_input = input.clone();
    let gate_result = saved_result.clone();
    let gate = probe::GateWal::new(move |batch| {
        let result = gate_result.lock().unwrap().clone();
        if (!initialize && result.len() != 32) || result.len() > MAX_RESULT {
            return Err(wal::Error::new(ffi::SQLITE_ABORT));
        }
        write_frame(
            &mut io::stdout().lock(),
            &Wire::Gate {
                changes: physical(batch)?,
                result,
            },
        )
        .map_err(|_| wal::Error::new(ffi::SQLITE_IOERR))?;
        match gate_input.lock().unwrap().recv_timeout(TIMEOUT) {
            Ok(Ok(Wire::Publish)) => Ok(()),
            _ => Err(wal::Error::new(ffi::SQLITE_ABORT)),
        }
    });
    let connection = probe::open(std::path::Path::new(args.last().unwrap()), gate)?;
    write_frame(&mut io::stdout().lock(), &Wire::Ready)?;
    let base = match input.lock().unwrap().recv_timeout(TIMEOUT)? {
        Ok(Wire::Start(revision)) if revision < i64::MAX as u64 => revision,
        _ => return Err("expected bounded start command".into()),
    };
    if initialize {
        connection.execute_batch(INIT_SCHEMA)?;
        connection.execute("INSERT INTO cache_meta VALUES(?1)", [(base + 1) as i64])?;
        connection.execute("INSERT INTO items VALUES(0, X'62617365')", [])?;
        connection.execute_batch("COMMIT")?;
        write_frame(&mut io::stdout().lock(), &Wire::Ack(Vec::new()))?;
        return Ok(());
    }
    let observed: u64 =
        connection.query_row("SELECT revision FROM cache_meta", [], |row| row.get(0))?;
    if observed != base {
        return Err("fixture SQLite head differs from admitted predecessor".into());
    }
    let mut statement = connection.prepare(SQL)?;
    let mut rows = statement.query([])?;
    // SQLite supplies this row before its final commit callback. It stays in a
    // private bounded buffer; it is neither an ACK nor an external result stream.
    let result: Vec<u8> = rows.next()?.ok_or("missing RETURNING row")?.get(0)?;
    if result.len() != 32 || result.len() > MAX_RESULT {
        return Err("unexpected bounded provisional result".into());
    }
    *saved_result.lock().unwrap() = result.clone();
    let completion = rows.next();
    let message = match completion {
        Ok(None) => Wire::Ack(result),
        Ok(Some(_)) => return Err("unexpected extra RETURNING row".into()),
        Err(error) => Wire::Rejected(
            error
                .sqlite_error()
                .ok_or("non-SQLite error")?
                .extended_code,
        ),
    };
    drop(rows);
    drop(statement);
    if !connection.is_autocommit() {
        connection.execute_batch("ROLLBACK")?;
    }
    // Ack is emitted only after native xFrames and the final sqlite3_step
    // returned successfully. A failed publish never takes this branch.
    write_frame(&mut io::stdout().lock(), &message)?;
    Ok(())
}
