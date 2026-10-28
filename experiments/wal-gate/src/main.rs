//! Subprocess used only by the process-exit probes. There is no service here.
mod probe;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use libsql_sys::ffi;
use libsql_sys::wal;
use probe::{CommitBatch, GateWal, PAGE_SIZE};

const EXIT_BEFORE_PUBLISH: i32 = 81;
const EXIT_AFTER_PUBLISH: i32 = 82;

fn persist_fixture(path: &Path, batch: &CommitBatch) -> std::io::Result<()> {
    // A bounded test fixture, not SCAP's production log format. It has no
    // quorum, identities, deduplication, cryptographic integrity, or manifest.
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(b"SCAPG0P1")?;
    file.write_all(&(PAGE_SIZE as u32).to_le_bytes())?;
    file.write_all(&batch.size_after.to_le_bytes())?;
    file.write_all(&(batch.pages.len() as u32).to_le_bytes())?;
    for page in &batch.pages {
        file.write_all(&page.number.to_le_bytes())?;
        file.write_all(&page.bytes)?;
    }
    file.sync_all()?;
    File::open(path.parent().expect("fixture has a parent"))?.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("usage: wal-gate-child <before-publish|after-publish> <db> <fixture>".into());
    }
    let before = args[1] == "before-publish";
    if !before && args[1] != "after-publish" {
        return Err("unknown probe mode".into());
    }
    let fixture = std::path::PathBuf::from(&args[3]);
    let gate = GateWal::new(move |batch| {
        if before {
            persist_fixture(&fixture, batch)
                .map_err(|_| wal::Error::new(ffi::SQLITE_IOERR_FSYNC))?;
            // Intentionally no Rust destructors / sqlite close / checkpoint.
            // Native xFrames has NOT yet been called for this commit.
            std::process::exit(EXIT_BEFORE_PUBLISH);
        }
        Ok(())
    });
    let conn = probe::open(Path::new(&args[2]), gate)?;
    conn.execute_batch("INSERT INTO items(id, payload) VALUES(42, randomblob(32));")?;
    // Native xFrames returned successfully; FULL synchronization was enabled.
    // This is process-crash recovery, not a power-loss or AZ failure test.
    std::process::exit(EXIT_AFTER_PUBLISH);
}
