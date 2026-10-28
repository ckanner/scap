//! Real libSQL engine probes, kept outside the product unit-coverage tier.
#[path = "../src/probe.rs"]
mod probe;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libsql_sys::ffi;
use libsql_sys::rusqlite;
use libsql_sys::wal;
use probe::{GateWal, MAX_PAGES, PAGE_SIZE};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "scap-wal-probe-{}-{stamp}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn initialize(path: &Path) {
    let conn = probe::open(path, GateWal::new(|_| Ok(()))).unwrap();
    conn.execute_batch(
        "CREATE TABLE items(id INTEGER PRIMARY KEY, payload BLOB NOT NULL); \
         INSERT INTO items VALUES(0, X'62617365'); PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .unwrap();
}

fn read_ids(conn: &rusqlite::Connection) -> Vec<i64> {
    conn.prepare("SELECT id FROM items ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn accepted_commit_is_visible_to_another_connection_and_after_reopen() {
    let dir = TestDirectory::new();
    let path = dir.path("db.sqlite");
    initialize(&path);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let writer = probe::open(
        &path,
        GateWal::new(move |batch| {
            assert!(!batch.pages.is_empty());
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    )
    .unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    writer
        .execute_batch("INSERT INTO items VALUES(1, X'61');")
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(read_ids(&reader), [0, 1]);
    drop(reader);
    drop(writer);
    assert_eq!(
        read_ids(&rusqlite::Connection::open(&path).unwrap()),
        [0, 1]
    );
}

#[test]
fn rejected_commit_never_becomes_visible_and_connection_can_rollback() {
    let dir = TestDirectory::new();
    let path = dir.path("db.sqlite");
    initialize(&path);
    let reject = Arc::new(AtomicBool::new(true));
    let reject_for_gate = reject.clone();
    let writer = probe::open(
        &path,
        GateWal::new(move |_| {
            if reject_for_gate.load(Ordering::SeqCst) {
                Err(wal::Error::new(ffi::SQLITE_ABORT))
            } else {
                Ok(())
            }
        }),
    )
    .unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    let error = writer
        .execute_batch("INSERT INTO items VALUES(1, X'61');")
        .unwrap_err();
    assert_eq!(
        error.sqlite_error().unwrap().extended_code,
        ffi::SQLITE_ABORT
    );
    assert_eq!(read_ids(&reader), [0]);
    if !writer.is_autocommit() {
        writer.execute_batch("ROLLBACK").unwrap();
    }
    assert_eq!(read_ids(&writer), [0]);
    reject.store(false, Ordering::SeqCst);
    writer
        .execute_batch("INSERT INTO items VALUES(2, X'62');")
        .unwrap();
    assert_eq!(read_ids(&reader), [0, 2]);
    drop(writer);
    drop(reader);
    assert_eq!(
        read_ids(&rusqlite::Connection::open(&path).unwrap()),
        [0, 2]
    );
}

#[test]
fn blocked_precommit_gate_keeps_external_reader_on_previous_state() {
    for accept in [false, true] {
        let dir = TestDirectory::new();
        let path = dir.path("db.sqlite");
        initialize(&path);
        let reader = rusqlite::Connection::open(&path).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (decision_tx, decision_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let decision_rx = Mutex::new(decision_rx);
        let worker = std::thread::spawn(move || {
            let gate = GateWal::new(move |_| {
                entered_tx
                    .send(())
                    .map_err(|_| wal::Error::new(ffi::SQLITE_ABORT))?;
                let decision = decision_rx
                    .lock()
                    .map_err(|_| wal::Error::new(ffi::SQLITE_ABORT))?
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|_| wal::Error::new(ffi::SQLITE_ABORT))?;
                if decision {
                    Ok(())
                } else {
                    Err(wal::Error::new(ffi::SQLITE_ABORT))
                }
            });
            let writer = probe::open(&path, gate).unwrap();
            let result = writer.execute_batch("INSERT INTO items VALUES(1, X'61');");
            done_tx.send(result.is_ok()).unwrap();
            result
        });
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(read_ids(&reader), [0]);
        assert_eq!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
        decision_tx.send(accept).unwrap();
        let result = worker.join().unwrap();
        assert_eq!(result.is_ok(), accept);
        assert_eq!(done_rx.recv().unwrap(), accept);
        assert_eq!(read_ids(&reader), if accept { vec![0, 1] } else { vec![0] });
    }
}

#[test]
fn rollback_and_savepoint_remove_discarded_changes_before_commit_capture() {
    let dir = TestDirectory::new();
    let path = dir.path("db.sqlite");
    initialize(&path);
    let count = Arc::new(AtomicUsize::new(0));
    let gate_count = count.clone();
    let writer = probe::open(
        &path,
        GateWal::new(move |_| {
            gate_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    )
    .unwrap();
    writer
        .execute_batch(
            "BEGIN IMMEDIATE; INSERT INTO items VALUES(1, X'61'); \
         SAVEPOINT s; INSERT INTO items VALUES(2, X'62'); ROLLBACK TO s; \
         RELEASE s; COMMIT;",
        )
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        read_ids(&rusqlite::Connection::open(&path).unwrap()),
        [0, 1]
    );
    writer
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO items VALUES(3, X'63'); ROLLBACK;")
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(read_ids(&writer), [0, 1]);
}

#[test]
fn raw_returning_rows_are_provisional_and_must_be_buffered_by_the_service() {
    let dir = TestDirectory::new();
    let path = dir.path("db.sqlite");
    initialize(&path);
    let count = Arc::new(AtomicUsize::new(0));
    let gate_count = count.clone();
    let writer = probe::open(
        &path,
        GateWal::new(move |_| {
            gate_count.fetch_add(1, Ordering::SeqCst);
            Err(wal::Error::new(ffi::SQLITE_ABORT))
        }),
    )
    .unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    let mut statement = writer
        .prepare("INSERT INTO items VALUES(1, X'61') RETURNING id")
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    let provisional: i64 = rows.next().unwrap().unwrap().get(0).unwrap();
    assert_eq!(provisional, 1);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(read_ids(&reader), [0]);
    let error = rows.next().unwrap_err();
    assert_eq!(
        error.sqlite_error().unwrap().extended_code,
        ffi::SQLITE_ABORT
    );
    drop(rows);
    drop(statement);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(read_ids(&reader), [0]);
}

#[test]
fn a_forced_spill_is_rejected_in_the_real_engine_without_partial_visibility() {
    let dir = TestDirectory::new();
    let path = dir.path("db.sqlite");
    initialize(&path);
    let count = Arc::new(AtomicUsize::new(0));
    let gate_count = count.clone();
    let writer = probe::open(
        &path,
        GateWal::new(move |_| {
            gate_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    )
    .unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    // Deliberately violate the probe's normal no-spill configuration to check
    // its fail-closed boundary through native SQLite, not only a helper test.
    let error = writer
        .execute_batch(
            "PRAGMA cache_size=5; PRAGMA cache_spill=ON; BEGIN IMMEDIATE; \
         WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100) \
         INSERT INTO items SELECT x, zeroblob(4096) FROM n; COMMIT;",
        )
        .unwrap_err();
    assert_eq!(
        error.sqlite_error().unwrap().extended_code,
        ffi::SQLITE_TOOBIG
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(read_ids(&reader), [0]);
    if !writer.is_autocommit() {
        writer.execute_batch("ROLLBACK").unwrap();
    }
    assert_eq!(read_ids(&writer), [0]);
}

#[test]
fn process_exit_after_native_commit_recovers_from_the_native_wal() {
    let dir = TestDirectory::new();
    let path = dir.path("db.sqlite");
    initialize(&path);
    let status = Command::new(env!("CARGO_BIN_EXE_wal-gate-child"))
        .arg("after-publish")
        .arg(&path)
        .arg(dir.path("unused.fixture"))
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(82));
    assert!(dir.path("db.sqlite-wal").exists());
    let recovered = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(read_ids(&recovered), [0, 42]);
    let size: i64 = recovered
        .query_row("SELECT length(payload) FROM items WHERE id=42", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(size, 32);
}

fn read_u32(file: &mut File) -> u32 {
    let mut bytes = [0_u8; 4];
    file.read_exact(&mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn process_exit_after_fixture_acceptance_before_publish_can_rebuild_from_pages() {
    let dir = TestDirectory::new();
    let working = dir.path("working.sqlite");
    let baseline = dir.path("baseline.sqlite");
    let fixture = dir.path("accepted.fixture");
    let recovered = dir.path("recovered.sqlite");
    initialize(&working);
    fs::copy(&working, &baseline).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wal-gate-child"))
        .arg("before-publish")
        .arg(&working)
        .arg(&fixture)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(81));
    // The original worker did not publish the INSERT into its local WAL.
    assert_eq!(
        read_ids(&rusqlite::Connection::open(&working).unwrap()),
        [0]
    );
    fs::copy(&baseline, &recovered).unwrap();
    let mut input = File::open(&fixture).unwrap();
    let mut magic = [0_u8; 8];
    input.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"SCAPG0P1");
    assert_eq!(read_u32(&mut input), PAGE_SIZE as u32);
    let size_after = read_u32(&mut input);
    let pages = read_u32(&mut input);
    assert!(size_after > 0 && pages > 0 && pages as usize <= MAX_PAGES);
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&recovered)
        .unwrap();
    for _ in 0..pages {
        let number = read_u32(&mut input);
        assert!(number > 0 && number <= size_after);
        let mut bytes = [0_u8; PAGE_SIZE];
        input.read_exact(&mut bytes).unwrap();
        output
            .seek(SeekFrom::Start(u64::from(number - 1) * PAGE_SIZE as u64))
            .unwrap();
        output.write_all(&bytes).unwrap();
    }
    assert_eq!(input.read(&mut [0_u8; 1]).unwrap(), 0);
    output
        .set_len(u64::from(size_after) * PAGE_SIZE as u64)
        .unwrap();
    output.sync_all().unwrap();
    drop(output);
    // No SQL is replayed. randomblob() output comes from captured engine pages.
    let restored = rusqlite::Connection::open(&recovered).unwrap();
    assert_eq!(read_ids(&restored), [0, 42]);
    let payload: Vec<u8> = restored
        .query_row("SELECT payload FROM items WHERE id=42", [], |r| r.get(0))
        .unwrap();
    assert_eq!(payload.len(), 32);
    assert!(fs::read(&fixture)
        .unwrap()
        .windows(payload.len())
        .any(|w| w == payload));
    let check: String = restored
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(check, "ok");
}
