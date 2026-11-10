use super::*;

#[test]
fn failure_codes_preserve_authority_semantics() {
    use scap_object::format::{FormatError, Request, Scope, Transition};
    use scap_object_sqlite::Error as Native;
    let receipt = Receipt {
        scope: Scope {
            deployment: 1,
            tenant: 1,
            database: 1,
            incarnation: 1,
            generation: 1,
        },
        request: Request {
            epoch: 1,
            id: 1,
            principal: 1,
            fingerprint: "a".repeat(64),
        },
        sequence: 1,
        transition: Transition {
            revision: 2,
            nonce: 3,
        },
        data_root: "b".repeat(64),
        result_hash: "c".repeat(64),
    };
    let cases = [
        (Error::Denied, "DENIED"),
        (Error::Lifecycle, "LIFECYCLE"),
        (Error::Fenced, "FENCED"),
        (Error::Conflict, "CONFLICT"),
        (Error::Store(StoreError::Conflict), "CONFLICT"),
        (Error::RequestConflict, "REQUEST_CONFLICT"),
        (Error::WindowFull, "WINDOW_FULL"),
        (Error::Closed, "CLOSED"),
        (Error::Retired, "RETIRED"),
        (Error::Unknown, "UNKNOWN"),
        (Error::Store(StoreError::Unknown), "UNKNOWN"),
        (Error::Store(StoreError::Missing), "MISSING"),
        (Error::Limit, "LIMIT"),
        (Error::Store(StoreError::Limit), "LIMIT"),
        (Error::Store(StoreError::Budget), "LIMIT"),
        (Error::Corrupt, "CORRUPT"),
        (Error::Format(FormatError::Invalid), "CORRUPT"),
        (Error::Store(StoreError::Corrupt), "CORRUPT"),
        (Error::StaleSnapshot, "STALE_SNAPSHOT"),
        (Error::SnapshotExpired, "SNAPSHOT_EXPIRED"),
        (Error::Gc(scap_object_store::GcError::Invalid), "INVALID"),
        (Error::Gc(scap_object_store::GcError::Limit), "LIMIT"),
        (Error::Gc(scap_object_store::GcError::Denied), "DENIED"),
        (
            Error::Gc(scap_object_store::GcError::Unsupported),
            "GC_UNSUPPORTED",
        ),
        (Error::Gc(scap_object_store::GcError::Corrupt), "CORRUPT"),
        (Error::Gc(scap_object_store::GcError::Unknown), "UNKNOWN"),
        (Error::Sql(scap_sql::SqlError::Invalid), "INVALID"),
        (Error::Store(StoreError::Invalid), "INVALID"),
        (Error::Engine(Native::ResultLimit), "LIMIT"),
        (Error::Engine(Native::ResourceExhausted), "LIMIT"),
        (Error::Sql(scap_sql::SqlError::ResourceExhausted), "LIMIT"),
        (Error::Engine(Native::Interrupted), "DEADLINE"),
        (Error::Engine(Native::OutcomeUnknown), "UNKNOWN"),
        (
            Error::Engine(Native::CommittedButUnavailable),
            "COMMITTED_BUT_UNAVAILABLE",
        ),
        (Error::Engine(Native::InvalidImage), "CORRUPT"),
        (Error::Engine(Native::InvalidSql), "ENGINE"),
    ];
    for (error, code) in cases {
        assert_eq!(Failure::from(error).code, code);
    }
    let committed = Failure::from(Error::CommittedButUnavailable(Box::new(receipt.clone())));
    assert_eq!(committed.code, "COMMITTED_BUT_UNAVAILABLE");
    assert_eq!(*committed.receipt.unwrap(), receipt);
}

use scap_object_store::{Condition, Objects, Stored};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const CREDENTIAL_NAMES: [&str; 2] = ["SCAP_TEST_ACCESS", "SCAP_TEST_SECRET"];
static CREDENTIAL_ENVIRONMENT: Mutex<()> = Mutex::new(());

struct RestoreCredentials([Option<OsString>; 2]);

impl RestoreCredentials {
    /// Every caller holds CREDENTIAL_ENVIRONMENT for this entire lifetime.
    fn capture() -> Self {
        Self(CREDENTIAL_NAMES.map(std::env::var_os))
    }
}

impl Drop for RestoreCredentials {
    fn drop(&mut self) {
        for (name, original) in CREDENTIAL_NAMES.into_iter().zip(&mut self.0) {
            match original.take() {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

pub(crate) struct TestCredentials {
    // Fields drop in declaration order, including during unwinding: restore
    // original values before releasing the process-wide environment lease.
    restore: RestoreCredentials,
    _lease: MutexGuard<'static, ()>,
}

pub(crate) fn test_credentials() -> TestCredentials {
    // A caught test panic poisons the mutex only after RestoreCredentials has
    // restored the environment. It is safe for the next fixture to acquire it.
    let lease = CREDENTIAL_ENVIRONMENT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let credentials = TestCredentials {
        restore: RestoreCredentials::capture(),
        _lease: lease,
    };
    std::env::set_var(CREDENTIAL_NAMES[0], "access");
    std::env::set_var(CREDENTIAL_NAMES[1], "secret");
    credentials
}

#[test]
fn shared_test_credentials_restore_original_values_after_unwinding() {
    let credentials = test_credentials();
    let original = credentials.restore.0.clone();
    let stopped = std::panic::catch_unwind(move || {
        let _credentials = credentials;
        panic!("intentional fixture unwind");
    });
    assert!(stopped.is_err());
    let credentials = test_credentials();
    assert!(credentials.restore.0 == original);
    assert_eq!(std::env::var_os(CREDENTIAL_NAMES[0]), Some("access".into()));
    assert_eq!(std::env::var_os(CREDENTIAL_NAMES[1]), Some("secret".into()));
}

#[test]
fn shared_test_credentials_preserve_preexisting_and_absent_keys_on_panic() {
    let _credentials = test_credentials();
    std::env::set_var(CREDENTIAL_NAMES[0], "prior fixture value");
    std::env::remove_var(CREDENTIAL_NAMES[1]);
    let restore = RestoreCredentials::capture();
    let stopped = std::panic::catch_unwind(move || {
        let _restore = restore;
        std::env::remove_var(CREDENTIAL_NAMES[0]);
        std::env::set_var(CREDENTIAL_NAMES[1], "temporary fixture value");
        panic!("intentional nested fixture unwind");
    });
    assert!(stopped.is_err());
    assert_eq!(
        std::env::var_os(CREDENTIAL_NAMES[0]),
        Some("prior fixture value".into())
    );
    assert!(std::env::var_os(CREDENTIAL_NAMES[1]).is_none());
}

#[derive(Default)]
pub(crate) struct Memory {
    pub(crate) values: Mutex<BTreeMap<String, Stored>>,
    pub(crate) calls: Mutex<Vec<String>>,
    pub(crate) fail_get: Mutex<Option<StoreError>>,
    pub(crate) fail_list: Mutex<Option<scap_object_store::ListError>>,
    pub(crate) fail_put: Mutex<Option<StoreError>>,
    pub(crate) lose_head: Mutex<bool>,
    pub(crate) fail_head_after: Mutex<Option<usize>>,
    serial: Mutex<u64>,
}

impl scap_object_store::Listings for Memory {
    fn list_page(
        &self,
        request: &scap_object_store::ListRequest<'_>,
        deadline: Instant,
    ) -> Result<scap_object_store::ListPage, scap_object_store::ListError> {
        use scap_object_store::{ListEnd, ListEntry, ListError, ListKind, ListMode, ListPage};
        self.calls
            .lock()
            .unwrap()
            .push(format!("LIST {}", request.prefix));
        if Instant::now() >= deadline {
            return Err(ListError::Unknown);
        }
        if let Some(error) = self.fail_list.lock().unwrap().take() {
            return Err(error);
        }
        let mut entries = BTreeMap::new();
        for key in self.values.lock().unwrap().keys() {
            let Some(rest) = key.strip_prefix(request.prefix) else {
                continue;
            };
            let (key, kind) = match (request.mode, rest.find('/')) {
                (ListMode::Children, Some(index)) => (
                    format!("{}{}", request.prefix, &rest[..=index]),
                    ListKind::Prefix,
                ),
                _ => (key.clone(), ListKind::Object),
            };
            if request.after.is_none_or(|after| key.as_str() > after) {
                entries.insert(key, kind);
            }
        }
        let more = entries.len() > 32;
        let entries: Vec<_> = entries
            .into_iter()
            .take(32)
            .map(|(key, kind)| ListEntry { key, kind })
            .collect();
        let end = if more {
            ListEnd::More {
                after: entries.last().unwrap().key.clone(),
            }
        } else {
            ListEnd::Exhausted
        };
        Ok(ListPage {
            entries,
            end,
            response_bytes: 128,
        })
    }
}

impl Objects for Memory {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        self.calls.lock().unwrap().push(format!("GET {key}"));
        if Instant::now() >= deadline {
            return Err(StoreError::Unknown);
        }
        if let Some(error) = self.fail_get.lock().unwrap().take() {
            return Err(error);
        }
        if key.ends_with("/head") {
            let mut count = self.fail_head_after.lock().unwrap();
            if let Some(remaining) = count.as_mut() {
                if *remaining == 0 {
                    *count = None;
                    return Err(StoreError::Unknown);
                }
                *remaining -= 1;
            }
        }
        let value = self
            .values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or(StoreError::Missing)?;
        if value.bytes.len() > maximum {
            return Err(StoreError::Limit);
        }
        Ok(value)
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        self.calls.lock().unwrap().push(format!("PUT {key}"));
        if Instant::now() >= deadline {
            return Err(StoreError::Unknown);
        }
        if let Some(error) = self.fail_put.lock().unwrap().take() {
            return Err(error);
        }
        let mut values = self.values.lock().unwrap();
        let matches = match condition {
            Condition::Absent => !values.contains_key(key),
            Condition::Match(etag) => values.get(key).is_some_and(|value| value.etag == etag),
        };
        if !matches {
            return Err(StoreError::Conflict);
        }
        let mut serial = self.serial.lock().unwrap();
        *serial += 1;
        let etag = format!("\"{}\"", *serial);
        values.insert(
            key.to_owned(),
            Stored {
                bytes: bytes.to_vec(),
                etag: etag.clone(),
            },
        );
        if key.ends_with("/head") && std::mem::take(&mut *self.lose_head.lock().unwrap()) {
            return Err(StoreError::Unknown);
        }
        Ok(etag)
    }
}

impl scap_object_store::Garbage for Memory {
    fn inspect(
        &self,
        prefix: &str,
        hash: &str,
        deadline: Instant,
    ) -> Result<scap_object_store::GcCandidate, scap_object_store::GcError> {
        use scap_object_store::{GcCandidate, GcError};
        self.calls
            .lock()
            .unwrap()
            .push(format!("INSPECT {prefix}{hash}"));
        if Instant::now() >= deadline {
            return Err(GcError::Unknown);
        }
        Ok(
            match self.values.lock().unwrap().get(&format!("{prefix}{hash}")) {
                Some(value) => GcCandidate::Present {
                    etag: value.etag.clone(),
                },
                None => GcCandidate::Missing,
            },
        )
    }

    fn delete(
        &self,
        prefix: &str,
        hash: &str,
        etag: &str,
        deadline: Instant,
    ) -> Result<scap_object_store::DeleteOutcome, scap_object_store::GcError> {
        use scap_object_store::{DeleteOutcome, GcError};
        let key = format!("{prefix}{hash}");
        self.calls.lock().unwrap().push(format!("DELETE {key}"));
        if Instant::now() >= deadline {
            return Err(GcError::Unknown);
        }
        let mut values = self.values.lock().unwrap();
        let outcome = match values.get(&key) {
            Some(value) if value.etag == etag => {
                values.remove(&key);
                DeleteOutcome::Applied
            }
            Some(_) => DeleteOutcome::Conflict,
            None => DeleteOutcome::Missing,
        };
        Ok(outcome)
    }
}

pub(crate) fn principal() -> auth::Principal {
    auth::Principal {
        deployment: 1,
        tenant: 2,
        principal: 3,
        provision: true,
        deployment_inventory: false,
    }
}

pub(crate) fn scope() -> wire::WireScope {
    wire::WireScope {
        deployment: wire::Decimal(1),
        tenant: wire::Decimal(2),
        database: wire::Decimal(3),
        incarnation: wire::Decimal(4),
        generation: wire::Decimal(5),
    }
}

pub(crate) fn call(action: wire::Action) -> wire::Call {
    wire::Call {
        version: 1,
        scope: scope(),
        action,
    }
}

pub(crate) fn until() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

pub(crate) fn sample_config(parent: &std::path::Path) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    serde_json::json!({
        "version":1, "listen":"127.0.0.1:0", "worker_instance":"100", "cache_directory":parent,
        "s3": {"endpoint":"http://127.0.0.1:1", "region":"test", "bucket":"scap-test",
            "access_key_env":"SCAP_TEST_ACCESS", "secret_key_env":"SCAP_TEST_SECRET",
            "session_token_env":null, "allow_http":true, "timeout_ms":1000},
        "admission": {"active_database_actors":2, "active_database_actors_per_tenant":2,
            "actor_idle_timeout_ms":60000, "control_workers":1, "queued_total":8, "queued_per_tenant":6,
            "queued_per_database":4, "reserved_controls":1, "data_intake":4, "control_intake":2,
            "recovery_intake":1, "max_body_bytes":1048576, "timeout_ms":1000, "recovery_timeout_ms":2000},
        "cache":{"pages_per_actor":2621440, "parallel_recoveries":1},
        "credentials":[{"sha256":format!("{:x}", Sha256::digest("a".repeat(32))), "deployment":"1", "tenant":"2",
            "principal":"3", "provision":true}]
    })
}

#[test]
fn actual_binary_wrapper_reports_invalid_cli_without_exiting_the_test_process() {
    assert_eq!(crate::entrypoint::main(), std::process::ExitCode::FAILURE);
}
