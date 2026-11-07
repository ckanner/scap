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
        (Error::Corrupt, "CORRUPT"),
        (Error::Format(FormatError::Invalid), "CORRUPT"),
        (Error::Store(StoreError::Corrupt), "CORRUPT"),
        (Error::StaleSnapshot, "STALE_SNAPSHOT"),
        (Error::Sql(scap_sql::SqlError::Invalid), "INVALID"),
        (Error::Store(StoreError::Invalid), "INVALID"),
        (Error::Engine(Native::ResultLimit), "LIMIT"),
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
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct Memory {
    pub(crate) values: Mutex<BTreeMap<String, Stored>>,
    pub(crate) calls: Mutex<Vec<String>>,
    pub(crate) fail_get: Mutex<Option<StoreError>>,
    pub(crate) fail_put: Mutex<Option<StoreError>>,
    pub(crate) lose_head: Mutex<bool>,
    pub(crate) fail_head_after: Mutex<Option<usize>>,
    serial: Mutex<u64>,
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

pub(crate) fn principal() -> auth::Principal {
    auth::Principal {
        deployment: 1,
        tenant: 2,
        principal: 3,
        provision: true,
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
        "admission": {"workers":2, "control_workers":1, "queued_per_worker":8, "queued_per_tenant":6,
            "queued_per_database":4, "reserved_controls":1, "data_intake":4, "control_intake":2,
            "recovery_intake":1, "max_body_bytes":1048576, "timeout_ms":1000, "recovery_timeout_ms":2000},
        "cache":{"sessions_per_worker":2, "pages_per_worker":2621440, "parallel_recoveries":1},
        "credentials":[{"sha256":format!("{:x}", Sha256::digest("a".repeat(32))), "deployment":"1", "tenant":"2",
            "principal":"3", "provision":true}]
    })
}

#[test]
fn actual_binary_wrapper_reports_invalid_cli_without_exiting_the_test_process() {
    assert_eq!(crate::entrypoint::main(), std::process::ExitCode::FAILURE);
}
