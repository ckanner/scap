use super::*;
use crate::tests::{until, Memory};
use scap_object_store::Stored;
use std::sync::{Arc, Barrier};
use std::time::Duration;

#[test]
fn explicit_identity_is_created_once_verified_and_never_reusable() {
    let memory = Memory::default();
    for worker in [1, u64::MAX] {
        claim(&memory, worker, until()).unwrap();
        let key = format!("{PREFIX}{worker}");
        let stored = memory.values.lock().unwrap().get(&key).cloned().unwrap();
        assert_eq!(&stored.bytes[..MAGIC.len()], MAGIC);
        assert_eq!(&stored.bytes[MAGIC.len()..], &worker.to_be_bytes());
        memory.calls.lock().unwrap().clear();
        assert_eq!(
            claim(&memory, worker, until()).unwrap_err().code,
            "INSTANCE_REUSED"
        );
        assert_eq!(*memory.calls.lock().unwrap(), [format!("PUT {key}")]);
        assert_eq!(memory.values.lock().unwrap().get(&key).unwrap(), &stored);
    }
    assert_eq!(memory.values.lock().unwrap().len(), 2);
    assert!(memory
        .values
        .lock()
        .unwrap()
        .keys()
        .all(|key| !key.starts_with("scap-object/")));
}

#[test]
fn zero_and_expired_startup_perform_no_object_io() {
    let memory = Memory::default();
    assert_eq!(claim(&memory, 0, until()).unwrap_err().code, "CONFIG");
    assert_eq!(
        claim(&memory, 1, Instant::now()).unwrap_err().code,
        "INSTANCE_UNKNOWN"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
}

#[test]
fn all_create_and_read_failures_close_startup_without_retry_or_adoption() {
    let errors = [
        StoreError::Missing,
        StoreError::Conflict,
        StoreError::Unknown,
        StoreError::Invalid,
        StoreError::Budget,
        StoreError::Limit,
        StoreError::Corrupt,
    ];
    for error in errors {
        let memory = Memory::default();
        *memory.fail_put.lock().unwrap() = Some(error.clone());
        let expected = if error == StoreError::Conflict {
            "INSTANCE_REUSED"
        } else {
            "INSTANCE_UNKNOWN"
        };
        assert_eq!(claim(&memory, 7, until()).unwrap_err().code, expected);
        assert_eq!(memory.calls.lock().unwrap().len(), 1);

        let memory = Memory::default();
        *memory.fail_get.lock().unwrap() = Some(error.clone());
        let expected = match error {
            StoreError::Missing | StoreError::Limit | StoreError::Corrupt => "INSTANCE_CORRUPT",
            _ => "INSTANCE_UNKNOWN",
        };
        assert_eq!(claim(&memory, 7, until()).unwrap_err().code, expected);
        assert_eq!(
            *memory.calls.lock().unwrap(),
            [format!("PUT {PREFIX}7"), format!("GET {PREFIX}7")]
        );
        assert_eq!(
            claim(&memory, 7, until()).unwrap_err().code,
            "INSTANCE_REUSED"
        );
    }
}

#[derive(Clone, Copy)]
enum Fault {
    LostCreate,
    EmptyEtag,
    ChangedBytes,
    ChangedEtag,
    LateCreate,
    LateRead,
}

struct FaultStore {
    memory: Memory,
    fault: Fault,
    deadline: Instant,
}

impl Objects for FaultStore {
    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        assert_eq!(deadline, self.deadline);
        assert_eq!(condition, Condition::Absent);
        let result = self.memory.put(key, bytes, condition, deadline)?;
        match self.fault {
            Fault::LostCreate => Err(StoreError::Unknown),
            Fault::EmptyEtag => Ok(String::new()),
            Fault::LateCreate => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                Ok(result)
            }
            _ => Ok(result),
        }
    }

    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        assert_eq!(deadline, self.deadline);
        assert_eq!(maximum, MAGIC.len() + 8);
        let mut stored = self.memory.get(key, maximum, deadline)?;
        match self.fault {
            Fault::ChangedBytes => stored.bytes[0] ^= 1,
            Fault::ChangedEtag => stored.etag = "\"different\"".into(),
            Fault::LateRead => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()))
            }
            _ => (),
        }
        Ok(stored)
    }
}

#[test]
fn lost_ack_corrupt_readback_and_elapsed_budget_never_allow_service_start() {
    for (fault, code, calls) in [
        (Fault::LostCreate, "INSTANCE_UNKNOWN", 1),
        (Fault::EmptyEtag, "INSTANCE_UNKNOWN", 1),
        (Fault::ChangedBytes, "INSTANCE_CORRUPT", 2),
        (Fault::ChangedEtag, "INSTANCE_CORRUPT", 2),
        (Fault::LateCreate, "INSTANCE_UNKNOWN", 1),
        (Fault::LateRead, "INSTANCE_UNKNOWN", 2),
    ] {
        let deadline = Instant::now() + Duration::from_millis(100);
        let store = FaultStore {
            memory: Memory::default(),
            fault,
            deadline,
        };
        assert_eq!(claim(&store, 7, deadline).unwrap_err().code, code);
        assert_eq!(store.memory.calls.lock().unwrap().len(), calls);
        // The marker remains consumed even though no service was started.
        assert_eq!(
            claim(&store.memory, 7, until()).unwrap_err().code,
            "INSTANCE_REUSED"
        );
        claim(&store.memory, 8, until()).unwrap();
    }
}

#[test]
fn two_startups_competing_for_one_identity_have_exactly_one_winner() {
    let memory = Arc::new(Memory::default());
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = vec![];
    for _ in 0..2 {
        let memory = memory.clone();
        let barrier = barrier.clone();
        tasks.push(std::thread::spawn(move || {
            barrier.wait();
            claim(memory.as_ref(), 91, until()).map_err(|error| error.code)
        }));
    }
    let results: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err("INSTANCE_REUSED"))
            .count(),
        1
    );
    assert_eq!(memory.values.lock().unwrap().len(), 1);
    assert_eq!(memory.calls.lock().unwrap().len(), 3);
}
