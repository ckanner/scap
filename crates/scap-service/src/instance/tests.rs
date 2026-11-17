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

#[test]
fn allocator_requires_bootstrap_preserves_explicit_claims_and_never_wraps() {
    let memory = Memory::default();
    assert_eq!(
        allocate(&memory, until()).unwrap_err().code,
        "INSTANCE_ALLOCATOR_MISSING"
    );
    assert_eq!(*memory.calls.lock().unwrap(), [format!("GET {ALLOCATOR}")]);
    initialize(&memory, 0, until()).unwrap();
    assert_eq!(
        initialize(&memory, 900, until()).unwrap_err().code,
        "INSTANCE_ALLOCATOR_EXISTS"
    );
    assert_eq!(allocate(&memory, until()).unwrap(), 1);
    claim(&memory, 2, until()).unwrap();
    assert_eq!(allocate(&memory, until()).unwrap(), 3);
    assert_eq!(allocate(&memory, until()).unwrap(), 4);
    assert_eq!(memory.values.lock().unwrap().len(), 5);
    assert!(!memory
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call.starts_with("LIST")));

    let memory = Memory::default();
    initialize(&memory, u64::MAX - 1, until()).unwrap();
    assert_eq!(allocate(&memory, until()).unwrap(), u64::MAX);
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        allocate(&memory, until()).unwrap_err().code,
        "INSTANCE_EXHAUSTED"
    );
    assert_eq!(*memory.calls.lock().unwrap(), [format!("GET {ALLOCATOR}")]);
    assert!(!memory
        .values
        .lock()
        .unwrap()
        .contains_key(&format!("{PREFIX}0")));
}

#[test]
fn allocator_rejects_malformed_counter_and_every_uncertain_transport_error() {
    for mutation in 0..4 {
        let memory = Memory::default();
        initialize(&memory, 0, until()).unwrap();
        let mut values = memory.values.lock().unwrap();
        let stored = values.get_mut(ALLOCATOR).unwrap();
        match mutation {
            0 => stored.etag.clear(),
            1 => stored.bytes.pop().map(|_| ()).unwrap(),
            2 => stored.bytes[0] ^= 1,
            _ => stored.bytes.push(0),
        }
        drop(values);
        memory.calls.lock().unwrap().clear();
        assert_eq!(
            allocate(&memory, until()).unwrap_err().code,
            "INSTANCE_CORRUPT"
        );
        assert_eq!(memory.calls.lock().unwrap().len(), 1);
    }
    for error in [
        StoreError::Missing,
        StoreError::Conflict,
        StoreError::Unknown,
        StoreError::Invalid,
        StoreError::Budget,
        StoreError::Limit,
        StoreError::Corrupt,
    ] {
        let memory = Memory::default();
        initialize(&memory, 0, until()).unwrap();
        memory.calls.lock().unwrap().clear();
        *memory.fail_get.lock().unwrap() = Some(error.clone());
        let expected = match error {
            StoreError::Missing => "INSTANCE_ALLOCATOR_MISSING",
            StoreError::Limit | StoreError::Corrupt => "INSTANCE_CORRUPT",
            _ => "INSTANCE_UNKNOWN",
        };
        assert_eq!(allocate(&memory, until()).unwrap_err().code, expected);
        assert_eq!(memory.calls.lock().unwrap().len(), 1);

        memory.calls.lock().unwrap().clear();
        *memory.fail_put.lock().unwrap() = Some(error.clone());
        let (expected, calls) = if error == StoreError::Conflict {
            // A new read of the unchanged counter is not a new candidate.
            ("INSTANCE_ALLOCATION_BUSY", 3)
        } else {
            ("INSTANCE_UNKNOWN", 2)
        };
        assert_eq!(allocate(&memory, until()).unwrap_err().code, expected);
        assert_eq!(memory.calls.lock().unwrap().len(), calls);
        assert_eq!(memory.values.lock().unwrap().len(), 1);
    }
    let memory = Memory::default();
    assert_eq!(
        allocate(&memory, Instant::now()).unwrap_err().code,
        "INSTANCE_UNKNOWN"
    );
    assert!(memory.calls.lock().unwrap().is_empty());
}

#[derive(Clone, Copy)]
enum AllocationFault {
    LostCounterAck,
    EmptyCounterEtag,
    LateCounterRead,
    LateCounterWrite,
    LostMarkerAck,
    CorruptMarkerRead,
    AnotherReservationAfterAck,
    EveryCandidateTaken,
    CounterRollback,
}

struct AllocationStore {
    memory: Memory,
    fault: AllocationFault,
    deadline: Instant,
}

impl Objects for AllocationStore {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        assert_eq!(deadline, self.deadline);
        let mut value = self.memory.get(key, maximum, deadline)?;
        if key == ALLOCATOR && matches!(self.fault, AllocationFault::LateCounterRead) {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        }
        if key.starts_with(PREFIX) && matches!(self.fault, AllocationFault::CorruptMarkerRead) {
            value.bytes[0] ^= 1;
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
        assert_eq!(deadline, self.deadline);
        if key == ALLOCATOR {
            let observed = self.memory.values.lock().unwrap().get(key).unwrap().clone();
            assert_eq!(condition, Condition::Match(&observed.etag));
            let etag = self.memory.put(key, bytes, condition, deadline)?;
            match self.fault {
                AllocationFault::LostCounterAck => return Err(StoreError::Unknown),
                AllocationFault::EmptyCounterEtag => return Ok(String::new()),
                AllocationFault::LateCounterWrite => {
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                }
                AllocationFault::AnotherReservationAfterAck => {
                    let reserved =
                        u64::from_be_bytes(bytes[ALLOCATOR_MAGIC.len()..].try_into().unwrap());
                    self.memory.put(
                        key,
                        &counter_bytes(reserved + 1),
                        Condition::Match(&etag),
                        deadline,
                    )?;
                }
                AllocationFault::EveryCandidateTaken => return Err(StoreError::Conflict),
                AllocationFault::CounterRollback => {
                    self.memory
                        .put(key, &counter_bytes(0), Condition::Match(&etag), deadline)?;
                    return Err(StoreError::Conflict);
                }
                _ => (),
            }
            return Ok(etag);
        }
        assert_eq!(condition, Condition::Absent);
        let etag = self.memory.put(key, bytes, condition, deadline)?;
        if matches!(self.fault, AllocationFault::LostMarkerAck) {
            return Err(StoreError::Unknown);
        }
        Ok(etag)
    }
}

#[test]
fn lost_or_late_allocator_results_burn_numbers_and_never_read_to_adopt() {
    for (fault, code, calls, next) in [
        (AllocationFault::LostCounterAck, "INSTANCE_UNKNOWN", 2, 2),
        (AllocationFault::EmptyCounterEtag, "INSTANCE_UNKNOWN", 2, 2),
        (AllocationFault::LateCounterRead, "INSTANCE_UNKNOWN", 1, 1),
        (AllocationFault::LateCounterWrite, "INSTANCE_UNKNOWN", 2, 2),
        (AllocationFault::LostMarkerAck, "INSTANCE_UNKNOWN", 3, 2),
        (AllocationFault::CorruptMarkerRead, "INSTANCE_CORRUPT", 4, 2),
    ] {
        let memory = Memory::default();
        initialize(&memory, 0, until()).unwrap();
        memory.calls.lock().unwrap().clear();
        let store = AllocationStore {
            memory,
            fault,
            deadline: Instant::now() + Duration::from_millis(100),
        };
        assert_eq!(allocate(&store, store.deadline).unwrap_err().code, code);
        assert_eq!(store.memory.calls.lock().unwrap().len(), calls);
        // A separate later startup chooses from fresh authority; it does not
        // reconcile or reuse the uncertain candidate from the failed call.
        assert_eq!(allocate(&store.memory, until()).unwrap(), next);
    }
}

#[test]
fn counter_advancement_is_not_marker_readback_and_attempts_are_bounded() {
    let memory = Memory::default();
    initialize(&memory, 0, until()).unwrap();
    let store = AllocationStore {
        memory,
        fault: AllocationFault::AnotherReservationAfterAck,
        deadline: until(),
    };
    assert_eq!(allocate(&store, store.deadline).unwrap(), 1);
    assert_eq!(allocate(&store.memory, until()).unwrap(), 3);

    let memory = Memory::default();
    initialize(&memory, 0, until()).unwrap();
    memory.calls.lock().unwrap().clear();
    let store = AllocationStore {
        memory,
        fault: AllocationFault::EveryCandidateTaken,
        deadline: until(),
    };
    assert_eq!(
        allocate(&store, store.deadline).unwrap_err().code,
        "INSTANCE_ALLOCATION_BUSY"
    );
    assert_eq!(
        store.memory.calls.lock().unwrap().len(),
        MAX_ALLOCATION_ATTEMPTS * 2
    );
    assert_eq!(
        allocate(&store.memory, until()).unwrap(),
        MAX_ALLOCATION_ATTEMPTS as u64 + 1
    );

    let memory = Memory::default();
    initialize(&memory, 5, until()).unwrap();
    let store = AllocationStore {
        memory,
        fault: AllocationFault::CounterRollback,
        deadline: until(),
    };
    assert_eq!(
        allocate(&store, store.deadline).unwrap_err().code,
        "INSTANCE_CORRUPT"
    );
    assert_eq!(store.memory.values.lock().unwrap().len(), 1);

    let memory = Memory::default();
    initialize(&memory, 0, until()).unwrap();
    for worker in 1..=MAX_ALLOCATION_ATTEMPTS as u64 {
        claim(&memory, worker, until()).unwrap();
    }
    memory.calls.lock().unwrap().clear();
    assert_eq!(
        allocate(&memory, until()).unwrap_err().code,
        "INSTANCE_ALLOCATION_BUSY"
    );
    assert_eq!(
        memory.calls.lock().unwrap().len(),
        MAX_ALLOCATION_ATTEMPTS * 3
    );
    assert_eq!(
        allocate(&memory, until()).unwrap(),
        MAX_ALLOCATION_ATTEMPTS as u64 + 1
    );
}

#[test]
fn concurrent_allocators_use_new_candidates_and_observed_etags() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Paired {
        memory: Memory,
        first_reads: AtomicUsize,
        barrier: Barrier,
    }
    impl Objects for Paired {
        fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
            let value = self.memory.get(key, maximum, deadline)?;
            if key == ALLOCATOR && self.first_reads.fetch_add(1, Ordering::SeqCst) < 2 {
                self.barrier.wait();
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
            self.memory.put(key, bytes, condition, deadline)
        }
    }
    let memory = Memory::default();
    initialize(&memory, 10, until()).unwrap();
    let store = Arc::new(Paired {
        memory,
        first_reads: AtomicUsize::new(0),
        barrier: Barrier::new(2),
    });
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || allocate(store.as_ref(), until()).unwrap())
        })
        .collect();
    let mut assigned: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
    assigned.sort_unstable();
    assert_eq!(assigned, [11, 12]);
    assert_eq!(store.memory.values.lock().unwrap().len(), 3);
    assert_eq!(store.first_reads.load(Ordering::SeqCst), 3);
}
