use super::*;
use std::cell::Cell;
use std::time::Duration;

thread_local! {
    static NOW: Cell<Option<Instant>> = const { Cell::new(None) };
}

fn now() -> Instant {
    NOW.with(|value| value.get().unwrap())
}

struct Probe {
    get: Result<Stored, StoreError>,
    put: Result<String, StoreError>,
    deadline: Instant,
    expire: bool,
    calls: Mutex<Vec<(bool, usize)>>,
}

impl Probe {
    fn new(bytes: usize, deadline: Instant) -> Self {
        Self {
            get: Ok(Stored {
                bytes: vec![1; bytes],
                etag: "original-etag".into(),
            }),
            put: Ok("created-etag".into()),
            deadline,
            expire: false,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn call(&self, put: bool, bytes: usize, deadline: Instant) {
        assert_eq!(deadline, self.deadline);
        self.calls.lock().unwrap().push((put, bytes));
        if self.expire {
            NOW.with(|value| value.set(Some(deadline)));
        }
    }
}

impl Objects for Probe {
    fn get(&self, key: &str, maximum: usize, deadline: Instant) -> Result<Stored, StoreError> {
        assert_eq!(key, "object");
        self.call(false, maximum, deadline);
        self.get.clone()
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        condition: Condition<'_>,
        deadline: Instant,
    ) -> Result<String, StoreError> {
        assert_eq!(key, "object");
        assert_eq!(condition, Condition::Match("unchanged-etag"));
        self.call(true, bytes.len(), deadline);
        self.put.clone()
    }
}

fn clock() -> Instant {
    let start = Instant::now();
    NOW.with(|value| value.set(Some(start)));
    start + Duration::from_secs(30)
}

fn source(probe: Arc<Probe>, budget: RestoreBudget, deadline: Instant) -> Arc<Meter> {
    let mut meter = Meter::source(probe, budget, deadline);
    Arc::get_mut(&mut meter).unwrap().now = now;
    meter
}

fn target(probe: Arc<Probe>, budget: RestoreBudget, deadline: Instant) -> Arc<Meter> {
    let mut meter = Meter::target(probe, budget, deadline);
    Arc::get_mut(&mut meter).unwrap().now = now;
    meter
}

#[test]
fn successful_gets_refund_only_unused_bytes_and_keep_the_call_reservation() {
    let deadline = clock();
    let probe = Arc::new(Probe::new(3, deadline));
    let meter = source(
        probe.clone(),
        RestoreBudget {
            source_gets: 2,
            source_bytes: 8,
            ..RestoreBudget::default()
        },
        deadline,
    );
    for _ in 0..2 {
        assert_eq!(
            meter.get("object", 6, deadline).unwrap(),
            probe.get.clone().unwrap()
        );
    }
    assert_eq!(*probe.calls.lock().unwrap(), vec![(false, 6), (false, 5)]);
    assert_eq!(meter.used.lock().unwrap().get_bytes, 6);
    assert_eq!(meter.get("object", 1, deadline), Err(StoreError::Budget));
    assert_eq!(probe.calls.lock().unwrap().len(), 2);
    assert_eq!(
        meter.put("object", b"", Condition::Match("unchanged-etag"), deadline),
        Err(StoreError::Budget)
    );

    let meter = source(
        probe.clone(),
        RestoreBudget {
            source_bytes: 0,
            ..RestoreBudget::default()
        },
        deadline,
    );
    assert_eq!(meter.get("object", 0, deadline), Err(StoreError::Budget));
    assert_eq!(probe.calls.lock().unwrap().len(), 2);
}

#[test]
fn failed_or_oversized_gets_never_refund_the_reserved_allowance() {
    let deadline = clock();
    for error in [
        StoreError::Missing,
        StoreError::Conflict,
        StoreError::Unknown,
        StoreError::Invalid,
        StoreError::Budget,
        StoreError::Corrupt,
        StoreError::Limit,
    ] {
        let mut probe = Probe::new(0, deadline);
        probe.get = Err(error.clone());
        let probe = Arc::new(probe);
        let meter = source(
            probe.clone(),
            RestoreBudget {
                source_bytes: 4,
                ..RestoreBudget::default()
            },
            deadline,
        );
        assert_eq!(meter.get("object", 4, deadline), Err(error));
        assert_eq!(meter.used.lock().unwrap().get_bytes, 4);
        assert_eq!(meter.get("object", 1, deadline), Err(StoreError::Budget));
        assert_eq!(probe.calls.lock().unwrap().len(), 1);
    }
    let mut limited = Probe::new(0, deadline);
    limited.get = Err(StoreError::Limit);
    let meter = source(
        Arc::new(limited),
        RestoreBudget {
            source_bytes: 3,
            ..RestoreBudget::default()
        },
        deadline,
    );
    assert_eq!(meter.get("object", 4, deadline), Err(StoreError::Budget));
    let meter = source(
        Arc::new(Probe::new(4, deadline)),
        RestoreBudget {
            source_bytes: 3,
            ..RestoreBudget::default()
        },
        deadline,
    );
    assert_eq!(meter.get("object", 3, deadline), Err(StoreError::Corrupt));
    assert_eq!(meter.used.lock().unwrap().get_bytes, 3);
}

#[test]
fn target_puts_preserve_original_condition_and_account_unknown_effects() {
    let deadline = clock();
    let probe = Arc::new(Probe::new(0, deadline));
    let meter = target(
        probe.clone(),
        RestoreBudget {
            target_puts: 2,
            target_put_bytes: 5,
            ..RestoreBudget::default()
        },
        deadline,
    );
    assert_eq!(
        meter.put(
            "object",
            b"123",
            Condition::Match("unchanged-etag"),
            deadline
        ),
        Ok("created-etag".into())
    );
    assert_eq!(
        meter.put(
            "object",
            b"123",
            Condition::Match("unchanged-etag"),
            deadline
        ),
        Err(StoreError::Budget)
    );
    assert_eq!(
        meter.put(
            "object",
            b"12",
            Condition::Match("unchanged-etag"),
            deadline
        ),
        Ok("created-etag".into())
    );
    assert_eq!(
        meter.put("object", b"", Condition::Match("unchanged-etag"), deadline),
        Err(StoreError::Budget)
    );
    assert_eq!(*probe.calls.lock().unwrap(), vec![(true, 3), (true, 2)]);
    let mut unknown = Probe::new(0, deadline);
    unknown.put = Err(StoreError::Unknown);
    let meter = target(
        Arc::new(unknown),
        RestoreBudget {
            target_puts: 1,
            ..RestoreBudget::default()
        },
        deadline,
    );
    assert_eq!(
        meter.put("object", b"1", Condition::Match("unchanged-etag"), deadline),
        Err(StoreError::Unknown)
    );
    assert_eq!(meter.used.lock().unwrap().put_bytes, 1);
    assert_eq!(
        meter.put("object", b"1", Condition::Match("unchanged-etag"), deadline),
        Err(StoreError::Budget)
    );
}

#[test]
fn original_and_child_deadlines_bound_both_sides_of_io_without_sleeping() {
    for put in [false, true] {
        for child_is_earlier in [false, true] {
            let original = clock();
            let child = if child_is_earlier {
                original - Duration::from_secs(1)
            } else {
                original + Duration::from_secs(1)
            };
            let effective = original.min(child);
            let mut probe = Probe::new(1, effective);
            probe.expire = true;
            let probe = Arc::new(probe);
            let meter = target(probe.clone(), RestoreBudget::default(), original);
            let result = if put {
                meter
                    .put("object", b"1", Condition::Match("unchanged-etag"), child)
                    .map(|_| ())
            } else {
                meter.get("object", 4, child).map(|_| ())
            };
            assert_eq!(result, Err(StoreError::Unknown));
            assert_eq!(probe.calls.lock().unwrap().len(), 1);
            if put {
                assert_eq!(meter.used.lock().unwrap().put_bytes, 1);
            } else {
                assert_eq!(meter.used.lock().unwrap().get_bytes, 4);
            }
            // Already expired calls cannot reserve anything or reach the store.
            assert_eq!(meter.get("object", 4, child), Err(StoreError::Unknown));
            assert_eq!(
                meter.put("object", b"1", Condition::Match("unchanged-etag"), child),
                Err(StoreError::Unknown)
            );
            assert_eq!(probe.calls.lock().unwrap().len(), 1);
        }
    }
}
