use super::*;
use crate::catalogue::tests::{deadline, Fault, Memory};
use scap_object_store::{ListEnd, ListMode};
use std::cell::RefCell;
use std::time::Duration;

struct Pages(Result<ListPage, ListError>);

impl Listings for Pages {
    fn list_page(&self, _: &ListRequest<'_>, _: Instant) -> Result<ListPage, ListError> {
        self.0.clone()
    }
}

fn page(bytes: usize) -> Result<ListPage, ListError> {
    Ok(ListPage {
        entries: vec![],
        end: ListEnd::Exhausted,
        response_bytes: bytes,
    })
}

fn request() -> ListRequest<'static> {
    ListRequest {
        prefix: "scap-object/v1/1/",
        mode: ListMode::Children,
        after: None,
    }
}

fn make_meter(
    objects: Arc<dyn Objects>,
    listing: Result<ListPage, ListError>,
    budget: RecoveryBudget,
) -> Arc<RecoveryMeter> {
    RecoveryMeter::new(
        objects,
        Arc::new(Pages(listing)),
        budget,
        deadline(),
        Instant::now,
    )
}

#[test]
fn fixed_job_caps_can_only_be_lowered_and_failed_reads_retain_their_cap() {
    for field in 0..6 {
        let mut budget = RecoveryBudget::default();
        match field {
            0 => budget.list_pages += 1,
            1 => budget.candidates += 1,
            2 => budget.exact_gets += 1,
            3 => budget.list_bytes += 1,
            4 => budget.metadata_bytes += 1,
            _ => budget.data_bytes += 1,
        }
        assert_eq!(budget.validate(), Err(RecoveryStop::Invalid));
    }
    assert!(RecoveryBudget::default().validate().is_ok());
    for key in [
        "scap-object/v1/1/2/3/head",
        "scap-object/v1/1/2/catalogue/v1/name/key",
        "scap-object/v1/1/2/3/objects/hash",
    ] {
        let metadata = key.contains("/head") || key.contains("/catalogue/");
        for error in [
            StoreError::Missing,
            StoreError::Unknown,
            StoreError::Limit,
            StoreError::Corrupt,
        ] {
            let objects = Arc::new(Memory::default());
            let meter = make_meter(objects.clone(), page(8), RecoveryBudget::default());
            objects.fail_at(1, Fault::Before(error.clone()));
            assert_eq!(meter.get(key, 5, deadline()), Err(error));
            let used = meter.usage();
            assert_eq!(used.exact_gets, 1);
            assert_eq!(used.metadata_bytes, if metadata { 5 } else { 0 });
            assert_eq!(used.data_bytes, if metadata { 0 } else { 5 });
            assert_eq!(meter.failure(RecoveryStop::Corrupt), RecoveryStop::Corrupt);
        }
    }
}

#[test]
fn successful_gets_refund_only_unused_bytes_and_all_quotas_stop_before_io() {
    for metadata in [false, true] {
        let key = if metadata {
            "scap-object/v1/1/2/3/head"
        } else {
            "scap-object/v1/1/2/3/objects/hash"
        };
        let objects = Arc::new(Memory::default());
        objects.set(key, vec![1, 2, 3]);
        let meter = make_meter(
            objects.clone(),
            page(8),
            RecoveryBudget {
                metadata_bytes: 5,
                data_bytes: 5,
                ..RecoveryBudget::default()
            },
        );
        assert_eq!(meter.get(key, 5, deadline()).unwrap().bytes, vec![1, 2, 3]);
        assert_eq!(meter.usage().metadata_bytes + meter.usage().data_bytes, 3);
        assert_eq!(meter.get(key, 5, deadline()), Err(StoreError::Budget));
        assert_eq!(meter.failure(RecoveryStop::Corrupt), RecoveryStop::Limit);
        assert_eq!(meter.usage().metadata_bytes + meter.usage().data_bytes, 5);
        let calls = objects.calls().len();
        assert_eq!(meter.get(key, 5, deadline()), Err(StoreError::Budget));
        assert_eq!(objects.calls().len(), calls);
        assert_eq!(
            meter.list_page(&request(), deadline()),
            Err(ListError::Limit)
        );
        assert_eq!(meter.check(deadline()), Err(RecoveryStop::Limit));
    }
    for (budget, key) in [
        (
            RecoveryBudget {
                exact_gets: 0,
                ..RecoveryBudget::default()
            },
            "objects/hash",
        ),
        (
            RecoveryBudget {
                metadata_bytes: 0,
                ..RecoveryBudget::default()
            },
            "scope/head",
        ),
        (
            RecoveryBudget {
                data_bytes: 0,
                ..RecoveryBudget::default()
            },
            "objects/hash",
        ),
    ] {
        let objects = Arc::new(Memory::default());
        let meter = make_meter(objects.clone(), page(8), budget);
        assert_eq!(meter.get(key, 1, deadline()), Err(StoreError::Budget));
        assert!(objects.calls().is_empty());
        assert_eq!(meter.usage().exact_gets, 0);
    }
    let meter = make_meter(
        Arc::new(Memory::default()),
        page(8),
        RecoveryBudget::default(),
    );
    assert_eq!(
        meter.put("scope/head", &[], Condition::Absent, deadline()),
        Err(StoreError::Invalid)
    );
}

struct Oversized;
impl Objects for Oversized {
    fn get(&self, _: &str, max: usize, _: Instant) -> Result<Stored, StoreError> {
        Ok(Stored {
            bytes: vec![0; max + 1],
            etag: "over-cap".into(),
        })
    }
    fn put(&self, _: &str, _: &[u8], _: Condition<'_>, _: Instant) -> Result<String, StoreError> {
        panic!("read-only test")
    }
}

#[test]
fn broken_ports_and_list_errors_cannot_refund_unobserved_cost_or_claim_empty_completion() {
    let meter = make_meter(Arc::new(Oversized), page(8), RecoveryBudget::default());
    assert_eq!(
        meter.get("scope/head", 5, deadline()),
        Err(StoreError::Corrupt)
    );
    assert_eq!(meter.usage().metadata_bytes, 5);
    for budget in [
        RecoveryBudget {
            list_pages: 0,
            ..RecoveryBudget::default()
        },
        RecoveryBudget {
            list_bytes: MAX_LIST_RESPONSE_BYTES as u64 - 1,
            ..RecoveryBudget::default()
        },
    ] {
        let meter = make_meter(Arc::new(Memory::default()), page(8), budget);
        assert_eq!(
            meter.list_page(&request(), deadline()),
            Err(ListError::Limit)
        );
        assert_eq!(meter.usage().list_pages, 0);
    }
    for error in [
        ListError::Denied,
        ListError::Unknown,
        ListError::Limit,
        ListError::Corrupt,
    ] {
        let meter = make_meter(
            Arc::new(Memory::default()),
            Err(error),
            RecoveryBudget::default(),
        );
        assert_eq!(meter.list_page(&request(), deadline()), Err(error));
        assert_eq!(meter.usage().list_bytes, MAX_LIST_RESPONSE_BYTES as u64);
        assert_eq!(meter.usage().list_pages, 1);
    }
    let meter = make_meter(
        Arc::new(Memory::default()),
        page(MAX_LIST_RESPONSE_BYTES + 1),
        RecoveryBudget::default(),
    );
    assert_eq!(
        meter.list_page(&request(), deadline()),
        Err(ListError::Corrupt)
    );
    assert_eq!(meter.usage().list_bytes, MAX_LIST_RESPONSE_BYTES as u64);
    let meter = make_meter(
        Arc::new(Memory::default()),
        page(8),
        RecoveryBudget {
            candidates: 2,
            ..RecoveryBudget::default()
        },
    );
    assert_eq!(meter.discovery_budget().candidates, 1);
    meter.counted_candidates(1);
    meter.retry_candidate().unwrap();
    assert_eq!(meter.discovery_budget().candidates, 0);
    assert_eq!(meter.retry_candidate(), Err(RecoveryStop::Limit));
    assert_eq!(meter.usage().candidates, 2);
}

thread_local! {
    static CLOCK: RefCell<(Instant, usize, usize)> = RefCell::new((Instant::now(), 0, 0));
}

fn clock(cut: usize) -> Instant {
    let now = Instant::now();
    CLOCK.with(|value| *value.borrow_mut() = (now, cut, 0));
    now + Duration::from_secs(30)
}

fn now() -> Instant {
    CLOCK.with(|value| {
        let mut value = value.borrow_mut();
        value.2 += 1;
        if value.2 >= value.1 {
            value.0 + Duration::from_secs(30)
        } else {
            value.0
        }
    })
}

#[test]
fn absolute_deadline_is_checked_before_and_after_both_ports() {
    let objects = Arc::new(Memory::default());
    objects.set("scope/head", vec![1, 2, 3]);
    for cut in [1, 2] {
        let until = clock(cut);
        let meter = RecoveryMeter::new(
            objects.clone(),
            Arc::new(Pages(page(8))),
            RecoveryBudget::default(),
            until,
            now,
        );
        assert_eq!(
            meter.get("scope/head", 5, deadline()),
            Err(StoreError::Unknown)
        );
        assert_eq!(meter.usage().metadata_bytes, if cut == 1 { 0 } else { 3 });
        let until = clock(cut);
        let meter = RecoveryMeter::new(
            objects.clone(),
            Arc::new(Pages(page(8))),
            RecoveryBudget::default(),
            until,
            now,
        );
        assert_eq!(
            meter.list_page(&request(), deadline()),
            Err(ListError::Unknown)
        );
        assert_eq!(meter.usage().list_bytes, if cut == 1 { 0 } else { 8 });
    }
}
