use super::*;

pub(crate) fn hold_aggregation(registry: &Registry) -> impl Drop + '_ {
    registry.state.lock().unwrap()
}

fn at(origin: Instant, micros: u64) -> Instant {
    origin + Duration::from_micros(micros)
}

fn summary(snapshot: &Snapshot, lane: Lane, interval: Interval) -> &Distribution {
    &snapshot.lanes[lane as usize].intervals[interval as usize].distribution
}

fn counts(distribution: &Distribution) -> (u64, u64, u64) {
    (
        distribution.completed.0,
        distribution.censored.0,
        distribution.not_reached.0,
    )
}

fn conserve(snapshot: &Snapshot) {
    assert!(snapshot.valid);
    for lane in &snapshot.lanes {
        assert_eq!(lane.acquired.0, lane.released.0 + lane.active.0);
        for interval in &lane.intervals {
            let distribution = &interval.distribution;
            assert_eq!(
                distribution.completed.0 + distribution.censored.0 + distribution.not_reached.0,
                lane.released.0
            );
            assert_eq!(
                distribution
                    .buckets
                    .iter()
                    .map(|value| value.0)
                    .sum::<u64>(),
                distribution.completed.0
            );
        }
    }
    let groups = &snapshot.groups;
    assert_eq!(
        groups.attempts.0,
        groups.active.0 + groups.declined.0 + groups.completed.0 + groups.incomplete.0
    );
    assert_eq!(
        groups.duration.completed.0,
        groups.declined.0 + groups.completed.0
    );
    assert_eq!(groups.duration.censored.0, groups.incomplete.0);
    assert_eq!(groups.duration.not_reached.0, 0);
    assert_eq!(
        groups
            .duration
            .buckets
            .iter()
            .map(|count| count.0)
            .sum::<u64>(),
        groups.duration.completed.0
    );
    for (sizes, entries, members) in [
        (&groups.selected_sizes, groups.attempts.0, groups.selected.0),
        (
            &groups.consumed_sizes,
            groups.completed.0,
            groups.consumed.0,
        ),
    ] {
        assert_eq!(sizes.iter().map(|count| count.0).sum::<u64>(), entries);
        assert_eq!(
            sizes
                .iter()
                .enumerate()
                .map(|(index, count)| (index as u64 + 1) * count.0)
                .sum::<u64>(),
            members
        );
    }
}

#[test]
fn empty_snapshot_has_fixed_coverage_lossless_counts_and_no_identity_labels() {
    let registry = Registry::default();
    let snapshot = registry.snapshot();
    conserve(&snapshot);
    let _guard = hold_aggregation(&registry);
    // Serialization only touches this independent copy while aggregation is
    // deliberately unavailable. There is no registry reference in Snapshot.
    let json = serde_json::to_value(snapshot).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["unit"], "microseconds");
    assert_eq!(json["valid"], true);
    assert_eq!(json["lanes"].as_array().unwrap().len(), 5);
    assert_eq!(
        json["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|lane| lane["lane"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["data", "control", "recovery", "catalogue", "restore"]
    );
    let intervals = json["lanes"][0]["intervals"].as_array().unwrap();
    assert_eq!(
        intervals
            .iter()
            .map(|interval| interval["interval"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "body",
            "pre_enqueue",
            "queue",
            "invocation",
            "encoding",
            "post_work_hold",
            "post_http_hold",
            "total_hold"
        ]
    );
    assert_eq!(intervals[0]["completed"], "0");
    assert_eq!(json["histogram_upper_bounds_us"][18], u64::MAX.to_string());
    let text = serde_json::to_string(&json).unwrap();
    for forbidden in [
        "tenant",
        "deployment",
        "database",
        "request",
        "sql",
        "discovery",
    ] {
        assert!(!text.contains(forbidden));
    }
    assert_eq!(serde_json::to_string(&Count(0)).unwrap(), "\"0\"");
    assert_eq!(
        serde_json::to_string(&Count(u64::MAX)).unwrap(),
        "\"18446744073709551615\""
    );
}

#[test]
fn independent_http_readiness_and_out_of_order_lock_arrival_preserve_actual_times() {
    let registry = Arc::new(Registry::new());
    let origin = Instant::now();
    let trace = registry.acquire(Lane::Data, origin);
    // A group may report trusted historical invocation marks after HTTP has
    // already timed out. Mutex acquisition order must not imply time order.
    for (stage, micros) in [
        (HTTP_READY, 400),
        (ENCODED, 1_400),
        (ENQUEUED, 200),
        (BODY, 100),
        (ENCODING, 1_100),
    ] {
        trace.mark_at(stage, at(origin, micros));
    }
    trace.consumed_invocation(at(origin, 300), at(origin, 1_000));
    let pending = registry.snapshot();
    conserve(&pending);
    assert_eq!(pending.lanes[0].active.0, 1);
    assert_eq!(pending.lanes[0].released.0, 0);
    assert_eq!(summary(&pending, Lane::Data, Interval::Body).completed.0, 0);
    trace.finish(at(origin, 2_000));
    let snapshot = registry.snapshot();
    conserve(&snapshot);
    for (interval, micros) in [
        (Interval::Body, 100),
        (Interval::PreEnqueue, 100),
        (Interval::Queue, 100),
        (Interval::Invocation, 700),
        (Interval::Encoding, 300),
        (Interval::PostWorkHold, 600),
        (Interval::PostHttpHold, 1_600),
        (Interval::TotalHold, 2_000),
    ] {
        let distribution = summary(&snapshot, Lane::Data, interval);
        assert_eq!(counts(distribution), (1, 0, 0));
        assert_eq!(distribution.total_us.0, micros);
    }
}

#[test]
fn early_exit_panic_and_encoding_without_worker_are_censored_or_not_reached() {
    let registry = Arc::new(Registry::new());
    let origin = Instant::now();
    // An upload failure never supplies a body boundary.
    registry.acquire(Lane::Data, origin).finish(at(origin, 100));
    // Body parsed, but a subsequent admission gate refuses enqueue.
    let gate = registry.acquire(Lane::Control, origin);
    gate.mark_at(BODY, at(origin, 10));
    gate.finish(at(origin, 100));
    // Receiver/deadline guard rejects an actually queued request.
    let queued = registry.acquire(Lane::Recovery, origin);
    queued.mark_at(ENQUEUED, at(origin, 10));
    queued.finish(at(origin, 100));
    // Worker unwinds without a trusted return.
    let panic = registry.acquire(Lane::Catalogue, origin);
    panic.mark_at(ENQUEUED, at(origin, 5));
    panic.mark_at(STARTED, at(origin, 10));
    panic.mark_at(ENCODING, at(origin, 20));
    panic.finish(at(origin, 100));
    // Failure encoding can run without any worker call.
    let failure = registry.acquire(Lane::Restore, origin);
    failure.mark_at(ENCODING, at(origin, 10));
    failure.mark_at(ENCODED, at(origin, 20));
    failure.mark_at(HTTP_READY, at(origin, 30));
    failure.finish(at(origin, 100));
    let snapshot = registry.snapshot();
    conserve(&snapshot);
    for (lane, interval, expected) in [
        (Lane::Data, Interval::Body, (0, 1, 0)),
        (Lane::Data, Interval::PreEnqueue, (0, 0, 1)),
        (Lane::Control, Interval::PreEnqueue, (0, 1, 0)),
        (Lane::Recovery, Interval::Queue, (0, 1, 0)),
        (Lane::Recovery, Interval::Invocation, (0, 0, 1)),
        (Lane::Catalogue, Interval::Invocation, (0, 1, 0)),
        (Lane::Catalogue, Interval::Encoding, (0, 1, 0)),
        (Lane::Catalogue, Interval::PostWorkHold, (0, 0, 1)),
        (Lane::Restore, Interval::Invocation, (0, 0, 1)),
        (Lane::Restore, Interval::Encoding, (1, 0, 0)),
        (Lane::Restore, Interval::PostWorkHold, (1, 0, 0)),
        (Lane::Restore, Interval::PostHttpHold, (1, 0, 0)),
    ] {
        assert_eq!(counts(summary(&snapshot, lane, interval)), expected);
    }
    assert_eq!(
        summary(&snapshot, Lane::Restore, Interval::PostWorkHold)
            .total_us
            .0,
        80
    );
}

#[test]
fn actual_hook_methods_cover_a_returned_worker_and_worker_only_hold() {
    let registry = Arc::new(Registry::new());
    let trace = registry.acquire(Lane::Data, Instant::now());
    trace.body_ready();
    trace.enqueued();
    trace.invocation_started();
    trace.http_response_ready();
    trace.invocation_returned();
    trace.encoding_started();
    trace.encoding_returned();
    trace.finish(Instant::now());
    let other = registry.acquire(Lane::Catalogue, Instant::now());
    other.enqueued();
    other.invocation_started();
    other.invocation_returned();
    other.finish(Instant::now());
    let snapshot = registry.snapshot();
    conserve(&snapshot);
    assert_eq!(
        counts(summary(&snapshot, Lane::Catalogue, Interval::PostWorkHold)),
        (1, 0, 0)
    );
    assert_eq!(
        counts(summary(&snapshot, Lane::Catalogue, Interval::Encoding)),
        (0, 0, 1)
    );
}

#[test]
fn histogram_uses_inclusive_upper_bounds_and_checked_microsecond_conversion() {
    for (index, upper) in HISTOGRAM_UPPER_BOUNDS_US.into_iter().enumerate() {
        for micros in [
            if index == 0 {
                0
            } else {
                HISTOGRAM_UPPER_BOUNDS_US[index - 1] + 1
            },
            upper,
        ] {
            let mut distribution = Distribution::default();
            assert!(distribution.record_duration(Duration::from_micros(micros)));
            assert_eq!(distribution.completed.0, 1);
            assert_eq!(distribution.total_us.0, micros);
            assert_eq!(distribution.buckets[index].0, 1);
            assert_eq!(
                distribution
                    .buckets
                    .iter()
                    .map(|count| count.0)
                    .sum::<u64>(),
                1
            );
        }
    }
    let mut distribution = Distribution::default();
    assert!(distribution.record_duration(Duration::from_nanos(999)));
    assert_eq!(distribution.total_us.0, 0);
    assert_eq!(distribution.buckets[0].0, 1);
    assert!(!distribution.record_duration(Duration::from_secs(u64::MAX / 1_000_000 + 1)));
    assert_eq!(distribution.completed.0, 1);
}

#[test]
fn duplicate_marks_and_reversed_dependencies_are_sticky_invalid_without_panicking() {
    let registry = Arc::new(Registry::new());
    let origin = Instant::now();
    let trace = registry.acquire(Lane::Data, origin);
    trace.mark_at(BODY, at(origin, 10));
    trace.mark_at(BODY, at(origin, 20));
    assert!(!registry.snapshot().valid);
    assert_eq!(trace.lock()[BODY], Some(at(origin, 10)));
    trace.finish(at(origin, 100));
    assert!(!registry.snapshot().valid);
    for marks in [
        vec![(BODY, 99)],
        vec![(BODY, 150), (ENQUEUED, 120)],
        vec![(ENQUEUED, 150), (STARTED, 120)],
        vec![(STARTED, 150), (RETURNED, 120)],
        vec![(ENCODING, 150), (ENCODED, 120)],
        vec![(RETURNED, 150), (ENCODING, 120)],
        vec![(HTTP_READY, 201)],
    ] {
        let registry = Arc::new(Registry::new());
        let trace = registry.acquire(Lane::Data, at(origin, 100));
        for (stage, micros) in marks {
            trace.mark_at(stage, at(origin, micros));
        }
        trace.finish(at(origin, 200));
        assert!(!registry.snapshot().valid);
    }
    let registry = Arc::new(Registry::new());
    registry.acquire(Lane::Data, at(origin, 100)).finish(origin);
    assert!(!registry.snapshot().valid);
    for stage in [STARTED, RETURNED, ENCODED] {
        let registry = Arc::new(Registry::new());
        let trace = registry.acquire(Lane::Data, origin);
        trace.mark_at(stage, at(origin, 10));
        trace.finish(at(origin, 100));
        assert!(!registry.snapshot().valid);
    }
}

#[test]
fn arithmetic_overflow_never_wraps_or_recovers_validity() {
    let mut count = Count(u64::MAX);
    assert!(!count.add(1));
    assert_eq!(count.0, u64::MAX);
    let mut count = Count(0);
    assert!(!count.release());
    assert_eq!(count.0, 0);
    for field in 0..3 {
        let mut distribution = Distribution::default();
        match field {
            0 => distribution.completed = Count(u64::MAX),
            1 => distribution.total_us = Count(u64::MAX),
            _ => distribution.buckets[0] = Count(u64::MAX),
        }
        assert!(!distribution.record_duration(Duration::from_micros(1)));
    }
    let registry = Arc::new(Registry::new());
    registry.state.lock().unwrap().lanes[0].acquired = Count(u64::MAX);
    let trace = registry.acquire(Lane::Data, Instant::now());
    assert!(!registry.snapshot().valid);
    trace.finish(Instant::now());
    assert!(!registry.snapshot().valid);
    let registry = Arc::new(Registry::new());
    let trace = registry.acquire(Lane::Data, Instant::now());
    registry.state.lock().unwrap().lanes[0].active = Count(0);
    trace.finish(Instant::now());
    assert!(!registry.snapshot().valid);
    let registry = Arc::new(Registry::new());
    let origin = Instant::now();
    let trace = registry.acquire(Lane::Data, origin);
    registry.state.lock().unwrap().lanes[0].intervals[7]
        .distribution
        .total_us = Count(u64::MAX);
    trace.finish(at(origin, 1));
    assert!(!registry.snapshot().valid);
}

#[test]
fn poisoned_diagnostic_locks_keep_the_snapshot_invalid_and_do_not_break_cleanup() {
    let registry = Arc::new(Registry::new());
    let trace = registry.acquire(Lane::Data, Instant::now());
    let _ = std::panic::catch_unwind(|| {
        let _guard = registry.state.lock().unwrap();
        panic!("injected aggregate owner panic");
    });
    assert!(!registry.snapshot().valid);
    trace.finish(Instant::now());
    let snapshot = registry.snapshot();
    assert!(!snapshot.valid);
    assert_eq!(snapshot.lanes[0].active.0, 0);
    assert_eq!(snapshot.lanes[0].released.0, 1);
    let registry = Arc::new(Registry::new());
    let trace = registry.acquire(Lane::Data, Instant::now());
    let _ = std::panic::catch_unwind(|| {
        let _guard = trace.times.lock().unwrap();
        panic!("injected trace owner panic");
    });
    trace.body_ready();
    assert!(!registry.snapshot().valid);
    trace.finish(Instant::now());
    assert!(!registry.snapshot().valid);
}

#[test]
fn groups_count_attempts_separately_and_only_trusted_prefixes_receive_envelopes() {
    let registry = Arc::new(Registry::new());
    let first = registry.acquire(Lane::Data, Instant::now());
    let suffix = registry.acquire(Lane::Data, Instant::now());
    first.enqueued();
    suffix.enqueued();
    let attempt = first.begin_group(2);
    let active = registry.snapshot();
    conserve(&active);
    assert_eq!(active.groups.active.0, 1);
    assert_eq!(active.groups.selected_sizes[1].0, 1);
    let (start, end) = attempt.completed(1);
    first.consumed_invocation(start, end);
    first.finish(Instant::now());
    suffix.finish(Instant::now());
    let snapshot = registry.snapshot();
    conserve(&snapshot);
    assert_eq!(snapshot.groups.completed.0, 1);
    assert_eq!(snapshot.groups.selected.0, 2);
    assert_eq!(snapshot.groups.consumed.0, 1);
    assert_eq!(snapshot.groups.consumed_sizes[0].0, 1);
    assert_eq!(
        counts(summary(&snapshot, Lane::Data, Interval::Queue)),
        (1, 1, 0)
    );
    assert_eq!(
        counts(summary(&snapshot, Lane::Data, Interval::Invocation)),
        (1, 0, 1)
    );
}

#[test]
fn declined_and_unwound_groups_never_invent_consumed_member_boundaries() {
    let registry = Arc::new(Registry::new());
    let trace = registry.acquire(Lane::Data, Instant::now());
    trace.begin_group(64).declined();
    let _ = std::panic::catch_unwind(|| {
        let _attempt = trace.begin_group(3);
        panic!("injected group unwind before trusted return");
    });
    // Ordinary abandonment has the same lack of a trusted return.
    drop(trace.begin_group(1));
    trace.finish(Instant::now());
    let snapshot = registry.snapshot();
    conserve(&snapshot);
    assert_eq!(snapshot.groups.attempts.0, 3);
    assert_eq!(snapshot.groups.declined.0, 1);
    assert_eq!(snapshot.groups.incomplete.0, 2);
    assert_eq!(snapshot.groups.selected.0, 68);
    assert_eq!(snapshot.groups.consumed.0, 0);
    assert_eq!(
        counts(summary(&snapshot, Lane::Data, Interval::Invocation)),
        (0, 0, 1)
    );
}

#[test]
fn invalid_group_sizes_counts_and_clock_reversal_fail_diagnostics_without_panicking() {
    for (selected, consumed) in [(0, 0), (65, 1), (1, 0), (1, 2), (64, 65)] {
        let registry = Arc::new(Registry::new());
        let trace = registry.acquire(Lane::Data, Instant::now());
        trace.begin_group(selected).completed(consumed);
        trace.finish(Instant::now());
        assert!(!registry.snapshot().valid);
    }
    let registry = Arc::new(Registry::new());
    let origin = Instant::now();
    let mut attempt = registry.begin_group(2, at(origin, 100));
    attempt.finish(Some(origin), GroupOutcome::Declined);
    assert!(!registry.snapshot().valid);
    let registry = Arc::new(Registry::new());
    registry.state.lock().unwrap().groups.attempts = Count(u64::MAX);
    registry.begin_group(1, origin).completed(1);
    assert!(!registry.snapshot().valid);
}

fn maximal(distribution: &mut Distribution) {
    distribution.completed = Count(u64::MAX);
    distribution.censored = Count(u64::MAX);
    distribution.not_reached = Count(u64::MAX);
    distribution.total_us = Count(u64::MAX);
    distribution.buckets.fill(Count(u64::MAX));
}

#[test]
fn fixed_memory_and_maximal_decimal_snapshot_fit_the_frozen_export_bound() {
    let mut snapshot = Registry::new().snapshot();
    snapshot.valid = false;
    for lane in &mut snapshot.lanes {
        lane.acquired = Count(u64::MAX);
        lane.released = Count(u64::MAX);
        lane.active = Count(u64::MAX);
        for interval in &mut lane.intervals {
            maximal(&mut interval.distribution);
        }
    }
    let group = &mut snapshot.groups;
    for count in [
        &mut group.attempts,
        &mut group.active,
        &mut group.selected,
        &mut group.consumed,
        &mut group.declined,
        &mut group.completed,
        &mut group.incomplete,
    ] {
        *count = Count(u64::MAX);
    }
    maximal(&mut group.duration);
    group.selected_sizes.fill(Count(u64::MAX));
    group.consumed_sizes.fill(Count(u64::MAX));
    let json = serde_json::to_vec(&snapshot).unwrap();
    let sizes = (
        std::mem::size_of::<Registry>(),
        std::mem::size_of::<Trace>(),
        std::mem::size_of::<GroupAttempt>(),
        std::mem::size_of::<Snapshot>(),
        json.len(),
    );
    eprintln!("lifecycle bytes (Registry, Trace, GroupAttempt, Snapshot, maximum JSON): {sizes:?}");
    assert!(sizes.0 <= 16_384);
    assert!(sizes.1 <= 256);
    assert!(sizes.2 <= 64);
    assert!(sizes.3 <= 16_384);
    assert!(sizes.4 <= 65_536);
}
