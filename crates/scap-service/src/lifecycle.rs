//! Fixed-size, optional diagnostics for the original intake lease lifetime.
//!
//! A trace never owns a lease, request, response or worker. Only the final lease
//! refund completes its samples. These overlapping intervals are resource
//! residence observations, not SQL timings or proof that a client received ACK.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Serialize, Serializer};

pub const HISTOGRAM_UPPER_BOUNDS_US: [u64; 19] = [
    100,
    500,
    1_000,
    5_000,
    10_000,
    50_000,
    100_000,
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    30_000_000,
    60_000_000,
    300_000_000,
    1_800_000_000,
    86_400_000_000,
    604_800_000_000,
    u64::MAX,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Data,
    Control,
    Recovery,
    Catalogue,
    Restore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Interval {
    Body,
    PreEnqueue,
    Queue,
    Invocation,
    Encoding,
    PostWorkHold,
    PostHttpHold,
    TotalHold,
}

/// Numbers remain u64 in the fixed snapshot and become lossless decimal
/// strings only while the already detached snapshot is serialized.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Count(pub u64);

impl Serialize for Count {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl Count {
    fn add(&mut self, amount: u64) -> bool {
        match self.0.checked_add(amount) {
            Some(next) => {
                self.0 = next;
                true
            }
            None => false,
        }
    }

    fn release(&mut self) -> bool {
        match self.0.checked_sub(1) {
            Some(next) => {
                self.0 = next;
                true
            }
            None => false,
        }
    }
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct Distribution {
    pub completed: Count,
    pub censored: Count,
    pub not_reached: Count,
    pub total_us: Count,
    pub buckets: [Count; 19],
}

impl Distribution {
    fn record(&mut self, start: Option<Instant>, end: Option<Instant>) -> bool {
        match (start, end) {
            (None, _) => self.not_reached.add(1),
            (Some(_), None) => self.censored.add(1),
            (Some(start), Some(end)) => match end.checked_duration_since(start) {
                Some(elapsed) => self.record_duration(elapsed),
                None => false,
            },
        }
    }

    fn record_duration(&mut self, elapsed: Duration) -> bool {
        let Ok(micros) = u64::try_from(elapsed.as_micros()) else {
            return false;
        };
        let bucket = HISTOGRAM_UPPER_BOUNDS_US.partition_point(|upper| *upper < micros);
        let mut valid = self.completed.add(1);
        valid &= self.total_us.add(micros);
        valid &= self.buckets[bucket].add(1);
        valid
    }
}

#[derive(Clone, Copy, Serialize)]
pub struct IntervalSnapshot {
    pub interval: Interval,
    #[serde(flatten)]
    pub distribution: Distribution,
}

#[derive(Clone, Copy, Serialize)]
pub struct LaneSnapshot {
    pub lane: Lane,
    pub acquired: Count,
    pub released: Count,
    pub active: Count,
    pub intervals: [IntervalSnapshot; 8],
}

impl LaneSnapshot {
    fn new(lane: Lane) -> Self {
        Self {
            lane,
            acquired: Count(0),
            released: Count(0),
            active: Count(0),
            intervals: [
                Interval::Body,
                Interval::PreEnqueue,
                Interval::Queue,
                Interval::Invocation,
                Interval::Encoding,
                Interval::PostWorkHold,
                Interval::PostHttpHold,
                Interval::TotalHold,
            ]
            .map(|interval| IntervalSnapshot {
                interval,
                distribution: Distribution::default(),
            }),
        }
    }
}

#[derive(Clone, Copy, Serialize)]
pub struct GroupSnapshot {
    pub attempts: Count,
    pub active: Count,
    pub selected: Count,
    pub consumed: Count,
    pub declined: Count,
    pub completed: Count,
    pub incomplete: Count,
    pub duration: Distribution,
    /// Index zero is one selected member; index 63 is 64 selected members.
    #[serde(serialize_with = "serialize_sizes")]
    pub selected_sizes: [Count; 64],
    #[serde(serialize_with = "serialize_sizes")]
    pub consumed_sizes: [Count; 64],
}

fn serialize_sizes<S: Serializer>(sizes: &[Count; 64], serializer: S) -> Result<S::Ok, S::Error> {
    sizes.as_slice().serialize(serializer)
}

#[derive(Clone, Copy, Serialize)]
pub struct Snapshot {
    pub version: u8,
    pub valid: bool,
    pub unit: &'static str,
    pub histogram_upper_bounds_us: [Count; 19],
    pub lanes: [LaneSnapshot; 5],
    pub groups: GroupSnapshot,
}

pub struct Registry {
    state: Mutex<Snapshot>,
    /// Trace hooks use only their fixed local state and this sticky flag; they
    /// never take the aggregate lock while a production queue lock is held.
    invalid: AtomicBool,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(Snapshot {
                version: 1,
                valid: true,
                unit: "microseconds",
                histogram_upper_bounds_us: HISTOGRAM_UPPER_BOUNDS_US.map(Count),
                lanes: [
                    Lane::Data,
                    Lane::Control,
                    Lane::Recovery,
                    Lane::Catalogue,
                    Lane::Restore,
                ]
                .map(LaneSnapshot::new),
                groups: GroupSnapshot {
                    attempts: Count(0),
                    active: Count(0),
                    selected: Count(0),
                    consumed: Count(0),
                    declined: Count(0),
                    completed: Count(0),
                    incomplete: Count(0),
                    duration: Distribution::default(),
                    selected_sizes: [Count(0); 64],
                    consumed_sizes: [Count(0); 64],
                },
            }),
            invalid: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Snapshot> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poison) => {
                let mut state = poison.into_inner();
                state.valid = false;
                state
            }
        }
    }

    /// Copy bounded state under one short lock; serialize only the returned
    /// value, after unlocking and without any business resource lock.
    pub fn snapshot(&self) -> Snapshot {
        let mut snapshot = *self.lock();
        snapshot.valid &= !self.invalid.load(Ordering::Acquire);
        snapshot
    }

    pub(crate) fn acquire(self: &Arc<Self>, lane: Lane, acquired: Instant) -> Trace {
        let mut state = self.lock();
        let counts = &mut state.lanes[lane as usize];
        let mut valid = counts.acquired.add(1);
        valid &= counts.active.add(1);
        state.valid &= valid;
        drop(state);
        Trace {
            registry: self.clone(),
            lane,
            acquired,
            times: Mutex::new([None; 7]),
        }
    }

    fn finish(
        &self,
        lane: Lane,
        acquired: Instant,
        times: [Option<Instant>; 7],
        released: Instant,
    ) {
        let mut state = self.lock();
        let counts = &mut state.lanes[lane as usize];
        let mut valid = counts.released.add(1);
        valid &= counts.active.release();
        // HTTP readiness has no ordering dependency on the worker. All marks
        // still lie inside the original lease lifetime, whatever lock order
        // concurrent callers happened to obtain.
        for time in times.into_iter().flatten() {
            valid &= time >= acquired && time <= released;
        }
        // Direct Rust submissions may legitimately omit HTTP body shrink,
        // but a returned call or encoder cannot lack its own start, and every
        // worker invocation still belongs to a successfully queued job.
        for (end, start) in [
            (STARTED, ENQUEUED),
            (RETURNED, STARTED),
            (ENCODED, ENCODING),
        ] {
            valid &= times[end].is_none() || times[start].is_some();
        }
        if let (Some(returned), Some(encoding)) = (times[RETURNED], times[ENCODING]) {
            valid &= returned <= encoding;
        }
        let work_end = times[RETURNED].max(times[ENCODED]);
        for (interval, (start, end)) in counts.intervals.iter_mut().zip([
            (Some(acquired), times[BODY]),
            (times[BODY], times[ENQUEUED]),
            (times[ENQUEUED], times[STARTED]),
            (times[STARTED], times[RETURNED]),
            (times[ENCODING], times[ENCODED]),
            (work_end, Some(released)),
            (times[HTTP_READY], Some(released)),
            (Some(acquired), Some(released)),
        ]) {
            valid &= interval.distribution.record(start, end);
        }
        state.valid &= valid;
    }

    fn begin_group(self: &Arc<Self>, selected: usize, started: Instant) -> GroupAttempt {
        let mut state = self.lock();
        let counts = &mut state.groups;
        let mut valid = counts.attempts.add(1);
        valid &= counts.active.add(1);
        if (1..=64).contains(&selected) {
            valid &= counts.selected.add(selected as u64);
            valid &= counts.selected_sizes[selected - 1].add(1);
        } else {
            valid = false;
        }
        state.valid &= valid;
        drop(state);
        GroupAttempt {
            registry: self.clone(),
            selected,
            started,
            finished: false,
        }
    }

    fn finish_group(
        &self,
        selected: usize,
        started: Instant,
        returned: Option<Instant>,
        outcome: GroupOutcome,
    ) {
        let mut state = self.lock();
        let counts = &mut state.groups;
        let mut valid = counts.active.release();
        match outcome {
            GroupOutcome::Completed(consumed) => {
                valid &= counts.completed.add(1);
                if (1..=64).contains(&consumed) && consumed <= selected {
                    valid &= counts.consumed.add(consumed as u64);
                    valid &= counts.consumed_sizes[consumed - 1].add(1);
                } else {
                    valid = false;
                }
            }
            GroupOutcome::Declined => valid &= counts.declined.add(1),
            GroupOutcome::Incomplete => valid &= counts.incomplete.add(1),
        }
        valid &= counts.duration.record(Some(started), returned);
        state.valid &= valid;
    }
}

const BODY: usize = 0;
const ENQUEUED: usize = 1;
const STARTED: usize = 2;
const RETURNED: usize = 3;
const ENCODING: usize = 4;
const ENCODED: usize = 5;
const HTTP_READY: usize = 6;

/// Embedded directly in Lease. In particular, this is not an Arc<Lease> or an
/// independently retained owner of the work being measured.
pub struct Trace {
    registry: Arc<Registry>,
    lane: Lane,
    acquired: Instant,
    times: Mutex<[Option<Instant>; 7]>,
}

impl Trace {
    fn lock(&self) -> MutexGuard<'_, [Option<Instant>; 7]> {
        match self.times.lock() {
            Ok(times) => times,
            Err(poison) => {
                self.registry.invalid.store(true, Ordering::Release);
                poison.into_inner()
            }
        }
    }

    fn mark_at(&self, stage: usize, at: Instant) {
        let mut times = self.lock();
        if times[stage].is_some() {
            self.registry.invalid.store(true, Ordering::Release);
        } else {
            times[stage] = Some(at);
        }
    }

    pub(crate) fn body_ready(&self) {
        self.mark_at(BODY, Instant::now());
    }

    pub(crate) fn enqueued(&self) {
        self.mark_at(ENQUEUED, Instant::now());
    }

    pub(crate) fn invocation_started(&self) {
        self.mark_at(STARTED, Instant::now());
    }

    pub(crate) fn invocation_returned(&self) {
        self.mark_at(RETURNED, Instant::now());
    }

    pub(crate) fn encoding_started(&self) {
        self.mark_at(ENCODING, Instant::now());
    }

    pub(crate) fn encoding_returned(&self) {
        self.mark_at(ENCODED, Instant::now());
    }

    pub(crate) fn http_response_ready(&self) {
        self.mark_at(HTTP_READY, Instant::now());
    }

    /// A trusted consumed group prefix shares the invocation envelope. This
    /// records no per-member SQL start and never marks an unconsumed suffix.
    pub(crate) fn consumed_invocation(&self, start: Instant, end: Instant) {
        self.mark_at(STARTED, start);
        self.mark_at(RETURNED, end);
    }

    pub(crate) fn begin_group(&self, selected: usize) -> GroupAttempt {
        self.registry.begin_group(selected, Instant::now())
    }

    pub(crate) fn finish(&self, released: Instant) {
        let times = *self.lock();
        self.registry
            .finish(self.lane, self.acquired, times, released);
    }
}

enum GroupOutcome {
    Completed(usize),
    Declined,
    Incomplete,
}

/// Observes a bounded worker group attempt without retaining any member.
/// Unwinding has no trusted consumed prefix and produces a censored attempt.
pub struct GroupAttempt {
    registry: Arc<Registry>,
    selected: usize,
    started: Instant,
    finished: bool,
}

impl GroupAttempt {
    pub(crate) fn completed(mut self, consumed: usize) -> (Instant, Instant) {
        let returned = Instant::now();
        self.finish(Some(returned), GroupOutcome::Completed(consumed));
        (self.started, returned)
    }

    pub(crate) fn declined(mut self) {
        self.finish(Some(Instant::now()), GroupOutcome::Declined);
    }

    fn finish(&mut self, returned: Option<Instant>, outcome: GroupOutcome) {
        self.finished = true;
        self.registry
            .finish_group(self.selected, self.started, returned, outcome);
    }
}

impl Drop for GroupAttempt {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(None, GroupOutcome::Incomplete);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
