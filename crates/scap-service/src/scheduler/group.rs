//! A selected prefix retains queue credits until its actual outcome is known.

use super::*;
use crate::group::{Member, Outcome, Profile};
use crate::wire::Action;

pub(super) enum Work {
    Single(Job),
    Group(Batch),
}

impl Work {
    pub(super) fn collect(
        shared: Arc<Shared>,
        queue: &mut DatabaseQueue,
        first: Job,
        profile: Option<Profile>,
    ) -> Self {
        let Some(profile) = profile else {
            return Self::Single(first);
        };
        if !queue.priority.is_empty() || first.reply.is_closed() || Instant::now() >= first.deadline
        {
            return Self::Single(first);
        }
        let Some(mut remaining) = input_remaining(&first.call, profile.max_input_bytes) else {
            return Self::Single(first);
        };
        let Ok(scope) = first.call.scope.native() else {
            return Self::Single(first);
        };
        let principal = first.principal.clone();
        let key = first.key.clone();
        let mut jobs = VecDeque::new();
        while jobs.len() + 1 < profile.max_members {
            let Some(next) = queue.normal.front() else {
                break;
            };
            if next.principal != principal
                || next.call.scope.native().ok().as_ref() != Some(&scope)
                || next.reply.is_closed()
                || Instant::now() >= next.deadline
            {
                break;
            }
            let Some(left) = input_remaining(&next.call, remaining) else {
                break;
            };
            remaining = left;
            jobs.push_back(queue.normal.pop_front().expect("observed normal job"));
        }
        if jobs.is_empty() {
            return Self::Single(first);
        }
        Self::Group(Batch {
            shared,
            key,
            first: Some(first),
            jobs,
            limits: profile.limits(),
        })
    }
}

/// Invalid/non-Execute envelopes remain barriers to queue collection.
fn input_remaining(call: &Call, maximum: usize) -> Option<usize> {
    if call.version != 1 {
        return None;
    }
    let Action::Execute {
        request,
        statements,
    } = &call.action
    else {
        return None;
    };
    crate::group::input_remaining(request, statements, maximum)
}

/// Worker drops before a panicking group's remaining credits and leases.
pub(super) struct ActorWorker {
    pub(super) worker: SingleWorker,
    pub(super) active: Option<Batch>,
}

pub(super) struct Batch {
    shared: Arc<Shared>,
    key: String,
    // The selected head stays inline. The ordinary path needs no new heap
    // allocation, and a declined group can consume this exact job alone.
    first: Option<Job>,
    jobs: VecDeque<Job>,
    limits: scap_object::GroupLimits,
}

impl Batch {
    pub(super) fn run(&mut self, worker: &mut dyn Worker) {
        let (outcome, attempt) = {
            let first = self.first.as_mut().expect("nonempty selected group");
            let mut trace = first._reservation.as_ref().and_then(|lease| lease.trace());
            let mut members = Vec::with_capacity(self.jobs.len() + 1);
            members.push(Member {
                principal: &first.principal,
                call: &first.call,
                deadline: first.deadline,
                output: first.output.as_mut(),
            });
            for job in &mut self.jobs {
                // Embedded callers can mix unreserved jobs with HTTP work.
                // Observe any traced member, without retaining another lease.
                trace = trace.or_else(|| job._reservation.as_ref().and_then(|lease| lease.trace()));
                members.push(Member {
                    principal: &job.principal,
                    call: &job.call,
                    deadline: job.deadline,
                    output: job.output.as_mut(),
                });
            }
            // The independent guard owns only diagnostic state. On panic it
            // cannot refund or retain any member's native/input/output lease.
            let attempt = trace.map(|trace| trace.begin_group(members.len()));
            (worker.execute_group(&mut members, self.limits), attempt)
        };
        let results = match outcome {
            Outcome::Declined => {
                if let Some(attempt) = attempt {
                    attempt.declined();
                }
                vec![perform(
                    worker,
                    self.first.as_mut().expect("nonempty selected group"),
                )]
            }
            Outcome::Completed(results) => {
                // A broken trusted worker must fail closed, not put possibly
                // executed work back in the queue or spin on an empty prefix.
                assert!(!results.is_empty() && results.len() <= self.jobs.len() + 1);
                if let Some(attempt) = attempt {
                    let (start, end) = attempt.completed(results.len());
                    // Only this trusted prefix participated in the returned
                    // invocation. These are shared call boundaries, not
                    // per-member SQL timings. The suffix keeps its old queue
                    // timestamp and has no invented invocation boundary.
                    for job in self.first.iter().chain(&self.jobs).take(results.len()) {
                        if let Some(trace) =
                            job._reservation.as_ref().and_then(|lease| lease.trace())
                        {
                            trace.consumed_invocation(start, end);
                        }
                    }
                }
                results.into_iter().map(Some).collect()
            }
        };
        self.finish(results);
    }

    /// Only a trusted consumed boundary can refund or requeue reservations.
    /// Keep this state transition separate from user worker execution/unwind.
    fn finish(&mut self, results: Vec<Option<Result<Value, Failure>>>) {
        let mut completed = Vec::with_capacity(results.len());
        let mut abandoned = Vec::new();
        {
            let mut state = lock(&self.shared.state);
            for result in results {
                let job = self
                    .first
                    .take()
                    .or_else(|| self.jobs.pop_front())
                    .expect("validated consumed prefix");
                state.usage.remove(&job);
                completed.push((job, result));
            }
            if state.closed {
                while let Some(job) = self.jobs.pop_front() {
                    state.usage.remove(&job);
                    abandoned.push(job);
                }
            } else {
                let actor = state.actors.get_mut(&self.key).expect("live group actor");
                // Keep untouched members before new arrivals. Their existing
                // Usage and intake/output reservations have never been freed.
                while let Some(job) = self.jobs.pop_back() {
                    actor.jobs.normal.push_front(job);
                }
            }
        }
        for (job, result) in completed {
            deliver(job, result);
        }
        for job in abandoned {
            job.fail(Failure::new("UNAVAILABLE"));
        }
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        // On unwind there is no trustworthy execution boundary. Closing each
        // reply lets HTTP report UNKNOWN; none of this work is resubmitted.
        let mut state = lock(&self.shared.state);
        for job in self.first.iter().chain(&self.jobs) {
            state.usage.remove(job);
        }
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
