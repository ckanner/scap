//! Blocking cell control adapter. SQL never drives Raft on its own thread;
//! it waits on the independently supervised runtime under the original budget.

use std::sync::atomic::AtomicBool;
use std::time::Instant;

use scap_cell_client::{CellPort, RuntimePort};
use scap_raft_driver::{ProposalResult, Status};
use scap_raft_runtime::{Answer, Error, Handle, Input, ReadView};
use scap_service::ServiceError;

use crate::failure;
use crate::worker::ControlPort;

#[derive(Clone)]
pub(crate) struct LocalPort {
    pub handle: Handle,
}

impl LocalPort {
    fn request(&self, input: Input, deadline: Instant) -> Result<Answer, Error> {
        self.handle.submit(input, deadline)?.wait()
    }
}

impl CellPort for LocalPort {
    fn identity(&self) -> scap_raft_store::Identity {
        self.handle.identity()
    }
    fn read(&mut self, deadline: Instant, cancelled: &AtomicBool) -> Result<ReadView, Error> {
        RuntimePort::new(self.handle.clone()).read(deadline, cancelled)
    }
    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ProposalResult, Error> {
        RuntimePort::new(self.handle.clone()).propose(data, deadline, cancelled)
    }
}

fn status(answer: Result<Answer, Error>) -> Result<Status, ServiceError> {
    match answer {
        Ok(Answer::Status(status)) => Ok(status),
        _ => Err(failure("UNAVAILABLE")),
    }
}

/// Checkpoint policy and reply validation are independent of thread scheduling.
/// A failed checkpoint must reach supervision rather than silently retaining an
/// ever-growing log after archive completion.
fn maintain(
    force: bool,
    mut request: impl FnMut(Input) -> Result<Answer, Error>,
) -> Result<(), ServiceError> {
    let status = status(request(Input::Status))?;
    let distance = status.applied.saturating_sub(status.snapshot_index);
    if distance > 0 && (force || distance >= 128) {
        match request(Input::Checkpoint) {
            Ok(Answer::Checkpointed) => (),
            _ => return Err(failure("CHECKPOINT_UNAVAILABLE")),
        }
    }
    Ok(())
}

impl ControlPort for LocalPort {
    fn leadership(&self, deadline: Instant) -> Result<(bool, u64), ServiceError> {
        let status = status(self.request(Input::Status, deadline))?;
        Ok((status.role == raft::StateRole::Leader, status.term))
    }
    fn maintain(&self, deadline: Instant, force: bool) -> Result<(), ServiceError> {
        maintain(force, |input| self.request(input, deadline))
    }
}

#[cfg(test)]
mod tests;
