use super::*;
use scap_raft_runtime::{Answer, Handle, Input};

/// Bounded synchronous calls to a runtime owned by a different thread. Waiting
/// never drives Raft and never resets the caller's absolute deadline.
#[derive(Clone)]
pub struct RuntimePort {
    handle: Handle,
}

impl RuntimePort {
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }
}

impl CellPort for RuntimePort {
    fn identity(&self) -> Identity {
        self.handle.identity()
    }

    fn read(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ReadView, scap_raft_runtime::Error> {
        read_answer(
            self.handle
                .submit(Input::Read, deadline)?
                .wait_cancelled(cancelled)?,
        )
    }

    fn propose(
        &mut self,
        data: Vec<u8>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<ProposalResult, scap_raft_runtime::Error> {
        proposal_answer(
            self.handle
                .submit(Input::ProposeTracked { data }, deadline)?
                .wait_cancelled(cancelled)?,
        )
    }
}

fn read_answer(answer: Answer) -> Result<ReadView, scap_raft_runtime::Error> {
    match answer {
        Answer::Read(view) => Ok(view),
        _ => Err(scap_raft_runtime::Error::Unknown),
    }
}

fn proposal_answer(answer: Answer) -> Result<ProposalResult, scap_raft_runtime::Error> {
    match answer {
        Answer::Applied(result) => Ok(result),
        _ => Err(scap_raft_runtime::Error::Unknown),
    }
}

#[cfg(test)]
mod tests;
