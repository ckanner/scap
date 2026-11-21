//! Independent native transactions share one original-ETag publication.
//! Only an all-fresh, distinct, same-principal group enters native staging.
//! Fallback and outer errors are decided before any member SQL is started.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use scap_object_sqlite::{GateDecision, GroupCommitGate, GroupMember, GroupRun, StagedTransaction};
use scap_sql::Statement;

use crate::data_tree::{self, DataObjects};
use crate::format::*;
use crate::head_publication::PreparedHead;
use crate::object_context::ObjectContext;
use crate::options::{input_size, MAX_REQUEST_BYTES};
use crate::{request, Database, Error, Options, Receipt, Resolution, Session, Snapshot};

pub const MAX_GROUP_MEMBERS: usize = 64;

/// Aggregate staging budgets, tightened by the current database's Options.
/// The group never reserves additional request epochs or retention windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupLimits {
    pub max_members: usize,
    pub max_input_bytes: usize,
    pub max_changed_pages: u32,
    pub max_result_bytes: u64,
}

impl Default for GroupLimits {
    fn default() -> Self {
        Self {
            max_members: 8,
            max_input_bytes: MAX_REQUEST_BYTES,
            max_changed_pages: 64 * 1024 * 1024 / PAGE_SIZE as u32,
            max_result_bytes: MAX_RESULT_BYTES as u64,
        }
    }
}

impl GroupLimits {
    pub fn validate(&self) -> Result<(), Error> {
        if !(2..=MAX_GROUP_MEMBERS).contains(&self.max_members)
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_REQUEST_BYTES
            || self.max_changed_pages == 0
            || self.max_changed_pages > MAX_PAGES
            || self.max_result_bytes == 0
            || self.max_result_bytes > MAX_RESULT_BYTES as u64
        {
            return Err(Error::Limit);
        }
        Ok(())
    }

    fn effective(self, options: &Options) -> Self {
        Self {
            max_members: self.max_members,
            max_input_bytes: self.max_input_bytes.min(options.max_input_bytes),
            max_changed_pages: self.max_changed_pages.min(options.max_changed_pages),
            max_result_bytes: self
                .max_result_bytes
                .min(options.sql.max_result_bytes as u64),
        }
    }
}

pub struct GroupRequest<'a> {
    pub identity: &'a Request,
    pub statements: &'a [Statement],
}

#[derive(Debug)]
pub struct GroupCommitted {
    pub receipt: Receipt,
    /// Exact original encoded result; no re-execution or re-encoding.
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct GroupCompletion {
    /// Consumed prefix, including its first failed member if one was started.
    /// Every member after this prefix is guaranteed not to have started SQL.
    pub results: Vec<Result<GroupCommitted, Arc<Error>>>,
}

#[derive(Debug)]
pub enum GroupExecution {
    /// No member SQL started. The caller may execute only its queue head using
    /// the ordinary path and leave the remaining original requests queued.
    Fallback,
    Completed(GroupCompletion),
}

struct GroupContext {
    base: Snapshot,
    objects: ObjectContext,
    requests: Vec<Request>,
    deadline: Instant,
}

/// This module alone can grant a multi-revision publication. General metadata,
/// owner, snapshot and storage candidates retain the ordinary serial + 1 rule.
/// A group reserves one serial and revision per fresh member; intermediate
/// values order its members but are never individually observable HEAD bodies.
pub(super) struct VerifiedGroupTransition {
    base: Snapshot,
    next: Head,
    members: u64,
}

impl VerifiedGroupTransition {
    fn new(base: Snapshot, next: Head, members: usize) -> Result<Self, Error> {
        if !(1..=MAX_GROUP_MEMBERS).contains(&members) {
            return Err(Error::Limit);
        }
        base.head.validate().map_err(Error::Format)?;
        if !crate::snapshot_format::cleanup_room(&next) {
            return Err(Error::Limit);
        }
        next.validate().map_err(Error::Format)?;
        let members = members as u64;
        let mut allowed = base.head.clone();
        allowed.revision = allowed.revision.checked_add(members).ok_or(Error::Limit)?;
        allowed.sequence = allowed.sequence.checked_add(members).ok_or(Error::Limit)?;
        allowed.head_serial = allowed
            .head_serial
            .checked_add(members)
            .ok_or(Error::Limit)?;
        allowed.transition = next.transition.clone();
        allowed.data_root = next.data_root.clone();
        allowed.windows[0] = next.windows[0].clone();
        if allowed != next
            || next.windows[0].count as u64 != base.head.windows[0].count as u64 + members
            || next.windows[0].result_bytes < base.head.windows[0].result_bytes
        {
            return Err(Error::Format(FormatError::Invalid));
        }
        Ok(Self {
            base,
            next,
            members,
        })
    }

    pub(super) fn into_parts(self) -> (Snapshot, Head, u64) {
        (self.base, self.next, self.members)
    }
}

impl Database {
    fn group_context(
        &self,
        principal: u64,
        requests: &[GroupRequest<'_>],
        limits: GroupLimits,
        deadline: Instant,
    ) -> Result<Option<GroupContext>, Error> {
        if requests.len() < 2 || requests.len() > limits.max_members {
            return Ok(None);
        }
        let mut ids = BTreeSet::new();
        let mut remaining = limits.max_input_bytes;
        for member in requests {
            let identity = member.identity;
            if identity.principal != principal
                || identity.epoch != requests[0].identity.epoch
                || !ids.insert(identity.id)
                || !request(identity.epoch, identity.id, principal, member.statements)
                    .is_ok_and(|actual| actual == *identity)
            {
                return Ok(None);
            }
            let Ok(bytes) = input_size(member.statements, remaining) else {
                return Ok(None);
            };
            if scap_sql::validate_statements(member.statements, self.options.sql).is_err() {
                return Ok(None);
            }
            remaining -= bytes;
        }
        let base = self.read_head(deadline)?;
        Self::authorize(&base.head, principal, true, true, false)?;
        Self::no_pending_owner(&base.head)?;
        let objects = ObjectContext::from_snapshot(self, &base, deadline)?;
        for member in requests {
            match self.resolve(&objects, &base.head, member.identity, deadline) {
                Ok(Resolution::Unknown) => {}
                Ok(_) | Err(Error::RequestConflict) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        self.writer(&base.head)?;
        let count = requests.len() as u64;
        if [
            base.head.revision,
            base.head.sequence,
            base.head.head_serial,
        ]
        .iter()
        .any(|value| value.checked_add(count).is_none())
        {
            return Ok(None);
        }
        let mut reserved = base.head.clone();
        reserved.revision += count;
        reserved.head_serial += count;
        if !crate::snapshot_format::cleanup_room(&reserved) {
            return Ok(None);
        }
        let window = &base.head.windows[0];
        // Preserve each member's ordinary MAX_RESULT_BYTES admission reserve.
        // When the bounded group cannot guarantee that reserve, use the queue's
        // ordinary head operation rather than execute a partially eligible group.
        let reserve = limits.max_result_bytes + MAX_RESULT_BYTES as u64;
        if window.count as usize + requests.len() > base.head.retention.max_entries as usize
            || window.result_bytes > base.head.retention.max_result_bytes.saturating_sub(reserve)
            || reserve > base.head.retention.max_result_bytes
        {
            return Ok(None);
        }
        Ok(Some(GroupContext {
            base,
            objects,
            requests: requests
                .iter()
                .map(|member| member.identity.clone())
                .collect(),
            deadline,
        }))
    }

    fn commit_group(
        &self,
        context: &GroupContext,
        prefix: &[StagedTransaction],
    ) -> Result<Vec<Receipt>, Error> {
        if prefix.is_empty() || prefix.len() > context.requests.len() {
            return Err(Error::Corrupt);
        }
        self.writer(&context.base.head)?;
        let mut head = context.base.head.clone();
        let mut receipts = Vec::with_capacity(prefix.len());
        for (staged, request) in prefix.iter().zip(&context.requests) {
            if head.windows[0].full(&head.retention) {
                return Err(Error::WindowFull);
            }
            let mut next = Self::next(&head, request.id)?;
            next.sequence = next.sequence.checked_add(1).ok_or(Error::Limit)?;
            next.data_root = data_tree::update(
                &context.objects,
                &head.data_root,
                &staged.batch,
                head.quota.max_pages().map_err(Error::Format)?,
                context.deadline,
            )?;
            let result_hash = context.objects.save(
                Payload::Result(StoredResult {
                    request: request.clone(),
                    sequence: next.sequence,
                    transition: next.transition.clone(),
                    data_root: next.data_root.clone(),
                    bytes: staged.result.clone(),
                }),
                context.deadline,
            )?;
            self.append(
                &context.objects,
                &mut next,
                Entry {
                    request: request.clone(),
                    outcome: OutcomeRef::Committed {
                        result: result_hash.clone(),
                    },
                    result_bytes: staged.result.len() as u64,
                },
                context.deadline,
            )?;
            receipts.push(Receipt {
                scope: self.scope.clone(),
                request: request.clone(),
                sequence: next.sequence,
                transition: next.transition.clone(),
                data_root: next.data_root.clone(),
                result_hash,
            });
            head = next;
        }
        let candidate =
            VerifiedGroupTransition::new(context.base.clone(), head.clone(), prefix.len())?;
        context.objects.healthy()?;
        let publication = PreparedHead::group(self, candidate, context.deadline)?;
        self.publish_manifest(&context.objects, &head, publication, context.deadline)?;
        Ok(receipts)
    }
}

type Publication = Option<Result<Vec<Receipt>, Arc<Error>>>;

struct Publisher {
    database: Database,
    context: GroupContext,
    outcome: Publication,
}

impl GroupCommitGate for Publisher {
    fn publish(&mut self, prefix: &[StagedTransaction]) -> GateDecision {
        if self.outcome.is_some() {
            return GateDecision::Unknown;
        }
        let outcome = self
            .database
            .commit_group(&self.context, prefix)
            .map_err(|error| Arc::new(self.context.objects.observe(error)));
        let decision = if outcome.is_ok() {
            GateDecision::Accepted
        } else {
            GateDecision::Unknown
        };
        self.outcome = Some(outcome);
        decision
    }
}

fn complete(run: GroupRun, publication: Publication) -> GroupCompletion {
    let mut results: Vec<_> = match (publication, run.outcome) {
        (Some(Ok(receipts)), Ok(bytes)) => receipts
            .into_iter()
            .zip(bytes)
            .map(|(receipt, bytes)| Ok(GroupCommitted { receipt, bytes }))
            .collect(),
        (Some(Ok(receipts)), Err(_)) => receipts
            .into_iter()
            .map(|receipt| Err(Arc::new(Error::CommittedButUnavailable(Box::new(receipt)))))
            .collect(),
        (Some(Err(error)), _) => (0..run.staged).map(|_| Err(error.clone())).collect(),
        (None, outcome) => {
            let error = Arc::new(match outcome {
                Err(error) => Error::Engine(error),
                Ok(_) => Error::Unknown,
            });
            (0..run.staged).map(|_| Err(error.clone())).collect()
        }
    };
    if let Some(error) = run.member_error {
        results.push(Err(Arc::new(Error::Engine(error))));
    }
    GroupCompletion { results }
}

impl Session {
    /// Automatic grouping only. A fallback or outer error guarantees that no
    /// SQL in this call started; Completed consumes exactly its result prefix.
    pub fn execute_group(
        &mut self,
        principal: u64,
        requests: &[GroupRequest<'_>],
        limits: GroupLimits,
        deadline: Instant,
    ) -> Result<GroupExecution, Error> {
        limits.validate()?;
        let limits = limits.effective(&self.database.options);
        let deadline = self.database.options.deadline(deadline, false);
        let Some(context) = self
            .database
            .group_context(principal, requests, limits, deadline)?
        else {
            return Ok(GroupExecution::Fallback);
        };
        self.align(&context.base.head, true)?;
        if !self.history_verified {
            self.database
                .verify_results(&context.objects, &context.base.head, deadline)?;
            self.history_verified = true;
        }
        let mut publisher = Publisher {
            database: self.database.clone(),
            context,
            outcome: None,
        };
        let interrupt: scap_object_sqlite::ReadInterrupt =
            Arc::new(move || Instant::now() >= deadline);
        let members: Vec<_> = requests
            .iter()
            .map(|member| GroupMember {
                statements: member.statements,
                interrupt: interrupt.clone(),
            })
            .collect();
        self.invalidated = true;
        let run = self.writer.execute_group(
            &members,
            scap_object_sqlite::GroupLimits {
                max_members: limits.max_members,
                max_changed_pages: limits.max_changed_pages,
                max_result_bytes: limits.max_result_bytes,
            },
            &mut publisher,
            interrupt,
        );
        self.finish_group(run, publisher.outcome)
    }

    fn finish_group(
        &mut self,
        run: GroupRun,
        publication: Publication,
    ) -> Result<GroupExecution, Error> {
        if run.attempted == 0 {
            return Err(match run.outcome {
                Err(error) => Error::Engine(error),
                Ok(_) => Error::Unknown,
            });
        }
        if let Some(Ok(receipts)) = &publication {
            self.data_root = receipts
                .last()
                .expect("published nonempty group")
                .data_root
                .clone();
            self.invalidated = run.member_error.is_some() || run.outcome.is_err();
        }
        Ok(GroupExecution::Completed(complete(run, publication)))
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
