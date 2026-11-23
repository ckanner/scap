//! Per-member service outcomes over one core publication, with no SQL replay.

use super::*;
use crate::group::{Member, Outcome};

struct PreparedMember {
    identity: scap_object::format::Request,
    statements: Vec<scap_sql::Statement>,
}

fn prepare(members: &[Member<'_>], maximum: usize) -> Option<Vec<PreparedMember>> {
    let first = members.first()?;
    let scope = first.call.scope.native().ok()?;
    let mut remaining = maximum;
    let mut inputs = Vec::with_capacity(members.len());
    for member in members {
        if member.call.version != 1
            || member.principal != first.principal
            || member.call.scope.native().ok().as_ref() != Some(&scope)
            || Instant::now() >= member.deadline
        {
            return None;
        }
        member.principal.authorize(&scope).ok()?;
        let Action::Execute {
            request,
            statements,
        } = &member.call.action
        else {
            return None;
        };
        let identity = request.native(member.principal.principal).ok()?;
        remaining = crate::group::input_remaining(request, statements, remaining)?;
        inputs.push((identity, statements));
    }
    // Bound the entire original wire group before cloning/decoding even the
    // first native payload. Direct Rust callers receive the same aggregate
    // admission guarantee as the production scheduler.
    let mut prepared = Vec::with_capacity(inputs.len());
    for (identity, statements) in inputs {
        let statements = wire::statements(statements).ok()?;
        let expected =
            scap_object::request(identity.epoch, identity.id, identity.principal, &statements)
                .ok()?;
        if expected != identity {
            return None;
        }
        prepared.push(PreparedMember {
            identity,
            statements,
        });
    }
    Some(prepared)
}

impl Engine {
    /// The core's completed vector is the consumed prefix. No returned error
    /// may cause an already-started member to fall back or return to queue.
    pub fn execute_group(
        &mut self,
        members: &mut [Member<'_>],
        limits: scap_object::GroupLimits,
    ) -> Outcome {
        if members.len() < 2 {
            return Outcome::Declined;
        }
        if let Err(error) = limits.validate() {
            return Outcome::Completed(vec![Err(Failure::from(error))]);
        }
        if members.len() > limits.max_members {
            return Outcome::Declined;
        }
        let maximum = limits.max_input_bytes.min(self.options.max_input_bytes);
        let Some(prepared) = prepare(members, maximum) else {
            return Outcome::Declined;
        };
        let path = match self.next_path() {
            Ok(path) => path,
            Err(error) => return Outcome::Completed(vec![Err(error)]),
        };
        let first = &members[0];
        let scope = first.call.scope.native().expect("prepared scope");
        let principal = first.principal.principal;
        let deadline = members.iter().map(|member| member.deadline).min().unwrap();
        let key = format!(
            "{}/inc/{}/gen/{}",
            head_key(&scope),
            scope.incarnation,
            scope.generation
        );
        let mut entry = match self.cache.remove(&key) {
            Some(entry) => entry,
            None => {
                let database = match Database::with_options(
                    self.objects.clone(),
                    scope,
                    self.worker,
                    self.options.clone(),
                ) {
                    Ok(database) => database,
                    Err(error) => return Outcome::Completed(vec![Err(Failure::from(error))]),
                };
                Cached {
                    database,
                    session: None,
                    touched: 0,
                }
            }
        };
        entry.touched = self.serial;
        let requests: Vec<_> = prepared
            .iter()
            .map(|member| scap_object::GroupRequest {
                identity: &member.identity,
                statements: &member.statements,
            })
            .collect();
        let executed = match self.session(principal, &mut entry, &path, deadline) {
            Ok(session) => session
                .execute_group(principal, &requests, limits, deadline)
                .map_err(Failure::from),
            Err(error) => Err(error),
        };
        let outcome = match executed {
            Ok(scap_object::GroupExecution::Fallback) => Outcome::Declined,
            Err(error) if error.code == "STALE_SNAPSHOT" => {
                // This is an outer, pre-SQL eligibility failure. A different
                // publication invalidated the private image. Re-enter only the
                // original queue head's ordinary path under its same deadline.
                entry.session = None;
                Outcome::Declined
            }
            Err(error) => {
                // Core's outer Err guarantees that no member SQL started.
                entry.session = None;
                Outcome::Completed(vec![Err(error)])
            }
            Ok(scap_object::GroupExecution::Completed(completion)) => {
                let mut results = Vec::with_capacity(completion.results.len());
                for (member, result) in members.iter_mut().zip(completion.results) {
                    results.push(match result {
                        Ok(committed) => group_committed(
                            committed,
                            self.options.result_memory_bytes,
                            member.output.as_deref_mut(),
                        ),
                        Err(error) => Err(Failure::from_ref(&error)),
                    });
                }
                if results.iter().any(Result::is_err) {
                    // Include native teardown in work lifetime before the
                    // scheduler can release a member's reservations.
                    entry.session = None;
                }
                Outcome::Completed(results)
            }
        };
        self.cache.insert(key, entry);
        self.trim();
        outcome
    }
}

fn group_committed(
    value: scap_object::GroupCommitted,
    memory: u64,
    output: Option<&mut crate::output::OutputContext>,
) -> Result<Value, Failure> {
    // Decode only one typed graph at a time. The raw group is already bounded
    // by core; service JSON/backings retain each member's independent charge.
    let result = scap_sql::decode_result_with_memory_limit(
        &value.bytes,
        scap_object::options::durable_sql_limits(),
        memory,
    )
    .map_err(|_| Failure {
        code: "COMMITTED_BUT_UNAVAILABLE",
        receipt: Some(Box::new(value.receipt.clone())),
        rejection: None,
    })?;
    match output {
        Some(output) => committed_budgeted(value.receipt, result, output),
        None => committed(value.receipt, result),
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
