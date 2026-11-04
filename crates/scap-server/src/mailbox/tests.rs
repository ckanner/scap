use super::*;
use crate::tests::{config, context, sql};
use std::time::{Duration, Instant};

fn setup() -> (Mailbox, mpsc::Receiver<Envelope>) {
    Mailbox::new(&config().databases, Arc::new(AtomicBool::new(false)))
}

fn operation() -> Operation {
    Operation::Execute {
        mode: Mode::Write,
        statements: vec![sql("SELECT 1")],
    }
}

fn code<T>(value: Result<T, ServiceError>) -> String {
    match value {
        Err(error) => error.code,
        Ok(_) => panic!("expected failure"),
    }
}

fn empty_result() -> TransactionResult {
    TransactionResult { statements: vec![] }
}

#[test]
fn bounded_admission_verifies_identity_input_and_original_request_budget() {
    for case in 0..5 {
        let (mailbox, _receiver) = setup();
        let mut request = context("alpha", 7);
        let mut op = operation();
        let expected = match case {
            0 => {
                mailbox.0.stopped.store(true, Ordering::Release);
                "UNAVAILABLE"
            }
            1 => {
                request.cancelled.store(true, Ordering::Release);
                "COMMIT_UNKNOWN"
            }
            2 => {
                request.deadline = Instant::now();
                "COMMIT_UNKNOWN"
            }
            3 => {
                request.credential = "wrong".into();
                "UNAUTHORIZED"
            }
            _ => {
                op = Operation::Execute {
                    mode: Mode::Write,
                    statements: vec![],
                };
                "INVALID_REQUEST"
            }
        };
        assert_eq!(code(mailbox.enqueue(request, Mode::Write, op)), expected);
        assert_eq!(mailbox.0.usage.lock().count, 0);
        assert_eq!(mailbox.0.usage.lock().bytes, 0);
    }
    let (mailbox, receiver) = setup();
    let request = context("alpha", 8);
    let deadline = request.deadline;
    let cancellation = request.cancelled.clone();
    let pending = mailbox.enqueue(request, Mode::Write, operation()).unwrap();
    let envelope = receiver.recv().unwrap();
    assert_eq!(
        envelope.request.database.identity,
        config().databases[0].identity
    );
    assert_eq!(
        envelope.request.context.admission,
        scap_cell::Admission {
            principal_id: 200,
            credential_id: 201,
            admission_id: 8,
            auth_epoch: 1
        }
    );
    assert_eq!(envelope.request.context.deadline, deadline);
    assert_eq!(pending.1, deadline);
    assert_eq!(envelope.request.request_id, 8);
    assert!(Arc::ptr_eq(
        &envelope.request.context.cancelled,
        &cancellation
    ));
    assert!(matches!(
        envelope.request.operation,
        Operation::Execute {
            mode: Mode::Write,
            ..
        }
    ));
    drop(pending);
    assert!(cancellation.load(Ordering::Acquire));
    // Cancellation does not reclaim an envelope still owned by the SQL thread.
    assert_eq!(mailbox.0.usage.lock().count, 1);
    drop(envelope);
    assert_eq!(mailbox.0.usage.lock().count, 0);
    assert_eq!(mailbox.0.usage.lock().bytes, 0);
}

#[test]
fn request_count_includes_work_dequeued_but_not_yet_released() {
    let (mailbox, receiver) = setup();
    let mut pending = Vec::new();
    for id in 1..=MAX_DATABASE_QUEUED {
        pending.push(
            mailbox
                .enqueue(context("alpha", id as u128), Mode::Write, operation())
                .unwrap(),
        );
    }
    assert_eq!(mailbox.0.usage.lock().count, MAX_DATABASE_QUEUED);
    let in_progress = receiver.recv().unwrap();
    assert_eq!(
        code(mailbox.enqueue(context("alpha", 100), Mode::Write, operation())),
        "OVERLOADED"
    );
    drop(in_progress);
    pending.push(
        mailbox
            .enqueue(context("alpha", 101), Mode::Write, operation())
            .unwrap(),
    );
    assert_eq!(mailbox.0.usage.lock().count, MAX_DATABASE_QUEUED);
    drop(receiver);
    assert_eq!(mailbox.0.usage.lock().count, 0);
    assert_eq!(mailbox.0.usage.lock().bytes, 0);
    drop(pending);
}

#[test]
fn database_quota_leaves_admission_for_other_databases_and_global_limits_remain_hard() {
    use sha2::{Digest, Sha256};
    fn scoped_context(database: &str, id: u128) -> RequestContext {
        let mut request = context(database, id);
        request.credential = format!("unit-token-{database}");
        request
    }
    let mut databases = Vec::new();
    for id in 1..=6 {
        let mut database = config().databases.remove(0);
        database.name = format!("db-{id}");
        database.identity.database_id = id;
        database.tokens[0].digest =
            Sha256::digest(format!("unit-token-{}", database.name).as_bytes()).into();
        databases.push(database);
    }
    let (mailbox, receiver) = Mailbox::new(&databases, Arc::new(AtomicBool::new(false)));
    let mut pending = Vec::new();
    for id in 1..=MAX_DATABASE_QUEUED {
        pending.push(
            mailbox
                .enqueue(scoped_context("db-1", id as u128), Mode::Write, operation())
                .unwrap(),
        );
    }
    assert_eq!(
        code(mailbox.enqueue(scoped_context("db-1", 100), Mode::Write, operation())),
        "OVERLOADED"
    );
    for database in 2..=4 {
        for id in 1..=MAX_DATABASE_QUEUED {
            pending.push(
                mailbox
                    .enqueue(
                        scoped_context(&format!("db-{database}"), id as u128),
                        Mode::Write,
                        operation(),
                    )
                    .unwrap(),
            );
        }
    }
    assert_eq!(mailbox.0.usage.lock().count, MAX_QUEUED);
    assert_eq!(
        code(mailbox.enqueue(scoped_context("db-5", 100), Mode::Write, operation())),
        "OVERLOADED"
    );
    let active = receiver.recv().unwrap();
    assert_eq!(mailbox.0.usage.lock().count, MAX_QUEUED);
    drop(active);
    pending.push(
        mailbox
            .enqueue(scoped_context("db-5", 101), Mode::Write, operation())
            .unwrap(),
    );
    drop(receiver);
    assert!(mailbox.0.usage.lock().databases.is_empty());
    assert_eq!(mailbox.0.usage.lock().count, 0);
    drop(pending);

    let (mailbox, receiver) = Mailbox::new(&databases, Arc::new(AtomicBool::new(false)));
    let statement = Statement {
        sql: "SELECT ?1".into(),
        parameters: vec![Value::Blob(vec![1; 32 * 1024]); 27],
    };
    let bytes = request_bytes(std::slice::from_ref(&statement), &databases[0]);
    let capacity = MAX_BYTES / bytes;
    let mut pending = Vec::new();
    for index in 0..capacity {
        pending.push(
            mailbox
                .enqueue(
                    scoped_context(&format!("db-{}", index / 2 + 1), index as u128 + 1),
                    Mode::Write,
                    Operation::Execute {
                        mode: Mode::Write,
                        statements: vec![statement.clone()],
                    },
                )
                .unwrap(),
        );
    }
    assert_eq!(mailbox.0.usage.lock().bytes, capacity * bytes);
    assert_eq!(
        code(mailbox.enqueue(
            scoped_context("db-6", 100),
            Mode::Write,
            Operation::Execute {
                mode: Mode::Write,
                statements: vec![statement]
            },
        )),
        "OVERLOADED"
    );
    drop(receiver);
    assert!(mailbox.0.usage.lock().databases.is_empty());
    assert_eq!(mailbox.0.usage.lock().bytes, 0);
    drop(pending);
}

#[test]
fn byte_reservations_include_policy_and_typed_parameter_allocations() {
    let database = config().databases.remove(0);
    let plain = request_bytes(&[sql("SELECT 1")], &database);
    let values = Statement {
        sql: "SELECT 1".into(),
        parameters: vec![
            Value::Null,
            Value::Integer(1),
            Value::Real(1.0),
            Value::Text("abc".into()),
            Value::Blob(vec![1, 2]),
        ],
    };
    assert_eq!(request_bytes(&[values], &database), plain + 5 * 32 + 5);
    let mut expanded = database.clone();
    expanded.tokens.resize(32, expanded.tokens[0].clone());
    assert_eq!(
        request_bytes(&[sql("SELECT 1")], &expanded) - plain,
        31 * std::mem::size_of::<TokenConfig>()
    );
    let large = Statement {
        sql: "SELECT ?1".into(),
        parameters: vec![Value::Blob(vec![1; 32 * 1024]); 27],
    };
    let bytes = request_bytes(std::slice::from_ref(&large), &database);
    assert!(bytes < MAX_REQUEST_BYTES);
    let capacity = MAX_DATABASE_BYTES / bytes;
    assert!(capacity < MAX_QUEUED);
    let (mailbox, receiver) = setup();
    let mut pending = Vec::new();
    for id in 1..=capacity {
        pending.push(
            mailbox
                .enqueue(
                    context("alpha", id as u128),
                    Mode::Write,
                    Operation::Execute {
                        mode: Mode::Write,
                        statements: vec![large.clone()],
                    },
                )
                .unwrap(),
        );
    }
    assert_eq!(mailbox.0.usage.lock().bytes, capacity * bytes);
    assert_eq!(
        code(mailbox.enqueue(
            context("alpha", 100),
            Mode::Write,
            Operation::Execute {
                mode: Mode::Write,
                statements: vec![large]
            }
        )),
        "OVERLOADED"
    );
    drop(receiver);
    assert_eq!(mailbox.0.usage.lock().bytes, 0);
    drop(pending);
    let (mailbox, _receiver) = setup();
    let too_large = Statement {
        sql: "SELECT ?1".into(),
        parameters: vec![Value::Blob(vec![1; 32 * 1024]); 33],
    };
    assert_eq!(
        code(mailbox.enqueue(
            context("alpha", 1),
            Mode::Write,
            Operation::Execute {
                mode: Mode::Write,
                statements: vec![too_large]
            }
        )),
        "OVERLOADED"
    );
    assert_eq!(mailbox.0.usage.lock().count, 0);
}

#[test]
fn a_disconnected_worker_releases_the_entire_reservation_and_cancels() {
    let (mailbox, receiver) = setup();
    drop(receiver);
    let request = context("alpha", 1);
    let cancelled = request.cancelled.clone();
    assert_eq!(
        code(mailbox.enqueue(request, Mode::Write, operation())),
        "UNAVAILABLE"
    );
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(mailbox.0.usage.lock().count, 0);
    assert_eq!(mailbox.0.usage.lock().bytes, 0);
}

#[tokio::test]
async fn ready_results_still_obey_original_deadline_and_cancellation() {
    for cancelled in [false, true] {
        let (mailbox, receiver) = setup();
        let request = context("alpha", 1);
        let cancellation = request.cancelled.clone();
        let (response, deadline, guard) =
            mailbox.enqueue(request, Mode::Write, operation()).unwrap();
        let envelope = receiver.recv().unwrap();
        assert!(envelope.reply.send(Ok(Reply::Sql(empty_result()))).is_ok());
        cancellation.store(cancelled, Ordering::Release);
        let deadline = if cancelled {
            deadline
        } else {
            Instant::now() - Duration::from_millis(1)
        };
        // An already-ready oneshot is polled before timeout_at's elapsed timer.
        assert_eq!(
            code(Mailbox::receive(Ok((response, deadline, guard))).await),
            "COMMIT_UNKNOWN"
        );
        assert!(cancellation.load(Ordering::Acquire));
    }
    assert_eq!(
        code(Mailbox::receive(Err(failure("INITIAL_FAILURE"))).await),
        "INITIAL_FAILURE"
    );
}

#[tokio::test(start_paused = true)]
async fn waiting_timeout_closed_response_and_dropped_future_never_claim_rollback() {
    let (mailbox, receiver) = setup();
    let request = context("alpha", 1);
    let cancellation = request.cancelled.clone();
    let pending = mailbox.enqueue(request, Mode::Write, operation()).unwrap();
    let envelope = receiver.recv().unwrap();
    assert_eq!(code(Mailbox::receive(Ok(pending)).await), "COMMIT_UNKNOWN");
    assert!(cancellation.load(Ordering::Acquire));
    assert_eq!(mailbox.0.usage.lock().count, 1);
    drop(envelope);
    let (mailbox, receiver) = setup();
    let pending = mailbox
        .enqueue(context("alpha", 2), Mode::Write, operation())
        .unwrap();
    drop(receiver.recv().unwrap());
    assert_eq!(code(Mailbox::receive(Ok(pending)).await), "COMMIT_UNKNOWN");
    let (mailbox, receiver) = setup();
    let request = context("alpha", 3);
    let cancelled = request.cancelled.clone();
    let future = mailbox.execute(Call {
        context: request,
        mode: Mode::Write,
        statements: vec![sql("SELECT 1")],
    });
    assert_eq!(mailbox.0.usage.lock().count, 1);
    drop(future);
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(mailbox.0.usage.lock().count, 1);
    drop(receiver.recv().unwrap());
    assert_eq!(mailbox.0.usage.lock().count, 0);
}

#[tokio::test]
async fn backend_reply_types_errors_and_outcome_permissions_are_checked() {
    for case in 0..4 {
        let (mailbox, receiver) = setup();
        let future = mailbox.execute(Call {
            context: context("alpha", 1),
            mode: Mode::Write,
            statements: vec![sql("SELECT 1")],
        });
        let envelope = receiver.recv().unwrap();
        let reply = match case {
            0 => Ok(Reply::Sql(empty_result())),
            1 => Ok(Reply::Outcome(Outcome::Unknown)),
            2 => Err(failure("WORKER_ERROR")),
            _ => {
                drop(envelope);
                assert_eq!(future.await.unwrap_err().code, "COMMIT_UNKNOWN");
                continue;
            }
        };
        assert!(envelope.reply.send(reply).is_ok());
        match case {
            0 => assert_eq!(future.await.unwrap(), empty_result()),
            1 => assert_eq!(future.await.unwrap_err().code, "INVALID_BACKEND_REPLY"),
            _ => assert_eq!(future.await.unwrap_err().code, "WORKER_ERROR"),
        }
    }
    for resolve in [false, true] {
        let (mailbox, receiver) = setup();
        let future = mailbox.outcome(OutcomeCall {
            context: context("alpha", 1),
            statements: vec![sql("SELECT 1")],
            resolve_or_cancel: resolve,
        });
        let envelope = receiver.recv().unwrap();
        assert!(
            matches!(envelope.request.operation, Operation::Outcome { resolve: actual, .. } if actual == resolve)
        );
        assert!(envelope
            .reply
            .send(Ok(Reply::Outcome(Outcome::Cancelled)))
            .is_ok());
        assert_eq!(future.await.unwrap(), Outcome::Cancelled);
    }
    let (mailbox, receiver) = setup();
    let future = mailbox.outcome(OutcomeCall {
        context: context("alpha", 1),
        statements: vec![sql("SELECT 1")],
        resolve_or_cancel: false,
    });
    assert!(receiver
        .recv()
        .unwrap()
        .reply
        .send(Ok(Reply::Sql(empty_result())))
        .is_ok());
    assert_eq!(future.await.unwrap_err().code, "INVALID_BACKEND_REPLY");
    let mut cfg = config();
    cfg.databases[0].tokens[0].permissions = scap_cell::READ;
    let (mailbox, receiver) = Mailbox::new(&cfg.databases, Arc::new(AtomicBool::new(false)));
    let read = mailbox.outcome(OutcomeCall {
        context: context("alpha", 1),
        statements: vec![sql("SELECT 1")],
        resolve_or_cancel: false,
    });
    assert!(receiver
        .recv()
        .unwrap()
        .reply
        .send(Ok(Reply::Outcome(Outcome::Unknown)))
        .is_ok());
    assert_eq!(read.await.unwrap(), Outcome::Unknown);
    let write = mailbox.outcome(OutcomeCall {
        context: context("alpha", 2),
        statements: vec![sql("SELECT 1")],
        resolve_or_cancel: true,
    });
    assert_eq!(write.await.unwrap_err().code, "UNAUTHORIZED");
}

#[tokio::test(start_paused = true)]
async fn status_requires_read_scope_and_obeys_reply_type_cancellation_and_deadline() {
    let expected = DatabaseStatus {
        revision: 7,
        base_revision: 7,
        tail_entries: 0,
        tail_bytes: 0,
        suspended: true,
        cold: true,
        owner_active: false,
        archived_revision: Some(7),
    };
    let mut cfg = config();
    cfg.databases[0].tokens[0].permissions = scap_cell::READ;
    for case in 0..6 {
        let (mailbox, receiver) = Mailbox::new(&cfg.databases, Arc::new(AtomicBool::new(false)));
        let mut request = context("alpha", 1);
        let cancelled = request.cancelled.clone();
        if case == 4 {
            request.cancelled.store(true, Ordering::Release);
        }
        if case == 5 {
            request.database = "beta".into();
        }
        let future = mailbox.status(request);
        if case >= 4 {
            assert_eq!(
                future.await.unwrap_err().code,
                if case == 4 {
                    "COMMIT_UNKNOWN"
                } else {
                    "UNAUTHORIZED"
                }
            );
            assert_eq!(mailbox.0.usage.lock().count, 0);
            continue;
        }
        let envelope = receiver.recv().unwrap();
        assert!(matches!(envelope.request.operation, Operation::Status));
        assert_eq!(
            mailbox.0.usage.lock().bytes,
            request_bytes(&[], &cfg.databases[0])
        );
        if case == 3 {
            assert_eq!(future.await.unwrap_err().code, "COMMIT_UNKNOWN");
            assert!(cancelled.load(Ordering::Acquire));
            assert_eq!(mailbox.0.usage.lock().count, 1);
            drop(envelope);
            assert_eq!(mailbox.0.usage.lock().count, 0);
            continue;
        }
        let reply = match case {
            0 => Ok(Reply::Status(expected.clone())),
            1 => Ok(Reply::Outcome(Outcome::Unknown)),
            _ => Err(failure("STATUS_UNAVAILABLE")),
        };
        assert!(envelope.reply.send(reply).is_ok());
        match case {
            0 => assert_eq!(future.await.unwrap(), expected),
            1 => assert_eq!(future.await.unwrap_err().code, "INVALID_BACKEND_REPLY"),
            _ => assert_eq!(future.await.unwrap_err().code, "STATUS_UNAVAILABLE"),
        }
        assert!(cancelled.load(Ordering::Acquire));
    }
}
