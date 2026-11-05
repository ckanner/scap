use super::*;

fn select() -> Vec<Statement> {
    vec![Statement {
        sql: "SELECT 42".into(),
        parameters: vec![],
    }]
}

#[test]
fn every_query_gets_new_authority_and_does_not_propose_a_transaction() {
    let kit = Kit::new();
    let factory = kit.factory();
    let effect = factory.effect.clone();
    let mut writer = kit.recover(factory, limits()).unwrap();
    let before = kit.port.0.borrow().state.encode();
    let head = writer.head();
    for _ in 0..2 {
        let completed = writer.query(kit.context.clone(), &select()).unwrap();
        assert_eq!(completed.position, kit.port.0.borrow().state.position());
        assert_eq!(completed.revision, head.revision);
        assert_eq!(completed.commit_hash, [0; 32]);
        assert_eq!(writer.head(), head);
        assert!(!writer.is_stopped());
    }
    assert_eq!(effect.borrow().query_calls, 2);
    assert_eq!(kit.port.0.borrow().reads, 5);
    assert_eq!(kit.port.0.borrow().proposals, 2);
    assert_eq!(kit.port.0.borrow().state.encode(), before);
}

#[test]
fn request_epoch_retirement_does_not_revoke_an_authorized_strong_read() {
    let kit = Kit::new();
    let factory = kit.factory();
    let effect = factory.effect.clone();
    let mut writer = kit.recover(factory, limits()).unwrap();
    {
        let state = &mut kit.port.0.borrow_mut().state;
        apply_data(
            state,
            scap_cell::encode_retention_activation(identity().cell, 11),
        );
        apply(
            state,
            CommandKind::ResolveOrCancel {
                request_id: 55,
                request_fingerprint: [9; 32],
            },
        );
        let cancelled = state.position();
        apply(
            state,
            CommandKind::AcknowledgeRequest {
                request_id: 55,
                request_fingerprint: [9; 32],
                expected: scap_cell::RequestTerminal::Cancelled {
                    position: cancelled,
                },
            },
        );
        apply(state, CommandKind::RotateRequests { expected_epoch: 1 });
        assert_eq!(
            state
                .database(identity().database.database_id)
                .unwrap()
                .request_epoch,
            2
        );
    }
    assert_eq!(kit.context.admission.request_epoch, 1);
    let result = writer.query(kit.context.clone(), &select()).unwrap();
    assert_eq!(result.revision, 0);
    assert_eq!(result.position, kit.port.0.borrow().state.position());
    assert_eq!(effect.borrow().query_calls, 1);
    assert_eq!(kit.port.0.borrow().proposals, 2);
    assert!(!writer.is_stopped());
}

#[test]
fn stale_local_identity_revision_or_digest_cannot_serve_a_strong_read() {
    for case in 0..3 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        let mut writer = kit.recover(factory, limits()).unwrap();
        match case {
            0 => writer.engine.head.identity.database.incarnation += 1,
            1 => writer.engine.head.revision += 1,
            _ => writer.engine.head.image_digest[0] ^= 1,
        }
        assert!(matches!(
            writer.query(kit.context.clone(), &select()),
            Err(Error::Image(scap_engine::Error::Head))
        ));
        assert_eq!(effect.borrow().query_calls, 0);
        assert!(writer.is_stopped());
        assert!(matches!(
            writer.query(kit.context.clone(), &select()),
            Err(Error::Stopped)
        ));
    }
}

#[test]
fn lost_quorum_changed_owner_and_revoked_read_authority_block_native_queries() {
    for case in 0..4 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        let mut writer = kit.recover(factory, limits()).unwrap();
        match case {
            0 => {
                kit.port.0.borrow_mut().fail_reads.insert(4);
            }
            1 => apply(
                &mut kit.port.0.borrow_mut().state,
                CommandKind::ClaimOwner {
                    operation_id: 20,
                    expected_epoch: 1,
                    worker_instance_id: 88,
                },
            ),
            2 => apply(
                &mut kit.port.0.borrow_mut().state,
                CommandKind::AuthFence {
                    operation_id: 20,
                    expected_epoch: 1,
                    policy: vec![Grant {
                        principal_id: 11,
                        permissions: WRITE | ADMIN,
                    }],
                },
            ),
            _ => kit.context.cancelled.store(true, Ordering::Release),
        }
        let mut context = kit.context.clone();
        if case == 2 {
            context.admission.auth_epoch = 2;
        }
        let error = writer.query(context, &select()).unwrap_err();
        match case {
            0 => assert!(matches!(
                error,
                Error::Client(scap_cell_client::Error::Unknown)
            )),
            1 => assert!(matches!(error, Error::Rejected(Reject::Fenced))),
            2 => assert!(matches!(error, Error::Rejected(Reject::Unauthorized))),
            _ => assert!(matches!(error, Error::Unknown)),
        }
        assert_eq!(effect.borrow().query_calls, 0);
        assert!(writer.is_stopped());
        assert_eq!(kit.port.0.borrow().proposals, 2);
    }
}

#[test]
fn an_invalid_physical_history_is_rejected_even_when_cell_bytes_are_valid() {
    let kit = Kit::new();
    let factory = kit.factory();
    let effect = factory.effect.clone();
    let mut writer = kit.recover(factory, limits()).unwrap();
    let physical_changes = vec![1];
    let ticket = CommitTicket {
        cell_id: identity().cell.cell_id,
        cell_incarnation: identity().cell.cell_incarnation,
        database_id: identity().database.database_id,
        incarnation: identity().database.incarnation,
        placement_generation: identity().database.placement_generation,
        owner_epoch: writer.owner().epoch,
        worker_instance_id: writer.owner().worker_instance_id,
        auth_epoch: 1,
        request_id: 55,
        predecessor: 0,
        payload_digest: scap_cell::payload_digest(&physical_changes),
    };
    apply(
        &mut kit.port.0.borrow_mut().state,
        CommandKind::Commit {
            write: scap_core::PreparedWrite {
                ticket,
                physical_changes,
            },
            request_fingerprint: [9; 32],
            result: vec![],
        },
    );
    assert_eq!(
        kit.port
            .0
            .borrow()
            .state
            .database(identity().database.database_id)
            .unwrap()
            .revision,
        1
    );
    assert!(matches!(
        writer.query(kit.context.clone(), &select()),
        Err(Error::Image(_))
    ));
    assert_eq!(effect.borrow().query_calls, 0);
}

#[test]
fn interrupted_failed_or_mutating_engines_never_release_a_read_result() {
    for mode in 1..=6 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        let mut writer = kit.recover(factory, limits()).unwrap();
        effect.borrow_mut().query_mode = mode;
        let error = writer.query(kit.context.clone(), &select()).unwrap_err();
        match mode {
            1 => assert!(matches!(
                error,
                Error::Native(scap_sqlite::Error::InvalidSql)
            )),
            2 | 3 => assert!(matches!(
                error,
                Error::Native(scap_sqlite::Error::Interrupted)
            )),
            4 | 5 => assert!(matches!(error, Error::Image(scap_engine::Error::Head))),
            _ => assert!(matches!(error, Error::Unknown)),
        }
        assert_eq!(effect.borrow().query_calls, 1);
        assert!(writer.is_stopped());
    }
}

#[test]
fn physical_native_queries_need_read_permission_without_write_and_keep_original_head() {
    let kit = Kit::new();
    let directory = Directory::new();
    let mut writer = Writer::recover(
        kit.client(),
        &kit.context,
        kit.request,
        &directory.0,
        limits(),
        kit.clock.clone(),
    )
    .unwrap();
    writer
        .execute(
            kit.context.clone(),
            55,
            &[
                Statement {
                    sql: "CREATE TABLE items(value BLOB)".into(),
                    parameters: vec![],
                },
                Statement {
                    sql: "INSERT INTO items VALUES(randomblob(8))".into(),
                    parameters: vec![],
                },
            ],
        )
        .unwrap();
    let expected_hash = kit
        .port
        .0
        .borrow()
        .state
        .database(identity().database.database_id)
        .unwrap()
        .commit_hash;
    let before = writer.head();
    apply(
        &mut kit.port.0.borrow_mut().state,
        CommandKind::AuthFence {
            operation_id: 20,
            expected_epoch: 1,
            policy: vec![
                Grant {
                    principal_id: 11,
                    permissions: READ,
                },
                Grant {
                    principal_id: 12,
                    permissions: READ | WRITE | ADMIN,
                },
            ],
        },
    );
    let mut context = kit.context.clone();
    context.admission.auth_epoch = 2;
    let query = [Statement {
        sql: "SELECT value FROM items".into(),
        parameters: vec![],
    }];
    let first = writer.query(context.clone(), &query).unwrap();
    let second = writer.query(context.clone(), &query).unwrap();
    assert_eq!(first.result, second.result);
    assert_eq!(first.revision, before.revision);
    assert_eq!(first.commit_hash, expected_hash);
    assert_eq!(first.position, kit.port.0.borrow().state.position());
    assert_eq!(writer.head(), before);
    assert!(!writer.is_stopped());
    assert_eq!(kit.port.0.borrow().proposals, 3);
    assert!(matches!(
        writer.execute(context, 56, &select()),
        Err(Error::Native(scap_sqlite::Error::Rejected(
            scap_core::Rejection::Unauthorized
        )))
    ));
}

#[test]
fn native_recovery_and_strong_reads_use_the_folded_base_and_keep_original_results() {
    let mut kit = Kit::new();
    let first_directory = Directory::new();
    let mut writer = Writer::recover(
        kit.client(),
        &kit.context,
        kit.request,
        &first_directory.0,
        limits(),
        kit.clock.clone(),
    )
    .unwrap();
    writer
        .execute(
            kit.context.clone(),
            100,
            &[Statement {
                sql: "CREATE TABLE items(value INTEGER)".into(),
                parameters: vec![],
            }],
        )
        .unwrap();
    let insert = [Statement {
        sql: "INSERT INTO items VALUES(7) RETURNING value".into(),
        parameters: vec![],
    }];
    let original = writer.execute(kit.context.clone(), 101, &insert).unwrap();
    for request_id in 102..=108 {
        writer
            .execute(kit.context.clone(), request_id, &insert)
            .unwrap();
    }
    let head = writer.head();
    {
        let state = &mut kit.port.0.borrow_mut().state;
        let view = state.database(identity().database.database_id).unwrap();
        assert_eq!(view.revision, 9);
        assert_eq!(view.base_revision, 8);
        assert_eq!(view.tail_entries, 1);
        assert!(view.tail_bytes > 0);
        apply(
            state,
            CommandKind::ResolveOrCancel {
                request_id: 109,
                request_fingerprint: [5; 32],
            },
        );
        apply(
            state,
            CommandKind::AuthFence {
                operation_id: 20,
                expected_epoch: 1,
                policy: vec![Grant {
                    principal_id: 11,
                    permissions: READ | WRITE | ADMIN,
                }],
            },
        );
    }
    assert!(matches!(
        writer.query(kit.context.clone(), &select()),
        Err(Error::Rejected(Reject::Unauthorized))
    ));
    assert!(writer.is_stopped());
    drop(writer);

    kit.context.admission.auth_epoch = 2;
    kit.request.expected_owner_epoch = 1;
    kit.request.worker_instance_id = 88;
    kit.request.claim_operation_id = 21;
    kit.request.activate_operation_id = 22;
    let recovered_directory = Directory::new();
    let mut recovered = Writer::recover(
        kit.client(),
        &kit.context,
        kit.request,
        &recovered_directory.0,
        limits(),
        kit.clock.clone(),
    )
    .unwrap();
    assert_eq!(recovered.head(), head);
    assert_eq!(recovered.owner().epoch, 2);
    let before = kit.port.0.borrow().state.encode();
    let query = [Statement {
        sql: "SELECT count(*), sum(value) FROM items".into(),
        parameters: vec![],
    }];
    let read = recovered.query(kit.context.clone(), &query).unwrap();
    assert_eq!(
        read.result.statements[0].rows,
        vec![vec![Value::Integer(8), Value::Integer(56)]]
    );
    assert_eq!(read.revision, 9);
    assert_eq!(kit.port.0.borrow().state.encode(), before);
    assert!(matches!(
        kit.port
            .0
            .borrow()
            .state
            .lookup(identity().database, kit.context.admission, 109, [5; 32])
            .unwrap(),
        scap_cell::Lookup::Cancelled { .. }
    ));
    let replay = recovered
        .execute(kit.context.clone(), 101, &insert)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.receipt, original.receipt);
    assert_eq!(replay.result, original.result);
    assert!(recovered.is_stopped());
    assert_eq!(kit.port.0.borrow().state.encode(), before);
}

#[test]
fn legacy_write_only_engines_fail_closed_for_the_new_query_api() {
    struct Legacy;
    impl Engine for Legacy {
        fn head(&self) -> Head {
            Image::empty(identity(), limits().engine).unwrap().head()
        }
        fn is_stopped(&self) -> bool {
            false
        }
        fn execute(
            &mut self,
            _: CommitTicket,
            _: &[Statement],
        ) -> Result<Completed, scap_sqlite::Error> {
            Err(scap_sqlite::Error::ReadUnsupported)
        }
    }
    assert!(matches!(
        Legacy.query(&select(), Arc::new(|| false)),
        Err(scap_sqlite::Error::ReadUnsupported)
    ));
}

#[test]
fn physical_history_verification_cannot_restart_the_original_read_deadline() {
    struct PhaseClock {
        base: Instant,
        calls: AtomicUsize,
        expires: usize,
    }
    impl Clock for PhaseClock {
        fn now(&self) -> Result<ClockReading, scap_raft_runtime::Error> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(ClockReading {
                instant: self.base + Duration::from_secs(if call >= self.expires { 60 } else { 0 }),
                unix_seconds: 1,
            })
        }
    }
    // The cell port retains its own clock so this isolates time spent outside
    // consensus: entry, physical-history verification, native guard and return.
    for expires in 1..=4 {
        let kit = Kit::new();
        let factory = kit.factory();
        let effect = factory.effect.clone();
        let mut writer = kit.recover(factory, limits()).unwrap();
        writer.clock = Arc::new(PhaseClock {
            base: kit.clock.base,
            calls: AtomicUsize::new(0),
            expires,
        });
        let error = writer.query(kit.context.clone(), &select()).unwrap_err();
        if expires == 3 {
            assert!(matches!(
                error,
                Error::Native(scap_sqlite::Error::Interrupted)
            ));
        } else {
            assert!(matches!(error, Error::Unknown));
        }
        assert_eq!(effect.borrow().query_calls, usize::from(expires > 2));
        assert!(writer.is_stopped());
        assert_eq!(kit.port.0.borrow().proposals, 2);
    }
}
