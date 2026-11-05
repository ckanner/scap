use super::*;

const STATE_MAGIC: &[u8; 8] = b"SCAPCELL";
const COMMAND_MAGIC: &[u8; 8] = b"SCAPCMD!";
const OUTCOME_MAGIC: &[u8; 8] = b"SCAPOUT!";
const ARCHIVE_MAGIC: &[u8; 8] = b"SCAPARC!";
const ACTIVATION_MAGIC: &[u8; 8] = b"SCAPACT!";
const ACTIVATION_OUTCOME_MAGIC: &[u8; 8] = b"SCAPACR!";
const RETENTION_MAGIC: &[u8; 8] = b"SCAPRET!";
const RETENTION_OUTCOME_MAGIC: &[u8; 8] = b"SCAPRR!1";
const ACTIVATION_VERSION: u8 = 1;
const WIRE_VERSION: u8 = 3;
const STATE_VERSION: u8 = 4;

struct Writer(Vec<u8>);

impl Writer {
    fn raw(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u32(&mut self, value: u32) {
        self.raw(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }
    fn u128(&mut self, value: u128) {
        self.raw(&value.to_be_bytes());
    }
    fn count(&mut self, value: usize) {
        self.u64(value as u64);
    }
    fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.raw(value);
    }
    fn cell(&mut self, value: CellIdentity) {
        self.u128(value.cell_id);
        self.u64(value.cell_incarnation);
    }
    fn position(&mut self, value: Position) {
        self.u64(value.term);
        self.u64(value.index);
    }
    fn database(&mut self, value: DatabaseIdentity) {
        self.u128(value.database_id);
        self.u64(value.incarnation);
        self.u64(value.placement_generation);
    }
    fn owner(&mut self, value: OwnerToken) {
        self.u64(value.epoch);
        self.u128(value.worker_instance_id);
    }
    fn archive_ref(&mut self, value: ArchiveRef) {
        self.position(value.source);
        self.u64(value.revision);
        self.raw(&value.commit_hash);
        self.raw(&value.object_digest);
        self.u32(value.object_bytes);
        self.raw(&value.metadata_digest);
    }
    fn base(&mut self, value: Option<&RecoveryBase>) {
        self.byte(u8::from(value.is_some()));
        if let Some(value) = value {
            self.position(value.source);
            self.u64(value.revision);
            self.raw(&value.commit_hash);
            self.raw(&value.image_digest);
            self.bytes(&value.bytes);
        }
    }
    fn admission(&mut self, value: Admission) {
        self.u128(value.principal_id);
        self.u128(value.credential_id);
        self.u128(value.admission_id);
        self.u64(value.auth_epoch);
    }
    fn request_admission(&mut self, value: Admission, with_epoch: bool) {
        self.admission(value);
        if with_epoch {
            self.u64(value.request_epoch);
        }
    }
    fn retired(&mut self, value: RetiredPrefix) {
        self.u64(value.revision);
        self.raw(&value.commit_hash);
        self.position(value.source);
    }
    fn policy(&mut self, policy: &[Grant]) {
        self.count(policy.len());
        for grant in policy {
            self.u128(grant.principal_id);
            self.byte(grant.permissions);
        }
    }
    fn limits(&mut self, value: Limits) {
        for field in [
            value.max_state_bytes,
            value.max_command_bytes,
            value.max_databases,
            value.max_policy_grants,
            value.max_admin_operations,
            value.max_requests_per_database,
            value.max_transaction_bytes,
            value.max_result_bytes,
        ] {
            self.u32(field);
        }
    }
    fn ticket(&mut self, value: &CommitTicket) {
        self.u128(value.cell_id);
        self.u64(value.cell_incarnation);
        self.u128(value.database_id);
        self.u64(value.incarnation);
        self.u64(value.placement_generation);
        self.u64(value.owner_epoch);
        self.u128(value.worker_instance_id);
        self.u64(value.auth_epoch);
        self.u128(value.request_id);
        self.u64(value.predecessor);
        self.raw(&value.payload_digest);
    }
    fn commit(&mut self, value: &CommitResult) {
        self.ticket(&value.receipt.ticket);
        self.u64(value.receipt.sequence);
        self.position(value.position);
    }
    fn transaction(&mut self, value: &AcceptedTransaction, include_hash: bool, with_epoch: bool) {
        self.request_admission(value.admission, with_epoch);
        self.raw(&value.request_fingerprint);
        self.commit(&value.commit);
        self.bytes(&value.physical_changes);
        self.bytes(&value.result);
        if include_hash {
            self.raw(&value.commit_hash);
        }
    }
    fn admin_result(&mut self, value: &AdminResult) {
        match value {
            AdminResult::Created => self.byte(0),
            AdminResult::OwnerClaimed(token) => {
                self.byte(1);
                self.owner(*token);
            }
            AdminResult::OwnerActivated => self.byte(2),
            AdminResult::AuthChanged(epoch) => {
                self.byte(3);
                self.u64(*epoch);
            }
            AdminResult::Suspended(epoch) => {
                self.byte(4);
                self.u64(*epoch);
            }
            AdminResult::ArchivePublished(digest) => {
                self.byte(5);
                self.raw(digest);
            }
            AdminResult::ArchivePruned(digest) => {
                self.byte(6);
                self.raw(digest);
            }
            AdminResult::ArchiveHydrated(digest) => {
                self.byte(7);
                self.raw(digest);
            }
        }
    }
    fn outcome(&mut self, value: &Outcome) {
        match value {
            Outcome::Administrative(result) => {
                self.byte(0);
                self.admin_result(result);
            }
            Outcome::AlreadyApplied(result) => {
                self.byte(1);
                self.admin_result(result);
            }
            Outcome::Accepted(result) => {
                self.byte(2);
                self.commit(result);
            }
            Outcome::AlreadyCommitted(result) => {
                self.byte(3);
                self.commit(result);
            }
            Outcome::Cancelled => self.byte(4),
            Outcome::AlreadyCancelled => self.byte(5),
            Outcome::Rejected(reason) => {
                self.byte(6);
                self.byte(*reason as u8);
            }
            Outcome::RequestAcknowledged => self.byte(7),
            Outcome::RequestsRotated { epoch } => {
                self.byte(8);
                self.u64(*epoch);
            }
        }
    }
    fn kind(&mut self, kind: &CommandKind) {
        match kind {
            CommandKind::Create {
                operation_id,
                policy,
            } => {
                self.byte(0);
                self.u128(*operation_id);
                self.policy(policy);
            }
            CommandKind::ClaimOwner {
                operation_id,
                expected_epoch,
                worker_instance_id,
            } => {
                self.byte(1);
                self.u128(*operation_id);
                self.u64(*expected_epoch);
                self.u128(*worker_instance_id);
            }
            CommandKind::ActivateOwner {
                operation_id,
                token,
                restored_revision,
                restored_hash,
            } => {
                self.byte(2);
                self.u128(*operation_id);
                self.owner(*token);
                self.u64(*restored_revision);
                self.raw(restored_hash);
            }
            CommandKind::AuthFence {
                operation_id,
                expected_epoch,
                policy,
            } => {
                self.byte(3);
                self.u128(*operation_id);
                self.u64(*expected_epoch);
                self.policy(policy);
            }
            CommandKind::Commit {
                write,
                request_fingerprint,
                result,
            } => {
                self.byte(4);
                self.ticket(&write.ticket);
                self.bytes(&write.physical_changes);
                self.raw(request_fingerprint);
                self.bytes(result);
            }
            CommandKind::ResolveOrCancel {
                request_id,
                request_fingerprint,
            } => {
                self.byte(5);
                self.u128(*request_id);
                self.raw(request_fingerprint);
            }
            CommandKind::SuspendDb {
                operation_id,
                token,
                expected_revision,
            } => {
                self.byte(6);
                self.u128(*operation_id);
                self.owner(*token);
                self.u64(*expected_revision);
            }
            CommandKind::PublishArchive {
                operation_id,
                expected_owner,
                expected_previous,
                archive,
            } => {
                self.byte(7);
                self.u128(*operation_id);
                self.owner(*expected_owner);
                self.byte(u8::from(expected_previous.is_some()));
                if let Some(digest) = expected_previous {
                    self.raw(digest);
                }
                self.archive_ref(*archive);
            }
            CommandKind::PruneArchive {
                operation_id,
                expected_owner,
                archive_digest,
            } => {
                self.byte(8);
                self.u128(*operation_id);
                self.owner(*expected_owner);
                self.raw(archive_digest);
            }
            CommandKind::HydrateArchive {
                operation_id,
                archive,
            } => {
                self.byte(9);
                self.u128(*operation_id);
                self.bytes(archive);
            }
            CommandKind::AcknowledgeRequest {
                request_id,
                request_fingerprint,
                expected,
            } => {
                self.byte(10);
                self.u128(*request_id);
                self.raw(request_fingerprint);
                match expected {
                    RequestTerminal::Committed { sequence } => {
                        self.byte(0);
                        self.u64(*sequence);
                    }
                    RequestTerminal::Cancelled { position } => {
                        self.byte(1);
                        self.position(*position);
                    }
                }
            }
            CommandKind::RotateRequests { expected_epoch } => {
                self.byte(11);
                self.u64(*expected_epoch);
            }
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.cursor.saturating_add(N);
        let source = self
            .bytes
            .get(self.cursor..end)
            .ok_or(Error::Malformed("truncated field"))?;
        let mut value = [0; N];
        value.copy_from_slice(source);
        self.cursor = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(self.take()?))
    }
    fn count(&mut self, limit: u32) -> Result<usize, Error> {
        let value = self.u64()?;
        if value > u64::from(limit) {
            return Err(Error::Limit);
        }
        Ok(value as usize)
    }
    fn bytes(&mut self, limit: u32) -> Result<Vec<u8>, Error> {
        let count = self.count(limit)?;
        let end = self.cursor.saturating_add(count);
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(Error::Malformed("truncated bytes"))?;
        self.cursor = end;
        Ok(bytes.to_vec())
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed("invalid boolean")),
        }
    }
    fn finish(&self) -> Result<(), Error> {
        if self.cursor != self.bytes.len() {
            return Err(Error::Malformed("trailing bytes"));
        }
        Ok(())
    }
    fn cell(&mut self) -> Result<CellIdentity, Error> {
        Ok(CellIdentity {
            cell_id: self.u128()?,
            cell_incarnation: self.u64()?,
        })
    }
    fn position(&mut self) -> Result<Position, Error> {
        Ok(Position {
            term: self.u64()?,
            index: self.u64()?,
        })
    }
    fn database(&mut self) -> Result<DatabaseIdentity, Error> {
        Ok(DatabaseIdentity {
            database_id: self.u128()?,
            incarnation: self.u64()?,
            placement_generation: self.u64()?,
        })
    }
    fn owner(&mut self) -> Result<OwnerToken, Error> {
        Ok(OwnerToken {
            epoch: self.u64()?,
            worker_instance_id: self.u128()?,
        })
    }
    fn archive_ref(&mut self) -> Result<ArchiveRef, Error> {
        Ok(ArchiveRef {
            source: self.position()?,
            revision: self.u64()?,
            commit_hash: self.take()?,
            object_digest: self.take()?,
            object_bytes: self.u32()?,
            metadata_digest: self.take()?,
        })
    }
    fn base(&mut self, limit: u32) -> Result<Option<RecoveryBase>, Error> {
        if !self.boolean()? {
            return Ok(None);
        }
        Ok(Some(RecoveryBase {
            source: self.position()?,
            revision: self.u64()?,
            commit_hash: self.take()?,
            image_digest: self.take()?,
            bytes: self.bytes(limit)?,
        }))
    }
    fn admission(&mut self) -> Result<Admission, Error> {
        Ok(Admission {
            principal_id: self.u128()?,
            credential_id: self.u128()?,
            admission_id: self.u128()?,
            auth_epoch: self.u64()?,
            request_epoch: 1,
        })
    }
    fn request_admission(&mut self, with_epoch: bool) -> Result<Admission, Error> {
        let mut admission = self.admission()?;
        if with_epoch {
            admission.request_epoch = self.u64()?;
        }
        Ok(admission)
    }
    fn retired(&mut self) -> Result<RetiredPrefix, Error> {
        Ok(RetiredPrefix {
            revision: self.u64()?,
            commit_hash: self.take()?,
            source: self.position()?,
        })
    }
    fn policy(&mut self, limit: u32) -> Result<Vec<Grant>, Error> {
        let count = self.count(limit)?;
        let mut values = Vec::new();
        for _ in 0..count {
            values.push(Grant {
                principal_id: self.u128()?,
                permissions: self.byte()?,
            });
        }
        Ok(values)
    }
    fn limits(&mut self) -> Result<Limits, Error> {
        Ok(Limits {
            max_state_bytes: self.u32()?,
            max_command_bytes: self.u32()?,
            max_databases: self.u32()?,
            max_policy_grants: self.u32()?,
            max_admin_operations: self.u32()?,
            max_requests_per_database: self.u32()?,
            max_transaction_bytes: self.u32()?,
            max_result_bytes: self.u32()?,
        })
    }
    fn ticket(&mut self) -> Result<CommitTicket, Error> {
        Ok(CommitTicket {
            cell_id: self.u128()?,
            cell_incarnation: self.u64()?,
            database_id: self.u128()?,
            incarnation: self.u64()?,
            placement_generation: self.u64()?,
            owner_epoch: self.u64()?,
            worker_instance_id: self.u128()?,
            auth_epoch: self.u64()?,
            request_id: self.u128()?,
            predecessor: self.u64()?,
            payload_digest: self.take()?,
        })
    }
    fn commit(&mut self) -> Result<CommitResult, Error> {
        Ok(CommitResult {
            receipt: CommitReceipt {
                ticket: self.ticket()?,
                sequence: self.u64()?,
            },
            position: self.position()?,
        })
    }
    fn transaction(
        &mut self,
        limits: Limits,
        with_epoch: bool,
    ) -> Result<AcceptedTransaction, Error> {
        Ok(AcceptedTransaction {
            admission: self.request_admission(with_epoch)?,
            request_fingerprint: self.take()?,
            commit: self.commit()?,
            physical_changes: self.bytes(limits.max_transaction_bytes)?,
            result: self.bytes(limits.max_result_bytes)?,
            commit_hash: self.take()?,
        })
    }
    fn admin_result(&mut self) -> Result<AdminResult, Error> {
        match self.byte()? {
            0 => Ok(AdminResult::Created),
            1 => Ok(AdminResult::OwnerClaimed(self.owner()?)),
            2 => Ok(AdminResult::OwnerActivated),
            3 => Ok(AdminResult::AuthChanged(self.u64()?)),
            4 => Ok(AdminResult::Suspended(self.u64()?)),
            5 => Ok(AdminResult::ArchivePublished(self.take()?)),
            6 => Ok(AdminResult::ArchivePruned(self.take()?)),
            7 => Ok(AdminResult::ArchiveHydrated(self.take()?)),
            _ => Err(Error::Malformed("unknown administrative result")),
        }
    }
    fn outcome(&mut self) -> Result<Outcome, Error> {
        match self.byte()? {
            0 => Ok(Outcome::Administrative(self.admin_result()?)),
            1 => Ok(Outcome::AlreadyApplied(self.admin_result()?)),
            2 => Ok(Outcome::Accepted(self.commit()?)),
            3 => Ok(Outcome::AlreadyCommitted(self.commit()?)),
            4 => Ok(Outcome::Cancelled),
            5 => Ok(Outcome::AlreadyCancelled),
            6 => Ok(Outcome::Rejected(self.rejection()?)),
            7 => Ok(Outcome::RequestAcknowledged),
            8 => Ok(Outcome::RequestsRotated { epoch: self.u64()? }),
            _ => Err(Error::Malformed("unknown outcome")),
        }
    }
    fn rejection(&mut self) -> Result<Reject, Error> {
        Ok(match self.byte()? {
            0 => Reject::Invalid,
            1 => Reject::Fenced,
            2 => Reject::Unauthorized,
            3 => Reject::NotFound,
            4 => Reject::Exists,
            5 => Reject::Conflict,
            6 => Reject::Cancelled,
            7 => Reject::Capacity,
            8 => Reject::TooLarge,
            9 => Reject::Exhausted,
            10 => Reject::Cold,
            11 => Reject::Retired,
            _ => return Err(Error::Malformed("unknown rejection")),
        })
    }
    fn kind(&mut self, limit: u32) -> Result<CommandKind, Error> {
        match self.byte()? {
            0 => Ok(CommandKind::Create {
                operation_id: self.u128()?,
                policy: self.policy(limit)?,
            }),
            1 => Ok(CommandKind::ClaimOwner {
                operation_id: self.u128()?,
                expected_epoch: self.u64()?,
                worker_instance_id: self.u128()?,
            }),
            2 => Ok(CommandKind::ActivateOwner {
                operation_id: self.u128()?,
                token: self.owner()?,
                restored_revision: self.u64()?,
                restored_hash: self.take()?,
            }),
            3 => Ok(CommandKind::AuthFence {
                operation_id: self.u128()?,
                expected_epoch: self.u64()?,
                policy: self.policy(limit)?,
            }),
            4 => Ok(CommandKind::Commit {
                write: PreparedWrite {
                    ticket: self.ticket()?,
                    physical_changes: self.bytes(limit)?,
                },
                request_fingerprint: self.take()?,
                result: self.bytes(limit)?,
            }),
            5 => Ok(CommandKind::ResolveOrCancel {
                request_id: self.u128()?,
                request_fingerprint: self.take()?,
            }),
            6 => Ok(CommandKind::SuspendDb {
                operation_id: self.u128()?,
                token: self.owner()?,
                expected_revision: self.u64()?,
            }),
            7 => Ok(CommandKind::PublishArchive {
                operation_id: self.u128()?,
                expected_owner: self.owner()?,
                expected_previous: if self.boolean()? {
                    Some(self.take()?)
                } else {
                    None
                },
                archive: self.archive_ref()?,
            }),
            8 => Ok(CommandKind::PruneArchive {
                operation_id: self.u128()?,
                expected_owner: self.owner()?,
                archive_digest: self.take()?,
            }),
            9 => Ok(CommandKind::HydrateArchive {
                operation_id: self.u128()?,
                archive: self.bytes(limit)?,
            }),
            10 => Ok(CommandKind::AcknowledgeRequest {
                request_id: self.u128()?,
                request_fingerprint: self.take()?,
                expected: match self.byte()? {
                    0 => RequestTerminal::Committed {
                        sequence: self.u64()?,
                    },
                    1 => RequestTerminal::Cancelled {
                        position: self.position()?,
                    },
                    _ => return Err(Error::Malformed("unknown request terminal")),
                },
            }),
            11 => Ok(CommandKind::RotateRequests {
                expected_epoch: self.u64()?,
            }),
            _ => Err(Error::Malformed("unknown command")),
        }
    }
}

fn seal(magic: &[u8; 8], version: u8, body: Vec<u8>) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.raw(magic);
    writer.byte(version);
    writer.bytes(&body);
    let digest = payload_digest(&writer.0);
    writer.raw(&digest);
    writer.0
}

fn open<'a>(bytes: &'a [u8], magic: &[u8; 8], version: u8, limit: u32) -> Result<&'a [u8], Error> {
    if bytes.len() > limit as usize {
        return Err(Error::Limit);
    }
    if bytes.len() < 49 {
        return Err(Error::Malformed("truncated envelope"));
    }
    // The minimum envelope guard proves these fixed header bytes exist. Keep
    // fallible reads for variable fields instead of inventing impossible EOFs.
    if &bytes[..8] != magic || bytes[8] == 0 || bytes[8] > version {
        return Err(Error::Malformed("unknown format"));
    }
    let mut reader = Reader { bytes, cursor: 9 };
    let length = reader.count(limit)?;
    let end = reader.cursor.saturating_add(length);
    if end.saturating_add(32) != bytes.len() {
        return Err(Error::Malformed("envelope length mismatch"));
    }
    if payload_digest(&bytes[..end]) != bytes[end..] {
        return Err(Error::Malformed("checksum mismatch"));
    }
    Ok(&bytes[reader.cursor..end])
}

pub(super) fn encode_command(command: &Command, limits: Limits) -> Result<Vec<u8>, Error> {
    let owned = match &command.kind {
        CommandKind::Create { policy, .. } | CommandKind::AuthFence { policy, .. } => {
            policy.len().saturating_mul(17)
        }
        CommandKind::Commit { write, result, .. } => {
            write.physical_changes.len().saturating_add(result.len())
        }
        CommandKind::HydrateArchive { archive, .. } => archive.len(),
        _ => 0,
    };
    if owned > limits.max_command_bytes as usize {
        return Err(Error::Limit);
    }
    let mut writer = Writer(Vec::new());
    writer.cell(command.cell);
    writer.database(command.database);
    let version = if command.admission.request_epoch != 1 || retention_command(&command.kind) {
        WIRE_VERSION
    } else {
        2
    };
    writer.request_admission(command.admission, version >= 3);
    writer.kind(&command.kind);
    let encoded = seal(COMMAND_MAGIC, version, writer.0);
    if encoded.len() > limits.max_command_bytes as usize {
        return Err(Error::Limit);
    }
    Ok(encoded)
}

pub(super) fn decode_command(bytes: &[u8], limits: Limits) -> Result<Command, Error> {
    let mut reader = Reader {
        bytes: open(bytes, COMMAND_MAGIC, WIRE_VERSION, limits.max_command_bytes)?,
        cursor: 0,
    };
    let command = Command {
        cell: reader.cell()?,
        database: reader.database()?,
        admission: reader.request_admission(bytes[8] >= 3)?,
        kind: reader.kind(limits.max_command_bytes)?,
    };
    if bytes[8] == 1
        && matches!(
            command.kind,
            CommandKind::SuspendDb { .. }
                | CommandKind::PublishArchive { .. }
                | CommandKind::PruneArchive { .. }
                | CommandKind::HydrateArchive { .. }
        )
    {
        return Err(Error::Malformed("new command in legacy envelope"));
    }
    if bytes[8] < 3 && retention_command(&command.kind) {
        return Err(Error::Malformed("retention command in legacy envelope"));
    }
    reader.finish()?;
    Ok(command)
}

pub(super) fn encode_applied_outcome(outcome: &AppliedOutcome) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.position(outcome.position);
    writer.outcome(&outcome.outcome);
    let version = if retention_outcome(&outcome.outcome) {
        WIRE_VERSION
    } else {
        2
    };
    seal(OUTCOME_MAGIC, version, writer.0)
}

pub(super) fn decode_applied_outcome(
    bytes: &[u8],
    expected: Position,
) -> Result<AppliedOutcome, Error> {
    let mut reader = Reader {
        bytes: open(
            bytes,
            OUTCOME_MAGIC,
            WIRE_VERSION,
            MAX_APPLIED_OUTCOME_BYTES,
        )?,
        cursor: 0,
    };
    let outcome = AppliedOutcome {
        position: reader.position()?,
        outcome: reader.outcome()?,
    };
    reader.finish()?;
    if bytes[8] == 1 && newer_outcome(&outcome.outcome) {
        return Err(Error::Malformed("new outcome in legacy envelope"));
    }
    if bytes[8] < 3 && retention_outcome(&outcome.outcome) {
        return Err(Error::Malformed("retention outcome in legacy envelope"));
    }
    if expected.term == 0 || expected.index == 0 || outcome.position != expected {
        return Err(Error::Position);
    }
    Ok(outcome)
}

pub(super) fn is_history_activation(bytes: &[u8]) -> bool {
    bytes.starts_with(ACTIVATION_MAGIC)
}

pub(super) fn encode_history_activation(cell: CellIdentity, administrator: u128) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.cell(cell);
    writer.u128(administrator);
    seal(ACTIVATION_MAGIC, ACTIVATION_VERSION, writer.0)
}

pub(super) fn decode_history_activation(bytes: &[u8]) -> Result<(CellIdentity, u128), Error> {
    let mut reader = Reader {
        bytes: open(
            bytes,
            ACTIVATION_MAGIC,
            ACTIVATION_VERSION,
            MAX_APPLIED_OUTCOME_BYTES,
        )?,
        cursor: 0,
    };
    let cell = reader.cell()?;
    let administrator = reader.u128()?;
    reader.finish()?;
    Ok((cell, administrator))
}

pub(super) fn encode_history_activation_outcome(outcome: &HistoryActivationOutcome) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.cell(outcome.cell);
    writer.position(outcome.position);
    writer.byte(u8::from(outcome.result.is_ok()));
    if let Err(reason) = outcome.result {
        writer.byte(reason as u8);
    }
    seal(ACTIVATION_OUTCOME_MAGIC, ACTIVATION_VERSION, writer.0)
}

pub(super) fn decode_history_activation_outcome(
    bytes: &[u8],
    expected_cell: CellIdentity,
    expected: Position,
) -> Result<HistoryActivationOutcome, Error> {
    let mut reader = Reader {
        bytes: open(
            bytes,
            ACTIVATION_OUTCOME_MAGIC,
            ACTIVATION_VERSION,
            MAX_APPLIED_OUTCOME_BYTES,
        )?,
        cursor: 0,
    };
    let cell = reader.cell()?;
    let position = reader.position()?;
    let result = if reader.boolean()? {
        Ok(())
    } else {
        Err(reader.rejection()?)
    };
    reader.finish()?;
    if cell != expected_cell || cell.cell_id == 0 || cell.cell_incarnation == 0 {
        return Err(Error::Binding);
    }
    if expected.term == 0 || expected.index == 0 || position != expected {
        return Err(Error::Position);
    }
    Ok(HistoryActivationOutcome {
        cell,
        position,
        result,
    })
}

pub(super) fn is_retention_activation(bytes: &[u8]) -> bool {
    bytes.starts_with(RETENTION_MAGIC)
}

pub(super) fn encode_retention_activation(cell: CellIdentity, administrator: u128) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.cell(cell);
    writer.u128(administrator);
    seal(RETENTION_MAGIC, ACTIVATION_VERSION, writer.0)
}

pub(super) fn decode_retention_activation(bytes: &[u8]) -> Result<(CellIdentity, u128), Error> {
    let mut reader = Reader {
        bytes: open(
            bytes,
            RETENTION_MAGIC,
            ACTIVATION_VERSION,
            MAX_APPLIED_OUTCOME_BYTES,
        )?,
        cursor: 0,
    };
    let cell = reader.cell()?;
    let administrator = reader.u128()?;
    reader.finish()?;
    Ok((cell, administrator))
}

pub(super) fn encode_retention_activation_outcome(outcome: &RetentionActivationOutcome) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.cell(outcome.cell);
    writer.position(outcome.position);
    writer.byte(u8::from(outcome.result.is_ok()));
    if let Err(reason) = outcome.result {
        writer.byte(reason as u8);
    }
    seal(RETENTION_OUTCOME_MAGIC, ACTIVATION_VERSION, writer.0)
}

pub(super) fn decode_retention_activation_outcome(
    bytes: &[u8],
    expected_cell: CellIdentity,
    expected: Position,
) -> Result<RetentionActivationOutcome, Error> {
    let mut reader = Reader {
        bytes: open(
            bytes,
            RETENTION_OUTCOME_MAGIC,
            ACTIVATION_VERSION,
            MAX_APPLIED_OUTCOME_BYTES,
        )?,
        cursor: 0,
    };
    let cell = reader.cell()?;
    let position = reader.position()?;
    let result = if reader.boolean()? {
        Ok(())
    } else {
        Err(reader.rejection()?)
    };
    reader.finish()?;
    if cell != expected_cell || cell.cell_id == 0 || cell.cell_incarnation == 0 {
        return Err(Error::Binding);
    }
    if expected.term == 0 || expected.index == 0 || position != expected {
        return Err(Error::Position);
    }
    Ok(RetentionActivationOutcome {
        cell,
        position,
        result,
    })
}

fn newer_outcome(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Administrative(
            AdminResult::Suspended(_)
                | AdminResult::ArchivePublished(_)
                | AdminResult::ArchivePruned(_)
                | AdminResult::ArchiveHydrated(_)
        ) | Outcome::AlreadyApplied(
            AdminResult::Suspended(_)
                | AdminResult::ArchivePublished(_)
                | AdminResult::ArchivePruned(_)
                | AdminResult::ArchiveHydrated(_)
        ) | Outcome::Rejected(Reject::Cold)
    )
}

fn retention_command(kind: &CommandKind) -> bool {
    matches!(
        kind,
        CommandKind::AcknowledgeRequest { .. } | CommandKind::RotateRequests { .. }
    )
}

fn retention_outcome(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::RequestAcknowledged
            | Outcome::RequestsRotated { .. }
            | Outcome::Rejected(Reject::Retired)
    )
}

pub(super) fn admin_digest(command: &Command) -> [u8; 32] {
    let mut writer = Writer(Vec::new());
    writer.raw(b"SCAP administrative intent v1");
    writer.cell(command.cell);
    writer.database(command.database);
    writer.u128(command.admission.principal_id);
    writer.kind(&command.kind);
    payload_digest(&writer.0)
}

pub(super) fn transaction_hash(previous: [u8; 32], transaction: &AcceptedTransaction) -> [u8; 32] {
    let mut writer = Writer(Vec::new());
    let scoped = transaction.admission.request_epoch != 1;
    writer.raw(if scoped {
        b"SCAP accepted transaction v2"
    } else {
        b"SCAP accepted transaction v1"
    });
    writer.raw(&previous);
    writer.transaction(transaction, false, scoped);
    payload_digest(&writer.0)
}

pub(super) fn archive_metadata(database: &Database) -> [u8; 32] {
    let mut writer = Writer(Vec::new());
    // Epoch 1 is byte-identical to old published archive coverage. Mutable
    // acknowledgement state is deliberately not part of physical coverage.
    let scoped = database.request_epoch != 1;
    writer.raw(if scoped {
        b"SCAP archive retained metadata v2"
    } else {
        b"SCAP archive retained metadata v1"
    });
    writer.database(database.identity);
    if scoped {
        writer.u64(database.request_epoch);
        writer.retired(database.retired);
    }
    writer.count(database.transactions.len());
    for transaction in &database.transactions {
        writer.request_admission(transaction.admission, scoped);
        writer.raw(&transaction.request_fingerprint);
        writer.commit(&transaction.commit);
        writer.bytes(&transaction.result);
        writer.raw(&transaction.commit_hash);
    }
    payload_digest(&writer.0)
}

pub(super) fn encode_archive(
    cell: CellIdentity,
    database: &Database,
    source: Position,
    physical_history_version: u8,
) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.cell(cell);
    writer.database(database.identity);
    writer.position(source);
    if physical_history_version >= 4 {
        writer.u64(database.request_epoch);
        writer.retired(database.retired);
    }
    writer.count(database.transactions.len());
    for transaction in &database.transactions {
        writer.transaction(transaction, true, physical_history_version >= 4);
    }
    if physical_history_version >= 3 {
        writer.base(database.base.as_ref());
    }
    seal(ARCHIVE_MAGIC, physical_history_version, writer.0)
}

pub(super) struct RestoredArchive {
    pub base: Option<RecoveryBase>,
    pub transactions: Vec<AcceptedTransaction>,
}

pub(super) fn decode_archive(
    bytes: &[u8],
    cell: CellIdentity,
    database: &Database,
    archive: ArchiveRef,
    limits: Limits,
    physical_history_version: u8,
) -> Result<RestoredArchive, Error> {
    let mut reader = Reader {
        bytes: open(
            bytes,
            ARCHIVE_MAGIC,
            physical_history_version,
            limits.max_command_bytes,
        )?,
        cursor: 0,
    };
    if bytes[8] < 2 {
        return Err(Error::Malformed("unknown archive version"));
    }
    if reader.cell()? != cell
        || reader.database()? != database.identity
        || reader.position()? != archive.source
    {
        return Err(Error::Binding);
    }
    if bytes[8] >= 4 {
        if reader.u64()? != database.request_epoch || reader.retired()? != database.retired {
            return Err(Error::Binding);
        }
    } else if database.request_epoch != 1 || database.retired != RetiredPrefix::EMPTY {
        return Err(Error::Binding);
    }
    let count = reader.count(limits.max_requests_per_database)?;
    if count != database.transactions.len() {
        return Err(Error::Binding);
    }
    let mut transactions = Vec::new();
    for retained in &database.transactions {
        let transaction = reader.transaction(limits, bytes[8] >= 4)?;
        if transaction.admission != retained.admission
            || transaction.request_fingerprint != retained.request_fingerprint
            || transaction.commit != retained.commit
            || transaction.result != retained.result
            || transaction.commit_hash != retained.commit_hash
        {
            return Err(Error::Binding);
        }
        transactions.push(transaction);
    }
    let base = if bytes[8] >= 3 {
        reader.base(limits.max_state_bytes)?
    } else {
        None
    };
    reader.finish()?;
    let mut restored = Database {
        transactions,
        base,
        cold: false,
        ..database.clone()
    };
    validate_base(&restored, cell, archive.source, limits)?;
    // The payload replaces the resident base. An absent base is valid only
    // before SQL history has been retired; validate that anchor before any
    // relative tail indexing, including archives with no retained transactions.
    validate_retirement(&restored, archive.source)?;
    let mut previous = restored.retired.commit_hash;
    for (index, transaction) in restored.transactions.iter().enumerate() {
        if index < restored.tail_start() {
            if !transaction.physical_changes.is_empty() {
                return Err(Error::Binding);
            }
        } else if transaction.physical_changes.is_empty()
            || payload_digest(&transaction.physical_changes)
                != transaction.commit.receipt.ticket.payload_digest
            || transaction_hash(previous, transaction) != transaction.commit_hash
        {
            return Err(Error::Binding);
        }
        previous = transaction.commit_hash;
    }
    if bytes[8] == 2 && physical_history_version >= 3 {
        restored
            .migrate_legacy(cell, limits)
            .map_err(|_| Error::Binding)?;
    } else if bytes[8] >= 3 && restored.compaction_due(limits) {
        return Err(Error::Malformed("archive physical tail exceeds v3 bound"));
    }
    Ok(RestoredArchive {
        base: restored.base,
        transactions: restored.transactions,
    })
}

pub(super) fn encode_state(state: &CellState, include_outcome: bool) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.cell(state.identity);
    writer.limits(state.limits);
    writer.u128(state.bootstrap_admin);
    writer.position(state.position);
    writer.count(state.databases.len());
    for database in state.databases.values() {
        writer.database(database.identity);
        writer.u64(database.auth_epoch);
        writer.owner(database.owner);
        writer.byte(u8::from(database.active));
        writer.policy(&database.policy);
        if state.physical_history_version >= 4 {
            writer.u64(database.request_epoch);
            writer.retired(database.retired);
            writer.byte(u8::from(database.retirement_position.is_some()));
            if let Some(position) = database.retirement_position {
                writer.position(position);
            }
        }
        writer.count(database.transactions.len());
        for transaction in &database.transactions {
            writer.transaction(transaction, true, state.physical_history_version >= 4);
        }
        writer.count(database.requests.len());
        for (&request, record) in &database.requests {
            writer.u128(request);
            match record {
                RequestRecord::Accepted(sequence) => {
                    writer.byte(0);
                    writer.u64(*sequence);
                }
                RequestRecord::Cancelled {
                    admission,
                    fingerprint,
                    position,
                } => {
                    writer.byte(1);
                    writer.request_admission(*admission, state.physical_history_version >= 4);
                    writer.raw(fingerprint);
                    writer.position(*position);
                }
            }
        }
        writer.byte(u8::from(database.suspended));
        writer.byte(u8::from(database.cold));
        writer.byte(u8::from(database.archive.is_some()));
        if let Some(archive) = database.archive {
            writer.archive_ref(archive);
        }
        if state.physical_history_version >= 3 {
            writer.base(database.base.as_ref());
        }
        if state.physical_history_version >= 4 {
            writer.count(database.acknowledged.len());
            for (&request_id, &position) in &database.acknowledged {
                writer.u128(request_id);
                writer.position(position);
            }
        }
    }
    writer.count(state.administration.len());
    for (&operation, record) in &state.administration {
        writer.u128(operation);
        writer.request_admission(record.admission, state.physical_history_version >= 4);
        writer.database(record.database);
        writer.raw(&record.digest);
        writer.admin_result(&record.result);
        writer.position(record.position);
    }
    let last = if include_outcome {
        state.last_outcome.as_ref()
    } else {
        None
    };
    if let Some(last) = last {
        writer.byte(1);
        writer.position(last.position);
        writer.outcome(&last.outcome);
    } else {
        writer.byte(0);
    }
    seal(STATE_MAGIC, state.physical_history_version, writer.0)
}

pub(super) fn decode_state(
    bytes: &[u8],
    identity: CellIdentity,
    limits: Limits,
) -> Result<CellState, Error> {
    validate_config(identity, limits)?;
    let mut reader = Reader {
        bytes: open(bytes, STATE_MAGIC, STATE_VERSION, limits.max_state_bytes)?,
        cursor: 0,
    };
    let actual_identity = reader.cell()?;
    let actual_limits = reader.limits()?;
    if actual_identity != identity || actual_limits != limits {
        return Err(Error::Binding);
    }
    let mut state = CellState {
        identity,
        limits,
        bootstrap_admin: reader.u128()?,
        physical_history_version: bytes[8].max(2),
        position: reader.position()?,
        databases: BTreeMap::new(),
        administration: BTreeMap::new(),
        last_outcome: None,
    };
    let count = reader.count(limits.max_databases)?;
    for _ in 0..count {
        let identity = reader.database()?;
        let mut database = Database {
            identity,
            auth_epoch: reader.u64()?,
            owner: reader.owner()?,
            active: reader.boolean()?,
            policy: reader.policy(limits.max_policy_grants)?,
            transactions: Vec::new(),
            requests: BTreeMap::new(),
            suspended: false,
            cold: false,
            archive: None,
            base: None,
            request_epoch: 1,
            retired: RetiredPrefix::EMPTY,
            retirement_position: None,
            acknowledged: BTreeMap::new(),
        };
        if bytes[8] >= 4 {
            database.request_epoch = reader.u64()?;
            database.retired = reader.retired()?;
            if reader.boolean()? {
                database.retirement_position = Some(reader.position()?);
            }
        }
        let count = reader.count(limits.max_requests_per_database)?;
        for _ in 0..count {
            database
                .transactions
                .push(reader.transaction(limits, bytes[8] >= 4)?);
        }
        let count = reader.count(limits.max_requests_per_database)?;
        for _ in 0..count {
            let request = reader.u128()?;
            let record = match reader.byte()? {
                0 => RequestRecord::Accepted(reader.u64()?),
                1 => RequestRecord::Cancelled {
                    admission: reader.request_admission(bytes[8] >= 4)?,
                    fingerprint: reader.take()?,
                    position: reader.position()?,
                },
                _ => return Err(Error::Malformed("unknown request record")),
            };
            if database.requests.insert(request, record).is_some() {
                return Err(Error::Malformed("duplicate request"));
            }
        }
        if bytes[8] >= 2 {
            database.suspended = reader.boolean()?;
            database.cold = reader.boolean()?;
            if reader.boolean()? {
                database.archive = Some(reader.archive_ref()?);
            }
        }
        if bytes[8] >= 3 {
            database.base = reader.base(limits.max_state_bytes)?;
        }
        if bytes[8] >= 4 {
            let count = reader.count(limits.max_requests_per_database)?;
            for _ in 0..count {
                let request = reader.u128()?;
                let position = reader.position()?;
                if database.acknowledged.insert(request, position).is_some() {
                    return Err(Error::Malformed("duplicate request acknowledgement"));
                }
            }
        }
        if state
            .databases
            .insert(identity.database_id, database)
            .is_some()
        {
            return Err(Error::Malformed("duplicate database"));
        }
    }
    let count = reader.count(limits.max_admin_operations)?;
    for _ in 0..count {
        let operation = reader.u128()?;
        let record = AdminRecord {
            admission: reader.request_admission(bytes[8] >= 4)?,
            database: reader.database()?,
            digest: reader.take()?,
            result: reader.admin_result()?,
            position: reader.position()?,
        };
        if bytes[8] == 1 && newer_outcome(&Outcome::Administrative(record.result.clone())) {
            return Err(Error::Malformed(
                "new administrative result in legacy state",
            ));
        }
        if state.administration.insert(operation, record).is_some() {
            return Err(Error::Malformed("duplicate administrative operation"));
        }
    }
    // Preserve the original envelope's rejection reserve before any rewrite.
    if reader
        .cursor
        .saturating_add(50)
        .saturating_add(RESERVED_BYTES)
        > limits.max_state_bytes as usize
    {
        return Err(Error::Limit);
    }
    if reader.boolean()? {
        let outcome = AppliedOutcome {
            position: reader.position()?,
            outcome: reader.outcome()?,
        };
        if bytes[8] == 1 && newer_outcome(&outcome.outcome) {
            return Err(Error::Malformed("new outcome in legacy state"));
        }
        if bytes[8] < 4 && retention_outcome(&outcome.outcome) {
            return Err(Error::Malformed("retention outcome in legacy state"));
        }
        state.last_outcome = Some(outcome);
    }
    reader.finish()?;
    validate_state(&state)?;
    for database in state.databases.values() {
        if bytes[8] >= 3 && !database.cold && database.compaction_due(limits) {
            return Err(Error::Malformed("physical tail exceeds v3 bound"));
        }
    }
    if !state.fits() {
        return Err(Error::Limit);
    }
    Ok(state)
}
