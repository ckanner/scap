use super::*;

const STATE_MAGIC: &[u8; 8] = b"SCAPCELL";
const COMMAND_MAGIC: &[u8; 8] = b"SCAPCMD!";
const VERSION: u8 = 1;

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
    fn admission(&mut self, value: Admission) {
        self.u128(value.principal_id);
        self.u128(value.credential_id);
        self.u128(value.admission_id);
        self.u64(value.auth_epoch);
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
    fn transaction(&mut self, value: &AcceptedTransaction, include_hash: bool) {
        self.admission(value.admission);
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
    fn admission(&mut self) -> Result<Admission, Error> {
        Ok(Admission {
            principal_id: self.u128()?,
            credential_id: self.u128()?,
            admission_id: self.u128()?,
            auth_epoch: self.u64()?,
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
    fn transaction(&mut self, limits: Limits) -> Result<AcceptedTransaction, Error> {
        Ok(AcceptedTransaction {
            admission: self.admission()?,
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
            6 => Ok(Outcome::Rejected(match self.byte()? {
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
                _ => return Err(Error::Malformed("unknown rejection")),
            })),
            _ => Err(Error::Malformed("unknown outcome")),
        }
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
            _ => Err(Error::Malformed("unknown command")),
        }
    }
}

fn seal(magic: &[u8; 8], body: Vec<u8>) -> Vec<u8> {
    let mut writer = Writer(Vec::new());
    writer.raw(magic);
    writer.byte(VERSION);
    writer.bytes(&body);
    let digest = payload_digest(&writer.0);
    writer.raw(&digest);
    writer.0
}

fn open<'a>(bytes: &'a [u8], magic: &[u8; 8], limit: u32) -> Result<&'a [u8], Error> {
    if bytes.len() > limit as usize {
        return Err(Error::Limit);
    }
    if bytes.len() < 49 {
        return Err(Error::Malformed("truncated envelope"));
    }
    // The minimum envelope guard proves these fixed header bytes exist. Keep
    // fallible reads for variable fields instead of inventing impossible EOFs.
    if &bytes[..8] != magic || bytes[8] != VERSION {
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
        _ => 0,
    };
    if owned > limits.max_command_bytes as usize {
        return Err(Error::Limit);
    }
    let mut writer = Writer(Vec::new());
    writer.cell(command.cell);
    writer.database(command.database);
    writer.admission(command.admission);
    writer.kind(&command.kind);
    let encoded = seal(COMMAND_MAGIC, writer.0);
    if encoded.len() > limits.max_command_bytes as usize {
        return Err(Error::Limit);
    }
    Ok(encoded)
}

pub(super) fn decode_command(bytes: &[u8], limits: Limits) -> Result<Command, Error> {
    let mut reader = Reader {
        bytes: open(bytes, COMMAND_MAGIC, limits.max_command_bytes)?,
        cursor: 0,
    };
    let command = Command {
        cell: reader.cell()?,
        database: reader.database()?,
        admission: reader.admission()?,
        kind: reader.kind(limits.max_command_bytes)?,
    };
    reader.finish()?;
    Ok(command)
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
    writer.raw(b"SCAP accepted transaction v1");
    writer.raw(&previous);
    writer.transaction(transaction, false);
    payload_digest(&writer.0)
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
        writer.count(database.transactions.len());
        for transaction in &database.transactions {
            writer.transaction(transaction, true);
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
                    writer.admission(*admission);
                    writer.raw(fingerprint);
                    writer.position(*position);
                }
            }
        }
    }
    writer.count(state.administration.len());
    for (&operation, record) in &state.administration {
        writer.u128(operation);
        writer.admission(record.admission);
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
    seal(STATE_MAGIC, writer.0)
}

pub(super) fn decode_state(
    bytes: &[u8],
    identity: CellIdentity,
    limits: Limits,
) -> Result<CellState, Error> {
    validate_config(identity, limits)?;
    let mut reader = Reader {
        bytes: open(bytes, STATE_MAGIC, limits.max_state_bytes)?,
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
        };
        let count = reader.count(limits.max_requests_per_database)?;
        for _ in 0..count {
            database.transactions.push(reader.transaction(limits)?);
        }
        let count = reader.count(limits.max_requests_per_database)?;
        for _ in 0..count {
            let request = reader.u128()?;
            let record = match reader.byte()? {
                0 => RequestRecord::Accepted(reader.u64()?),
                1 => RequestRecord::Cancelled {
                    admission: reader.admission()?,
                    fingerprint: reader.take()?,
                    position: reader.position()?,
                },
                _ => return Err(Error::Malformed("unknown request record")),
            };
            if database.requests.insert(request, record).is_some() {
                return Err(Error::Malformed("duplicate request"));
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
            admission: reader.admission()?,
            database: reader.database()?,
            digest: reader.take()?,
            result: reader.admin_result()?,
            position: reader.position()?,
        };
        if state.administration.insert(operation, record).is_some() {
            return Err(Error::Malformed("duplicate administrative operation"));
        }
    }
    if reader.boolean()? {
        state.last_outcome = Some(AppliedOutcome {
            position: reader.position()?,
            outcome: reader.outcome()?,
        });
    }
    reader.finish()?;
    validate_state(&state)?;
    Ok(state)
}
