use std::collections::BTreeMap;

use scap_cell::Admission;
use scap_service::{Mode, RequestContext, ServiceError};
use sha2::{Digest, Sha256};

use crate::config::{DatabaseConfig, TokenConfig};
use crate::failure;

/// Immutable configured bindings. The cell performs the authoritative policy
/// and auth-epoch check on every operation, including an outcome lookup.
pub(crate) struct Verifier {
    bindings: BTreeMap<(String, [u8; 32]), (DatabaseConfig, TokenConfig)>,
}

impl Verifier {
    pub(crate) fn new(databases: &[DatabaseConfig]) -> Self {
        let mut bindings = BTreeMap::new();
        for db in databases {
            for token in &db.tokens {
                bindings.insert((db.name.clone(), token.digest), (db.clone(), token.clone()));
            }
        }
        Self { bindings }
    }

    pub(crate) fn verify(
        &self,
        context: &RequestContext,
        mode: Mode,
    ) -> Result<(DatabaseConfig, Admission), ServiceError> {
        let required = match mode {
            Mode::Read => scap_cell::READ,
            Mode::Write => scap_cell::READ | scap_cell::WRITE,
        };
        self.verify_permissions(context, required)
    }

    pub(crate) fn verify_administrator(
        &self,
        context: &RequestContext,
    ) -> Result<(DatabaseConfig, Admission), ServiceError> {
        self.verify_permissions(context, scap_cell::READ | scap_cell::ADMIN)
    }

    fn verify_permissions(
        &self,
        context: &RequestContext,
        required: u8,
    ) -> Result<(DatabaseConfig, Admission), ServiceError> {
        if context.credential.is_empty()
            || context.credential.len() > 4096
            || context.request_id == 0
            || context.request_epoch == 0
        {
            return Err(failure("UNAUTHORIZED"));
        }
        let digest: [u8; 32] = Sha256::digest(context.credential.as_bytes()).into();
        let (database, token) = self
            .bindings
            .get(&(context.database.clone(), digest))
            .ok_or_else(|| failure("UNAUTHORIZED"))?;
        if token.permissions & required != required {
            return Err(failure("UNAUTHORIZED"));
        }
        Ok((
            database.clone(),
            Admission {
                principal_id: token.principal_id,
                credential_id: token.credential_id,
                admission_id: context.request_id,
                auth_epoch: token.auth_epoch,
                request_epoch: context.request_epoch,
            },
        ))
    }
}

#[cfg(test)]
mod tests;
