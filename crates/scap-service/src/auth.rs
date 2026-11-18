//! Deployment credentials select trusted principals; HEAD still grants access.

use scap_object::format::Scope;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{wire::Decimal, Failure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub deployment: u64,
    pub tenant: u64,
    pub principal: u64,
    pub provision: bool,
    pub deployment_inventory: bool,
}

impl Principal {
    pub fn authorize(&self, scope: &Scope) -> Result<(), Failure> {
        if self.deployment != scope.deployment || self.tenant != scope.tenant {
            return Err(Failure::new("DENIED"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub sha256: String,
    pub deployment: Decimal,
    pub tenant: Decimal,
    pub principal: Decimal,
    pub provision: bool,
    #[serde(default)]
    pub deployment_inventory: bool,
}

#[derive(Clone)]
pub struct Authenticator(Vec<([u8; 32], Principal)>);

impl Authenticator {
    /// Keep direct service assembly within the same deployment restriction as
    /// parsed GC configuration; no storage effect is needed to check this.
    pub(crate) fn validate_gc_deployment(&self, deployment: u64) -> Result<(), Failure> {
        if self
            .0
            .iter()
            .any(|(_, principal)| principal.deployment != deployment)
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(())
    }

    pub fn new(credentials: Vec<Credential>) -> Result<Self, Failure> {
        if credentials.is_empty() || credentials.len() > 4096 {
            return Err(Failure::new("CONFIG"));
        }
        let mut entries = Vec::new();
        for credential in credentials {
            let hash = decode_hash(&credential.sha256)?;
            if credential.deployment.0 == 0
                || credential.tenant.0 == 0
                || credential.principal.0 == 0
                || entries.iter().any(|(existing, _)| existing == &hash)
            {
                return Err(Failure::new("CONFIG"));
            }
            entries.push((
                hash,
                Principal {
                    deployment: credential.deployment.0,
                    tenant: credential.tenant.0,
                    principal: credential.principal.0,
                    provision: credential.provision,
                    deployment_inventory: credential.deployment_inventory,
                },
            ));
        }
        Ok(Self(entries))
    }

    pub fn authenticate(&self, header: Option<&str>) -> Result<Principal, Failure> {
        let token = header
            .and_then(|header| header.strip_prefix("Bearer "))
            .filter(|token| {
                token.len() >= 32
                    && token.len() <= 1024
                    && token.bytes().all(|byte| byte.is_ascii_graphic())
            })
            .ok_or_else(|| Failure::new("UNAUTHENTICATED"))?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        // Compare fixed-size digests using the constant-time primitive. Never
        // log tokens, hashes or raw authorization headers in errors.
        for (hash, principal) in &self.0 {
            if bool::from(hash.ct_eq(&digest)) {
                found = Some(principal.clone());
            }
        }
        found.ok_or_else(|| Failure::new("UNAUTHENTICATED"))
    }
}

pub(crate) fn decode_hash(text: &str) -> Result<[u8; 32], Failure> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::new("CONFIG"));
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        // Syntax was checked above; indexing is by ASCII bytes.
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("validated hex");
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
