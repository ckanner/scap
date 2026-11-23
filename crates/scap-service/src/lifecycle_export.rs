//! Independently authenticated, single-owner bounded lifecycle export.

use std::io::{self, Write};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{lifecycle::Registry, Failure};

pub const MAX_RESPONSE_BYTES: usize = 65536;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub token_sha256: String,
}

impl Profile {
    pub fn checked(&self) -> Result<[u8; 32], Failure> {
        if self.version != 1 {
            return Err(Failure::new("CONFIG"));
        }
        crate::auth::decode_hash(&self.token_sha256)
    }
}

/// The permit follows the actual exported bytes, not just this method call.
pub struct Diagnostics {
    digest: [u8; 32],
    pub registry: Arc<Registry>,
    permits: Arc<Semaphore>,
}

pub(crate) struct Export {
    pub bytes: Vec<u8>,
    pub permit: OwnedSemaphorePermit,
}

impl Diagnostics {
    pub fn new(profile: &Profile) -> Result<Self, Failure> {
        let digest = profile.checked()?;
        Ok(Self {
            digest,
            registry: Arc::new(Registry::new()),
            permits: Arc::new(Semaphore::new(1)),
        })
    }

    pub(crate) fn export(&self, authorization: Option<&str>) -> Result<Export, Failure> {
        self.export_using(authorization, || encode(&self.registry.snapshot()))
    }

    fn export_using(
        &self,
        authorization: Option<&str>,
        encode: impl FnOnce() -> Result<Vec<u8>, Failure>,
    ) -> Result<Export, Failure> {
        self.authenticate(authorization)?;
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::new("BACKPRESSURE"))?;
        let bytes = encode()?;
        Ok(Export { bytes, permit })
    }

    fn authenticate(&self, authorization: Option<&str>) -> Result<(), Failure> {
        let token = authorization
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| {
                (32..=1024).contains(&token.len())
                    && token.bytes().all(|byte| byte.is_ascii_graphic())
            })
            .ok_or_else(|| Failure::new("DENIED"))?;
        let digest: [u8; 32] = Sha256::digest(token).into();
        if !bool::from(self.digest.ct_eq(&digest)) {
            return Err(Failure::new("DENIED"));
        }
        Ok(())
    }
}

struct Bounded(Vec<u8>);

impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES - self.0.len() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, Failure> {
    let mut writer = Bounded(Vec::with_capacity(MAX_RESPONSE_BYTES));
    serde_json::to_writer(&mut writer, value).map_err(|_| Failure::new("UNAVAILABLE"))?;
    Ok(writer.0)
}

#[cfg(test)]
pub(crate) mod tests;
