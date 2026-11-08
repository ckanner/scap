//! Opaque scan checkpoints are authenticated state, never authorization.
//!
//! A fresh random startup salt derives a separate AEAD key for each daemon.
//! Nonces are unique monotonic counters under that key. Restart or another
//! daemon requires starting the scan again; no cursor is database authority.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{aead, error::Unspecified, hkdf, rand::SecureRandom};
use sha2::{Digest, Sha256};

use crate::{auth::Principal, Failure};

pub const MAX_CHECKPOINT_BYTES: usize = 8192;
pub const MAX_CURSOR_BYTES: usize = 16 * 1024;
const LIFETIME_SECONDS: u64 = 600;
const MAX_ISSUED: u64 = 1 << 32;
const VERSION: u8 = 1;
const HEADER: usize = 13;
const TAG: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Names,
    Inventory,
}

impl View {
    fn byte(self) -> u8 {
        match self {
            Self::Names => 1,
            Self::Inventory => 2,
        }
    }
}

/// Binds object namespace and the fixed discovery protocol/budget profile.
pub fn namespace(endpoint: &str, region: &str, bucket: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"SCAP-DISCOVERY-NAMESPACE-v1\0");
    for value in [endpoint, region, bucket] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

pub struct CursorCodec {
    key: aead::LessSafeKey,
    namespace: [u8; 32],
    worker: u64,
    counter: AtomicU64,
    origin: Instant,
}

struct KeyLength;

impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

impl CursorCodec {
    pub fn new(master: [u8; 32], namespace: [u8; 32], worker: u64) -> Result<Self, Failure> {
        Self::with_entropy(master, namespace, worker, random)
    }

    fn with_entropy(
        master: [u8; 32],
        namespace: [u8; 32],
        worker: u64,
        fill: fn(&mut [u8]) -> Result<(), Unspecified>,
    ) -> Result<Self, Failure> {
        let mut salt = [0; 32];
        entropy_result(fill(&mut salt))?;
        Self::derive(master, salt, namespace, worker)
    }

    fn derive(
        master: [u8; 32],
        salt: [u8; 32],
        namespace: [u8; 32],
        worker: u64,
    ) -> Result<Self, Failure> {
        if worker == 0 {
            return Err(Failure::new("CONFIG"));
        }
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt);
        let prk = salt.extract(&master);
        let worker_bytes = worker.to_be_bytes();
        let info = [
            b"SCAP-DISCOVERY-CURSOR-KEY-v1".as_slice(),
            &namespace,
            &worker_bytes,
        ];
        let okm = prk
            .expand(&info, KeyLength)
            .expect("32-byte HKDF output is within the SHA256 expansion bound");
        let mut key = [0; 32];
        okm.fill(&mut key)
            .expect("HKDF output length is exactly 32");
        let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key)
            .expect("ChaCha20Poly1305 key length is exactly 32");
        Ok(Self {
            key: aead::LessSafeKey::new(key),
            namespace,
            worker,
            counter: AtomicU64::new(0),
            origin: Instant::now(),
        })
    }

    fn aad(&self, principal: &Principal, view: View) -> Vec<u8> {
        let mut bytes = b"SCAP-DISCOVERY-CURSOR-v1\0".to_vec();
        bytes.extend(self.namespace);
        bytes.extend(self.worker.to_be_bytes());
        bytes.extend(principal.deployment.to_be_bytes());
        bytes.extend(principal.tenant.to_be_bytes());
        bytes.extend(principal.principal.to_be_bytes());
        bytes.push(view.byte());
        bytes
    }

    pub fn seal(
        &self,
        principal: &Principal,
        view: View,
        checkpoint: &[u8],
    ) -> Result<String, Failure> {
        self.seal_at(principal, view, checkpoint, self.origin.elapsed().as_secs())
    }

    fn seal_at(
        &self,
        principal: &Principal,
        view: View,
        checkpoint: &[u8],
        now: u64,
    ) -> Result<String, Failure> {
        if checkpoint.is_empty() || checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(Failure::new("LIMIT"));
        }
        let expires = now
            .checked_add(LIFETIME_SECONDS)
            .ok_or_else(|| Failure::new("UNAVAILABLE"))?;
        let counter = self
            .counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value < MAX_ISSUED {
                    Some(value + 1)
                } else {
                    None
                }
            })
            .map_err(|_| Failure::new("UNAVAILABLE"))?;
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let mut plaintext = expires.to_be_bytes().to_vec();
        plaintext.extend_from_slice(checkpoint);
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.aad(principal, view)),
                &mut plaintext,
            )
            .expect("fixed nonce and at most 8200 plaintext bytes satisfy AEAD bounds");
        let mut token = vec![VERSION];
        token.extend(nonce);
        token.extend(plaintext);
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    pub fn open(&self, principal: &Principal, view: View, token: &str) -> Result<Vec<u8>, Failure> {
        self.open_at(principal, view, token, self.origin.elapsed().as_secs())
    }

    fn open_at(
        &self,
        principal: &Principal,
        view: View,
        token: &str,
        now: u64,
    ) -> Result<Vec<u8>, Failure> {
        if token.len() > MAX_CURSOR_BYTES {
            return Err(Failure::new("CURSOR_INVALID"));
        }
        let mut bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| Failure::new("CURSOR_INVALID"))?;
        if bytes.len() < HEADER + TAG + 9
            || bytes.len() > HEADER + TAG + 8 + MAX_CHECKPOINT_BYTES
            || bytes[0] != VERSION
        {
            return Err(Failure::new("CURSOR_INVALID"));
        }
        let nonce: [u8; 12] = bytes[1..HEADER].try_into().expect("checked token header");
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.aad(principal, view)),
                &mut bytes[HEADER..],
            )
            .map_err(|_| Failure::new("CURSOR_INVALID"))?;
        let expires =
            u64::from_be_bytes(plaintext[..8].try_into().expect("checked plaintext size"));
        if now >= expires || expires - now > LIFETIME_SECONDS {
            return Err(Failure::new("CURSOR_INVALID"));
        }
        Ok(plaintext[8..].to_vec())
    }
}

fn random(bytes: &mut [u8]) -> Result<(), Unspecified> {
    ring::rand::SystemRandom::new().fill(bytes)
}

fn entropy_result(result: Result<(), Unspecified>) -> Result<(), Failure> {
    result.map_err(|_| Failure::new("CONFIG"))
}

#[cfg(test)]
mod tests;
