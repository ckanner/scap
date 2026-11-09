//! Shared `/v1` encoding-buffer credits, retained by work and response bytes.
//!
//! This covers service-created wire/Base64/JSON backing and a conservative
//! small projection allowance. Core inputs, typed results, SQLite, other HTTP
//! routes, allocator overhead and transport buffers remain outside this pool.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use axum::body::Bytes;
use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine};
use scap_object::Receipt;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{auth::Principal, wire, Failure};

pub const BASE_BYTES: usize = 65_536;
const SMALL_BYTES: usize = 2_048;
const JSON_OVERHEAD: usize = 711;
const MAX_JSON_BYTES: usize = scap_object::format::MAX_RESULT_BYTES.div_ceil(3) * 4 + JSON_OVERHEAD;

/// One daemon's ordinary `/v1` encoding buffers only. Reserved credits protect
/// small control/recovery work from data traffic, not large lookup responses.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub bytes: usize,
    pub bytes_per_tenant: usize,
    pub control_bytes: usize,
    pub control_bytes_per_tenant: usize,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            bytes: 512 * 1024 * 1024,
            bytes_per_tenant: 256 * 1024 * 1024,
            control_bytes: 8 * 1024 * 1024,
            control_bytes_per_tenant: 1024 * 1024,
        }
    }
}

fn maximum_peak(raw: usize) -> Option<usize> {
    base64::encoded_len(raw, true)?
        .checked_mul(2)?
        .checked_add(JSON_OVERHEAD)?
        .checked_add(BASE_BYTES)
}

impl Profile {
    pub fn checked(self) -> Result<Self, Failure> {
        let minimum = maximum_peak(scap_object::format::MAX_RESULT_BYTES)
            .expect("fixed durable result extent fits the supported target");
        let shared = self.bytes.checked_sub(self.control_bytes);
        let local = self
            .bytes_per_tenant
            .checked_sub(self.control_bytes_per_tenant);
        if self.version != 1
            || self.bytes > isize::MAX as usize
            || self.bytes_per_tenant > self.bytes
            || self.control_bytes < BASE_BYTES
            || self.control_bytes_per_tenant < BASE_BYTES
            || self.control_bytes_per_tenant > self.control_bytes
            || shared.is_none_or(|n| n < minimum)
            || local.is_none_or(|n| n < minimum)
            || local > shared
        {
            return Err(Failure::new("CONFIG"));
        }
        Ok(self)
    }
}

type Tenant = (u64, u64);

#[derive(Default)]
struct Count {
    shared: usize,
    control: usize,
    leases: usize,
}

impl Count {
    fn bytes(&self, control: bool) -> usize {
        if control {
            self.control
        } else {
            self.shared
        }
    }

    fn add(&mut self, control: bool, bytes: usize) {
        if control {
            self.control += bytes;
        } else {
            self.shared += bytes;
        }
    }

    fn remove(&mut self, control: bool, bytes: usize) {
        if control {
            self.control -= bytes;
        } else {
            self.shared -= bytes;
        }
    }
}

#[derive(Default)]
struct Usage {
    all: Count,
    tenants: BTreeMap<Tenant, Count>,
}

pub struct Pool {
    profile: Profile,
    usage: Mutex<Usage>,
}

impl Pool {
    pub fn new(profile: Profile) -> Result<Self, Failure> {
        Ok(Self {
            profile: profile.checked()?,
            usage: Mutex::new(Usage::default()),
        })
    }

    fn limits(&self, control: bool) -> (usize, usize) {
        if control {
            (
                self.profile.control_bytes,
                self.profile.control_bytes_per_tenant,
            )
        } else {
            (
                self.profile.bytes - self.profile.control_bytes,
                self.profile.bytes_per_tenant - self.profile.control_bytes_per_tenant,
            )
        }
    }

    /// Trusted tenant identity and an already checked admission class are the
    /// only keys. Both scopes are checked before inserting or charging a key.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        principal: &Principal,
        control: bool,
    ) -> Result<OutputContext, Failure> {
        self.acquire_with(principal, control, &mut Vec::try_reserve_exact)
    }

    fn acquire_with(
        self: &Arc<Self>,
        principal: &Principal,
        control: bool,
        allocate: &mut Allocate<'_>,
    ) -> Result<OutputContext, Failure> {
        let tenant = (principal.deployment, principal.tenant);
        let (global, local) = self.limits(control);
        let mut usage = self.usage.lock().map_err(|_| Failure::new("UNAVAILABLE"))?;
        let empty = Count::default();
        let current = usage.tenants.get(&tenant).unwrap_or(&empty);
        if BASE_BYTES > global - usage.all.bytes(control)
            || BASE_BYTES > local - current.bytes(control)
        {
            return Err(Failure::new("BACKPRESSURE"));
        }
        usage.all.add(control, BASE_BYTES);
        let current = usage.tenants.entry(tenant).or_default();
        current.add(control, BASE_BYTES);
        current.leases += 1;
        drop(usage);
        let base = Arc::new(BaseLease {
            pool: self.clone(),
            tenant,
            control,
        });
        let small =
            allocate_exact(SMALL_BYTES, allocate).map_err(|_| Failure::new("BACKPRESSURE"))?;
        Ok(OutputContext {
            small,
            value_charge: None,
            receipt: None,
            head_only: false,
            base,
        })
    }

    fn charge(base: &Arc<BaseLease>, bytes: usize) -> Result<CapacityCharge, Failure> {
        let pool = &base.pool;
        let (global, local) = pool.limits(false);
        let mut usage = pool.usage.lock().map_err(|_| Failure::new("UNAVAILABLE"))?;
        let current = usage.tenants.get(&base.tenant).expect("live output lease");
        if bytes > global - usage.all.shared || bytes > local - current.shared {
            return Err(Failure::new("LIMIT"));
        }
        usage.all.shared += bytes;
        usage
            .tenants
            .get_mut(&base.tenant)
            .expect("live output lease")
            .shared += bytes;
        Ok(CapacityCharge {
            base: base.clone(),
            bytes,
        })
    }
}

struct BaseLease {
    pool: Arc<Pool>,
    tenant: Tenant,
    control: bool,
}

impl Drop for BaseLease {
    fn drop(&mut self) {
        // A poisoned admission lock rejects new work; existing owners must
        // still release their exact charges instead of leaking the tenant key.
        let mut usage = self
            .pool
            .usage
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        usage.all.remove(self.control, BASE_BYTES);
        let tenant = usage
            .tenants
            .get_mut(&self.tenant)
            .expect("live output tenant");
        tenant.remove(self.control, BASE_BYTES);
        tenant.leases -= 1;
        if tenant.leases == 0 {
            usage.tenants.remove(&self.tenant);
        }
    }
}

struct CapacityCharge {
    base: Arc<BaseLease>,
    bytes: usize,
}

impl Drop for CapacityCharge {
    fn drop(&mut self) {
        let mut usage = self
            .base
            .pool
            .usage
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        usage.all.shared -= self.bytes;
        usage
            .tenants
            .get_mut(&self.base.tenant)
            .expect("live output tenant")
            .shared -= self.bytes;
    }
}

/// Backing storage is always destroyed before its credit. The small final
/// buffer uses the pre-acquired base credit and therefore has no extra charge.
pub(crate) struct Buffer {
    bytes: Vec<u8>,
    charge: Option<CapacityCharge>,
}

impl Buffer {
    pub(crate) fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

type Allocate<'a> =
    dyn FnMut(&mut Vec<u8>, usize) -> Result<(), std::collections::TryReserveError> + 'a;

fn allocate_exact(length: usize, allocate: &mut Allocate<'_>) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    allocate(&mut bytes, length).map_err(|_| Failure::new("LIMIT"))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

/// Explicit per-call ownership for a trusted budget-aware worker. There is no
/// TLS state, unmetered default conversion or post-allocation accounting.
pub struct OutputContext {
    small: Vec<u8>,
    value_charge: Option<CapacityCharge>,
    receipt: Option<Receipt>,
    head_only: bool,
    base: Arc<BaseLease>,
}

pub(crate) struct WorkHold {
    _base: Arc<BaseLease>,
}

impl OutputContext {
    pub(crate) fn work_hold(&self) -> WorkHold {
        WorkHold {
            _base: self.base.clone(),
        }
    }

    pub(crate) fn claim(&self, principal: &Principal, control: bool) -> Result<(), Failure> {
        if self.base.tenant != (principal.deployment, principal.tenant)
            || self.base.control != control
        {
            return Err(Failure::new("DENIED"));
        }
        Ok(())
    }

    pub(crate) fn allocate(&self, length: usize) -> Result<Buffer, Failure> {
        self.allocate_with(length, &mut Vec::try_reserve_exact)
    }

    fn allocate_with(&self, length: usize, allocate: &mut Allocate<'_>) -> Result<Buffer, Failure> {
        let charge = Pool::charge(&self.base, length)?;
        let bytes = allocate_exact(length, allocate)?;
        Ok(Buffer {
            bytes,
            charge: Some(charge),
        })
    }

    pub(crate) fn base64(&mut self, raw: &[u8]) -> Result<String, Failure> {
        self.base64_with(raw, &mut Vec::try_reserve_exact)
    }

    fn base64_with(&mut self, raw: &[u8], allocate: &mut Allocate<'_>) -> Result<String, Failure> {
        let length = base64_length(raw.len())?;
        let mut buffer = self.allocate_with(length, allocate)?;
        STANDARD
            .encode_slice(raw, buffer.as_mut())
            .expect("exact Base64 extent");
        let Buffer { bytes, charge } = buffer;
        let value = String::from_utf8(bytes).expect("Base64 is ASCII");
        // One Engine invocation materializes at most one result. Replacing a
        // still-live String's charge would violate this ownership boundary.
        assert!(self.value_charge.is_none());
        self.value_charge = charge;
        Ok(value)
    }

    pub(crate) fn committed(&mut self, receipt: Receipt) {
        self.receipt = Some(receipt);
    }

    pub(crate) fn receipt(&self) -> &Receipt {
        self.receipt.as_ref().expect("trusted committed output")
    }

    pub(crate) fn committed_unavailable(&mut self) -> Failure {
        Failure {
            code: "COMMITTED_BUT_UNAVAILABLE",
            receipt: Some(Box::new(
                self.receipt.take().expect("trusted committed output"),
            )),
        }
    }

    pub(crate) fn head_result(&mut self) {
        self.head_only = true;
    }

    fn encode(
        &mut self,
        value: &Result<Value, Failure>,
        allocate: &mut Allocate<'_>,
    ) -> Result<Encoded, Failure> {
        let error = value.as_ref().err().map(wire::failed);
        let (status, envelope) = match value {
            Ok(value) => (StatusCode::OK, Envelope::Success(wire::success(value))),
            Err(failure) => (
                crate::http::failure_status(failure),
                Envelope::Failure(error.as_ref().expect("error projection")),
            ),
        };
        let length = json_length(&envelope, MAX_JSON_BYTES)?;
        let buffer = if length <= SMALL_BYTES {
            write_json(&envelope, &mut self.small[..length])
                .expect("counted immutable JSON and exact small destination");
            let mut bytes = std::mem::take(&mut self.small);
            bytes.truncate(length);
            Buffer {
                bytes,
                charge: None,
            }
        } else {
            let mut buffer = self.allocate_with(length, allocate)?;
            write_json(&envelope, buffer.as_mut())
                .expect("counted immutable JSON and exact reserved destination");
            buffer
        };
        Ok(Encoded { status, buffer })
    }
}

fn base64_length(length: usize) -> Result<usize, Failure> {
    base64::encoded_len(length, true).ok_or_else(|| Failure::new("LIMIT"))
}

/// Both successful values and Failure receipts precede their credit on drop.
pub(crate) struct OwnedValue {
    value: Result<Value, Failure>,
    context: OutputContext,
}

impl OwnedValue {
    pub(crate) fn new(value: Result<Value, Failure>, context: OutputContext) -> Self {
        Self { value, context }
    }

    pub(crate) fn finish(self, deadline: Instant) -> Option<Reply> {
        self.finish_with(deadline, &mut Instant::now, &mut Vec::try_reserve_exact)
    }

    fn finish_with(
        mut self,
        deadline: Instant,
        now: &mut dyn FnMut() -> Instant,
        allocate: &mut Allocate<'_>,
    ) -> Option<Reply> {
        if now() >= deadline {
            return None;
        }
        let encoded = match self.context.encode(&self.value, allocate) {
            Ok(encoded) => encoded,
            Err(_) => {
                if self.value.is_ok() {
                    if self.context.head_only {
                        return None;
                    }
                    let failure = if self.context.receipt.is_some() {
                        self.context.committed_unavailable()
                    } else {
                        Failure::new("LIMIT")
                    };
                    // Drop Base64/receipt projection before releasing credit.
                    self.value = Err(failure);
                }
                self.context.value_charge = None;
                // Existing UNKNOWN/CBU errors are never upgraded or rewritten.
                self.context.encode(&self.value, allocate).ok()?
            }
        };
        let Encoded { status, buffer } = encoded;
        let owner = FinalOwner {
            buffer,
            _base: self.context.base.clone(),
        };
        // The final Bytes will own its exact backing and base lease. Remaining
        // Value/Base64 owners disappear while their Context is still alive.
        drop(self);
        if now() >= deadline {
            return None;
        }
        Some(Reply {
            status,
            bytes: Bytes::from_owner(owner),
        })
    }
}

struct Encoded {
    status: StatusCode,
    buffer: Buffer,
}

pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) bytes: Bytes,
}

struct FinalOwner {
    buffer: Buffer,
    _base: Arc<BaseLease>,
}

impl AsRef<[u8]> for FinalOwner {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Envelope<'a> {
    Success(wire::Success<&'a Value>),
    Failure(&'a Value),
}

struct Counter {
    bytes: usize,
    maximum: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum - self.bytes {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn json_length(value: &Envelope<'_>, maximum: usize) -> Result<usize, Failure> {
    let mut counter = Counter { bytes: 0, maximum };
    serde_json::to_writer(&mut counter, value).map_err(|_| Failure::new("LIMIT"))?;
    Ok(counter.bytes)
}

fn write_json(value: &Envelope<'_>, mut destination: &mut [u8]) -> Result<(), Failure> {
    serde_json::to_writer(&mut destination, value).map_err(|_| Failure::new("LIMIT"))?;
    assert!(destination.is_empty(), "counted JSON extent");
    Ok(())
}

// Layout assumptions behind the documented small projection credit. Fixed
// dependency features use BTreeMap; preserve_order would fail this guard.
const _: () = {
    assert!(std::mem::size_of::<Value>() <= 64);
    assert!(std::mem::size_of::<String>() <= 24);
    assert!(std::mem::size_of::<usize>() <= 8);
    assert!(std::mem::align_of::<Value>() <= 16);
    assert!(std::mem::align_of::<String>() <= 16);
    assert!(std::mem::size_of::<serde_json::Map<String, Value>>() <= 32);
    assert!(
        std::mem::size_of::<BaseLease>()
            + std::mem::size_of::<WorkHold>()
            + std::mem::size_of::<OwnedValue>()
            + std::mem::size_of::<OutputContext>()
            + std::mem::size_of::<FinalOwner>()
            + 128
            <= 1024
    );
};

#[cfg(test)]
pub(crate) mod tests;
