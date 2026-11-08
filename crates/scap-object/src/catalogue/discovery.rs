//! Resumable metadata discovery, without a caller-supplied inventory.
//!
//! A completed scan covers preexisting permanent slots under the supported
//! ordered LIST contract. It is not a cross-key snapshot or data-health proof.

use std::sync::Arc;
use std::time::{Duration, Instant};

use scap_object_store::{ListEnd, ListError, ListKind, ListMode, ListRequest, Listings, Objects};
use serde::{Deserialize, Serialize};

use super::discovery_budget::Meter;
use super::{Catalogue, CatalogueError, Creation};
use crate::format::Scope;
use crate::Options;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    Invalid,
    Denied,
    Limit,
    Conflict,
    Unknown,
    Corrupt,
}

impl From<CatalogueError> for DiscoveryError {
    fn from(value: CatalogueError) -> Self {
        match value {
            CatalogueError::Invalid => Self::Invalid,
            CatalogueError::Denied => Self::Denied,
            CatalogueError::Limit => Self::Limit,
            CatalogueError::Conflict | CatalogueError::IdentityConflict => Self::Conflict,
            CatalogueError::Unknown => Self::Unknown,
            CatalogueError::NotFound | CatalogueError::Corrupt => Self::Corrupt,
        }
    }
}

impl From<ListError> for DiscoveryError {
    fn from(value: ListError) -> Self {
        match value {
            ListError::Invalid => Self::Invalid,
            ListError::Denied => Self::Denied,
            ListError::Limit => Self::Limit,
            ListError::Corrupt => Self::Corrupt,
            ListError::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryBudget {
    pub list_pages: usize,
    pub candidates: usize,
    pub exact_gets: usize,
    pub list_bytes: usize,
    pub metadata_bytes: usize,
}

impl Default for DiscoveryBudget {
    fn default() -> Self {
        Self {
            list_pages: 4,
            candidates: 128,
            exact_gets: 512,
            list_bytes: 4 * 1024 * 1024,
            metadata_bytes: 16 * 1024 * 1024,
        }
    }
}

impl DiscoveryBudget {
    pub(super) fn validate(self) -> Result<Self, DiscoveryError> {
        let maximum = Self::default();
        if self.list_pages > maximum.list_pages
            || self.candidates > maximum.candidates
            || self.exact_gets > maximum.exact_gets
            || self.list_bytes > maximum.list_bytes
            || self.metadata_bytes > maximum.metadata_bytes
        {
            return Err(DiscoveryError::Invalid);
        }
        Ok(self)
    }
}

/// Conservative budget consumption. Failed I/O retains its reserved byte cap;
/// actual HTTP traffic must be measured independently from the wire trace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryUsage {
    pub list_pages: usize,
    pub candidates: usize,
    pub exact_gets: usize,
    pub list_bytes: usize,
    pub metadata_bytes: usize,
}

/// Construct only from trusted deployment recovery configuration. A provision
/// bit, ADMIN grant or client JSON is not a recovery capability. This capability
/// permits metadata inspection; it grants no SQL permission or mutation.
pub struct RecoveryCapability {
    pub(super) deployment: u64,
    pub(super) worker: u64,
}

impl RecoveryCapability {
    pub fn trusted_deployment(deployment: u64, worker: u64) -> Result<Self, DiscoveryError> {
        if deployment == 0 || worker == 0 {
            return Err(DiscoveryError::Invalid);
        }
        Ok(Self { deployment, worker })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Name,
    Create,
    Control,
    AbortProof,
    Head,
    OrphanPrefix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataState {
    DescriptorOnly,
    Reserved,
    Provisioning,
    Bound,
    Ready,
    Maintenance,
    Aborting,
    Aborted,
    Deleting,
    Deleted,
    NameConflict,
    IdentityConflict,
    ControlAdmitted,
    Orphan,
}

/// The exact immutable control conditions, observed under the trusted metadata
/// capability. Possessing them grants no right to impersonate the principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedControl {
    pub kind: crate::format::NamedDeletionKind,
    pub principal: u64,
    pub operation: u64,
    pub expected_name_revision: u64,
    pub expected_head_revision: Option<u64>,
    pub nonce: u64,
}

/// Minimal verified metadata. No data/result closure or native file has been
/// checked. Consumers must reread authority before using any returned identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredRecord {
    pub key: String,
    pub kind: RecordKind,
    pub state: MetadataState,
    pub creation: Option<Creation>,
    pub scope: Option<Scope>,
    pub binding_revision: Option<u64>,
    pub head_revision: Option<u64>,
    pub control: Option<ObservedControl>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRecovery {
    NotRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryCompletion {
    pub traversal_exhausted: bool,
    pub preexisting_slots_covered: bool,
    pub metadata_classified: u64,
    pub data_recovery: DataRecovery,
    pub recovery_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Names,
    Creates,
    Controls,
    Proofs,
    Slots,
}

impl Phase {
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Names => Some(Self::Creates),
            Self::Creates => Some(Self::Controls),
            Self::Controls => Some(Self::Proofs),
            Self::Proofs => Some(Self::Slots),
            Self::Slots => None,
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::Names => "catalogue/v1/name/",
            Self::Creates => "catalogue/v1/create/",
            Self::Controls => "catalogue/v1/control/",
            Self::Proofs => "catalogue/v1/abort-proof/",
            Self::Slots => "",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantScan {
    tenant: u64,
    prefix: String,
    phase: Phase,
    after: Option<String>,
}

/// Server-internal state, deliberately not a wire DTO or authorization token.
/// Its private owner binds it to this inventory instance/configuration. Loss of
/// the instance requires restarting from the deployment prefix, never an empty
/// successful result. A future HTTP layer must protect its own cursor encoding.
#[derive(Clone, Debug)]
pub struct InventoryCursor {
    owner: Arc<()>,
    tenant_after: Option<String>,
    tenant: Option<TenantScan>,
    classified: u64,
    finished: bool,
}

#[derive(Clone, Debug)]
pub struct InventoryPage {
    pub records: Vec<DiscoveredRecord>,
    pub cursor: InventoryCursor,
    pub completion: DiscoveryCompletion,
    pub usage: DiscoveryUsage,
    pub stopped: Option<DiscoveryError>,
}

#[derive(Clone)]
pub struct RecoveryInventory {
    objects: Arc<dyn Objects>,
    listings: Arc<dyn Listings>,
    deployment: u64,
    worker: u64,
    options: Options,
    owner: Arc<()>,
    pub(super) now: fn() -> Instant,
}

impl RecoveryInventory {
    pub fn new(
        objects: Arc<dyn Objects>,
        listings: Arc<dyn Listings>,
        capability: RecoveryCapability,
        options: Options,
    ) -> Result<Self, DiscoveryError> {
        options.validate().map_err(|_| DiscoveryError::Invalid)?;
        Ok(Self {
            objects,
            listings,
            deployment: capability.deployment,
            worker: capability.worker,
            options,
            owner: Arc::new(()),
            now: Instant::now,
        })
    }

    pub fn begin(&self) -> InventoryCursor {
        InventoryCursor {
            owner: self.owner.clone(),
            tenant_after: None,
            tenant: None,
            classified: 0,
            finished: false,
        }
    }

    pub fn page(
        &self,
        mut cursor: InventoryCursor,
        budget: DiscoveryBudget,
        deadline: Instant,
    ) -> Result<InventoryPage, DiscoveryError> {
        if !Arc::ptr_eq(&cursor.owner, &self.owner) {
            return Err(DiscoveryError::Invalid);
        }
        let meter = Meter::new(self.objects.clone(), budget.validate()?, self.now);
        let deadline = deadline.min((self.now)() + Duration::from_secs(5));
        let mut records = Vec::new();
        let stopped = self
            .advance(&mut cursor, &meter, &mut records, deadline)
            .err()
            .map(|error| meter.failure(error));
        Ok(InventoryPage {
            completion: DiscoveryCompletion {
                traversal_exhausted: cursor.finished,
                preexisting_slots_covered: cursor.finished,
                metadata_classified: cursor.classified,
                data_recovery: DataRecovery::NotRun,
                recovery_complete: false,
            },
            cursor,
            records,
            usage: meter.usage(),
            stopped,
        })
    }

    fn advance(
        &self,
        cursor: &mut InventoryCursor,
        meter: &Arc<Meter>,
        records: &mut Vec<DiscoveredRecord>,
        deadline: Instant,
    ) -> Result<(), DiscoveryError> {
        while !cursor.finished {
            meter.page(deadline)?;
            let (prefix, mode, after) = match &cursor.tenant {
                Some(scan) => (
                    format!("{}{}", scan.prefix, scan.phase.suffix()),
                    if scan.phase == Phase::Slots {
                        ListMode::Children
                    } else {
                        ListMode::Keys
                    },
                    scan.after.as_deref(),
                ),
                None => (
                    format!("scap-object/v1/{}/", self.deployment),
                    ListMode::Children,
                    cursor.tenant_after.as_deref(),
                ),
            };
            let page = self.listings.list_page(
                &ListRequest {
                    prefix: &prefix,
                    mode,
                    after,
                },
                deadline,
            )?;
            meter.listed(page.response_bytes)?;
            meter.remaining(deadline)?;
            if cursor.tenant.is_none() {
                match page.entries.first() {
                    Some(entry) => {
                        meter.candidate(deadline)?;
                        if entry.kind != ListKind::Prefix {
                            return Err(DiscoveryError::Corrupt);
                        }
                        let tenant = component(&entry.key, &prefix, true)?;
                        cursor.tenant = Some(TenantScan {
                            tenant,
                            prefix: entry.key.clone(),
                            phase: Phase::Names,
                            after: None,
                        });
                    }
                    None => {
                        if page.end != ListEnd::Exhausted {
                            return Err(DiscoveryError::Corrupt);
                        }
                        cursor.finished = true;
                    }
                }
                continue;
            }
            let scan = cursor.tenant.as_mut().expect("selected tenant");
            // Configuration and tenant identity were already validated at
            // construction/checkpoint decoding; classification cannot introduce
            // a different worker, namespace or runtime budget.
            let catalogue = Catalogue {
                objects: meter.clone(),
                deployment: self.deployment,
                tenant: scan.tenant,
                worker: self.worker,
                options: self.options.clone(),
            };
            for entry in &page.entries {
                meter.candidate(deadline)?;
                let record = catalogue.discover_record(scan.phase, entry, deadline)?;
                meter.remaining(deadline)?;
                if let Some(record) = record {
                    cursor.classified = cursor
                        .classified
                        .checked_add(1)
                        .ok_or(DiscoveryError::Limit)?;
                    records.push(record);
                }
                scan.after = Some(entry.key.clone());
            }
            if page.end == ListEnd::Exhausted {
                match scan.phase.next() {
                    Some(phase) => {
                        scan.phase = phase;
                        scan.after = None;
                    }
                    None => {
                        cursor.tenant_after = Some(scan.prefix.clone());
                        cursor.tenant = None;
                    }
                }
            } else if page.entries.is_empty() {
                return Err(DiscoveryError::Corrupt);
            }
        }
        Ok(())
    }
}

pub(super) fn component(key: &str, prefix: &str, directory: bool) -> Result<u64, DiscoveryError> {
    let suffix = key.strip_prefix(prefix).ok_or(DiscoveryError::Corrupt)?;
    let text = if directory {
        suffix.strip_suffix('/').ok_or(DiscoveryError::Corrupt)?
    } else {
        suffix
    };
    let value: u64 = text.parse().map_err(|_| DiscoveryError::Corrupt)?;
    if value == 0 || value.to_string() != text {
        return Err(DiscoveryError::Corrupt);
    }
    Ok(value)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryCheckpoint {
    schema: u32,
    deployment: u64,
    tenant_after: Option<String>,
    tenant: Option<TenantScan>,
    classified: u64,
    finished: bool,
}

impl RecoveryInventory {
    pub fn checkpoint(&self, cursor: &InventoryCursor) -> Result<Vec<u8>, DiscoveryError> {
        if !Arc::ptr_eq(&self.owner, &cursor.owner) {
            return Err(DiscoveryError::Invalid);
        }
        let checkpoint = InventoryCheckpoint {
            schema: 1,
            deployment: self.deployment,
            tenant_after: cursor.tenant_after.clone(),
            tenant: cursor.tenant.clone(),
            classified: cursor.classified,
            finished: cursor.finished,
        };
        Ok(serde_json::to_vec(&checkpoint).expect("fixed checkpoint fields"))
    }

    /// Call only after authenticating the enclosing server cursor (including
    /// deployment/configuration, principal, view, startup epoch and expiry).
    /// Strict decoding prevents malformed state; it cannot authenticate a
    /// caller's claim that earlier keys were already classified.
    pub fn resume_authenticated(&self, bytes: &[u8]) -> Result<InventoryCursor, DiscoveryError> {
        if bytes.len() > 8192 {
            return Err(DiscoveryError::Invalid);
        }
        let value: InventoryCheckpoint =
            serde_json::from_slice(bytes).map_err(|_| DiscoveryError::Invalid)?;
        if serde_json::to_vec(&value).expect("fixed checkpoint fields") != bytes
            || value.schema != 1
            || value.deployment != self.deployment
            || (value.finished && value.tenant.is_some())
        {
            return Err(DiscoveryError::Invalid);
        }
        let root = format!("scap-object/v1/{}/", self.deployment);
        if let Some(after) = &value.tenant_after {
            component(after, &root, true).map_err(|_| DiscoveryError::Invalid)?;
        }
        if let Some(scan) = &value.tenant {
            if scan.tenant == 0
                || scan.prefix != format!("{}{}/", root, scan.tenant)
                || value
                    .tenant_after
                    .as_ref()
                    .is_some_and(|after| scan.prefix <= *after)
            {
                return Err(DiscoveryError::Invalid);
            }
            if let Some(after) = &scan.after {
                frontier(after, &scan.prefix, scan.phase)?;
            }
        }
        Ok(InventoryCursor {
            owner: self.owner.clone(),
            tenant_after: value.tenant_after,
            tenant: value.tenant,
            classified: value.classified,
            finished: value.finished,
        })
    }
}

pub(super) fn frontier(key: &str, tenant: &str, phase: Phase) -> Result<(), DiscoveryError> {
    let prefix = format!("{}{}", tenant, phase.suffix());
    let suffix = key.strip_prefix(&prefix).ok_or(DiscoveryError::Invalid)?;
    let number = |text: &str| component(text, "", false).map_err(|_| DiscoveryError::Invalid);
    match phase {
        Phase::Names => {
            if suffix.len() != 64
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(DiscoveryError::Invalid);
            }
        }
        Phase::Creates | Phase::Proofs => {
            let (principal, operation) = suffix.split_once('/').ok_or(DiscoveryError::Invalid)?;
            number(principal)?;
            number(operation)?;
        }
        Phase::Controls => {
            let (principal, rest) = suffix.split_once('/').ok_or(DiscoveryError::Invalid)?;
            let (kind, operation) = rest.split_once('/').ok_or(DiscoveryError::Invalid)?;
            number(principal)?;
            if kind != "abort" && kind != "delete" {
                return Err(DiscoveryError::Invalid);
            }
            number(operation)?;
        }
        Phase::Slots => {
            if suffix != "catalogue/" {
                component(suffix, "", true).map_err(|_| DiscoveryError::Invalid)?;
            }
        }
    }
    Ok(())
}
