//! Tenant-scoped visible names authorized by one fresh stable view per item.

use scap_object_store::{ListEnd, ListKind, ListMode, ListRequest, Listings};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::discovery::{DiscoveryBudget, DiscoveryError, DiscoveryUsage};
use super::discovery_budget::Meter;
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleName {
    pub creation: Creation,
    pub binding_revision: u64,
    pub head_revision: u64,
}

/// Private server state; never serialize it directly into a user cursor.
#[derive(Clone, Debug)]
pub struct NameCursor {
    owner: Arc<()>,
    principal: u64,
    after: Option<String>,
    finished: bool,
}

#[derive(Clone, Debug)]
pub struct NamePage {
    pub names: Vec<VisibleName>,
    pub cursor: NameCursor,
    pub traversal_exhausted: bool,
    pub stopped: Option<DiscoveryError>,
    /// Internal cost accounting; a wire layer must not expose denied-item
    /// counts, raw frontiers, or other tenants' metadata to ordinary users.
    pub usage: DiscoveryUsage,
}

#[derive(Clone)]
pub struct VisibleNames {
    catalogue: Catalogue,
    listings: Arc<dyn Listings>,
    owner: Arc<()>,
    pub(super) now: fn() -> Instant,
}

impl VisibleNames {
    /// Catalogue deployment/tenant must come from trusted authentication.
    pub fn new(catalogue: Catalogue, listings: Arc<dyn Listings>) -> Self {
        Self {
            catalogue,
            listings,
            owner: Arc::new(()),
            now: Instant::now,
        }
    }

    pub fn begin(&self, caller: Caller) -> Result<NameCursor, DiscoveryError> {
        Catalogue::caller(caller)?;
        Ok(NameCursor {
            owner: self.owner.clone(),
            principal: caller.principal,
            after: None,
            finished: false,
        })
    }

    pub fn page(
        &self,
        caller: Caller,
        mut cursor: NameCursor,
        budget: DiscoveryBudget,
        deadline: Instant,
    ) -> Result<NamePage, DiscoveryError> {
        Catalogue::caller(caller)?;
        if !Arc::ptr_eq(&self.owner, &cursor.owner) || caller.principal != cursor.principal {
            return Err(DiscoveryError::Invalid);
        }
        let meter = Meter::new(self.catalogue.objects.clone(), budget.validate()?, self.now);
        let catalogue = Catalogue {
            objects: meter.clone(),
            ..self.catalogue.clone()
        };
        let deadline = deadline.min((self.now)() + Duration::from_secs(5));
        let mut names = Vec::new();
        let stopped = self
            .advance(
                caller,
                &catalogue,
                &mut cursor,
                &meter,
                &mut names,
                deadline,
            )
            .err()
            .map(|error| meter.failure(error));
        Ok(NamePage {
            names,
            traversal_exhausted: cursor.finished,
            cursor,
            stopped,
            usage: meter.usage(),
        })
    }

    fn advance(
        &self,
        caller: Caller,
        catalogue: &Catalogue,
        cursor: &mut NameCursor,
        meter: &Arc<Meter>,
        names: &mut Vec<VisibleName>,
        deadline: Instant,
    ) -> Result<(), DiscoveryError> {
        let prefix = format!("{}/name/", catalogue.prefix());
        while !cursor.finished {
            meter.page(deadline)?;
            let page = self.listings.list_page(
                &ListRequest {
                    prefix: &prefix,
                    mode: ListMode::Keys,
                    after: cursor.after.as_deref(),
                },
                deadline,
            )?;
            meter.listed(page.response_bytes)?;
            meter.remaining(deadline)?;
            for entry in &page.entries {
                meter.candidate(deadline)?;
                if entry.kind != ListKind::Object {
                    return Err(DiscoveryError::Corrupt);
                }
                let visible = match catalogue.visible_candidate(caller, entry, deadline) {
                    Ok(name) => name,
                    Err(DiscoveryError::Denied) => None,
                    Err(error) => return Err(error),
                };
                meter.remaining(deadline)?;
                if let Some(name) = visible {
                    names.push(name);
                }
                cursor.after = Some(entry.key.clone());
            }
            if page.end == ListEnd::Exhausted {
                cursor.finished = true;
            } else if page.entries.is_empty() {
                return Err(DiscoveryError::Corrupt);
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameCheckpoint {
    schema: u32,
    deployment: u64,
    tenant: u64,
    principal: u64,
    after: Option<String>,
    finished: bool,
}

impl VisibleNames {
    pub fn checkpoint(&self, cursor: &NameCursor) -> Result<Vec<u8>, DiscoveryError> {
        if !Arc::ptr_eq(&self.owner, &cursor.owner) {
            return Err(DiscoveryError::Invalid);
        }
        Ok(serde_json::to_vec(&NameCheckpoint {
            schema: 1,
            deployment: self.catalogue.deployment,
            tenant: self.catalogue.tenant,
            principal: cursor.principal,
            after: cursor.after.clone(),
            finished: cursor.finished,
        })
        .expect("fixed checkpoint fields"))
    }

    /// The server must first authenticate its enclosing encrypted cursor and
    /// reauthenticate the real caller. These bytes are not an access token.
    pub fn resume_authenticated(
        &self,
        caller: Caller,
        bytes: &[u8],
    ) -> Result<NameCursor, DiscoveryError> {
        Catalogue::caller(caller)?;
        if bytes.len() > 8192 {
            return Err(DiscoveryError::Invalid);
        }
        let value: NameCheckpoint =
            serde_json::from_slice(bytes).map_err(|_| DiscoveryError::Invalid)?;
        if serde_json::to_vec(&value).expect("fixed checkpoint fields") != bytes
            || value.schema != 1
            || value.deployment != self.catalogue.deployment
            || value.tenant != self.catalogue.tenant
            || value.principal != caller.principal
        {
            return Err(DiscoveryError::Invalid);
        }
        if let Some(after) = &value.after {
            super::discovery::frontier(
                after,
                &format!("scap-object/v1/{}/{}/", value.deployment, value.tenant),
                super::discovery::Phase::Names,
            )?;
        }
        Ok(NameCursor {
            owner: self.owner.clone(),
            principal: value.principal,
            after: value.after,
            finished: value.finished,
        })
    }
}
