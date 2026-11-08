//! One bounded page of candidate discovery. LIST never establishes authority.

use std::error::Error;
use std::fmt;
use std::time::Instant;

use object_store::list::{PaginatedListOptions, PaginatedListResult, PaginatedListStore};
use object_store::path::Path;
use tokio::runtime::Handle;

use crate::S3;

pub const MAX_LIST_ENTRIES: usize = 32;
pub const MAX_LIST_RESPONSE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_LIST_TOKEN_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListMode {
    Keys,
    Children,
}

/// A nonempty canonical prefix ending in `/`, and an optional exclusive UTF-8
/// byte-order frontier in that prefix. Children frontiers may end in `/`.
/// Only S3 general-purpose buckets and backends implementing their ordered
/// ListObjectsV2 contract are supported. Directory buckets are not supported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListRequest<'a> {
    pub prefix: &'a str,
    pub mode: ListMode,
    pub after: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListKind {
    Object,
    Prefix,
}

/// A candidate raw key or immediate child prefix, never a database authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListEntry {
    pub key: String,
    pub kind: ListKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListEnd {
    /// This response explicitly says the requested traversal is exhausted.
    /// It is not a cross-page snapshot or a global recovery-complete claim.
    Exhausted,
    /// The last returned candidate, suitable for StartAfter only after the
    /// caller has classified every preceding candidate. On a classification
    /// budget/error, persist only the last classified entry, not this frontier.
    More { after: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPage {
    pub entries: Vec<ListEntry>,
    pub end: ListEnd,
    pub response_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListError {
    Invalid,
    Limit,
    Corrupt,
    Denied,
    Unknown,
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ListError {}

pub trait Listings: Send + Sync {
    /// Fetch at most 32 candidates in one request and at most 1 MiB of XML.
    /// Errors, including missing buckets and expired deadlines, are never an
    /// empty page. Exact GET and current authorization must classify entries.
    fn list_page(
        &self,
        request: &ListRequest<'_>,
        deadline: Instant,
    ) -> Result<ListPage, ListError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Context {
    pub bucket: String,
    pub prefix: String,
    pub mode: ListMode,
    pub after: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Proof {
    pub context: Context,
    pub objects: Vec<String>,
    pub prefixes: Vec<String>,
    pub token: Option<String>,
    pub page: ListPage,
}

impl Listings for S3 {
    fn list_page(
        &self,
        request: &ListRequest<'_>,
        deadline: Instant,
    ) -> Result<ListPage, ListError> {
        if Handle::try_current().is_ok() || self.bucket.ends_with("--x-s3") {
            return Err(ListError::Invalid);
        }
        let context = Context::new(&self.bucket, request)?;
        remaining(deadline)?;
        let mut options = PaginatedListOptions {
            offset: context.after.clone(),
            delimiter: match context.mode {
                ListMode::Keys => None,
                ListMode::Children => Some("/".into()),
            },
            max_keys: Some(MAX_LIST_ENTRIES),
            ..Default::default()
        };
        options.extensions.insert(context.clone());
        let outcome = self.runtime.block_on(async {
            tokio::time::timeout_at(deadline.into(), async {
                let result = self
                    .store
                    .list_paginated(Some(&context.prefix), options)
                    .await
                    .map_err(list_error)?;
                validate_result(&context, result)
            })
            .await
            .map_err(|_| ListError::Unknown)?
        });
        // CPU parsing is also charged to the caller's original absolute bound.
        remaining(deadline)?;
        outcome
    }
}

impl Context {
    fn new(bucket: &str, request: &ListRequest<'_>) -> Result<Self, ListError> {
        if !canonical_prefix(request.prefix) {
            return Err(ListError::Invalid);
        }
        let context = Self {
            bucket: bucket.into(),
            prefix: request.prefix.into(),
            mode: request.mode,
            after: request.after.map(str::to_owned),
        };
        if let Some(after) = request.after {
            let kind = if after.ends_with('/') {
                ListKind::Prefix
            } else {
                ListKind::Object
            };
            context.check_entry(after, kind)?;
        }
        Ok(context)
    }

    pub fn check_entry(&self, key: &str, kind: ListKind) -> Result<(), ListError> {
        let suffix = key.strip_prefix(&self.prefix).ok_or(ListError::Invalid)?;
        if suffix.is_empty() {
            return Err(ListError::Invalid);
        }
        let valid = match kind {
            ListKind::Object => {
                canonical_key(key) && (self.mode == ListMode::Keys || !suffix.contains('/'))
            }
            ListKind::Prefix => {
                self.mode == ListMode::Children
                    && canonical_prefix(key)
                    && !suffix[..suffix.len() - 1].contains('/')
            }
        };
        if !valid {
            return Err(ListError::Invalid);
        }
        Ok(())
    }
}

fn canonical_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 1024 {
        return false;
    }
    Path::parse(key).is_ok_and(|path| path.as_ref() == key)
}

fn canonical_prefix(prefix: &str) -> bool {
    prefix.len() <= 1024 && prefix.strip_suffix('/').is_some_and(canonical_key)
}

fn remaining(deadline: Instant) -> Result<(), ListError> {
    if Instant::now() >= deadline {
        return Err(ListError::Unknown);
    }
    Ok(())
}

fn validate_result(
    context: &Context,
    mut result: PaginatedListResult,
) -> Result<ListPage, ListError> {
    let proof = result
        .result
        .extensions
        .remove::<Proof>()
        .ok_or(ListError::Corrupt)?;
    if proof.context != *context
        || proof.token != result.page_token
        || proof.objects.len() != result.result.objects.len()
        || proof.prefixes.len() != result.result.common_prefixes.len()
    {
        return Err(ListError::Corrupt);
    }
    for (raw, parsed) in proof.objects.iter().zip(&result.result.objects) {
        if raw != parsed.location.as_ref() {
            return Err(ListError::Corrupt);
        }
    }
    for (raw, parsed) in proof.prefixes.iter().zip(&result.result.common_prefixes) {
        if raw.strip_suffix('/') != Some(parsed.as_ref()) {
            return Err(ListError::Corrupt);
        }
    }
    Ok(proof.page)
}

fn list_error(error: object_store::Error) -> ListError {
    let mut source: Option<&(dyn Error + 'static)> = Some(&error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<ListError>() {
            return *error;
        }
        source = error.source();
    }
    ListError::Unknown
}

#[cfg(test)]
#[path = "listing_tests.rs"]
mod tests;
