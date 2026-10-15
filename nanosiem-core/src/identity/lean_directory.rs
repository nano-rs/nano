// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity directory reads for a trusted-local lean install (NAN-3767).
//!
//! On open core the identity directory (Okta / Entra directory sync, pushed
//! and observed identities) lives in the lean enrichment coordinator's
//! tenant object-store snapshot. The tenant's `query[T]` serves read-only
//! views of it through the cell router:
//!
//! * `POST /v1/identity/directory/users`  — filtered page of raw rows,
//! * `POST /v1/identity/directory/lookup` — every row whose e-mail, UPN or
//!   username equals a value (the inputs to the provenance merge),
//! * `POST /v1/identity/directory/stats`  — counts by feed, source kind and
//!   account status.
//!
//! This client maps those answers onto the API's existing [`UserRecord`] /
//! [`UserListResponse`] shapes so `/api/identity/*` serves the snapshot
//! unchanged. PostgreSQL keeps feed state only; nothing here writes.
//!
//! Tenant pinning: the route (and so the URL's `/v1/tenants/{T}` segment) is
//! the dedicated cell route resolved from the trusted-local env, every body
//! names that tenant, and every response envelope must name it back.
//!
//! Precedence: the store keeps every feed's row with its provenance, and
//! readers apply `pull > push > observed` (NAN-3489 decision 3). A lookup
//! picks the winning users row by that rank and fills its empty fields from
//! the other rows of the same person in the same order; `<provider>:groups`
//! membership sub-feed rows contribute groups only.

use super::{ListUsersParams, UserListResponse, UserRecord};
use crate::lake_http::LakeRequestBuilderExt;
use crate::search::lake_cell::LakeCellRoute;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// The worker's page-size ceiling (`lean_identity_query::MAX_PAGE`).
pub const DIRECTORY_MAX_PAGE: usize = 1000;
/// Membership sub-feed suffix (`<provider>:groups`).
const GROUPS_SUFFIX: &str = ":groups";
/// Pages scanned to find one exact `(feed, external_id)` row.
const GET_MAX_PAGES: usize = 5;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum LeanDirectoryError {
    #[error("identity directory configuration error: {0}")]
    Configuration(String),
    /// The caller's input breaks the worker's request contract.
    #[error("identity directory request is invalid: {0}")]
    Invalid(String),
    #[error("identity directory request failed: {0}")]
    Request(String),
    #[error("identity directory response failed its tenant or shape contract")]
    ResponseContract,
}

/// One raw directory row as `query[T]` serializes it (`IdentityRow`).
/// Unknown fields are tolerated so a widened row never breaks reads.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct DirectoryRow {
    pub feed_id: String,
    pub external_id: String,
    pub source_kind: String,
    pub version: i64,
    pub observed_at: Option<i64>,
    pub username: String,
    pub upn: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub department: String,
    pub title: String,
    pub manager_upn: String,
    pub manager_display_name: String,
    pub company: String,
    pub office_location: String,
    pub city: String,
    pub country: String,
    pub groups: Vec<String>,
    pub account_enabled: Option<bool>,
    pub account_status: String,
    pub mfa_enabled: Option<bool>,
    pub last_sign_in_at: Option<i64>,
    pub created_in_directory_at: Option<i64>,
    pub phone: String,
    pub employee_id: String,
    pub employee_type: String,
    pub last_observed_at: Option<i64>,
}

/// `query[T]`'s directory counts (`IdentityStats`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DirectoryStats {
    pub total: u64,
    pub by_feed: BTreeMap<String, u64>,
    pub by_source_kind: BTreeMap<String, u64>,
    pub by_account_status: BTreeMap<String, u64>,
}

impl DirectoryStats {
    /// Feeds that hold people (every feed but membership sub-feeds).
    pub fn user_feeds(&self) -> impl Iterator<Item = (&str, u64)> {
        self.by_feed
            .iter()
            .filter(|(feed, _)| !is_groups_feed(feed))
            .map(|(feed, count)| (feed.as_str(), *count))
    }

    /// People across user feeds.
    pub fn total_users(&self) -> u64 {
        self.user_feeds().map(|(_, count)| count).sum()
    }

    /// People in the feeds `provider` names: an exact feed id, or a provider
    /// prefix (`okta` → `okta:users`). Anything else (a legacy provider id)
    /// matches nothing and counts 0.
    pub fn provider_users(&self, provider: &str) -> u64 {
        self.user_feeds()
            .filter(|(feed, _)| feed_matches(feed, provider))
            .map(|(_, count)| count)
            .sum()
    }

    fn status(&self, status: &str) -> u64 {
        self.by_account_status.get(status).copied().unwrap_or(0)
    }

    pub fn active_users(&self) -> u64 {
        self.status("active")
    }

    pub fn disabled_users(&self) -> u64 {
        self.status("disabled") + self.status("suspended")
    }
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    result: Value,
}

#[derive(Deserialize)]
struct ListResult {
    total: u64,
    #[serde(default)]
    users: Vec<DirectoryRow>,
}

#[derive(Deserialize)]
struct LookupResult {
    #[serde(default)]
    rows: Vec<DirectoryRow>,
}

/// Typed client for one tenant's `query[T]` identity directory routes.
#[derive(Clone)]
pub struct LeanIdentityDirectoryClient {
    http: reqwest::Client,
    route: Arc<LakeCellRoute>,
    timeout: Duration,
}

impl LeanIdentityDirectoryClient {
    /// The trusted-local install's dedicated cell route (the same route
    /// search, IOC and prevalence read through).
    pub fn from_env() -> Result<Self, LeanDirectoryError> {
        let route = crate::search::lake_cell::dedicated_route_from_env()
            .map_err(LeanDirectoryError::Configuration)?
            .ok_or_else(|| {
                LeanDirectoryError::Configuration(format!(
                    "the lean identity directory needs the dedicated cell route ({} and {})",
                    crate::search::lake_cell::LAKE_CELL_ROUTES_FILE_ENV,
                    crate::search::lake_cell::LAKE_CELL_ROUTER_TOKEN_FILE_ENV
                ))
            })?;
        Self::from_route(route, DEFAULT_TIMEOUT)
    }

    pub fn from_route(
        route: Arc<LakeCellRoute>,
        timeout: Duration,
    ) -> Result<Self, LeanDirectoryError> {
        route
            .validate_query_base()
            .map_err(LeanDirectoryError::Configuration)?;
        if route.tenant_id.is_nil() {
            return Err(LeanDirectoryError::Configuration(
                "the lean identity directory tenant is nil".to_string(),
            ));
        }
        let http = crate::search::lake_cell::lake_cell_http_client_builder(timeout)
            .build()
            .map_err(|error| LeanDirectoryError::Configuration(error.to_string()))?;
        Ok(Self {
            http,
            route,
            timeout,
        })
    }

    fn tenant(&self) -> String {
        self.route.tenant_id.as_hyphenated().to_string()
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        mut body: Value,
    ) -> Result<T, LeanDirectoryError> {
        let tenant = self.tenant();
        body["tenant_id"] = Value::String(tenant.clone());
        // Re-read per call: the router bearer may rotate.
        let bearer = self
            .route
            .read_router_token()
            .map_err(LeanDirectoryError::Configuration)?;
        let response = self
            .http
            .post(format!("{}{}", self.route.query_base_url, path))
            .bearer_auth(bearer)
            .json(&body)
            .send_idempotent_with_recovery_within(Some(self.timeout))
            .await
            .map_err(|error| LeanDirectoryError::Request(error.to_string()))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| LeanDirectoryError::Request(error.to_string()))?;
        let envelope: Option<Envelope> = serde_json::from_slice(&bytes).ok();
        if !status.is_success() || envelope.as_ref().is_none_or(|e| !e.ok) {
            let detail = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| format!("query worker returned HTTP {status}"));
            return Err(LeanDirectoryError::Request(format!(
                "HTTP {status}: {}",
                truncate(&detail, 512)
            )));
        }
        let envelope = envelope.ok_or(LeanDirectoryError::ResponseContract)?;
        if envelope.tenant_id.as_deref() != Some(tenant.as_str()) {
            return Err(LeanDirectoryError::ResponseContract);
        }
        serde_json::from_value(envelope.result).map_err(|_| LeanDirectoryError::ResponseContract)
    }

    pub async fn stats(&self) -> Result<DirectoryStats, LeanDirectoryError> {
        let stats: DirectoryStats = self.post("/v1/identity/directory/stats", json!({})).await?;
        if stats.by_feed.values().sum::<u64>() > stats.total {
            return Err(LeanDirectoryError::ResponseContract);
        }
        Ok(stats)
    }

    async fn list_page(
        &self,
        feed_id: &str,
        search: Option<&str>,
        account_status: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(u64, Vec<DirectoryRow>), LeanDirectoryError> {
        let mut filter = json!({ "feed_id": feed_id });
        if let Some(search) = search {
            filter["search"] = json!(search);
        }
        if let Some(status) = account_status {
            filter["account_status"] = json!(status);
        }
        let result: ListResult = self
            .post(
                "/v1/identity/directory/users",
                json!({ "filter": filter, "offset": offset, "limit": limit }),
            )
            .await?;
        if result.users.len() > limit
            || (result.total as usize) < result.users.len()
            || result.users.iter().any(|row| row.feed_id != feed_id)
        {
            return Err(LeanDirectoryError::ResponseContract);
        }
        Ok((result.total, result.users))
    }

    /// One page of people. Membership sub-feeds are not people, so the page
    /// walks the user feeds in feed order (the snapshot's own row order),
    /// one worker page per feed, and the total is the sum of their totals.
    pub async fn list(
        &self,
        params: &ListUsersParams,
    ) -> Result<UserListResponse, LeanDirectoryError> {
        let search = params
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(search) = search {
            if search.len() > 256 || search.chars().any(char::is_control) {
                return Err(LeanDirectoryError::Invalid(
                    "search must be at most 256 printable characters".to_string(),
                ));
            }
        }
        let account_status = params
            .account_status
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let page = params.page.max(1);
        let page_size = params.page_size.clamp(1, DIRECTORY_MAX_PAGE as i64);
        let stats = self.stats().await?;
        let feeds: Vec<&str> = match params.provider_id.as_deref().filter(|p| !p.is_empty()) {
            // An explicit membership feed may still be browsed directly.
            Some(provider) if is_groups_feed(provider) => stats
                .by_feed
                .keys()
                .filter(|feed| feed.as_str() == provider)
                .map(String::as_str)
                .collect(),
            Some(provider) => stats
                .user_feeds()
                .filter(|(feed, _)| feed_matches(feed, provider))
                .map(|(feed, _)| feed)
                .collect(),
            None => stats.user_feeds().map(|(feed, _)| feed).collect(),
        };
        let mut skip = usize::try_from((page - 1).saturating_mul(page_size)).unwrap_or(usize::MAX);
        let mut need = page_size as usize;
        let mut total = 0u64;
        let mut users = Vec::new();
        for feed in feeds {
            let (feed_total, rows) = self
                .list_page(feed, search, account_status, skip, need.max(1))
                .await?;
            total += feed_total;
            for row in rows.into_iter().take(need) {
                users.push(row_to_record(row));
                need -= 1;
            }
            skip = skip.saturating_sub(usize::try_from(feed_total).unwrap_or(usize::MAX));
        }
        Ok(UserListResponse {
            users,
            total: i64::try_from(total).map_err(|_| LeanDirectoryError::ResponseContract)?,
            page,
            page_size: params.page_size,
        })
    }

    /// The exact `(feed, external_id)` row: the worker has no keyed read,
    /// so search the feed for the id and keep the exact match.
    async fn get_row(
        &self,
        feed_id: &str,
        external_id: &str,
    ) -> Result<Option<DirectoryRow>, LeanDirectoryError> {
        if external_id.len() > 256 || external_id.chars().any(char::is_control) {
            return Ok(None);
        }
        let mut offset = 0usize;
        for _ in 0..GET_MAX_PAGES {
            let (total, rows) = self
                .list_page(feed_id, Some(external_id), None, offset, DIRECTORY_MAX_PAGE)
                .await?;
            let len = rows.len();
            if let Some(row) = rows.into_iter().find(|row| row.external_id == external_id) {
                return Ok(Some(row));
            }
            offset += len;
            if len == 0 || offset as u64 >= total {
                break;
            }
        }
        Ok(None)
    }

    /// One person by composite id (`"{feed_id}|{external_id}"`), with the
    /// provider's membership sub-feed groups folded in.
    pub async fn get_user(
        &self,
        feed_id: &str,
        external_id: &str,
    ) -> Result<Option<UserRecord>, LeanDirectoryError> {
        if !valid_feed_id(feed_id) {
            return Ok(None);
        }
        let Some(row) = self.get_row(feed_id, external_id).await? else {
            return Ok(None);
        };
        let groups = self.membership_groups(&row).await?;
        Ok(Some(merge_person(&row, &[], groups)))
    }

    /// Groups from the `<provider>:groups` row keyed like this users row.
    async fn membership_groups(
        &self,
        row: &DirectoryRow,
    ) -> Result<Vec<String>, LeanDirectoryError> {
        let Some((provider, _)) = row.feed_id.split_once(':') else {
            return Ok(Vec::new());
        };
        if is_groups_feed(&row.feed_id) {
            return Ok(Vec::new());
        }
        let groups_feed = format!("{provider}{GROUPS_SUFFIX}");
        Ok(self
            .get_row(&groups_feed, &row.external_id)
            .await?
            .map(|membership| membership.groups)
            .unwrap_or_default())
    }

    /// The best person for an e-mail, UPN or username (exact,
    /// case-insensitive), merged across feeds by precedence.
    pub async fn lookup(&self, identifier: &str) -> Result<Option<UserRecord>, LeanDirectoryError> {
        let value = identifier.trim();
        if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            return Err(LeanDirectoryError::Invalid(
                "lookup value must be 1-1024 printable characters".to_string(),
            ));
        }
        let result: LookupResult = self
            .post("/v1/identity/directory/lookup", json!({ "value": value }))
            .await?;
        let rows: Vec<DirectoryRow> = result
            .rows
            .into_iter()
            .filter(|row| row.account_status != "deleted")
            .collect();
        let Some(primary) = rows.iter().max_by_key(|row| primary_rank(row)).cloned() else {
            return Ok(None);
        };
        let mut groups = self.membership_groups(&primary).await?;
        let linked: Vec<&DirectoryRow> = rows
            .iter()
            .filter(|row| *row != &primary && same_person(&primary, row))
            .collect();
        for row in &linked {
            if provider_of(&row.feed_id) == provider_of(&primary.feed_id) {
                groups.extend(row.groups.iter().cloned());
            }
        }
        Ok(Some(merge_person(&primary, &linked, groups)))
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn is_groups_feed(feed_id: &str) -> bool {
    feed_id.ends_with(GROUPS_SUFFIX)
}

fn provider_of(feed_id: &str) -> &str {
    feed_id
        .split_once(':')
        .map_or(feed_id, |(prefix, _)| prefix)
}

fn feed_matches(feed: &str, provider: &str) -> bool {
    feed == provider || provider_of(feed) == provider
}

fn valid_feed_id(feed_id: &str) -> bool {
    !feed_id.is_empty()
        && feed_id.len() <= 256
        && feed_id.as_bytes()[0].is_ascii_alphanumeric()
        && feed_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

/// `pull > push > observed` (NAN-3489 decision 3).
fn source_rank(kind: &str) -> u8 {
    match kind {
        "pull" => 2,
        "push" => 1,
        _ => 0,
    }
}

/// Users rows beat membership rows; then source precedence, then an active
/// account, then the newest version.
fn primary_rank(row: &DirectoryRow) -> (bool, u8, bool, i64) {
    (
        !is_groups_feed(&row.feed_id),
        source_rank(&row.source_kind),
        row.account_status == "active",
        row.version,
    )
}

fn same_person(a: &DirectoryRow, b: &DirectoryRow) -> bool {
    if provider_of(&a.feed_id) == provider_of(&b.feed_id) && a.external_id == b.external_id {
        return true;
    }
    let addresses = |row: &DirectoryRow| -> BTreeSet<String> {
        [&row.email, &row.upn]
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase())
            .collect()
    };
    !addresses(a).is_disjoint(&addresses(b))
}

fn text(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn millis(value: Option<i64>) -> Option<DateTime<Utc>> {
    value
        .filter(|ms| *ms > 0)
        .and_then(DateTime::<Utc>::from_timestamp_millis)
}

fn row_to_record(row: DirectoryRow) -> UserRecord {
    let synced = millis(row.observed_at.or(row.last_observed_at));
    UserRecord {
        id: UserRecord::composite_id(&row.feed_id, &row.external_id),
        username: text(&row.username),
        upn: text(&row.upn),
        email: text(&row.email),
        display_name: text(&row.display_name),
        first_name: text(&row.first_name),
        last_name: text(&row.last_name),
        department: text(&row.department),
        title: text(&row.title),
        manager_upn: text(&row.manager_upn),
        manager_display_name: text(&row.manager_display_name),
        company: text(&row.company),
        office_location: text(&row.office_location),
        city: text(&row.city),
        country: text(&row.country),
        groups: (!row.groups.is_empty()).then_some(row.groups),
        account_enabled: row.account_enabled,
        account_status: text(&row.account_status),
        mfa_enabled: row.mfa_enabled,
        last_sign_in_at: millis(row.last_sign_in_at),
        created_in_directory_at: millis(row.created_in_directory_at),
        phone: text(&row.phone),
        employee_id: text(&row.employee_id),
        employee_type: text(&row.employee_type),
        last_synced_at: synced,
        sync_hash: None,
        updated_at: synced,
        provider_id: row.feed_id,
        external_id: row.external_id,
    }
}

/// The primary row with every empty field filled from `linked` rows in
/// precedence order. Account state stays the primary users row's.
fn merge_person(
    primary: &DirectoryRow,
    linked: &[&DirectoryRow],
    groups: Vec<String>,
) -> UserRecord {
    let mut merged = primary.clone();
    let mut donors: Vec<&&DirectoryRow> = linked
        .iter()
        .filter(|row| !is_groups_feed(&row.feed_id))
        .collect();
    donors.sort_by_key(|row| std::cmp::Reverse((source_rank(&row.source_kind), row.version)));
    macro_rules! fill {
        ($($field:ident),*) => {$(
            if merged.$field.is_empty() {
                if let Some(donor) = donors.iter().find(|d| !d.$field.is_empty()) {
                    merged.$field.clone_from(&donor.$field);
                }
            }
        )*};
    }
    fill!(
        username,
        upn,
        email,
        display_name,
        first_name,
        last_name,
        department,
        title,
        manager_upn,
        manager_display_name,
        company,
        office_location,
        city,
        country,
        phone,
        employee_id,
        employee_type
    );
    macro_rules! fill_option {
        ($($field:ident),*) => {$(
            if merged.$field.is_none() {
                merged.$field = donors.iter().find_map(|d| d.$field);
            }
        )*};
    }
    fill_option!(mfa_enabled, last_sign_in_at, created_in_directory_at);
    let mut all: BTreeSet<String> = merged.groups.drain(..).collect();
    all.extend(groups);
    merged.groups = all.into_iter().collect();
    row_to_record(merged)
}

#[cfg(test)]
#[path = "lean_directory_tests.rs"]
mod tests;
