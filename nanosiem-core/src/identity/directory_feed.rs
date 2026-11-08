// SPDX-License-Identifier: AGPL-3.0-or-later

//! G22 (port of NAN-3503 to the ClickHouse product): the directory writer
//! behind a connector identity feed (`kind: identity`).
//!
//! On main, identity feeds staged snapshots at the lake's lean enrichment
//! coordinator. Here the directory is the ClickHouse `user_registry`
//! ReplacingMergeTree (keyed `(provider_id, external_id)`, latest `version`
//! wins) with the provider row in PostgreSQL `identity_providers`; the
//! connector runner writes both through this type, so a feed's users land in
//! the same table the native syncs and the `user_registry_dict` read.
//!
//! ```text
//!  feed (connector_feeds.id) ─► identity_providers row  id = cfeed_<feed>,
//!                                 connector_feed_id = <feed>  (one per feed)
//!  users page (full)  ─► upsert: replace the user's attributes; groups kept
//!  users page (delta) ─► upsert: patch (an absent field is unchanged);
//!                          `deleted: true` tombstones the user
//!  full run committed ─► retire_absent: tombstone live users not in the run
//!  memberships        ─► replace_groups: every live user's `groups` set to
//!                          what the walk found (none: emptied)
//! ```
//!
//! Every write is a higher-`version` row, so a later write always wins and a
//! retried page is idempotent. Versions are strictly increasing per writer
//! (wall-clock milliseconds, bumped past the previous one), so two writes to
//! the same user inside one millisecond still order.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::repository::{user_registry_read_source, IdentityRepository, IdentityRepositoryError};
use super::types::{UserRecordUpsert, UserRegistryRow};

/// Free-text `user_registry` columns a connector row may carry.
pub const DIRECTORY_TEXT_FIELDS: &[&str] = &[
    "username",
    "upn",
    "email",
    "display_name",
    "first_name",
    "last_name",
    "department",
    "title",
    "manager_upn",
    "manager_display_name",
    "company",
    "office_location",
    "city",
    "country",
    "phone",
    "employee_id",
    "employee_type",
];

/// Rows per ClickHouse INSERT.
const CHUNK: usize = 1000;

/// One canonical directory row from a connector program. `None` / absent
/// means "not sent": a full row replaces the user's attributes (absent =
/// empty), a delta row patches them (absent = unchanged).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectoryRow {
    pub external_id: String,
    /// Present text columns (keys from [`DIRECTORY_TEXT_FIELDS`]).
    pub text: BTreeMap<String, String>,
    pub account_status: Option<String>,
    pub account_enabled: Option<bool>,
    pub mfa_enabled: Option<bool>,
    /// Epoch milliseconds.
    pub last_sign_in_at: Option<i64>,
    pub created_in_directory_at: Option<i64>,
    /// Groups carried on the users row itself (most specs send memberships
    /// on their own streams instead).
    pub groups: Option<Vec<String>>,
    /// A tombstone: the vendor reports the user removed.
    pub deleted: bool,
    /// The row names its manager by id only and the id is resolved later:
    /// keep the stored `manager_upn` instead of clearing it.
    pub keep_manager: bool,
}

/// The `identity_providers.provider_type` a bundled identity connector feeds.
pub fn provider_type_for_connector(connector: &str) -> Option<&'static str> {
    match connector {
        "entra_directory" => Some("entra_id"),
        "okta_users" => Some("okta"),
        _ => None,
    }
}

/// The `identity_providers.id` of a feed: its `cfeed_...` typeid (stable,
/// unique per feed, within the VARCHAR(50) id).
pub fn provider_id_for_feed(feed_id: Uuid) -> String {
    crate::typeid::encode(crate::typeid::connector_feed::PREFIX, &feed_id)
}

#[derive(Debug, thiserror::Error)]
pub enum DirectoryFeedError {
    #[error(transparent)]
    Repository(#[from] IdentityRepositoryError),
    #[error(transparent)]
    ClickHouse(#[from] clickhouse::error::Error),
    #[error("identity provider id {0} is already used by a provider that is not this feed's")]
    ProviderIdTaken(String),
}

impl From<sqlx::Error> for DirectoryFeedError {
    fn from(e: sqlx::Error) -> Self {
        Self::Repository(IdentityRepositoryError::DatabaseError(e))
    }
}

/// Writes one connector identity feed's users into `user_registry`.
pub struct FeedDirectory {
    repo: IdentityRepository,
    provider_id: String,
    last_version: AtomicI64,
}

impl std::fmt::Debug for FeedDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedDirectory").field("provider_id", &self.provider_id).finish_non_exhaustive()
    }
}

impl FeedDirectory {
    /// The feed's provider row, created on first use and kept in step with
    /// the feed's name. A row with the same id that some other owner holds
    /// is refused.
    pub async fn open(
        repo: IdentityRepository,
        feed_id: Uuid,
        name: &str,
        provider_type: &str,
    ) -> Result<Self, DirectoryFeedError> {
        let provider_id = provider_id_for_feed(feed_id);
        let name: String = name.chars().filter(|c| !c.is_control()).take(100).collect();
        let affected = sqlx::query(
            "INSERT INTO identity_providers (id, name, provider_type, enabled, config, connector_feed_id)
             VALUES ($1, $2, $3, true, '{}'::jsonb, $4)
             ON CONFLICT (id) DO UPDATE
                SET name = EXCLUDED.name, provider_type = EXCLUDED.provider_type, enabled = true
              WHERE identity_providers.connector_feed_id = EXCLUDED.connector_feed_id",
        )
        .bind(&provider_id)
        .bind(&name)
        .bind(provider_type)
        .bind(feed_id)
        .execute(repo.pool())
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(DirectoryFeedError::ProviderIdTaken(provider_id));
        }
        Ok(Self {
            repo,
            provider_id,
            last_version: AtomicI64::new(0),
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// A version above every one this writer used and above the clock.
    fn next_version(&self) -> i64 {
        let now = Utc::now().timestamp_millis();
        let mut prev = self.last_version.load(Ordering::SeqCst);
        loop {
            let next = now.max(prev + 1);
            match self.last_version.compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return next,
                Err(seen) => prev = seen,
            }
        }
    }

    /// Mark the provider's sync as running.
    pub async fn mark_running(&self) -> Result<(), DirectoryFeedError> {
        self.repo
            .update_sync_status(&self.provider_id, "in_progress", None, None, None, None)
            .await?;
        Ok(())
    }

    /// Record the run's outcome on the provider row (status, error, user
    /// count, duration, rows applied).
    pub async fn finish(
        &self,
        status: &str,
        error: Option<&str>,
        duration_ms: i64,
        rows: u64,
    ) -> Result<(), DirectoryFeedError> {
        let users = self.repo.get_user_count(&self.provider_id).await.ok().map(|n| n.clamp(0, i32::MAX as i64) as i32);
        let counts = super::gate::SyncTally { total: rows, dead_lettered: 0, first_reason: None };
        self.repo
            .finish_sync(&self.provider_id, status, error, users, Some(duration_ms), Some(&counts))
            .await?;
        Ok(())
    }

    const SELECT: &'static str = "SELECT provider_id, external_id, username, upn, email, display_name, \
        first_name, last_name, department, title, manager_upn, \
        manager_display_name, company, office_location, city, country, groups, \
        account_enabled, account_status, mfa_enabled, \
        toUnixTimestamp64Milli(last_sign_in_at) AS last_sign_in_at, \
        toUnixTimestamp64Milli(created_in_directory_at) AS created_in_directory_at, \
        phone, employee_id, employee_type, sync_hash, \
        toUnixTimestamp64Milli(last_synced_at) AS last_synced_at, version";

    /// The latest row (any status) of each of `ids`.
    async fn rows_by_id(&self, ids: &[String]) -> Result<HashMap<String, UserRegistryRow>, DirectoryFeedError> {
        let mut out = HashMap::with_capacity(ids.len());
        if ids.is_empty() {
            return Ok(out);
        }
        let ch = self.repo.ch()?;
        let src = user_registry_read_source();
        for chunk in ids.chunks(CHUNK) {
            let rows: Vec<UserRegistryRow> = ch
                .query(&format!("{} FROM {src} WHERE provider_id = ? AND has(?, external_id)", Self::SELECT))
                .bind(&self.provider_id)
                .bind(chunk.to_vec())
                .fetch_all()
                .await?;
            for r in rows {
                out.insert(r.external_id.clone(), r);
            }
        }
        Ok(out)
    }

    /// Every live (not deleted) row of the feed's provider.
    async fn live_rows(&self) -> Result<Vec<UserRegistryRow>, DirectoryFeedError> {
        Ok(self.repo.fetch_live_rows_for_provider(&self.provider_id).await?)
    }

    async fn write(&self, rows: &[UserRecordUpsert]) -> Result<(), DirectoryFeedError> {
        let ch = self.repo.ch()?;
        for chunk in rows.chunks(CHUNK) {
            IdentityRepository::insert_user_rows(ch, &self.provider_id, self.next_version(), chunk).await?;
        }
        Ok(())
    }

    /// Upsert one page. `patch`: a delta page (absent fields unchanged).
    /// Returns the rows written.
    pub async fn upsert(&self, rows: &[DirectoryRow], patch: bool) -> Result<u64, DirectoryFeedError> {
        if rows.is_empty() {
            return Ok(0);
        }
        // Later rows for the same user win within a page too.
        let mut latest: Vec<&DirectoryRow> = Vec::with_capacity(rows.len());
        let mut index: HashMap<&str, usize> = HashMap::new();
        for r in rows {
            match index.get(r.external_id.as_str()) {
                Some(&i) => latest[i] = r,
                None => {
                    index.insert(&r.external_id, latest.len());
                    latest.push(r);
                }
            }
        }
        let ids: Vec<String> = latest.iter().map(|r| r.external_id.clone()).collect();
        let existing = self.rows_by_id(&ids).await?;
        let merged: Vec<UserRecordUpsert> =
            latest.iter().map(|r| merge(r, existing.get(&r.external_id), patch)).collect();
        self.write(&merged).await?;
        Ok(merged.len() as u64)
    }

    /// Manager references (upn, else email, else username) of stored users,
    /// for rows that name their manager by id.
    pub async fn references(&self, ids: &[String]) -> Result<HashMap<String, String>, DirectoryFeedError> {
        let rows = self.rows_by_id(ids).await?;
        Ok(rows
            .into_values()
            .filter(|r| r.account_status != "deleted")
            .filter_map(|r| {
                let reference = [&r.upn, &r.email, &r.username].into_iter().find(|s| !s.is_empty())?.clone();
                Some((r.external_id, reference))
            })
            .collect())
    }

    /// Set `manager_upn` on `(user external_id, manager reference)` pairs.
    pub async fn set_managers(&self, pairs: &[(String, String)]) -> Result<u64, DirectoryFeedError> {
        let ids: Vec<String> = pairs.iter().map(|(u, _)| u.clone()).collect();
        let existing = self.rows_by_id(&ids).await?;
        let rows: Vec<UserRecordUpsert> = pairs
            .iter()
            .filter_map(|(user, manager)| {
                let row = existing.get(user)?;
                (row.manager_upn != *manager).then(|| {
                    let mut up = upsert_from_row(row);
                    up.manager_upn = Some(manager.clone());
                    up.sync_hash = hash_of(&up);
                    up
                })
            })
            .collect();
        self.write(&rows).await?;
        Ok(rows.len() as u64)
    }

    /// After a committed full run: tombstone every live user the run did
    /// not return. Returns how many were retired.
    pub async fn retire_absent(&self, seen: &HashSet<String>) -> Result<u64, DirectoryFeedError> {
        let gone: Vec<UserRecordUpsert> = self
            .live_rows()
            .await?
            .iter()
            .filter(|r| !seen.contains(&r.external_id))
            .map(|r| {
                let mut up = upsert_from_row(r);
                up.account_status = "deleted".into();
                up.account_enabled = false;
                up.sync_hash = hash_of(&up);
                up
            })
            .collect();
        self.write(&gone).await?;
        Ok(gone.len() as u64)
    }

    /// Tombstone every live user of the feed (the feed is being removed).
    pub async fn retire_all(&self) -> Result<u64, DirectoryFeedError> {
        self.retire_absent(&HashSet::new()).await
    }

    /// A complete membership walk: each live user's `groups` becomes what
    /// the walk found for them (sorted, deduped), users it did not name get
    /// none. Returns `(users changed, members not in the directory)`.
    pub async fn replace_groups(&self, groups: &HashMap<String, Vec<String>>) -> Result<(u64, u64), DirectoryFeedError> {
        let live = self.live_rows().await?;
        let known: HashSet<&str> = live.iter().map(|r| r.external_id.as_str()).collect();
        let unmatched = groups.keys().filter(|m| !known.contains(m.as_str())).count() as u64;
        let changed: Vec<UserRecordUpsert> = live
            .iter()
            .filter_map(|r| {
                let mut want = groups.get(&r.external_id).cloned().unwrap_or_default();
                want.sort();
                want.dedup();
                let mut have = r.groups.clone();
                have.sort();
                (want != have).then(|| {
                    let mut up = upsert_from_row(r);
                    up.groups = want;
                    up.sync_hash = hash_of(&up);
                    up
                })
            })
            .collect();
        self.write(&changed).await?;
        Ok((changed.len() as u64, unmatched))
    }
}

fn opt(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn ts(ms: i64) -> Option<DateTime<Utc>> {
    (ms != 0).then(|| DateTime::<Utc>::from_timestamp_millis(ms)).flatten()
}

/// A stored row as an upsert carrying everything forward.
fn upsert_from_row(r: &UserRegistryRow) -> UserRecordUpsert {
    UserRecordUpsert {
        external_id: r.external_id.clone(),
        username: opt(&r.username),
        upn: opt(&r.upn),
        email: opt(&r.email),
        display_name: opt(&r.display_name),
        first_name: opt(&r.first_name),
        last_name: opt(&r.last_name),
        department: opt(&r.department),
        title: opt(&r.title),
        manager_upn: opt(&r.manager_upn),
        manager_display_name: opt(&r.manager_display_name),
        company: opt(&r.company),
        office_location: opt(&r.office_location),
        city: opt(&r.city),
        country: opt(&r.country),
        groups: r.groups.clone(),
        account_enabled: r.account_enabled != 0,
        account_status: r.account_status.clone(),
        mfa_enabled: Some(r.mfa_enabled != 0),
        last_sign_in_at: ts(r.last_sign_in_at),
        created_in_directory_at: ts(r.created_in_directory_at),
        phone: opt(&r.phone),
        employee_id: opt(&r.employee_id),
        employee_type: opt(&r.employee_type),
        sync_hash: r.sync_hash.clone(),
    }
}

fn text_slot<'a>(up: &'a mut UserRecordUpsert, field: &str) -> Option<&'a mut Option<String>> {
    Some(match field {
        "username" => &mut up.username,
        "upn" => &mut up.upn,
        "email" => &mut up.email,
        "display_name" => &mut up.display_name,
        "first_name" => &mut up.first_name,
        "last_name" => &mut up.last_name,
        "department" => &mut up.department,
        "title" => &mut up.title,
        "manager_upn" => &mut up.manager_upn,
        "manager_display_name" => &mut up.manager_display_name,
        "company" => &mut up.company,
        "office_location" => &mut up.office_location,
        "city" => &mut up.city,
        "country" => &mut up.country,
        "phone" => &mut up.phone,
        "employee_id" => &mut up.employee_id,
        "employee_type" => &mut up.employee_type,
        _ => return None,
    })
}

/// Merge a connector row over the stored one (see [`DirectoryRow`]).
pub fn merge(row: &DirectoryRow, existing: Option<&UserRegistryRow>, patch: bool) -> UserRecordUpsert {
    let mut up = match existing {
        Some(e) => upsert_from_row(e),
        None => UserRecordUpsert {
            external_id: row.external_id.clone(),
            username: None,
            upn: None,
            email: None,
            display_name: None,
            first_name: None,
            last_name: None,
            department: None,
            title: None,
            manager_upn: None,
            manager_display_name: None,
            company: None,
            office_location: None,
            city: None,
            country: None,
            groups: Vec::new(),
            account_enabled: false,
            account_status: "unknown".into(),
            mfa_enabled: None,
            last_sign_in_at: None,
            created_in_directory_at: None,
            phone: None,
            employee_id: None,
            employee_type: None,
            sync_hash: String::new(),
        },
    };
    if row.deleted {
        // A tombstone keeps the rest of the record (who was removed).
        for field in DIRECTORY_TEXT_FIELDS {
            if let (Some(v), Some(slot)) = (row.text.get(*field), text_slot(&mut up, field)) {
                *slot = Some(v.clone());
            }
        }
        up.account_status = "deleted".into();
        up.account_enabled = false;
        up.sync_hash = hash_of(&up);
        return up;
    }
    for field in DIRECTORY_TEXT_FIELDS {
        let keep = patch || (*field == "manager_upn" && row.keep_manager);
        if let Some(slot) = text_slot(&mut up, field) {
            match row.text.get(*field) {
                Some(v) => *slot = Some(v.clone()),
                None if keep => {}
                None => *slot = None,
            }
        }
    }
    if let Some(g) = &row.groups {
        up.groups = g.clone();
    }
    match (patch, row.mfa_enabled) {
        (_, Some(m)) => up.mfa_enabled = Some(m),
        (false, None) => up.mfa_enabled = None,
        (true, None) => {}
    }
    match (patch, row.last_sign_in_at) {
        (_, Some(ms)) => up.last_sign_in_at = ts(ms),
        (false, None) => up.last_sign_in_at = None,
        (true, None) => {}
    }
    match (patch, row.created_in_directory_at) {
        (_, Some(ms)) => up.created_in_directory_at = ts(ms),
        (false, None) => up.created_in_directory_at = None,
        (true, None) => {}
    }
    // Status and enabled: what the row says, else derived from the other,
    // else (a patch) what was stored, else (a full row) `unknown`.
    let status = row.account_status.clone().or_else(|| match row.account_enabled {
        Some(true) => Some("active".to_string()),
        Some(false) => Some("disabled".to_string()),
        None => None,
    });
    match status {
        Some(s) => up.account_status = s,
        None if patch && existing.is_some() => {
            // A patch that does not touch status revives a tombstoned user
            // (the vendor sent it again) as unknown rather than deleted.
            if up.account_status == "deleted" {
                up.account_status = "unknown".into();
            }
        }
        None => up.account_status = "unknown".into(),
    }
    up.account_enabled = row.account_enabled.unwrap_or(up.account_status == "active");
    up.sync_hash = hash_of(&up);
    up
}

/// A content hash of the directory record (change detection; not secret).
fn hash_of(up: &UserRecordUpsert) -> String {
    let mut h = Sha256::new();
    let mut put = |s: &str| {
        h.update(s.as_bytes());
        h.update([0u8]);
    };
    put(&up.external_id);
    for v in [
        &up.username, &up.upn, &up.email, &up.display_name, &up.first_name, &up.last_name, &up.department,
        &up.title, &up.manager_upn, &up.manager_display_name, &up.company, &up.office_location, &up.city,
        &up.country, &up.phone, &up.employee_id, &up.employee_type,
    ] {
        put(v.as_deref().unwrap_or(""));
    }
    put(&up.groups.join(","));
    put(&up.account_status);
    put(if up.account_enabled { "1" } else { "0" });
    put(match up.mfa_enabled {
        Some(true) => "1",
        Some(false) => "0",
        None => "",
    });
    put(&up.last_sign_in_at.map(|t| t.timestamp_millis().to_string()).unwrap_or_default());
    put(&up.created_in_directory_at.map(|t| t.timestamp_millis().to_string()).unwrap_or_default());
    hex::encode(h.finalize())
}

#[cfg(test)]
#[path = "directory_feed_tests.rs"]
mod tests;
