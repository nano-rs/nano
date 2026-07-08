// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity provider repository
//!
//! Database operations for identity providers and the user registry.

use sqlx::PgPool;
use thiserror::Error;
use tracing::instrument;

use super::types::*;
use crate::crypto::EncryptionService;
use crate::db::dual_pool::{on_cluster_clause, TableNames};

/// Deduped read source for `user_registry` (NAN-1728).
///
/// `user_registry` is a per-shard ReplacingMergeTree with an additive
/// `_distributed` wrapper (in DISTRIBUTED_TABLES). Reads MUST route through the
/// wrapper so a user is visible regardless of which shard the sync INSERT landed
/// on. But `FINAL` on a Distributed table only collapses WITHIN each shard, so
/// the same `(provider_id, external_id)` written to two shards survives as two
/// rows. On a cluster we therefore wrap the wrapper in a subquery that keeps the
/// single highest-`version` row per logical user across shards
/// (`ORDER BY version DESC LIMIT 1 BY provider_id, external_id`). `SELECT *`
/// omits MATERIALIZED columns, so the `*_lc` filter columns are re-exposed
/// explicitly. On single-node `.read()` returns the local name and this yields
/// exactly `nanosiem.user_registry FINAL` — byte-identical to the pre-NAN-1728
/// query.
fn user_registry_read_source() -> String {
    let tn = TableNames::new(!on_cluster_clause().is_empty());
    let table = tn.read("user_registry");
    if tn.is_clustered() {
        format!(
            "(SELECT *, username_lc, upn_lc, email_lc FROM {table} FINAL \
             ORDER BY version DESC LIMIT 1 BY provider_id, external_id)"
        )
    } else {
        format!("{table} FINAL")
    }
}

// =============================================================================
// Error Types
// =============================================================================

#[derive(Error, Debug)]
pub enum IdentityRepositoryError {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),
    #[error("Provider already exists: {0}")]
    ProviderAlreadyExists(String),
    #[error("Invalid provider type: {0}")]
    InvalidProviderType(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("ClickHouse error: {0}")]
    ClickHouse(#[from] clickhouse::error::Error),
}

// =============================================================================
// Repository
// =============================================================================

/// CHUNK size for batched ClickHouse INSERTs of directory rows (mirrors the
/// IOC/IP enrichment writers).
const CH_INSERT_CHUNK: usize = 1000;

#[derive(Clone)]
pub struct IdentityRepository {
    /// PostgreSQL pool — config/metadata only (identity_providers, creds,
    /// sync_status, delta_link). NAN-1117 moved the user_registry payload off
    /// PG into ClickHouse.
    pool: PgPool,
    /// ClickHouse client for the user_registry directory feed (read + write).
    /// Optional so the marketplace install path (PG-only credential push) can
    /// construct the repo without a CH client; the payload methods error with
    /// `ClickHouseNotConfigured` rather than silently writing PG.
    clickhouse: Option<clickhouse::Client>,
    encryption: EncryptionService,
}

impl IdentityRepository {
    /// Construct a PG-only repository (config/metadata; no user_registry
    /// payload access). Used by the marketplace credential-push path.
    pub fn new(pool: PgPool) -> Self {
        Self {
            encryption: EncryptionService::from_env(),
            pool,
            clickhouse: None,
        }
    }

    /// Construct a full repository with the ClickHouse client backing the
    /// user_registry directory feed (NAN-1117). Used by the API state ctor.
    pub fn new_with_clickhouse(pool: PgPool, clickhouse: clickhouse::Client) -> Self {
        Self {
            encryption: EncryptionService::from_env(),
            pool,
            clickhouse: Some(clickhouse),
        }
    }

    /// Get the ClickHouse client or a typed error if it was never configured.
    fn ch(&self) -> Result<&clickhouse::Client, IdentityRepositoryError> {
        self.clickhouse.as_ref().ok_or_else(|| {
            IdentityRepositoryError::EncryptionError(
                "ClickHouse client not configured for identity user_registry".to_string(),
            )
        })
    }

    // ========================================================================
    // Provider CRUD
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn list_providers(&self) -> Result<Vec<IdentityProvider>, IdentityRepositoryError> {
        let providers = sqlx::query_as::<_, IdentityProvider>(
            "SELECT id, name, provider_type, enabled, credentials_encrypted, config,
                    sync_status, last_sync_at, last_sync_error, last_sync_duration_ms,
                    user_count, deprovisioned_count, delta_link, created_at, updated_at
             FROM identity_providers ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(providers)
    }

    #[instrument(skip(self))]
    pub async fn get_provider(
        &self,
        id: &str,
    ) -> Result<IdentityProvider, IdentityRepositoryError> {
        sqlx::query_as::<_, IdentityProvider>(
            "SELECT id, name, provider_type, enabled, credentials_encrypted, config,
                    sync_status, last_sync_at, last_sync_error, last_sync_duration_ms,
                    user_count, deprovisioned_count, delta_link, created_at, updated_at
             FROM identity_providers WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| IdentityRepositoryError::ProviderNotFound(id.to_string()))
    }

    #[instrument(skip(self))]
    pub async fn create_provider(
        &self,
        req: &CreateIdentityProvider,
    ) -> Result<IdentityProvider, IdentityRepositoryError> {
        // Validate provider type
        let _pt: IdentityProviderType = req
            .provider_type
            .parse()
            .map_err(|_| IdentityRepositoryError::InvalidProviderType(req.provider_type.clone()))?;

        let result = sqlx::query_as::<_, IdentityProvider>(
            "INSERT INTO identity_providers (id, name, provider_type, enabled, config)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, name, provider_type, enabled, credentials_encrypted, config,
                       sync_status, last_sync_at, last_sync_error, last_sync_duration_ms,
                       user_count, deprovisioned_count, delta_link, created_at, updated_at",
        )
        .bind(&req.id)
        .bind(&req.name)
        .bind(&req.provider_type)
        .bind(req.enabled)
        .bind(&req.config)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("identity_providers_pkey") {
                    return IdentityRepositoryError::ProviderAlreadyExists(req.id.clone());
                }
            }
            IdentityRepositoryError::DatabaseError(e)
        })?;

        Ok(result)
    }

    #[instrument(skip(self))]
    pub async fn update_provider(
        &self,
        id: &str,
        req: &UpdateIdentityProvider,
    ) -> Result<IdentityProvider, IdentityRepositoryError> {
        // Ensure provider exists
        let _existing = self.get_provider(id).await?;

        let result = sqlx::query_as::<_, IdentityProvider>(
            "UPDATE identity_providers
             SET name = COALESCE($2, name),
                 enabled = COALESCE($3, enabled),
                 config = COALESCE($4, config)
             WHERE id = $1
             RETURNING id, name, provider_type, enabled, credentials_encrypted, config,
                       sync_status, last_sync_at, last_sync_error, last_sync_duration_ms,
                       user_count, deprovisioned_count, delta_link, created_at, updated_at",
        )
        .bind(id)
        .bind(&req.name)
        .bind(req.enabled)
        .bind(&req.config)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    #[instrument(skip(self))]
    pub async fn delete_provider(&self, id: &str) -> Result<(), IdentityRepositoryError> {
        let rows = sqlx::query("DELETE FROM identity_providers WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();

        if rows == 0 {
            return Err(IdentityRepositoryError::ProviderNotFound(id.to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // Credentials (encrypted)
    // ========================================================================

    #[instrument(skip(self, credentials))]
    pub async fn update_credentials(
        &self,
        id: &str,
        credentials: &serde_json::Value,
    ) -> Result<(), IdentityRepositoryError> {
        let _existing = self.get_provider(id).await?;

        let plaintext = serde_json::to_vec(credentials)
            .map_err(|e| IdentityRepositoryError::EncryptionError(e.to_string()))?;
        let encrypted = self
            .encryption
            .encrypt(&plaintext)
            .map_err(|e| IdentityRepositoryError::EncryptionError(e.to_string()))?;
        let encrypted_bytes = serde_json::to_vec(&encrypted)
            .map_err(|e| IdentityRepositoryError::EncryptionError(e.to_string()))?;

        sqlx::query("UPDATE identity_providers SET credentials_encrypted = $2 WHERE id = $1")
            .bind(id)
            .bind(&encrypted_bytes)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get_decrypted_credentials(
        &self,
        id: &str,
    ) -> Result<serde_json::Value, IdentityRepositoryError> {
        let provider = self.get_provider(id).await?;
        let encrypted_bytes = provider.credentials_encrypted.ok_or_else(|| {
            IdentityRepositoryError::EncryptionError("No credentials stored".to_string())
        })?;

        let encrypted: crate::crypto::EncryptedData = serde_json::from_slice(&encrypted_bytes)
            .map_err(|e| IdentityRepositoryError::EncryptionError(e.to_string()))?;
        let plaintext = self
            .encryption
            .decrypt(&encrypted)
            .map_err(|e| IdentityRepositoryError::EncryptionError(e.to_string()))?;
        let value: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| IdentityRepositoryError::EncryptionError(e.to_string()))?;

        Ok(value)
    }

    // ========================================================================
    // Sync Status
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn update_sync_status(
        &self,
        id: &str,
        status: &str,
        error: Option<&str>,
        user_count: Option<i32>,
        duration_ms: Option<i64>,
        delta_link: Option<&str>,
    ) -> Result<(), IdentityRepositoryError> {
        sqlx::query(
            "UPDATE identity_providers
             SET sync_status = $2,
                 last_sync_error = $3,
                 user_count = COALESCE($4, user_count),
                 last_sync_duration_ms = $5,
                 delta_link = COALESCE($6, delta_link),
                 last_sync_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE last_sync_at END
             WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(error)
        .bind(user_count)
        .bind(duration_ms)
        .bind(delta_link)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ========================================================================
    // User Registry — Bulk Operations
    // ========================================================================

    /// Column list (and matching VALUES tuple) for a user_registry INSERT.
    /// `version` is the ReplacingMergeTree version (ms epoch); the materialized
    /// *_lc columns are NOT listed (CH computes them).
    const USER_COLUMNS: &'static str = "(provider_id, external_id, username, upn, email, \
        display_name, first_name, last_name, department, title, manager_upn, \
        manager_display_name, company, office_location, city, country, groups, \
        account_enabled, account_status, mfa_enabled, last_sign_in_at, \
        created_in_directory_at, phone, employee_id, employee_type, sync_hash, \
        last_synced_at, version)";
    const USER_VALUE_TUPLE: &'static str =
        "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    /// Build + execute a single multi-row INSERT for `rows` (length >= 1).
    /// DateTime64(3) columns are bound as ms-epoch i64 (0 = unset).
    async fn insert_user_rows(
        ch: &clickhouse::Client,
        provider_id: &str,
        version_ms: i64,
        rows: &[UserRecordUpsert],
    ) -> Result<(), clickhouse::error::Error> {
        // Writes the LOCAL name. NAN-1728: user_registry is a per-shard
        // ReplacingMergeTree with an additive `_distributed` wrapper; this INSERT
        // (used for both fresh upserts and the higher-version tombstones that
        // implement soft-delete) lands on whichever shard the connection hit. The
        // write path is deliberately left per-shard; reads route through the
        // wrapper and collapse cross-shard duplicates by latest version (see
        // `user_registry_read_source`). Single-node: the one shard holds all rows.
        let tuples = vec![Self::USER_VALUE_TUPLE; rows.len()].join(", ");
        let sql = format!(
            "INSERT INTO nanosiem.user_registry {} VALUES {}",
            Self::USER_COLUMNS,
            tuples
        );
        let opt_str = |v: &Option<String>| v.clone().unwrap_or_default();
        let opt_ms = |v: &Option<chrono::DateTime<chrono::Utc>>| -> i64 {
            v.map(|d| d.timestamp_millis()).unwrap_or(0)
        };

        let mut q = ch.query(&sql);
        for r in rows {
            q = q
                .bind(provider_id)
                .bind(&r.external_id)
                .bind(opt_str(&r.username))
                .bind(opt_str(&r.upn))
                .bind(opt_str(&r.email))
                .bind(opt_str(&r.display_name))
                .bind(opt_str(&r.first_name))
                .bind(opt_str(&r.last_name))
                .bind(opt_str(&r.department))
                .bind(opt_str(&r.title))
                .bind(opt_str(&r.manager_upn))
                .bind(opt_str(&r.manager_display_name))
                .bind(opt_str(&r.company))
                .bind(opt_str(&r.office_location))
                .bind(opt_str(&r.city))
                .bind(opt_str(&r.country))
                .bind(r.groups.clone())
                .bind(if r.account_enabled { 1u8 } else { 0u8 })
                .bind(&r.account_status)
                .bind(if r.mfa_enabled.unwrap_or(false) { 1u8 } else { 0u8 })
                .bind(opt_ms(&r.last_sign_in_at))
                .bind(opt_ms(&r.created_in_directory_at))
                .bind(opt_str(&r.phone))
                .bind(opt_str(&r.employee_id))
                .bind(opt_str(&r.employee_type))
                .bind(r.sync_hash.clone())
                .bind(version_ms)
                .bind(version_ms);
        }
        q.execute().await
    }

    /// Mark users as deleted if they weren't touched during the current sync.
    /// Any live user whose last_synced_at is before `cutoff` wasn't in the
    /// provider's response. CH version of the old PG soft-delete UPDATE: read
    /// the deduped live rows, re-insert the stale ones as a higher-version
    /// deleted row (full record carried forward).
    #[instrument(skip(self))]
    pub async fn mark_absent_users_by_sync_time(
        &self,
        provider_id: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, IdentityRepositoryError> {
        let cutoff_ms = cutoff.timestamp_millis();
        let live = self.fetch_live_rows_for_provider(provider_id).await?;
        let stale: Vec<UserRegistryRow> = live
            .into_iter()
            .filter(|r| r.last_synced_at < cutoff_ms)
            .collect();
        self.soft_delete_rows(stale).await
    }

    /// Read the current (deduped, non-deleted) rows for a provider via FINAL +
    /// argMax-safe filtering. Returns the latest version of each
    /// (provider_id, external_id) whose latest account_status is not 'deleted'.
    async fn fetch_live_rows_for_provider(
        &self,
        provider_id: &str,
    ) -> Result<Vec<UserRegistryRow>, IdentityRepositoryError> {
        // Routes through the `_distributed` wrapper on clusters (see
        // `user_registry_read_source`) so the read half of the soft-delete
        // read-mutate cycle sees every shard's live rows, cross-shard collapsed to
        // the latest version per user. Single-node → local `… FINAL`,
        // byte-identical.
        let ch = self.ch()?;
        let src = user_registry_read_source();
        let rows: Vec<UserRegistryRow> = ch
            .query(&format!(
                "SELECT provider_id, external_id, username, upn, email, display_name, \
                    first_name, last_name, department, title, manager_upn, \
                    manager_display_name, company, office_location, city, country, groups, \
                    account_enabled, account_status, mfa_enabled, \
                    toUnixTimestamp64Milli(last_sign_in_at) AS last_sign_in_at, \
                    toUnixTimestamp64Milli(created_in_directory_at) AS created_in_directory_at, \
                    phone, employee_id, employee_type, sync_hash, \
                    toUnixTimestamp64Milli(last_synced_at) AS last_synced_at, version \
                 FROM {src} \
                 WHERE provider_id = ? AND account_status != 'deleted'",
            ))
            .bind(provider_id)
            .fetch_all()
            .await?;
        Ok(rows)
    }

    /// Re-insert the given rows as higher-version tombstones (account_status =
    /// 'deleted', account_enabled = 0), carrying the rest of the record forward.
    async fn soft_delete_rows(
        &self,
        rows: Vec<UserRegistryRow>,
    ) -> Result<u64, IdentityRepositoryError> {
        if rows.is_empty() {
            return Ok(0);
        }
        let ch = self.ch()?;
        let version_ms = chrono::Utc::now().timestamp_millis();
        let mut count = 0u64;
        for chunk in rows.chunks(CH_INSERT_CHUNK) {
            let upserts: Vec<UserRecordUpsert> = chunk
                .iter()
                .map(|r| UserRecordUpsert {
                    external_id: r.external_id.clone(),
                    username: Some(r.username.clone()),
                    upn: Some(r.upn.clone()),
                    email: Some(r.email.clone()),
                    display_name: Some(r.display_name.clone()),
                    first_name: Some(r.first_name.clone()),
                    last_name: Some(r.last_name.clone()),
                    department: Some(r.department.clone()),
                    title: Some(r.title.clone()),
                    manager_upn: Some(r.manager_upn.clone()),
                    manager_display_name: Some(r.manager_display_name.clone()),
                    company: Some(r.company.clone()),
                    office_location: Some(r.office_location.clone()),
                    city: Some(r.city.clone()),
                    country: Some(r.country.clone()),
                    groups: r.groups.clone(),
                    account_enabled: false,
                    account_status: "deleted".to_string(),
                    mfa_enabled: Some(r.mfa_enabled != 0),
                    last_sign_in_at: chrono::DateTime::from_timestamp_millis(r.last_sign_in_at),
                    created_in_directory_at: chrono::DateTime::from_timestamp_millis(
                        r.created_in_directory_at,
                    ),
                    phone: Some(r.phone.clone()),
                    employee_id: Some(r.employee_id.clone()),
                    employee_type: Some(r.employee_type.clone()),
                    sync_hash: r.sync_hash.clone(),
                })
                .collect();
            // provider_id is uniform within fetch_live_rows_for_provider results.
            let provider_id = chunk[0].provider_id.clone();
            Self::insert_user_rows(ch, &provider_id, version_ms, &upserts).await?;
            count += chunk.len() as u64;
        }
        Ok(count)
    }

    // ========================================================================
    // User Registry — Queries
    //
    // NAN-1728: `user_registry` is a per-shard ReplacingMergeTree with an additive
    // `_distributed` wrapper (in DISTRIBUTED_TABLES). Every read below builds its
    // FROM via `user_registry_read_source()`, which routes to the wrapper on
    // clusters and cross-shard-collapses to the latest version per
    // (provider_id, external_id) — because `FINAL` on a Distributed table only
    // dedups within a shard. On single-node it degrades to `nanosiem.user_registry
    // FINAL`, byte-identical to the pre-NAN-1728 queries.
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn list_users(
        &self,
        params: &ListUsersParams,
    ) -> Result<UserListResponse, IdentityRepositoryError> {
        let offset = (params.page.max(1) - 1) * params.page_size;
        let (users, total) = self.list_users_inner(params, offset).await?;

        Ok(UserListResponse {
            users,
            total,
            page: params.page.max(1),
            page_size: params.page_size,
        })
    }

    /// Full SELECT column list for hydrating a `UserRegistryRow` from CH. The
    /// DateTime64(3) columns are projected to ms-epoch i64 to match the row
    /// struct. Used by list/lookup/get_user over `... FINAL`.
    const SELECT_COLS: &'static str = "provider_id, external_id, username, upn, email, \
        display_name, first_name, last_name, department, title, manager_upn, \
        manager_display_name, company, office_location, city, country, groups, \
        account_enabled, account_status, mfa_enabled, \
        toUnixTimestamp64Milli(last_sign_in_at) AS last_sign_in_at, \
        toUnixTimestamp64Milli(created_in_directory_at) AS created_in_directory_at, \
        phone, employee_id, employee_type, sync_hash, \
        toUnixTimestamp64Milli(last_synced_at) AS last_synced_at, version";

    async fn list_users_inner(
        &self,
        params: &ListUsersParams,
        offset: i64,
    ) -> Result<(Vec<UserRecord>, i64), IdentityRepositoryError> {
        let ch = self.ch()?;

        // Build the WHERE predicate (deduped via FINAL). All user values are
        // bound, never spliced. The optional search matches the same four
        // fields as the old PG path, case-insensitively via lower(col) LIKE.
        let mut conds: Vec<String> = vec!["account_status != 'deleted'".to_string()];
        if params.provider_id.is_some() {
            conds.push("provider_id = ?".to_string());
        }
        if params.account_status.is_some() {
            conds.push("account_status = ?".to_string());
        }
        if params.search.is_some() {
            conds.push(
                "(username_lc LIKE ? OR lower(display_name) LIKE ? OR email_lc LIKE ? \
                 OR lower(department) LIKE ?)"
                    .to_string(),
            );
        }
        let where_clause = conds.join(" AND ");
        let search_like = params
            .search
            .as_ref()
            .map(|s| format!("%{}%", s.to_lowercase()));

        // Bind helper: applies the conditional binds in declaration order.
        // (clickhouse::query::Query::bind consumes+returns self.)
        let apply_binds = |mut q: clickhouse::query::Query| -> clickhouse::query::Query {
            if let Some(pid) = &params.provider_id {
                q = q.bind(pid.clone());
            }
            if let Some(status) = &params.account_status {
                q = q.bind(status.clone());
            }
            if let Some(like) = &search_like {
                q = q.bind(like.clone()).bind(like.clone()).bind(like.clone()).bind(like.clone());
            }
            q
        };

        // Count over the deduped set — routed through the `_distributed` wrapper
        // + cross-shard version-collapse on clusters (see
        // `user_registry_read_source`); local `… FINAL` on single-node. Counting
        // over the collapsed source avoids the ~Nx over-count a bare
        // `Distributed FINAL` would produce (FINAL only dedups within a shard).
        let src = user_registry_read_source();
        let count_sql = format!(
            "SELECT count() FROM {src} WHERE {where_clause}"
        );
        let total: u64 = apply_binds(ch.query(&count_sql)).fetch_one().await?;

        // Page of rows (same deduped source).
        let data_sql = format!(
            "SELECT {cols} FROM {src} WHERE {where_clause} \
             ORDER BY display_name LIMIT ? OFFSET ?",
            cols = Self::SELECT_COLS
        );
        let rows: Vec<UserRegistryRow> = apply_binds(ch.query(&data_sql))
            .bind(params.page_size)
            .bind(offset)
            .fetch_all()
            .await?;

        let users: Vec<UserRecord> = rows.into_iter().map(UserRecord::from).collect();
        Ok((users, total as i64))
    }

    /// Look up a user by username, UPN, or email (case-insensitive exact match).
    /// Prefers active accounts if duplicates exist across providers. Reads the
    /// deduped (FINAL) CH set and excludes deleted users.
    #[instrument(skip(self))]
    pub async fn lookup_user_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserRecord>, IdentityRepositoryError> {
        let ch = self.ch()?;
        let lower = identifier.to_lowercase();
        let src = user_registry_read_source();
        let sql = format!(
            "SELECT {cols} FROM {src} \
             WHERE account_status != 'deleted' \
               AND (username_lc = ? OR upn_lc = ? OR email_lc = ?) \
             ORDER BY account_status = 'active' DESC, version DESC \
             LIMIT 1",
            cols = Self::SELECT_COLS
        );
        let rows: Vec<UserRegistryRow> = ch
            .query(&sql)
            .bind(lower.clone())
            .bind(lower.clone())
            .bind(lower)
            .fetch_all()
            .await?;
        Ok(rows.into_iter().next().map(UserRecord::from))
    }

    /// Fetch a single user by the composite id `"{provider_id}|{external_id}"`
    /// (NAN-1117: replaced the BIGSERIAL id — CH has no synthetic key).
    #[instrument(skip(self))]
    pub async fn get_user(&self, id: &str) -> Result<UserRecord, IdentityRepositoryError> {
        let ch = self.ch()?;
        let (provider_id, external_id) = UserRecord::split_composite_id(id)
            .ok_or_else(|| IdentityRepositoryError::ProviderNotFound(format!("User {}", id)))?;
        // Deduped source (wrapper + cross-shard collapse on clusters): without it
        // a `Distributed FINAL … LIMIT 1` could return a stale-version row from
        // one shard. The collapse keeps one latest-version row per user, so
        // LIMIT 1 is unambiguous.
        let src = user_registry_read_source();
        let sql = format!(
            "SELECT {cols} FROM {src} \
             WHERE provider_id = ? AND external_id = ? LIMIT 1",
            cols = Self::SELECT_COLS
        );
        let rows: Vec<UserRegistryRow> = ch
            .query(&sql)
            .bind(provider_id)
            .bind(external_id)
            .fetch_all()
            .await?;
        rows.into_iter()
            .next()
            .map(UserRecord::from)
            .ok_or_else(|| IdentityRepositoryError::ProviderNotFound(format!("User {}", id)))
    }

    #[instrument(skip(self))]
    pub async fn get_user_count(&self, provider_id: &str) -> Result<i64, IdentityRepositoryError> {
        let ch = self.ch()?;
        let src = user_registry_read_source();
        let count: u64 = ch
            .query(&format!(
                "SELECT count() FROM {src} \
                 WHERE provider_id = ? AND account_status != 'deleted'",
            ))
            .bind(provider_id)
            .fetch_one()
            .await?;
        Ok(count as i64)
    }

    // ========================================================================
    // Stats
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> Result<IdentityStats, IdentityRepositoryError> {
        let ch = self.ch()?;

        // Aggregate counts over the deduped CH set — wrapper + cross-shard
        // version-collapse on clusters (see `user_registry_read_source`), local
        // `… FINAL` on single-node. Counting over the collapsed source is what
        // makes these totals correct on a cluster (a bare `Distributed FINAL`
        // count would multiply by the number of shards a user was written to).
        let src = user_registry_read_source();
        let total_users: u64 = ch
            .query(&format!(
                "SELECT count() FROM {src} \
                 WHERE account_status != 'deleted'",
            ))
            .fetch_one()
            .await?;
        let active_users: u64 = ch
            .query(&format!(
                "SELECT count() FROM {src} \
                 WHERE account_status = 'active'",
            ))
            .fetch_one()
            .await?;
        let disabled_users: u64 = ch
            .query(&format!(
                "SELECT count() FROM {src} \
                 WHERE account_status IN ('disabled', 'suspended')",
            ))
            .fetch_one()
            .await?;

        // Per-provider live counts from CH (the old PG LEFT JOIN broke once the
        // payload moved cross-DB — split: provider list + sync status from PG,
        // counts from CH, merged in Rust).
        #[derive(Debug, clickhouse::Row, serde::Deserialize)]
        struct ProviderCount {
            provider_id: String,
            #[serde(rename = "cnt")]
            cnt: u64,
        }
        let provider_counts: Vec<ProviderCount> = ch
            .query(&format!(
                "SELECT provider_id, count() AS cnt FROM {src} \
                 WHERE account_status != 'deleted' GROUP BY provider_id",
            ))
            .fetch_all()
            .await?;
        let count_by_provider: std::collections::HashMap<String, i64> = provider_counts
            .into_iter()
            .map(|p| (p.provider_id, p.cnt as i64))
            .collect();

        // Provider metadata from PG (config side stays PG).
        #[derive(sqlx::FromRow)]
        struct ProviderMetaRow {
            provider_id: String,
            provider_name: String,
            provider_type: String,
            last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
            sync_status: Option<String>,
        }
        let providers: Vec<ProviderMetaRow> = sqlx::query_as(
            "SELECT id AS provider_id, name AS provider_name, provider_type,
                    last_sync_at, sync_status
             FROM identity_providers
             ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(IdentityStats {
            total_users: total_users as i64,
            active_users: active_users as i64,
            disabled_users: disabled_users as i64,
            providers: providers
                .into_iter()
                .map(|r| ProviderStatsSummary {
                    user_count: *count_by_provider.get(&r.provider_id).unwrap_or(&0),
                    provider_id: r.provider_id,
                    provider_name: r.provider_name,
                    provider_type: r.provider_type,
                    last_sync_at: r.last_sync_at,
                    sync_status: r.sync_status,
                })
                .collect(),
        })
    }
}
