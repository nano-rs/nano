// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity provider repository
//!
//! Database operations for identity providers and the user registry.

use sqlx::PgPool;
use std::collections::HashSet;
use thiserror::Error;
use tracing::instrument;

use super::types::*;
use crate::crypto::EncryptionService;

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
}

// =============================================================================
// Repository
// =============================================================================

#[derive(Clone)]
pub struct IdentityRepository {
    pool: PgPool,
    encryption: EncryptionService,
}

impl IdentityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self {
            encryption: EncryptionService::from_env(),
            pool,
        }
    }

    // ========================================================================
    // Provider CRUD
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn list_providers(&self) -> Result<Vec<IdentityProvider>, IdentityRepositoryError> {
        let providers = sqlx::query_as::<_, IdentityProvider>(
            "SELECT id, name, provider_type, enabled, credentials_encrypted, config,
                    sync_status, last_sync_at, last_sync_error, last_sync_duration_ms,
                    user_count, delta_link, created_at, updated_at
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
                    user_count, delta_link, created_at, updated_at
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
                       user_count, delta_link, created_at, updated_at",
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
                       user_count, delta_link, created_at, updated_at",
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

    /// Upsert users from a sync. Uses sync_hash for change detection to skip no-ops.
    #[instrument(skip(self, records))]
    pub async fn upsert_users(
        &self,
        provider_id: &str,
        records: &[UserRecordUpsert],
    ) -> Result<(u64, u64), IdentityRepositoryError> {
        if records.is_empty() {
            return Ok((0, 0));
        }

        let mut created = 0u64;
        let updated = 0u64;

        // Process in batches of 500 to avoid query parameter limits
        for chunk in records.chunks(500) {
            let mut query = String::from(
                "INSERT INTO user_registry (
                    provider_id, external_id, username, upn, email, display_name,
                    first_name, last_name, department, title, manager_upn, manager_display_name,
                    company, office_location, city, country, groups,
                    account_enabled, account_status, mfa_enabled, last_sign_in_at,
                    created_in_directory_at, phone, employee_id, employee_type,
                    last_synced_at, sync_hash
                ) VALUES ",
            );

            let mut param_idx = 1u32;
            let binds: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
            let _ = binds; // suppress unused warning

            // Build values clauses
            let mut values_parts: Vec<String> = Vec::new();
            for _record in chunk {
                let placeholders: Vec<String> = (param_idx..param_idx + 27)
                    .map(|i| format!("${}", i))
                    .collect();
                values_parts.push(format!("({})", placeholders.join(", ")));
                param_idx += 27;
            }
            query.push_str(&values_parts.join(", "));

            query.push_str(
                " ON CONFLICT (provider_id, external_id) DO UPDATE SET
                    username = EXCLUDED.username,
                    upn = EXCLUDED.upn,
                    email = EXCLUDED.email,
                    display_name = EXCLUDED.display_name,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    department = EXCLUDED.department,
                    title = EXCLUDED.title,
                    manager_upn = EXCLUDED.manager_upn,
                    manager_display_name = EXCLUDED.manager_display_name,
                    company = EXCLUDED.company,
                    office_location = EXCLUDED.office_location,
                    city = EXCLUDED.city,
                    country = EXCLUDED.country,
                    groups = EXCLUDED.groups,
                    account_enabled = EXCLUDED.account_enabled,
                    account_status = EXCLUDED.account_status,
                    mfa_enabled = EXCLUDED.mfa_enabled,
                    last_sign_in_at = EXCLUDED.last_sign_in_at,
                    created_in_directory_at = EXCLUDED.created_in_directory_at,
                    phone = EXCLUDED.phone,
                    employee_id = EXCLUDED.employee_id,
                    employee_type = EXCLUDED.employee_type,
                    last_synced_at = EXCLUDED.last_synced_at,
                    sync_hash = EXCLUDED.sync_hash
                WHERE user_registry.sync_hash IS DISTINCT FROM EXCLUDED.sync_hash",
            );

            // Build the query with dynamic bindings
            let mut q = sqlx::query(&query);
            for record in chunk {
                q = q
                    .bind(provider_id)
                    .bind(&record.external_id)
                    .bind(&record.username)
                    .bind(&record.upn)
                    .bind(&record.email)
                    .bind(&record.display_name)
                    .bind(&record.first_name)
                    .bind(&record.last_name)
                    .bind(&record.department)
                    .bind(&record.title)
                    .bind(&record.manager_upn)
                    .bind(&record.manager_display_name)
                    .bind(&record.company)
                    .bind(&record.office_location)
                    .bind(&record.city)
                    .bind(&record.country)
                    .bind(&record.groups)
                    .bind(record.account_enabled)
                    .bind(&record.account_status)
                    .bind(record.mfa_enabled)
                    .bind(record.last_sign_in_at)
                    .bind(record.created_in_directory_at)
                    .bind(&record.phone)
                    .bind(&record.employee_id)
                    .bind(&record.employee_type)
                    .bind(chrono::Utc::now())
                    .bind(&record.sync_hash);
            }

            let result = q.execute(&self.pool).await?;
            // rows_affected includes both inserts and updates where sync_hash changed
            let affected = result.rows_affected();
            // We can't distinguish created vs updated with a single query,
            // so we count total affected and will refine in the service layer
            created += affected;
        }

        // For simplicity, return affected rows as "created" — service layer
        // can compute more precise numbers if needed.
        Ok((created, updated))
    }

    /// Mark users from this provider that are NOT in the given set of external_ids as deleted.
    #[instrument(skip(self, present_external_ids))]
    pub async fn mark_absent_users(
        &self,
        provider_id: &str,
        present_external_ids: &HashSet<String>,
    ) -> Result<u64, IdentityRepositoryError> {
        if present_external_ids.is_empty() {
            return Ok(0);
        }

        let ids: Vec<&str> = present_external_ids.iter().map(|s| s.as_str()).collect();
        let result = sqlx::query(
            "UPDATE user_registry
             SET account_status = 'deleted', account_enabled = false
             WHERE provider_id = $1
               AND external_id != ALL($2)
               AND account_status != 'deleted'",
        )
        .bind(provider_id)
        .bind(&ids)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get the current database server time.
    /// Use this instead of `chrono::Utc::now()` when comparing against DB-set timestamps
    /// to avoid clock skew between application and database servers.
    pub async fn db_now(&self) -> Result<chrono::DateTime<chrono::Utc>, IdentityRepositoryError> {
        let (now,): (chrono::DateTime<chrono::Utc>,) =
            sqlx::query_as("SELECT NOW()").fetch_one(&self.pool).await?;
        Ok(now)
    }

    /// Mark users as deleted if they weren't touched during the current sync.
    /// Any user whose last_synced_at is before `cutoff` wasn't in the
    /// provider's response. This avoids collecting all external_ids in memory.
    ///
    /// IMPORTANT: `cutoff` must come from `db_now()`, not the application clock,
    /// to avoid clock skew causing false deletions.
    #[instrument(skip(self))]
    pub async fn mark_absent_users_by_sync_time(
        &self,
        provider_id: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, IdentityRepositoryError> {
        let result = sqlx::query(
            "UPDATE user_registry
             SET account_status = 'deleted', account_enabled = false
             WHERE provider_id = $1
               AND last_synced_at < $2
               AND account_status != 'deleted'",
        )
        .bind(provider_id)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ========================================================================
    // User Registry — Queries
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

    async fn list_users_inner(
        &self,
        params: &ListUsersParams,
        offset: i64,
    ) -> Result<(Vec<UserRecord>, i64), IdentityRepositoryError> {
        let search_term = params
            .search
            .as_ref()
            .map(|s| format!("%{}%", s.to_lowercase()));

        // Count query
        let total: i64 = match (&params.provider_id, &params.account_status, &search_term) {
            (Some(pid), Some(status), Some(search)) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE provider_id = $1 AND account_status = $2 AND (lower(username) LIKE $3 OR lower(display_name) LIKE $3 OR lower(email) LIKE $3 OR lower(department) LIKE $3)"
                ).bind(pid).bind(status).bind(search).fetch_one(&self.pool).await?
            }
            (Some(pid), Some(status), None) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE provider_id = $1 AND account_status = $2"
                ).bind(pid).bind(status).fetch_one(&self.pool).await?
            }
            (Some(pid), None, Some(search)) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE provider_id = $1 AND (lower(username) LIKE $2 OR lower(display_name) LIKE $2 OR lower(email) LIKE $2 OR lower(department) LIKE $2)"
                ).bind(pid).bind(search).fetch_one(&self.pool).await?
            }
            (None, Some(status), Some(search)) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE account_status = $1 AND (lower(username) LIKE $2 OR lower(display_name) LIKE $2 OR lower(email) LIKE $2 OR lower(department) LIKE $2)"
                ).bind(status).bind(search).fetch_one(&self.pool).await?
            }
            (Some(pid), None, None) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE provider_id = $1"
                ).bind(pid).fetch_one(&self.pool).await?
            }
            (None, Some(status), None) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE account_status = $1"
                ).bind(status).fetch_one(&self.pool).await?
            }
            (None, None, Some(search)) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM user_registry WHERE (lower(username) LIKE $1 OR lower(display_name) LIKE $1 OR lower(email) LIKE $1 OR lower(department) LIKE $1)"
                ).bind(search).fetch_one(&self.pool).await?
            }
            (None, None, None) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM user_registry")
                    .fetch_one(&self.pool).await?
            }
        };

        // Data query
        let users: Vec<UserRecord> = match (&params.provider_id, &params.account_status, &search_term) {
            (Some(pid), Some(status), Some(search)) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE provider_id = $1 AND account_status = $2 AND (lower(username) LIKE $3 OR lower(display_name) LIKE $3 OR lower(email) LIKE $3 OR lower(department) LIKE $3) ORDER BY display_name LIMIT $4 OFFSET $5"
                ).bind(pid).bind(status).bind(search).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (Some(pid), Some(status), None) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE provider_id = $1 AND account_status = $2 ORDER BY display_name LIMIT $3 OFFSET $4"
                ).bind(pid).bind(status).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (Some(pid), None, Some(search)) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE provider_id = $1 AND (lower(username) LIKE $2 OR lower(display_name) LIKE $2 OR lower(email) LIKE $2 OR lower(department) LIKE $2) ORDER BY display_name LIMIT $3 OFFSET $4"
                ).bind(pid).bind(search).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (None, Some(status), Some(search)) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE account_status = $1 AND (lower(username) LIKE $2 OR lower(display_name) LIKE $2 OR lower(email) LIKE $2 OR lower(department) LIKE $2) ORDER BY display_name LIMIT $3 OFFSET $4"
                ).bind(status).bind(search).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (Some(pid), None, None) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE provider_id = $1 ORDER BY display_name LIMIT $2 OFFSET $3"
                ).bind(pid).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (None, Some(status), None) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE account_status = $1 ORDER BY display_name LIMIT $2 OFFSET $3"
                ).bind(status).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (None, None, Some(search)) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry WHERE (lower(username) LIKE $1 OR lower(display_name) LIKE $1 OR lower(email) LIKE $1 OR lower(department) LIKE $1) ORDER BY display_name LIMIT $2 OFFSET $3"
                ).bind(search).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
            (None, None, None) => {
                sqlx::query_as(
                    "SELECT * FROM user_registry ORDER BY display_name LIMIT $1 OFFSET $2"
                ).bind(params.page_size).bind(offset).fetch_all(&self.pool).await?
            }
        };

        Ok((users, total))
    }

    /// Look up a user by username, UPN, or email (case-insensitive exact match).
    /// Prefers active accounts if duplicates exist across providers.
    #[instrument(skip(self))]
    pub async fn lookup_user_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserRecord>, IdentityRepositoryError> {
        let lower = identifier.to_lowercase();
        sqlx::query_as::<_, UserRecord>(
            "SELECT * FROM user_registry
             WHERE lower(username) = $1 OR lower(upn) = $1 OR lower(email) = $1
             ORDER BY account_status = 'active' DESC, updated_at DESC
             LIMIT 1",
        )
        .bind(&lower)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[instrument(skip(self))]
    pub async fn get_user(&self, id: i64) -> Result<UserRecord, IdentityRepositoryError> {
        sqlx::query_as::<_, UserRecord>("SELECT * FROM user_registry WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| IdentityRepositoryError::ProviderNotFound(format!("User {}", id)))
    }

    #[instrument(skip(self))]
    pub async fn get_user_count(&self, provider_id: &str) -> Result<i64, IdentityRepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_registry WHERE provider_id = $1 AND account_status != 'deleted'"
        )
        .bind(provider_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    // ========================================================================
    // Stats
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> Result<IdentityStats, IdentityRepositoryError> {
        let total_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_registry WHERE account_status != 'deleted'",
        )
        .fetch_one(&self.pool)
        .await?;

        let active_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_registry WHERE account_status = 'active'",
        )
        .fetch_one(&self.pool)
        .await?;

        let disabled_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_registry WHERE account_status IN ('disabled', 'suspended')",
        )
        .fetch_one(&self.pool)
        .await?;

        #[derive(sqlx::FromRow)]
        struct ProviderRow {
            provider_id: String,
            provider_name: String,
            provider_type: String,
            user_count: i64,
            last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
            sync_status: Option<String>,
        }

        let providers: Vec<ProviderRow> = sqlx::query_as(
            "SELECT p.id AS provider_id, p.name AS provider_name, p.provider_type,
                    COUNT(u.id) AS user_count, p.last_sync_at, p.sync_status
             FROM identity_providers p
             LEFT JOIN user_registry u ON u.provider_id = p.id AND u.account_status != 'deleted'
             GROUP BY p.id, p.name, p.provider_type, p.last_sync_at, p.sync_status
             ORDER BY p.name",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(IdentityStats {
            total_users,
            active_users,
            disabled_users,
            providers: providers
                .into_iter()
                .map(|r| ProviderStatsSummary {
                    provider_id: r.provider_id,
                    provider_name: r.provider_name,
                    provider_type: r.provider_type,
                    user_count: r.user_count,
                    last_sync_at: r.last_sync_at,
                    sync_status: r.sync_status,
                })
                .collect(),
        })
    }
}
