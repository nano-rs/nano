// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-source RBAC scope registry persistence (NAN-1797 / NAN-1789).
//!
//! Admin CRUD data access for the two PostgreSQL tables introduced in migration
//! 242:
//!
//! - `restricted_source_types` — the deny-by-omission registry. A `source_type`
//!   string value listed here becomes invisible-by-default; an empty table is
//!   today's "allow all" behaviour exactly.
//! - `source_type_grants` — which groups may see a restricted `source_type`.
//!   A user's visibility is all unrestricted sources ∪ sources granted to any of
//!   their groups; granting to the "Everyone" system group un-restricts a value
//!   without deleting the registry row.
//!
//! This repository backs the admin surface (registry + grant editor). The live
//! request-path resolver ([`crate::auth::source_scope_resolver`]) computes the
//! per-user denied set with its own cached raw query and does NOT go through this
//! struct; [`SourceScopeRepository::denied_for_user`] re-implements the same
//! restricted-minus-granted difference purely as an admin-view convenience
//! ("what would this user be denied right now?").
//!
//! Mirrors the runtime-`sqlx` repository pattern (no compile-time macros in this
//! repo): holds a [`PgPool`] directly, `thiserror` error enum with a `#[from]`
//! `sqlx::Error` bridge plus a `NotFound` variant for missing-row deletes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Errors from the source-scope repository.
#[derive(Debug, thiserror::Error)]
pub enum SourceScopeError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// A delete targeted a `source_type` (or grant on it) that does not exist.
    #[error("restricted source type not found: {0}")]
    NotFound(String),
}

/// A row of `restricted_source_types`: a `source_type` value that is
/// invisible-by-default until granted to a group.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct RestrictedSourceType {
    /// The event-borne `source_type` string value (the enforceable unit — not a
    /// `log_sources` UUID; events never carry that).
    pub source_type: String,
    /// Optional admin-authored note ("insider-threat feed").
    pub description: Option<String>,
    /// The admin who registered it, if the user row still exists.
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A row of `source_type_grants`, enriched with the granted group's display
/// name via a `LEFT JOIN groups` so admin views need no second lookup.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct SourceTypeGrant {
    /// The restricted `source_type` this grant unlocks.
    pub source_type: String,
    /// The group that may see it.
    pub group_id: Uuid,
    /// Display name of `group_id`. `None` only if the group row is gone (races a
    /// cascade delete); populated for every live grant.
    pub group_name: Option<String>,
    /// The admin who created the grant, if the user row still exists.
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Repository for the restricted-source registry and its group grants.
#[derive(Clone)]
pub struct SourceScopeRepository {
    pool: PgPool,
}

/// Bump the singleton cross-process invalidation counter (NAN-1807). Run in the
/// same transaction as every registry/grant mutation so resolvers on other
/// processes drop their caches within their short version-check throttle.
const BUMP_SCOPE_VERSION_SQL: &str = "UPDATE source_scope_version SET version = version + 1";

impl SourceScopeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ------------------------------------------------------------------
    // Restricted source registry
    // ------------------------------------------------------------------

    /// List every restricted `source_type`, ordered by value.
    pub async fn list_restricted(&self) -> Result<Vec<RestrictedSourceType>, SourceScopeError> {
        let rows = sqlx::query_as::<_, RestrictedSourceType>(
            r#"
            SELECT source_type, description, created_by, created_at
            FROM restricted_source_types
            ORDER BY source_type
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Register a `source_type` as restricted (idempotent — re-adding an
    /// existing value refreshes its `description`). Returns the stored row.
    /// Bumps the cross-process version signal in the same transaction (NAN-1807).
    pub async fn add_restricted(
        &self,
        source_type: &str,
        description: Option<&str>,
        created_by: Option<Uuid>,
    ) -> Result<RestrictedSourceType, SourceScopeError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, RestrictedSourceType>(
            r#"
            INSERT INTO restricted_source_types (source_type, description, created_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (source_type) DO UPDATE SET
                description = EXCLUDED.description
            RETURNING source_type, description, created_by, created_at
            "#,
        )
        .bind(source_type)
        .bind(description)
        .bind(created_by)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(BUMP_SCOPE_VERSION_SQL).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Un-restrict a `source_type` (cascades its grants). Returns
    /// [`SourceScopeError::NotFound`] if the value was not registered.
    pub async fn remove_restricted(&self, source_type: &str) -> Result<(), SourceScopeError> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(r#"DELETE FROM restricted_source_types WHERE source_type = $1"#)
            .bind(source_type)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            // tx rolls back on drop — nothing changed, no version bump.
            return Err(SourceScopeError::NotFound(source_type.to_string()));
        }
        sqlx::query(BUMP_SCOPE_VERSION_SQL).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Grants
    // ------------------------------------------------------------------

    /// List the groups granted a given restricted `source_type`.
    pub async fn list_grants(
        &self,
        source_type: &str,
    ) -> Result<Vec<SourceTypeGrant>, SourceScopeError> {
        let rows = sqlx::query_as::<_, SourceTypeGrant>(
            r#"
            SELECT g.source_type, g.group_id, grp.name AS group_name,
                   g.created_by, g.created_at
            FROM source_type_grants g
            LEFT JOIN groups grp ON grp.id = g.group_id
            WHERE g.source_type = $1
            ORDER BY grp.name NULLS LAST, g.group_id
            "#,
        )
        .bind(source_type)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// List the restricted sources a given group is granted.
    pub async fn list_grants_for_group(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<SourceTypeGrant>, SourceScopeError> {
        let rows = sqlx::query_as::<_, SourceTypeGrant>(
            r#"
            SELECT g.source_type, g.group_id, grp.name AS group_name,
                   g.created_by, g.created_at
            FROM source_type_grants g
            LEFT JOIN groups grp ON grp.id = g.group_id
            WHERE g.group_id = $1
            ORDER BY g.source_type
            "#,
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Grant a group visibility of a restricted `source_type` (idempotent — a
    /// duplicate grant preserves the original grantor/timestamp). The
    /// `source_type` must already be registered (FK to
    /// `restricted_source_types`); a grant on an unregistered value surfaces as
    /// [`SourceScopeError::Database`]. Returns the stored grant, group name
    /// joined in.
    pub async fn add_grant(
        &self,
        source_type: &str,
        group_id: Uuid,
        created_by: Option<Uuid>,
    ) -> Result<SourceTypeGrant, SourceScopeError> {
        // CTE so ON CONFLICT DO UPDATE (a no-op touch preserving the original
        // created_by) always RETURNs the row, then LEFT JOIN groups for the
        // display name.
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, SourceTypeGrant>(
            r#"
            WITH upsert AS (
                INSERT INTO source_type_grants (source_type, group_id, created_by)
                VALUES ($1, $2, $3)
                ON CONFLICT (source_type, group_id) DO UPDATE SET
                    created_by = source_type_grants.created_by
                RETURNING source_type, group_id, created_by, created_at
            )
            SELECT u.source_type, u.group_id, grp.name AS group_name,
                   u.created_by, u.created_at
            FROM upsert u
            LEFT JOIN groups grp ON grp.id = u.group_id
            "#,
        )
        .bind(source_type)
        .bind(group_id)
        .bind(created_by)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(BUMP_SCOPE_VERSION_SQL).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Revoke a group's grant on a `source_type`. Returns
    /// [`SourceScopeError::NotFound`] if no such grant existed.
    pub async fn remove_grant(
        &self,
        source_type: &str,
        group_id: Uuid,
    ) -> Result<(), SourceScopeError> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            r#"DELETE FROM source_type_grants WHERE source_type = $1 AND group_id = $2"#,
        )
        .bind(source_type)
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            // tx rolls back on drop — nothing changed, no version bump.
            return Err(SourceScopeError::NotFound(source_type.to_string()));
        }
        sqlx::query(BUMP_SCOPE_VERSION_SQL).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Admin-view convenience: the denied set for one user
    // ------------------------------------------------------------------

    /// The `source_type` values a user is currently denied = restricted minus
    /// (restricted granted to any group the user belongs to). Ordered by value.
    ///
    /// This mirrors the live resolver's difference logic for admin previews. The
    /// request-path resolver runs its own cached copy of this query; keep the two
    /// in sync if the semantics change.
    pub async fn denied_for_user(&self, user_id: Uuid) -> Result<Vec<String>, SourceScopeError> {
        let rows: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT rst.source_type
            FROM restricted_source_types rst
            WHERE NOT EXISTS (
                SELECT 1
                FROM source_type_grants g
                JOIN user_groups ug ON ug.group_id = g.group_id
                WHERE g.source_type = rst.source_type
                  AND ug.user_id = $1
            )
            ORDER BY rst.source_type
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

// DB-touching tests live in a dedicated sibling file (repo convention: tests in
// sibling files, not large inline modules) and are `#[ignore]`d — they need a
// live migrated Postgres (`pg-integration-tests` CI lane / local
// `docker compose up -d postgres`).
#[cfg(test)]
#[path = "source_scope_tests.rs"]
mod source_scope_tests;
