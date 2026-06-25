// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic-check definition repository (NAN-1538).
//!
//! CRUD over `observability_synthetic_checks` (migration 210). Storage is a
//! UUID primary key; over the wire the id serializes as a typeid
//! (`synth_<base32>`). These are the *definitions* — what to probe and how
//! often. The probe *results* live in ClickHouse
//! (`synthetic_check_results`, migration 142), written by the nanosiem-jobs
//! runner and summarized for the response by the search layer
//! ([`crate::search::SearchService::observability_synthetics_summary`] +
//! [`crate::query::synthetic_summary_sql`] / [`crate::query::synthetic_history_sql`]).
//! The live `uptime_pct` / `p50_latency_ms` / `history` are NOT stored here —
//! the api handler computes them from ClickHouse and merges them onto each
//! definition for the response, mirroring the SLO subsystem.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

/// Allowed `check_type` values (mirrors the storage CHECK constraint). Only
/// `http` ships today; the column + enum leave room for `tcp`/`browser` later.
pub const SYNTHETIC_CHECK_TYPES: &[&str] = &["http"];

/// Interval bounds (seconds) enforced both by the PG CHECK constraint and here
/// so a bad value is rejected before it hits the DB with a clear error.
pub const SYNTHETIC_MIN_INTERVAL_SECS: i32 = 30;
pub const SYNTHETIC_MAX_INTERVAL_SECS: i32 = 3600;

#[derive(Error, Debug)]
pub enum SyntheticCheckRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Synthetic check not found: {0}")]
    NotFound(Uuid),
    #[error("Invalid synthetic check: {0}")]
    Invalid(String),
}

/// A stored synthetic-check definition. The live summary fields
/// (`uptime_pct`, `p50_latency_ms`, `history`) are computed separately by the
/// api layer from ClickHouse and are NOT part of this row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SyntheticCheck {
    #[serde(with = "crate::typeid::synth")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    /// Probe type. Only `http` ships today.
    pub check_type: String,
    pub target_url: String,
    /// How often to run the check, in seconds (30..=3600).
    pub interval_secs: i32,
    /// HTTP status that counts as a success (default 200).
    pub expected_status: i32,
    /// Per-run request timeout in seconds (default 10).
    pub timeout_secs: i32,
    pub enabled: bool,
    #[serde(with = "crate::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SyntheticCheckRepository {
    pool: PgPool,
}

impl SyntheticCheckRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// All synthetic-check definitions, name-ordered.
    pub async fn list(&self) -> Result<Vec<SyntheticCheck>, SyntheticCheckRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, check_type, target_url, interval_secs, expected_status,
                   timeout_secs, enabled, created_by, created_at, updated_at
            FROM observability_synthetic_checks
            ORDER BY name ASC, created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_check).collect())
    }

    /// Only the enabled checks — the set the runner schedules (NAN-1538).
    /// Ordered oldest-first by `id` for a stable iteration order across ticks.
    pub async fn list_enabled(&self) -> Result<Vec<SyntheticCheck>, SyntheticCheckRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, check_type, target_url, interval_secs, expected_status,
                   timeout_secs, enabled, created_by, created_at, updated_at
            FROM observability_synthetic_checks
            WHERE enabled = TRUE
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_check).collect())
    }

    /// Fetch one synthetic-check definition by id.
    pub async fn get(&self, id: Uuid) -> Result<SyntheticCheck, SyntheticCheckRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, check_type, target_url, interval_secs, expected_status,
                   timeout_secs, enabled, created_by, created_at, updated_at
            FROM observability_synthetic_checks
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SyntheticCheckRepositoryError::NotFound(id))?;

        Ok(Self::row_to_check(&row))
    }

    /// Insert a new synthetic-check definition. `expected_status` / `timeout_secs`
    /// default to 200 / 10 at the DB; the caller passes through the request's
    /// optionals already defaulted. Validates `interval_secs` and `check_type`
    /// before the insert for a clean error (the PG CHECK is the backstop).
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        name: &str,
        check_type: &str,
        target_url: &str,
        interval_secs: i32,
        expected_status: i32,
        timeout_secs: i32,
        enabled: bool,
        created_by: Option<Uuid>,
    ) -> Result<SyntheticCheck, SyntheticCheckRepositoryError> {
        Self::validate(check_type, interval_secs)?;
        let row = sqlx::query(
            r#"
            INSERT INTO observability_synthetic_checks
                (name, check_type, target_url, interval_secs, expected_status,
                 timeout_secs, enabled, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, check_type, target_url, interval_secs, expected_status,
                      timeout_secs, enabled, created_by, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(check_type)
        .bind(target_url)
        .bind(interval_secs)
        .bind(expected_status)
        .bind(timeout_secs)
        .bind(enabled)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(Self::row_to_check(&row))
    }

    /// Update an existing synthetic-check definition (full replace of the
    /// editable fields). Validates `interval_secs` / `check_type` first.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        id: Uuid,
        name: &str,
        check_type: &str,
        target_url: &str,
        interval_secs: i32,
        expected_status: i32,
        timeout_secs: i32,
        enabled: bool,
    ) -> Result<SyntheticCheck, SyntheticCheckRepositoryError> {
        Self::validate(check_type, interval_secs)?;
        let row = sqlx::query(
            r#"
            UPDATE observability_synthetic_checks
            SET name = $2,
                check_type = $3,
                target_url = $4,
                interval_secs = $5,
                expected_status = $6,
                timeout_secs = $7,
                enabled = $8,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, check_type, target_url, interval_secs, expected_status,
                      timeout_secs, enabled, created_by, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(check_type)
        .bind(target_url)
        .bind(interval_secs)
        .bind(expected_status)
        .bind(timeout_secs)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SyntheticCheckRepositoryError::NotFound(id))?;

        Ok(Self::row_to_check(&row))
    }

    /// Delete a synthetic-check definition. Returns whether a row was removed.
    pub async fn delete(&self, id: Uuid) -> Result<bool, SyntheticCheckRepositoryError> {
        let result = sqlx::query("DELETE FROM observability_synthetic_checks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Reject an out-of-range interval or unsupported check type before the DB
    /// round trip (the PG CHECK constraints are the backstop).
    fn validate(check_type: &str, interval_secs: i32) -> Result<(), SyntheticCheckRepositoryError> {
        if !SYNTHETIC_CHECK_TYPES.contains(&check_type) {
            return Err(SyntheticCheckRepositoryError::Invalid(format!(
                "unsupported check_type '{check_type}' (allowed: {})",
                SYNTHETIC_CHECK_TYPES.join(", ")
            )));
        }
        if !(SYNTHETIC_MIN_INTERVAL_SECS..=SYNTHETIC_MAX_INTERVAL_SECS).contains(&interval_secs) {
            return Err(SyntheticCheckRepositoryError::Invalid(format!(
                "interval_secs {interval_secs} out of range [{SYNTHETIC_MIN_INTERVAL_SECS}, {SYNTHETIC_MAX_INTERVAL_SECS}]"
            )));
        }
        Ok(())
    }

    fn row_to_check(row: &sqlx::postgres::PgRow) -> SyntheticCheck {
        SyntheticCheck {
            id: row.get("id"),
            name: row.get("name"),
            check_type: row.get("check_type"),
            target_url: row.get("target_url"),
            interval_secs: row.get("interval_secs"),
            expected_status: row.get("expected_status"),
            timeout_secs: row.get("timeout_secs"),
            enabled: row.get("enabled"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}
