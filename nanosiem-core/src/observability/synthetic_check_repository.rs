// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic-check definition repository (NAN-1538).
//!
//! CRUD over `observability_synthetic_checks` (migration 210). Storage is a
//! UUID primary key; over the wire the id serializes as a typeid
//! (`synth_<base32>`). These are the *definitions* — what to probe and how
//! often. The probe *results* live in the selected observability store (native
//! OTLP metrics in Iceberg for the lake profile; ClickHouse for the retiring
//! legacy profile) and are summarized for the response by the search layer.
//! PostgreSQL additionally owns the small `next_run_at` scheduling watermark:
//! it is control-plane metadata, not a probe-result store, and lets multiple
//! jobs replicas claim due checks atomically without depending on asynchronous
//! lake visibility.
//! The live `uptime_pct` / `p50_latency_ms` / `history` are NOT stored here —
//! the API handler computes them from the active observability store and merges them onto each
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
/// API layer from telemetry and are NOT part of this row.
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

    /// Atomically claim enabled checks whose configured interval has elapsed.
    ///
    /// The claim advances `next_run_at` in the same PostgreSQL statement that
    /// returns each definition. `FOR UPDATE SKIP LOCKED` makes this safe across
    /// jobs replicas and leader failover. Probe payloads/results do not live in
    /// PostgreSQL; this is only the durable scheduler watermark. Advancing from
    /// `NOW()` intentionally avoids a rapid catch-up storm after an outage.
    pub async fn claim_due_enabled(
        &self,
        limit: i64,
    ) -> Result<Vec<SyntheticCheck>, SyntheticCheckRepositoryError> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"
            WITH due AS (
                SELECT id
                FROM observability_synthetic_checks
                WHERE enabled = TRUE
                  AND next_run_at <= NOW()
                ORDER BY next_run_at ASC, id ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE observability_synthetic_checks AS checks
            SET next_run_at = NOW() + make_interval(secs => checks.interval_secs)
            FROM due
            WHERE checks.id = due.id
            RETURNING checks.id, checks.name, checks.check_type, checks.target_url,
                      checks.interval_secs, checks.expected_status, checks.timeout_secs,
                      checks.enabled, checks.created_by, checks.created_at, checks.updated_at
            "#,
        )
        .bind(limit)
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
                next_run_at = CASE
                    WHEN enabled = FALSE AND $8 = TRUE THEN NOW()
                    ELSE next_run_at
                END,
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
