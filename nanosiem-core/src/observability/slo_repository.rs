// SPDX-License-Identifier: AGPL-3.0-or-later

//! SLO definition repository (NAN-1536).
//!
//! CRUD over `observability_slos` (migration 209). Storage is a UUID primary
//! key; over the wire the id serializes as a typeid (`slo_<base32>`). The live
//! attainment fields (`current`, `budget_remaining_pct`, `burn_rate`,
//! `status`) are NOT stored here — the api handler computes them from
//! `otel_spans` and merges them onto the definition for the response.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::query::SliKind;

#[derive(Error, Debug)]
pub enum SloRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("SLO not found: {0}")]
    NotFound(Uuid),
    #[error("Invalid SLO: {0}")]
    Invalid(String),
}

/// The SLI kind an SLO is measured against. Mirrors the storage CHECK
/// constraint (`'availability' | 'latency'`) and maps to the query layer's
/// [`SliKind`] for spans-based compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SloSliKind {
    Availability,
    Latency,
}

impl SloSliKind {
    /// Parse the stored/string form (`availability` | `latency`).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "availability" => Some(Self::Availability),
            "latency" => Some(Self::Latency),
            _ => None,
        }
    }

    /// The stored/string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Availability => "availability",
            Self::Latency => "latency",
        }
    }

    /// Map to the query-layer compute enum.
    pub fn to_query_kind(self) -> SliKind {
        match self {
            Self::Availability => SliKind::Availability,
            Self::Latency => SliKind::Latency,
        }
    }
}

/// A stored SLO definition. The live attainment fields are computed separately
/// by the api layer and are NOT part of this row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SloDefinition {
    #[serde(with = "crate::typeid::slo")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub service: String,
    pub sli_kind: SloSliKind,
    /// Objective as a fraction in (0,1], e.g. 0.995 = 99.5%.
    pub target: f64,
    /// Rolling evaluation window in days.
    pub window_days: i32,
    /// Per-span latency threshold (ms) for `sli_kind = latency`; `None` for availability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_threshold_ms: Option<f64>,
    #[serde(with = "crate::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SloRepository {
    pool: PgPool,
}

impl SloRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// All SLO definitions, grouped by service then newest-first.
    pub async fn list(&self) -> Result<Vec<SloDefinition>, SloRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, service, sli_kind, target, window_days,
                   latency_threshold_ms, created_by, created_at, updated_at
            FROM observability_slos
            ORDER BY service ASC, created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(Self::row_to_slo).collect()
    }

    /// Fetch one SLO definition by id.
    pub async fn get(&self, id: Uuid) -> Result<SloDefinition, SloRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, service, sli_kind, target, window_days,
                   latency_threshold_ms, created_by, created_at, updated_at
            FROM observability_slos
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SloRepositoryError::NotFound(id))?;

        Self::row_to_slo(&row)
    }

    /// Insert a new SLO definition.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        name: &str,
        service: &str,
        sli_kind: SloSliKind,
        target: f64,
        window_days: i32,
        latency_threshold_ms: Option<f64>,
        created_by: Option<Uuid>,
    ) -> Result<SloDefinition, SloRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO observability_slos
                (name, service, sli_kind, target, window_days, latency_threshold_ms, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, name, service, sli_kind, target, window_days,
                      latency_threshold_ms, created_by, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(service)
        .bind(sli_kind.as_str())
        .bind(target)
        .bind(window_days)
        .bind(latency_threshold_ms)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        Self::row_to_slo(&row)
    }

    /// Update an existing SLO definition (full replace of the editable fields).
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        id: Uuid,
        name: &str,
        service: &str,
        sli_kind: SloSliKind,
        target: f64,
        window_days: i32,
        latency_threshold_ms: Option<f64>,
    ) -> Result<SloDefinition, SloRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE observability_slos
            SET name = $2,
                service = $3,
                sli_kind = $4,
                target = $5,
                window_days = $6,
                latency_threshold_ms = $7,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, service, sli_kind, target, window_days,
                      latency_threshold_ms, created_by, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(service)
        .bind(sli_kind.as_str())
        .bind(target)
        .bind(window_days)
        .bind(latency_threshold_ms)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SloRepositoryError::NotFound(id))?;

        Self::row_to_slo(&row)
    }

    /// Delete an SLO definition. Returns whether a row was removed.
    pub async fn delete(&self, id: Uuid) -> Result<bool, SloRepositoryError> {
        let result = sqlx::query("DELETE FROM observability_slos WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn row_to_slo(row: &sqlx::postgres::PgRow) -> Result<SloDefinition, SloRepositoryError> {
        let kind_str: String = row.get("sli_kind");
        let sli_kind = SloSliKind::from_str(&kind_str).ok_or_else(|| {
            SloRepositoryError::Invalid(format!("unknown sli_kind '{kind_str}'"))
        })?;
        Ok(SloDefinition {
            id: row.get("id"),
            name: row.get("name"),
            service: row.get("service"),
            sli_kind,
            target: row.get("target"),
            window_days: row.get("window_days"),
            latency_threshold_ms: row.get("latency_threshold_ms"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}
