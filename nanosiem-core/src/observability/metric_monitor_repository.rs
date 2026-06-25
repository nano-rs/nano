// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metric-monitor definition repository (NAN-1540).
//!
//! CRUD over `observability_metric_monitors` (migration 211). Storage is a UUID
//! primary key; over the wire the id serializes as a typeid (`mon_<base32>`).
//!
//! A monitor is a saved metrics-v2 query (`metric_name` + `agg` + optional
//! `group_by` + tag `filters`) plus a `comparator`/`threshold` and an evaluation
//! cadence. The panic-safe jobs runner evaluates due enabled monitors over the
//! trailing `window_secs` window and raises through the existing alert/signal
//! path on breach — the monitor *result* is NOT persisted (mirrors the SLO
//! definition store).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum MetricMonitorRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Metric monitor not found: {0}")]
    NotFound(Uuid),
    #[error("Invalid metric monitor: {0}")]
    Invalid(String),
}

/// Breach test applied to the per-series aggregate (`value <comparator>
/// threshold`). Mirrors the storage CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MonitorComparator {
    Gt,
    Gte,
    Lt,
    Lte,
}

impl MonitorComparator {
    /// Parse the stored/wire form (`gt`|`gte`|`lt`|`lte`).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "gt" => Some(Self::Gt),
            "gte" => Some(Self::Gte),
            "lt" => Some(Self::Lt),
            "lte" => Some(Self::Lte),
            _ => None,
        }
    }

    /// The stored/wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
        }
    }

    /// Evaluate `value <comparator> threshold` — the breach test the runner
    /// applies to each series's aggregate.
    pub fn breached(self, value: f64, threshold: f64) -> bool {
        match self {
            Self::Gt => value > threshold,
            Self::Gte => value >= threshold,
            Self::Lt => value < threshold,
            Self::Lte => value <= threshold,
        }
    }
}

/// A single `key = value` tag filter persisted on a monitor — the metrics-v2
/// tag filter, stored as a JSON object in the `filters` array. Maps 1:1 to
/// [`crate::query::MetricTagFilter`] (this is the owned/serde form; the query
/// layer borrows).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MonitorTagFilter {
    pub key: String,
    pub value: String,
}

/// A stored metric-monitor definition. The evaluation result (breach state) is
/// computed by the jobs runner and is NOT part of this row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MetricMonitor {
    #[serde(with = "crate::typeid::metric_monitor")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub metric_name: String,
    /// Aggregation: `avg|sum|min|max|count|rate|p50|p95|p99`. Validated at the
    /// API layer against [`crate::query::MetricAgg::from_str`].
    pub agg: String,
    /// Optional tag/attribute key to split into per-series evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    /// Tag filters ANDed over the metric's attributes/resource_attributes maps.
    pub filters: Vec<MonitorTagFilter>,
    pub comparator: MonitorComparator,
    pub threshold: f64,
    /// Trailing window (seconds) the aggregate is computed over.
    pub window_secs: i32,
    /// Runner cadence in seconds (30..=3600).
    pub eval_interval_secs: i32,
    pub enabled: bool,
    #[serde(with = "crate::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct MetricMonitorRepository {
    pool: PgPool,
}

impl MetricMonitorRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// All monitor definitions, name-ordered (console list).
    pub async fn list(&self) -> Result<Vec<MetricMonitor>, MetricMonitorRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, metric_name, agg, group_by, filters, comparator,
                   threshold, window_secs, eval_interval_secs, enabled,
                   created_by, created_at, updated_at
            FROM observability_metric_monitors
            ORDER BY name ASC, created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(Self::row_to_monitor).collect()
    }

    /// All ENABLED monitors — the runner's evaluation set. (The runner applies
    /// its own due-time gate against `eval_interval_secs`; this just trims the
    /// disabled rows in SQL.)
    pub async fn list_enabled(&self) -> Result<Vec<MetricMonitor>, MetricMonitorRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, metric_name, agg, group_by, filters, comparator,
                   threshold, window_secs, eval_interval_secs, enabled,
                   created_by, created_at, updated_at
            FROM observability_metric_monitors
            WHERE enabled = TRUE
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(Self::row_to_monitor).collect()
    }

    /// Fetch one monitor by id.
    pub async fn get(&self, id: Uuid) -> Result<MetricMonitor, MetricMonitorRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, metric_name, agg, group_by, filters, comparator,
                   threshold, window_secs, eval_interval_secs, enabled,
                   created_by, created_at, updated_at
            FROM observability_metric_monitors
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MetricMonitorRepositoryError::NotFound(id))?;

        Self::row_to_monitor(&row)
    }

    /// Insert a new monitor definition.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        name: &str,
        metric_name: &str,
        agg: &str,
        group_by: Option<&str>,
        filters: &[MonitorTagFilter],
        comparator: MonitorComparator,
        threshold: f64,
        window_secs: i32,
        eval_interval_secs: i32,
        enabled: bool,
        created_by: Option<Uuid>,
    ) -> Result<MetricMonitor, MetricMonitorRepositoryError> {
        let filters_json = serde_json::to_value(filters)
            .map_err(|e| MetricMonitorRepositoryError::Invalid(format!("filters: {e}")))?;
        let row = sqlx::query(
            r#"
            INSERT INTO observability_metric_monitors
                (name, metric_name, agg, group_by, filters, comparator, threshold,
                 window_secs, eval_interval_secs, enabled, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, name, metric_name, agg, group_by, filters, comparator,
                      threshold, window_secs, eval_interval_secs, enabled,
                      created_by, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(metric_name)
        .bind(agg)
        .bind(group_by)
        .bind(filters_json)
        .bind(comparator.as_str())
        .bind(threshold)
        .bind(window_secs)
        .bind(eval_interval_secs)
        .bind(enabled)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        Self::row_to_monitor(&row)
    }

    /// Update a monitor definition (full replace of the editable fields).
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        id: Uuid,
        name: &str,
        metric_name: &str,
        agg: &str,
        group_by: Option<&str>,
        filters: &[MonitorTagFilter],
        comparator: MonitorComparator,
        threshold: f64,
        window_secs: i32,
        eval_interval_secs: i32,
        enabled: bool,
    ) -> Result<MetricMonitor, MetricMonitorRepositoryError> {
        let filters_json = serde_json::to_value(filters)
            .map_err(|e| MetricMonitorRepositoryError::Invalid(format!("filters: {e}")))?;
        let row = sqlx::query(
            r#"
            UPDATE observability_metric_monitors
            SET name = $2,
                metric_name = $3,
                agg = $4,
                group_by = $5,
                filters = $6,
                comparator = $7,
                threshold = $8,
                window_secs = $9,
                eval_interval_secs = $10,
                enabled = $11,
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, metric_name, agg, group_by, filters, comparator,
                      threshold, window_secs, eval_interval_secs, enabled,
                      created_by, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(metric_name)
        .bind(agg)
        .bind(group_by)
        .bind(filters_json)
        .bind(comparator.as_str())
        .bind(threshold)
        .bind(window_secs)
        .bind(eval_interval_secs)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MetricMonitorRepositoryError::NotFound(id))?;

        Self::row_to_monitor(&row)
    }

    /// Delete a monitor. Returns whether a row was removed.
    pub async fn delete(&self, id: Uuid) -> Result<bool, MetricMonitorRepositoryError> {
        let result = sqlx::query("DELETE FROM observability_metric_monitors WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn row_to_monitor(
        row: &sqlx::postgres::PgRow,
    ) -> Result<MetricMonitor, MetricMonitorRepositoryError> {
        let comparator_str: String = row.get("comparator");
        let comparator = MonitorComparator::from_str(&comparator_str).ok_or_else(|| {
            MetricMonitorRepositoryError::Invalid(format!("unknown comparator '{comparator_str}'"))
        })?;
        let filters_json: serde_json::Value = row.get("filters");
        let filters: Vec<MonitorTagFilter> = serde_json::from_value(filters_json)
            .map_err(|e| MetricMonitorRepositoryError::Invalid(format!("filters: {e}")))?;
        Ok(MetricMonitor {
            id: row.get("id"),
            name: row.get("name"),
            metric_name: row.get("metric_name"),
            agg: row.get("agg"),
            group_by: row.get("group_by"),
            filters,
            comparator,
            threshold: row.get("threshold"),
            window_secs: row.get("window_secs"),
            eval_interval_secs: row.get("eval_interval_secs"),
            enabled: row.get("enabled"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}
