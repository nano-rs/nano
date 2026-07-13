// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled report types (NAN-1793).
//!
//! Domain models for report definitions, run history, and artifact metadata.
//! Mirrors the scheduler's `types.rs` split: a `*Row` (sqlx::FromRow) mirrors the
//! table; the public model carries typeid serde and hides internal claim state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

/// What a report runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportSourceType {
    /// A saved nPL search run over a relative time window → CSV + HTML.
    Search,
    /// A dashboard whose panels are executed server-side → one HTML report.
    Dashboard,
}

impl ReportSourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Dashboard => "dashboard",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "search" => Some(Self::Search),
            "dashboard" => Some(Self::Dashboard),
            _ => None,
        }
    }
}

/// Terminal (and in-flight) run status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportRunStatus {
    Running,
    Success,
    Failed,
}

impl ReportRunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

/// A scheduled report definition.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReportDefinition {
    #[serde(with = "typeid::report")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_type: ReportSourceType,
    /// nPL query snapshot (search reports only).
    pub source_query: Option<String>,
    /// Provenance link to the query_library entry (search reports only).
    pub saved_query_id: Option<i32>,
    /// Dashboard the panels are executed from (dashboard reports only).
    #[serde(default, with = "typeid::dashboard::opt")]
    #[schema(value_type = Option<String>)]
    pub source_dashboard_id: Option<Uuid>,
    /// Relative lookback window applied as [now - N, now] at run time.
    pub time_range_seconds: i64,
    pub cron_expression: String,
    /// Execution identity captured at definition time.
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub owner_id: Uuid,
    /// Owner display name (joined for listing); `None` outside list/get.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    pub enabled: bool,
    /// Keep at most this many most-recent runs per definition.
    pub retention_runs: i32,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_status: Option<String>,
    pub last_run_error: Option<String>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database row for a report definition. Includes internal claim state that the
/// public [`ReportDefinition`] never exposes.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReportDefinitionRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_type: String,
    pub source_query: Option<String>,
    pub saved_query_id: Option<i32>,
    pub source_dashboard_id: Option<Uuid>,
    pub time_range_seconds: i64,
    pub cron_expression: String,
    pub owner_id: Uuid,
    #[sqlx(default)]
    pub owner_name: Option<String>,
    pub enabled: bool,
    pub retention_runs: i32,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_status: Option<String>,
    pub last_run_error: Option<String>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub claim_generation: i64,
    pub claim_run_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<ReportDefinitionRow> for ReportDefinition {
    type Error = String;

    fn try_from(row: ReportDefinitionRow) -> Result<Self, Self::Error> {
        let source_type = ReportSourceType::from_str(&row.source_type)
            .ok_or_else(|| format!("unknown report source_type '{}'", row.source_type))?;
        Ok(Self {
            id: row.id,
            name: row.name,
            description: row.description,
            source_type,
            source_query: row.source_query,
            saved_query_id: row.saved_query_id,
            source_dashboard_id: row.source_dashboard_id,
            time_range_seconds: row.time_range_seconds,
            cron_expression: row.cron_expression,
            owner_id: row.owner_id,
            owner_name: row.owner_name,
            enabled: row.enabled,
            retention_runs: row.retention_runs,
            last_run_at: row.last_run_at,
            last_run_status: row.last_run_status,
            last_run_error: row.last_run_error,
            next_run_at: row.next_run_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// A "due" definition claimed by a scheduler node, carrying the claim state the
/// executor needs to fence and release it.
#[derive(Debug, Clone)]
pub struct ClaimedReportDefinition {
    pub definition: ReportDefinition,
    pub claim_generation: i64,
    pub claim_run_id: Uuid,
}

/// One execution of a report definition.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReportRun {
    #[serde(with = "typeid::report_run")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::report")]
    #[schema(value_type = String)]
    pub definition_id: Uuid,
    pub status: String,
    pub triggered_by: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub row_count: Option<i64>,
    pub truncated: bool,
    pub artifact_truncated: bool,
    pub error: Option<String>,
    /// Artifact metadata (never bytes); populated on run-detail reads.
    #[serde(default)]
    pub artifacts: Vec<ReportArtifactMeta>,
}

/// Database row for a run (no artifacts joined).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ReportRunRow {
    pub id: Uuid,
    pub definition_id: Uuid,
    pub status: String,
    pub triggered_by: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub row_count: Option<i64>,
    pub truncated: bool,
    pub artifact_truncated: bool,
    pub error: Option<String>,
}

impl From<ReportRunRow> for ReportRun {
    fn from(row: ReportRunRow) -> Self {
        Self {
            id: row.id,
            definition_id: row.definition_id,
            status: row.status,
            triggered_by: row.triggered_by,
            started_at: row.started_at,
            finished_at: row.finished_at,
            duration_ms: row.duration_ms,
            row_count: row.row_count,
            truncated: row.truncated,
            artifact_truncated: row.artifact_truncated,
            error: row.error,
            artifacts: Vec::new(),
        }
    }
}

/// Artifact metadata (excludes the `content` bytea).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ReportArtifactMeta {
    #[serde(with = "typeid::report_artifact")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::report_run")]
    #[schema(value_type = String)]
    pub run_id: Uuid,
    pub kind: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

/// Artifact bytes for download (metadata + content).
#[derive(Debug, Clone)]
pub struct ReportArtifactContent {
    pub filename: String,
    pub content_type: String,
    pub content: Vec<u8>,
}

/// A rendered artifact produced by the renderer, ready to persist.
#[derive(Debug, Clone)]
pub struct RenderedArtifact {
    pub kind: String,
    pub filename: String,
    pub content_type: String,
    pub content: Vec<u8>,
}

/// Input for creating a report definition. `owner_id` is set from the
/// authenticated caller in the handler (execution identity).
#[derive(Debug, Clone)]
pub struct NewReportDefinition {
    pub name: String,
    pub description: Option<String>,
    pub source_type: ReportSourceType,
    pub source_query: Option<String>,
    pub saved_query_id: Option<i32>,
    pub source_dashboard_id: Option<Uuid>,
    pub time_range_seconds: i64,
    pub cron_expression: String,
    pub owner_id: Uuid,
    pub enabled: bool,
    pub retention_runs: i32,
}

/// Partial update for a report definition. Every field is optional; `None`
/// leaves the stored value unchanged.
#[derive(Debug, Clone, Default)]
pub struct UpdateReportDefinition {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    /// Replacement nPL query (search reports only). `None` keeps the stored
    /// query; the service rejects empty/whitespace values and dashboard reports.
    pub source_query: Option<String>,
    pub time_range_seconds: Option<i64>,
    pub cron_expression: Option<String>,
    pub enabled: Option<bool>,
    pub retention_runs: Option<i32>,
}
