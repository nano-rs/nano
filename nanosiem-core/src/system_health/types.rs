// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

pub const DEFAULT_TENANT_ID: &str = "default";
pub const SYSTEM_HEALTH_EVENT_TYPE: &str = "system_health";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl HealthSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Informational => "informational",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthCategory {
    Integration,
    Enrichment,
    LogSource,
    Ingestion,
    Parser,
    Storage,
    Query,
    Credential,
    Service,
}

impl HealthCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integration => "integration",
            Self::Enrichment => "enrichment",
            Self::LogSource => "log_source",
            Self::Ingestion => "ingestion",
            Self::Parser => "parser",
            Self::Storage => "storage",
            Self::Query => "query",
            Self::Credential => "credential",
            Self::Service => "service",
        }
    }
}

/// Producer-owned health signal. `dedup_key` must be stable for one resource
/// and condition (for example `integration:<id>:run_failed`).
#[derive(Debug, Clone)]
pub struct PublishHealthEvent {
    pub tenant_id: String,
    pub dedup_key: String,
    pub category: HealthCategory,
    pub severity: HealthSeverity,
    pub title: String,
    pub summary: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub diagnostic_context: serde_json::Value,
    pub remediation: Option<String>,
    pub source: String,
}

impl PublishHealthEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dedup_key: impl Into<String>,
        category: HealthCategory,
        severity: HealthSeverity,
        title: impl Into<String>,
        summary: impl Into<String>,
        resource_type: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID.to_string(),
            dedup_key: dedup_key.into(),
            category,
            severity,
            title: title.into(),
            summary: summary.into(),
            resource_type: resource_type.into(),
            resource_id: None,
            resource_name: None,
            diagnostic_context: serde_json::json!({}),
            remediation: None,
            source: source.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct SystemHealthEvent {
    pub id: Uuid,
    pub tenant_id: String,
    pub dedup_key: String,
    pub category: String,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub summary: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub diagnostic_context: serde_json::Value,
    pub remediation: Option<String>,
    pub source: String,
    pub occurrence_count: i64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub last_notified_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct HealthDelivery {
    pub id: Uuid,
    pub event_id: Uuid,
    pub webhook_id: Uuid,
    pub webhook_name: String,
    pub event_action: String,
    pub status: String,
    pub attempt_count: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub last_status_code: Option<i32>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ClaimedHealthDelivery {
    pub id: Uuid,
    pub event_id: Uuid,
    pub webhook_id: Uuid,
    pub event_action: String,
    pub attempt_count: i32,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct HealthEventList {
    pub events: Vec<SystemHealthEvent>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct HealthBusSummary {
    pub active: i64,
    pub unacknowledged: i64,
    pub critical: i64,
    pub high: i64,
    pub delivery_pending: i64,
    pub delivery_dead: i64,
}
