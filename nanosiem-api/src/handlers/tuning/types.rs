// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::tuning::{ProposalType, TuningStatus};

/// Query parameters for listing proposals
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct ListProposalsQuery {
    /// Filter by rule ID
    #[serde(default, with = "nanosiem_core::typeid::rule::opt")]
    #[param(value_type = Option<String>)]
    pub rule_id: Option<Uuid>,
    /// Filter by status
    pub status: Option<TuningStatus>,
    /// Filter by proposal type (query_tuning or hint_update)
    pub proposal_type: Option<ProposalType>,
    /// Limit number of results
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
}

/// Query parameters for listing metrics
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct ListMetricsQuery {
    /// Limit number of results
    pub limit: Option<i64>,
}

/// Query parameters for listing breaches
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct ListBreachesQuery {
    /// Limit number of results
    pub limit: Option<i64>,
}

pub(crate) fn default_limit() -> i64 {
    50
}

/// Query parameters for listing logs
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct ListLogsQuery {
    /// Filter by rule ID
    #[serde(default, with = "nanosiem_core::typeid::rule::opt")]
    #[param(value_type = Option<String>)]
    pub rule_id: Option<Uuid>,
    /// Filter by status
    pub status: Option<TuningStatus>,
    /// Limit number of results
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
}

/// Request to approve a tuning proposal
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApproveProposalRequest {
    /// Optional comment from approver
    pub comment: Option<String>,
    /// Optional modified query — if provided, overrides the AI-proposed query.
    /// Allows analysts to tweak the proposal before approving.
    pub modified_query: Option<String>,
    /// Skip syntax validation (default: false). Requires detections:promote and a non-empty comment.
    #[serde(default)]
    pub skip_validation: bool,
}

/// Request to reject a tuning proposal
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RejectProposalRequest {
    /// Reason for rejection
    pub reason: String,
}

/// Request to revert a tuning
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RevertRequest {
    /// Version ID to revert to
    pub version_id: i32,
    /// Reason for revert
    pub reason: String,
}

/// Request to mark notification as read
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MarkReadRequest {
    /// Optional timestamp (defaults to now)
    pub read_at: Option<DateTime<Utc>>,
}

/// Rule-level tuning settings
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TuningSettings {
    /// Whether auto-tuning is enabled for this rule
    pub auto_tuning_enabled: bool,
    /// Minimum confidence threshold (0.0 - 1.0)
    pub auto_tuning_min_confidence: f64,
    /// Whether this rule is marked as critical (no auto-tuning)
    pub auto_tuning_critical: bool,
    /// Timestamp until which auto-tuning is disabled (cooldown)
    pub auto_tuning_disabled_until: Option<DateTime<Utc>>,
    /// Whether to automatically apply high-confidence proposals without manual review
    pub auto_apply_enabled: bool,
}

/// Response for proposal approval
#[derive(Debug, Clone, Copy, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Applied,
    PrOpened,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApprovalResponse {
    pub success: bool,
    pub message: String,
    pub version_id: Option<i32>,
    pub outcome: Option<ApprovalOutcome>,
    pub status: Option<TuningStatus>,
    pub pr_url: Option<String>,
    pub effective_query: Option<String>,
    /// True when PostgreSQL committed but real-time ClickHouse DDL will retry.
    pub runtime_sync_pending: bool,
    pub runtime_sync_error: Option<String>,
}

/// Response for proposal rejection
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RejectionResponse {
    pub success: bool,
    pub message: String,
}

/// Response for rule version
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RuleVersionResponse {
    pub id: i32,
    #[serde(with = "nanosiem_core::typeid::rule")]
    #[schema(value_type = String)]
    pub rule_id: Uuid,
    pub version_number: i32,
    pub query: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub enabled: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    #[serde(with = "nanosiem_core::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_by_name: Option<String>,
    pub change_reason: String,
    pub tuning_proposal_id: Option<Uuid>,
    pub reverted_from_version: Option<i32>,
}
