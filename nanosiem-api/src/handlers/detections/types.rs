// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request/response types for detection endpoints

use nanosiem_core::DetectionRule;
use nanosiem_core::Severity;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Query parameters for listing detection rules
#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct ListDetectionsQuery {
    pub severity: Option<Severity>,
    /// Filter by rule mode (staging, live, alerting, paused)
    pub mode: Option<String>,
    /// Filter by detection mode (real-time, scheduled)
    pub detection_mode: Option<String>,
}

/// Request for testing a detection rule
#[derive(Debug, Deserialize, ToSchema)]
pub struct TestRuleRequest {
    #[serde(default)]
    pub query: String,
    /// Number of days back from now (legacy fallback; ignored when
    /// `time_range` is provided).
    #[serde(default = "default_test_days")]
    pub days: i64,
    /// Explicit `[start, end]` window. Preferred over `days`. Must be at
    /// most 14 days wide; longer ranges return a 400 (NAN-741).
    pub time_range: Option<TimeRangeRequest>,
    /// Cron expression to step at when testing an ad-hoc query (no saved
    /// rule). Ignored by `/api/rules/{id}/test`, which always uses the saved
    /// rule's `schedule_cron`. Defaults to `*/5 * * * *` (every 5 minutes)
    /// when omitted.
    #[serde(default)]
    pub schedule_cron: Option<String>,
    /// Lookback window in minutes for ad-hoc query tests. Ignored by
    /// `/api/rules/{id}/test`. Defaults to 15 when omitted.
    #[serde(default)]
    pub lookback_minutes: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TimeRangeRequest {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

fn default_test_days() -> i64 {
    7
}

/// Request for importing detection rules
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportRulesRequest {
    pub rules: Vec<nanosiem_core::NewDetectionRule>,
}

/// Response for import operation
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportResponse {
    pub imported: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Response for detection creation/update with optional warnings
#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionResponse {
    #[serde(flatten)]
    pub rule: DetectionRule,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct StatsQuery {
    pub days: Option<i32>,
}

/// Query parameters for fetching detection matches
#[derive(Debug, Deserialize, IntoParams)]
pub struct DetectionMatchesQuery {
    /// Maximum number of matches to return
    #[serde(default = "default_matches_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
    /// Optional start time filter (ISO 8601)
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional end time filter (ISO 8601)
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_matches_limit() -> i64 {
    100
}

/// Response for detection matches
#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionMatchesResponse {
    /// Total number of matches (alerts) for this detection
    pub total: i64,
    /// Matches (alerts with their matched events)
    pub matches: Vec<DetectionMatch>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionMatch {
    /// Alert ID
    #[serde(with = "nanosiem_core::typeid::rule")]
    #[schema(value_type = String)]
    pub id: Uuid,
    /// When the alert was created (detection timestamp)
    pub detected_at: chrono::DateTime<chrono::Utc>,
    /// Severity of the alert
    pub severity: String,
    /// Status of the alert
    pub status: String,
    /// Number of events that matched
    pub event_count: i32,
    /// The actual events that triggered this detection
    pub events: Vec<serde_json::Value>,
    /// Whether the match has been reviewed by an analyst (NAN-494).
    /// Null on legacy responses; absent in JSON when false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed: Option<bool>,
    /// When the match was reviewed, if at all (NAN-494).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request for formatting a query
#[derive(Debug, Deserialize, ToSchema)]
pub struct FormatQueryRequest {
    pub query: String,
}

/// Response for formatted query
#[derive(Debug, Serialize, ToSchema)]
pub struct FormatQueryResponse {
    pub formatted_query: String,
}

/// Request for validating a detection rule before creation
#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateDetectionRequest {
    /// The detection query to validate
    pub query: String,
    /// Desired detection mode (real-time or scheduled)
    pub detection_mode: Option<String>,
}

/// Response from detection validation
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateDetectionResponse {
    /// Whether the query is valid
    pub valid: bool,
    /// The effective detection mode that will be used
    pub effective_mode: String,
    /// Whether a materialized view will be created
    pub creates_materialized_view: bool,
    /// Human-readable explanation of mode selection
    pub mode_reason: String,
    /// Any warnings about the configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Validation errors if query is invalid
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    /// Fields referenced in the query (for debugging)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub referenced_fields: Vec<String>,
}

// =============================================================================
// Home page aggregates (NAN-370)
// =============================================================================

/// Detection engine health counts for the Home page "Detection health" pulse card.
#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionHealthSummary {
    /// Unread tuning notifications across all users
    pub needs_tuning: i64,
    /// Count of rules that produced > 500 matches in the last 7 days
    pub noisy_count: i64,
    /// Count of Live/Alerting rules with no matches in the last 7 days
    pub silent_count: i64,
}

/// Query parameters for GET /api/rules/noisy
#[derive(Debug, Deserialize, IntoParams)]
pub struct NoisyRulesQuery {
    /// Max number of rules to return (1..=20). Defaults to 5.
    pub limit: Option<i32>,
}

/// A single entry in the "noisiest rules" list.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoisyRule {
    /// Detection rule ID (TypeID-encoded string)
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Total matches over the last 7 days
    pub match_count: i64,
    /// Total alerts over the last 7 days
    pub alert_count: i64,
    /// Event-to-alert ratio (alerts / matches). Placeholder for a future real FP metric
    /// based on analyst feedback. 0.0..=1.0.
    pub fp_rate: f64,
    /// Direction of the match count trend: "up" (+20% vs yesterday), "down" (-20%), "flat"
    pub trend: String,
}

/// Response for GET /api/rules/noisy
#[derive(Debug, Serialize, ToSchema)]
pub struct NoisyRulesResponse {
    pub rules: Vec<NoisyRule>,
}

/// Fleet health counts for the `/rules` overview strip "Fleet health" cell.
///
/// Computed over the **schedulable** detection fleet — rules in Live or
/// Alerting mode, scheduled (not real-time), with a non-null `schedule_cron`.
/// Rules in staging/paused or pure real-time materialized-view rules are
/// excluded because they do not flow through the scheduler claim/release loop.
///
/// `healthy + slow + errors` may be less than `total` when a rule is in the
/// fleet but has not yet had a first scheduled run (`last_run_at IS NULL`).
/// The frontend treats those as "pending" and displays them implicitly via
/// the `total - (healthy + slow + errors)` remainder.
#[derive(Debug, Serialize, ToSchema)]
pub struct FleetHealthSummary {
    /// Total schedulable rules in the fleet (Live/Alerting + scheduled + has cron)
    pub total: i64,
    /// Rules that ran on schedule (`next_run_at` not far overdue) and whose
    /// most-recent recorded execution time is under [`SLOW_DURATION_MS`].
    pub healthy: i64,
    /// Rules that ran on schedule but whose most-recent recorded execution
    /// time is at or above [`SLOW_DURATION_MS`].
    pub slow: i64,
    /// Rules whose `next_run_at` is more than [`STUCK_THRESHOLD_SECS`] past due.
    /// The scheduler is failing to advance them — typically because every run
    /// is timing out, the node holding the claim crashed, or the rule throws.
    pub errors: i64,
}
