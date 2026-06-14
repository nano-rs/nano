// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types for SIEM health check reports

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Overall health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn from_score(score: i32) -> Self {
        if score >= 80 {
            Self::Healthy
        } else if score >= 50 {
            Self::Warning
        } else {
            Self::Critical
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A stored SIEM health report
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SiemHealthReport {
    pub id: Uuid,
    pub overall_score: i32,
    pub overall_status: String,
    pub ingestion_score: i32,
    pub parsing_score: i32,
    pub detection_score: i32,
    /// NAN-569: nullable for backward compat with reports generated before
    /// enrichment scoring landed.
    pub enrichment_score: Option<i32>,
    /// NAN-569: nullable for backward compat with reports generated before
    /// alerting scoring landed.
    pub alerting_score: Option<i32>,
    pub summary: String,
    pub metrics: serde_json::Value,
    pub recommendations: serde_json::Value,
    pub dimension_details: serde_json::Value,
    pub triggered_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub duration_ms: Option<i32>,
}

/// Summary of a report (for list views, without full metrics/details)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SiemHealthReportSummary {
    pub id: Uuid,
    pub overall_score: i32,
    pub overall_status: String,
    pub ingestion_score: i32,
    pub parsing_score: i32,
    pub detection_score: i32,
    pub enrichment_score: Option<i32>,
    pub alerting_score: Option<i32>,
    pub summary: String,
    pub triggered_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub duration_ms: Option<i32>,
}

/// Collected metrics from ClickHouse + PostgreSQL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedMetrics {
    pub ingestion: IngestionMetrics,
    pub parsing: ParsingMetrics,
    pub enrichment: EnrichmentMetrics,
    pub detection: DetectionMetrics,
    pub alerting: AlertingMetrics,
    pub collected_at: DateTime<Utc>,
}

/// Ingestion health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionMetrics {
    /// Per-source-type volume (last 24h)
    pub source_volumes: Vec<SourceVolumeMetric>,
    /// Total events in last 24h
    pub total_events_24h: u64,
    /// Total events in prior 24h (for comparison)
    pub total_events_prior_24h: u64,
    /// Source types that had events in prior 24h but zero in last 24h
    pub silent_sources: Vec<String>,
    /// Insert-path integrity signals (NAN-1405). `default` so reports stored
    /// before this field existed still deserialize.
    #[serde(default)]
    pub insert_integrity: InsertIntegrityMetrics,
}

/// Insert-path integrity signals (NAN-1405) — the NAN-1404 silent-loss kill
/// chain. With `wait_for_async_insert=0` every ACK in the ingest chain fires
/// before the flush, so a failing flush discards batches while Vector, HTTP
/// 200s, and `QueryFinish` entries all look healthy. These probes watch the
/// storage-layer tells instead of the ACK layer. Each probe degrades to its
/// default when the app user lacks the system-table grant (pre-NAN-1405
/// deployments) — `probes_available` records whether ANY probe answered.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InsertIntegrityMetrics {
    /// Whether the system-table probes could run at all (grants present).
    pub probes_available: bool,
    /// Finished INSERTs into the logs table over the last hour (query_log) —
    /// the ACK-layer count. NOTE: per-query async-insert entries report
    /// written_rows=0 even when healthy (the rows are written by the flush),
    /// so written_rows is NOT a loss signal — verified live during NAN-1405
    /// (791/795 healthy inserts read 0). The loss test pairs this with
    /// `new_parts_1h` below.
    pub logs_inserts_1h: u64,
    /// New parts created for the logs table over the last hour (part_log) —
    /// the storage-layer count. `logs_inserts_1h > 0` with `new_parts_1h == 0`
    /// is the NAN-1404 fingerprint: inserts ACKing while nothing reaches disk
    /// (the exact correlation that diagnosed Saturn).
    pub new_parts_1h: u64,
    /// Whether the `system.part_log` probe actually ran (NAN-1461). The
    /// `query_log` and `part_log` grants are independent — a tenant can have one
    /// and not the other — so a failed part_log read leaves `new_parts_1h` at its
    /// default 0. Without this flag the inserts-without-parts critical can't tell
    /// "measured 0 parts" (real loss) from "couldn't measure" (missing grant) and
    /// false-alarms data loss. `serde(default)` so pre-NAN-1461 reports deserialize.
    #[serde(default)]
    pub new_parts_probe_ok: bool,
    /// system.errors counter for MEMORY_LIMIT_EXCEEDED (code 241), only when
    /// its last occurrence is within 24h (the counter never resets).
    pub memory_limit_errors: u64,
    /// system.errors counter for CACHE_DICTIONARY_UPDATE_FAIL (code 510),
    /// 24h-recency-gated — the hash_prevalence_dict collateral signature.
    pub cache_dictionary_update_fails: u64,
    /// Dictionaries referenced by the logs table's MATERIALIZED columns that
    /// are currently FAILED. Any entry here is a guaranteed ingestion halt
    /// today (dictGetOrDefault THROWS at flush when the dict is FAILED).
    pub failed_logs_dictionaries: Vec<FailedDictionary>,
    /// Flush failures from system.asynchronous_insert_log over the last hour.
    /// None when the log is not enabled (pre-NAN-1405 server config).
    pub async_insert_failures_1h: Option<u64>,
    /// Most recent flush exception (truncated), if any.
    pub last_async_insert_error: Option<String>,
    /// Dictionary-staging refresh MVs (`*_dict_refresh`, NAN-1407) that are
    /// failing or stale. Stale enrichment, NOT data loss — that distinction
    /// is the whole point of the staging indirection: rows keep landing with
    /// the last good snapshot while the refresh is broken. `serde(default)`
    /// so reports stored before NAN-1407 still deserialize.
    #[serde(default)]
    pub stale_dict_refreshes: Vec<StaleDictRefresh>,
}

/// A FAILED ClickHouse dictionary referenced by the logs table DDL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedDictionary {
    /// Fully qualified name (`nanosiem.ip_enrichment_dict`).
    pub name: String,
    /// Truncated last_exception from system.dictionaries.
    pub last_exception: String,
}

/// A failing/stale dictionary-staging refresh MV from system.view_refreshes
/// (NAN-1407). Flagged when `exception != ''` (the refresher keeps retrying
/// on schedule and keeps last good data — visible failure, no loss) or when
/// the last successful refresh is over an hour old (covers a silently
/// stuck/disabled refresher; the longest refresh cadence is 10 minutes, so
/// 1h ≈ 6 missed cycles — generous enough to never flap on a slow refresh,
/// tight enough to catch a wedged one the same day).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleDictRefresh {
    /// View name (`ip_enrichment_dict_refresh`).
    pub view: String,
    /// Truncated exception from system.view_refreshes ('' when the refresh
    /// succeeds but is stale).
    pub exception: String,
    /// Seconds since the last successful refresh; 0 when the view has never
    /// succeeded (NULL last_success_time).
    pub last_success_age_secs: u64,
}

/// Volume metric for a single source type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceVolumeMetric {
    pub source_type: String,
    pub count_24h: u64,
    pub count_prior_24h: u64,
    /// Percentage change: ((current - prior) / prior) * 100
    pub change_pct: f64,
}

/// Parsing health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsingMetrics {
    /// Per-source-type field coverage
    pub field_coverage: Vec<FieldCoverageMetric>,
    /// Source types with high ext column usage (> 50% of events)
    pub high_ext_sources: Vec<ExtUsageMetric>,
}

/// Field coverage for a source type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCoverageMetric {
    pub source_type: String,
    pub total_events: u64,
    pub src_ip_filled_pct: f64,
    pub user_filled_pct: f64,
    pub event_type_filled_pct: f64,
    pub message_filled_pct: f64,
}

/// Ext column usage for a source type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtUsageMetric {
    pub source_type: String,
    pub total_events: u64,
    pub ext_usage_pct: f64,
}

/// Enrichment health metrics — fleet-wide fill rates over the last 24h.
///
/// All percentages are in 0.0..=100.0 range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentMetrics {
    /// Total events evaluated (last 24h).
    pub total_events_24h: u64,
    /// % of events with `enriched_src_country` populated.
    pub geoip_fill_pct: f64,
    /// % of events with `enriched_src_asn` populated.
    pub asn_fill_pct: f64,
    /// % of events with any IOC hit (`ioc_confidence > 0`).
    pub ioc_hit_pct: f64,
    /// % of events with user-identity enrichment (`user_identity_department`).
    pub identity_fill_pct: f64,
    /// Identity fill % over the *prior* 24h window (24-48h ago). Lets a
    /// consumer distinguish "identity was never configured" (prior also 0 →
    /// not a finding, or LOW) from "identity enrichment was flowing and
    /// stopped" (prior > 0, now 0 → a real regression). NAN-1178.
    #[serde(default)]
    pub identity_fill_prior_pct: f64,
    /// Per-source coverage (top sources by event volume).
    pub per_source_coverage: Vec<EnrichmentCoverageMetric>,
    /// Installed marketplace/custom enrichment providers and their run status.
    /// Lets the analyzer ground a low coverage number: a 0% IOC hit rate or 0%
    /// identity fill means "no provider installed → expected" vs "provider
    /// installed but failing → actionable", depending on this list. GeoIP/ASN
    /// is native (IPinfo Lite) and does NOT appear here. NAN-1178.
    #[serde(default)]
    pub providers: Vec<EnrichmentProviderStatus>,
}

/// Status of one installed marketplace/custom enrichment provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentProviderStatus {
    /// Display name, e.g. "ThreatFox IOC Feed".
    pub name: String,
    /// Provider category: "data" (IOC/lookup feeds), "agent", "identity", ...
    pub enrichment_type: String,
    /// Whether the operator has this provider enabled.
    pub enabled: bool,
    /// Last run outcome: "success", "failed", "running", or `None` if never run.
    pub last_run_status: Option<String>,
}

/// Per-source enrichment coverage row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentCoverageMetric {
    pub source_type: String,
    pub total_events: u64,
    pub geoip_pct: f64,
    pub ioc_pct: f64,
    pub identity_pct: f64,
}

/// Detection health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetrics {
    /// Total enabled rules
    pub total_enabled_rules: i64,
    /// Total detection matches today (sum of `detection_daily_stats.match_count`).
    /// Distinguishes "engine is actively firing detections" from "nothing is
    /// matching" — used so a detections-only deployment (rules in Live mode,
    /// no alerting) isn't mistaken for an alerting outage. NAN-1178.
    #[serde(default)]
    pub total_matches_24h: i64,
    /// Total rules in each mode
    pub rules_by_mode: Vec<RulesByMode>,
    /// Rules that haven't matched in 30+ days
    pub stale_rules: Vec<StaleRule>,
    /// Rules with very high match rates (potential noise)
    pub noisy_rules: Vec<NoisyRule>,
    /// Total alerts by severity in last 24h
    pub alerts_24h_by_severity: Vec<AlertsBySeverity>,
}

/// Rule count by mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesByMode {
    pub mode: String,
    pub count: i64,
}

/// A rule that hasn't matched recently
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleRule {
    pub rule_name: String,
    pub last_matched: Option<DateTime<Utc>>,
    pub days_since_match: i64,
}

/// A rule with high match rate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoisyRule {
    pub rule_name: String,
    pub matches_24h: i64,
    pub severity: String,
}

/// Alert count by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsBySeverity {
    pub severity: String,
    pub count: i64,
}

/// Alerting health metrics over the last 24h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingMetrics {
    /// Alert volume (last 24h).
    pub total_alerts_24h: i64,
    /// Alert volume (prior 24h, for delta).
    pub total_alerts_prior_24h: i64,
    /// Counts by status (new / acknowledged / closed).
    pub by_status: Vec<AlertStatusCount>,
    /// Mean time-to-acknowledge in minutes (last 24h, only over acked alerts).
    /// `None` when no alerts were acknowledged in the window.
    pub mean_mtta_minutes: Option<f64>,
    /// Active webhook destinations (enabled = true).
    pub active_webhooks: i64,
    /// Webhook deliveries in last 24h.
    pub webhook_deliveries_24h: i64,
    /// Webhook delivery success rate as a percentage (0.0..=100.0). `None` if
    /// no deliveries occurred in the window.
    pub webhook_success_pct: Option<f64>,
    /// Active queue routing rules (enabled = true).
    pub active_routing_rules: i64,
}

/// Alert count by status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatusCount {
    pub status: String,
    pub count: i64,
}

/// AI analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub overall_score: i32,
    pub ingestion_score: i32,
    pub parsing_score: i32,
    pub enrichment_score: i32,
    pub detection_score: i32,
    pub alerting_score: i32,
    pub summary: String,
    pub recommendations: Vec<Recommendation>,
    pub dimension_details: DimensionDetails,
}

/// A single recommendation from the AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub title: String,
    pub description: String,
    pub priority: String, // "critical", "high", "medium", "low"
}

/// Detailed findings per dimension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionDetails {
    pub ingestion: String,
    pub parsing: String,
    pub enrichment: String,
    pub detection: String,
    pub alerting: String,
}
