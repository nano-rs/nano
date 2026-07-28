// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types for SIEM health check reports

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{ArtifactScope, SourceProvenance};

/// Replacement text for the free-prose half of a health report that a
/// source-restricted reader may not receive (NAN-2222).
///
/// A health report is a *separable* artifact. Its `source_type`-keyed metric
/// vectors are attributable and can be pruned per partition
/// ([`CollectedMetrics::retain_source_partitions`]); its AI narrative,
/// recommendations, and per-dimension analysis are free text that can name any
/// contributing source and cannot be pruned. Only the second half is withheld,
/// and only when the stored provenance does not prove the report disjoint from
/// the reader's deny set.
pub const WITHHELD_NARRATIVE_NOTICE: &str = "Health-report narrative withheld: the AI summary, recommendations, and per-dimension analysis are not source-attributed, and this report's stored provenance does not prove it disjoint from the source types you are denied. Scores and the per-source metrics you are permitted to see are unaffected.";

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
    /// Known origin manifest for the stored payload, used to decide which
    /// parts of the report a source-restricted reader may receive.
    #[serde(skip)]
    #[schema(ignore)]
    pub source_types: Vec<String>,
    /// False until every global score, recommendation, and prose block can be
    /// tied to source-partitioned inputs (NAN-2153 / NAN-2089).
    #[serde(skip)]
    #[schema(ignore)]
    pub source_types_complete: bool,
}

impl SiemHealthReport {
    /// May this reader receive the report's unattributed free prose?
    ///
    /// This is NAN-2089's whole-artifact classifier, unchanged — applied to the
    /// narrative instead of to the row's existence. It is satisfied only by a
    /// non-empty, resolved, provably complete manifest disjoint from the deny
    /// set, so legacy (`'{}'` + FALSE) and partially attributed reports keep
    /// failing closed exactly as before.
    pub fn narrative_visible_to(&self, scope: &ArtifactScope) -> bool {
        scope.allows(&self.source_types, self.source_types_complete)
    }

    /// Reduce a stored report to what `scope` may see (NAN-2222).
    ///
    /// 1. Every `source_type`-keyed partition denied to the reader is dropped
    ///    and the exact ingestion totals are recomputed from what remains.
    /// 2. The non-attributable narrative is replaced with
    ///    [`WITHHELD_NARRATIVE_NOTICE`] unless the stored provenance proves the
    ///    report disjoint from the deny set.
    ///
    /// Scores, status, timing, and non-partitioned fleet aggregates are
    /// deliberately preserved: they are scalars over the whole deployment
    /// rather than per-source data, and withholding them would leave the
    /// `settings:system` monitoring callers this endpoint exists for with
    /// nothing to poll. Attributing them remains NAN-2089's work.
    ///
    /// An unrestricted scope returns immediately, so a SYSTEM/admin read stays
    /// byte-identical to the stored row.
    pub fn apply_artifact_scope(&mut self, scope: &ArtifactScope) {
        if scope.is_unrestricted() {
            return;
        }

        // A restricted viewer gets no metrics at all if the stored JSON cannot
        // be deserialized into the typed partition contract — an unparseable
        // blob cannot be pruned, so it fails closed.
        match serde_json::from_value::<CollectedMetrics>(self.metrics.clone()) {
            Ok(mut metrics) => {
                metrics.retain_source_partitions(scope);
                self.metrics =
                    serde_json::to_value(metrics).unwrap_or_else(|_| serde_json::json!({}));
            }
            Err(_) => self.metrics = serde_json::json!({}),
        }

        if !self.narrative_visible_to(scope) {
            self.summary = WITHHELD_NARRATIVE_NOTICE.to_string();
            self.recommendations = serde_json::json!([]);
            self.dimension_details = serde_json::json!({});
        }
    }
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
    /// Same manifest as [`SiemHealthReport::source_types`]; carried so the list
    /// view applies the identical narrative policy as the detail view.
    #[serde(skip)]
    #[schema(ignore)]
    pub source_types: Vec<String>,
    #[serde(skip)]
    #[schema(ignore)]
    pub source_types_complete: bool,
}

impl SiemHealthReportSummary {
    /// List-view counterpart of [`SiemHealthReport::apply_artifact_scope`].
    ///
    /// A summary row carries no per-source partitions, so only the narrative
    /// half of the policy applies. Rows are never dropped: the list is not
    /// filtered, so page size and `total` cannot become an oracle for report
    /// activity the reader may not see.
    pub fn apply_artifact_scope(&mut self, scope: &ArtifactScope) {
        if scope.is_unrestricted() {
            return;
        }
        if !scope.allows(&self.source_types, self.source_types_complete) {
            self.summary = WITHHELD_NARRATIVE_NOTICE.to_string();
        }
    }
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

impl CollectedMetrics {
    /// Union every source identity exposed by today's per-source collectors.
    ///
    /// This remains deliberately incomplete: detection and alerting totals,
    /// fleet-wide enrichment rates, integrity probes, recommendations, and
    /// generated prose are not yet partition-attributed. Persisting the known
    /// envelope is useful to the follow-up migrations, but claiming it is the
    /// complete report provenance would be a source-scoped fail-open.
    ///
    /// NAN-2222: this stamp is honest and stays. What changed is that report
    /// VISIBILITY no longer hinges on it — an unconditionally incomplete stamp
    /// combined with a read gate that required `source_types_complete` made
    /// every report permanently unreadable by every restricted principal. The
    /// completeness bit now governs the narrative half of the artifact
    /// ([`SiemHealthReport::narrative_visible_to`]), which is exactly the part
    /// it truthfully describes, and will start admitting prose on its own once
    /// NAN-2089 attributes the global scores and generated text.
    pub fn source_provenance(&self) -> SourceProvenance {
        let source_types = self
            .ingestion
            .source_volumes
            .iter()
            .map(|metric| metric.source_type.as_str())
            .chain(self.ingestion.silent_sources.iter().map(String::as_str))
            .chain(
                self.parsing
                    .field_coverage
                    .iter()
                    .map(|metric| metric.source_type.as_str()),
            )
            .chain(
                self.parsing
                    .high_ext_sources
                    .iter()
                    .map(|metric| metric.source_type.as_str()),
            )
            .chain(
                self.enrichment
                    .per_source_coverage
                    .iter()
                    .map(|metric| metric.source_type.as_str()),
            );
        SourceProvenance::incomplete(source_types)
    }

    /// Retain the source-partitioned metrics visible to a current viewer.
    ///
    /// Health reports are durable SYSTEM artifacts, so this is applied after a
    /// stored report is loaded as well as at viewer-triggered collection time.
    /// Each keyed row is treated as a complete single-source artifact through
    /// the shared provenance classifier. Blank/unresolved source identities
    /// therefore fail closed for a restricted viewer.
    ///
    /// The ingestion totals are exact sums of `source_volumes` and are
    /// recomputed after filtering. The remaining fleet-wide RATIOS
    /// (`enrichment.*_pct`) are not derivable from the persisted top-N
    /// partitions and stay for NAN-2089 to handle together with narrative,
    /// recommendations, and scores.
    ///
    /// `enrichment.total_events_24h` is recomputed too (NAN-2222). It is
    /// `count()` over the same logs, window, and predicate the ingestion
    /// group-by sums, so leaving it while pruning `ingestion.total_events_24h`
    /// published the denied sources' exact 24h event volume as the difference
    /// of two returned fields — the precise datum this pruning exists to hide,
    /// recoverable with one subtraction.
    pub fn retain_source_partitions(&mut self, scope: &ArtifactScope) {
        if scope.is_unrestricted() {
            return;
        }

        let is_visible =
            |source_type: &str| scope.allows_provenance(&SourceProvenance::complete([source_type]));

        self.ingestion
            .source_volumes
            .retain(|metric| is_visible(&metric.source_type));
        self.ingestion
            .silent_sources
            .retain(|source_type| is_visible(source_type));
        self.ingestion.total_events_24h = self
            .ingestion
            .source_volumes
            .iter()
            .fold(0_u64, |total, metric| {
                total.saturating_add(metric.count_24h)
            });
        self.ingestion.total_events_prior_24h = self
            .ingestion
            .source_volumes
            .iter()
            .fold(0_u64, |total, metric| {
                total.saturating_add(metric.count_prior_24h)
            });

        self.parsing
            .field_coverage
            .retain(|metric| is_visible(&metric.source_type));
        self.parsing
            .high_ext_sources
            .retain(|metric| is_visible(&metric.source_type));
        self.enrichment
            .per_source_coverage
            .retain(|metric| is_visible(&metric.source_type));
        // Re-denominate the fleet rollup over the partitions that survived, so
        // it can no longer be differenced against the pruned ingestion total.
        // The retained rows are the collector's top-N (≥100 events), so this
        // UNDER-counts the reader's own visible volume — an undercount only
        // ever hides visible data, never denied data.
        self.enrichment.total_events_24h = self
            .enrichment
            .per_source_coverage
            .iter()
            .fold(0_u64, |total, metric| {
                total.saturating_add(metric.total_events)
            });
    }
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
    /// Dictionaries referenced by the logs table's MATERIALIZED columns that are
    /// currently unhealthy: either `FAILED*` status, OR a non-empty
    /// `last_exception` at any status. The second case catches a degraded
    /// CACHE dict (the prevalence dicts) — a broken source flips it to `LOADED`
    /// while every `dictGetOrDefault` throws at flush, so a status-only filter
    /// missed the halt (NAN-1667, gap G2). Either way any entry is a guaranteed
    /// ingestion halt today. `last_exception` clears on recovery, so a recovered
    /// dict drops out on the next probe (no false positives).
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

/// An unhealthy ClickHouse dictionary referenced by the logs table DDL — either
/// `FAILED*` status or a degraded CACHE dict carrying a live `last_exception`
/// (NAN-1667). Both halt inserts at flush.
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
    /// NAN-1643: ingest-lowercase invariant violations over the last hour.
    /// The query generator compares `LOWERCASE_NORMALIZED_FIELDS` columns RAW
    /// (no lower() wrapper) so their bloom/PK indexes prune; that is only
    /// correct while ingest keeps those columns all-lowercase. Any entry here
    /// means a lane (new source, backfill, parser regression) is writing
    /// mixed-case and raw-compare queries are silently missing those rows.
    /// `serde(default)` so reports stored before NAN-1643 still deserialize.
    #[serde(default)]
    pub lowercase_invariant_violations: Vec<LowercaseInvariantViolation>,
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

/// A logs column that broke the ingest-lowercase invariant in the probe
/// window (NAN-1643).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LowercaseInvariantViolation {
    /// Physical `logs` column name (`src_ip`, `user`, …).
    pub column: String,
    /// Rows in the window where `col != lower(col)`.
    pub violation_count: u64,
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
    /// Installed enrichment providers and their run status. Lets the analyzer
    /// ground a low coverage number: a 0% IOC hit rate, 0% identity fill, or 0%
    /// GeoIP means "no provider installed / never synced → expected" vs
    /// "provider active but failing → actionable", depending on this list.
    /// Includes both `custom_enrichments` feeds and native providers — the
    /// GeoIP/ASN provider (IPinfo Lite) is surfaced here as `enrichment_type =
    /// "geo"` with a `never_synced` status until it has loaded data
    /// (NAN-1178, NAN-2002).
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
    /// Last run outcome for scheduled `data` feeds: "success", "failed",
    /// "running", or `None` if never run. `agent`-type on-demand lookups
    /// (VirusTotal, AbuseIPDB, …) are never scheduled, so the collector
    /// normalizes their null status to `"on_demand"` (NAN-1994) — a null here
    /// therefore only ever means a scheduled feed that has not yet run.
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
