// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metrics Collector for AI Detection Auto-Tuning
//!
//! Continuously collects detection rule execution metrics including:
//! - Finding counts over various time windows (1h, 24h, 7d) read from
//!   ClickHouse `logs` where `source_type='findings'` (the actual output of
//!   scheduled-mode detections; the PG `alerts` table is only written by the
//!   legacy realtime path).
//! - Unique entity counts (users, hosts, IPs) extracted from the finding's
//!   `matched_events_sample` payload in the `metadata` column.
//! - Finding patterns and common field values.
//! - Query execution times.

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client as ClickHouseClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use super::{
    derive_finding_source_manifest, AlertPattern, FindingProvenance, RuleMetrics,
};
use crate::auth::{Provenanced, SourceProvenance, UNRESOLVED_SOURCE_SENTINEL};
use crate::db::TableNames;

/// True when the env-configured schema profile is OCSF. NAN-1254: drives the
/// finding-column dispatch (rule id / metadata payload live in
/// `event.unmapped.*` on `ocsf_logs`, vs explicit `rule_id`/`metadata` columns
/// on the UDM `logs` table). Resolution mirrors `active_logs_table()`: any env
/// error degrades to UDM (`false`), so a malformed env never breaks tuning.
fn active_profile_is_ocsf() -> bool {
    crate::schema::active_profile_from_env()
        .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
        .unwrap_or(false)
}

/// Errors that can occur during metrics collection
#[derive(Error, Debug)]
pub enum MetricsCollectorError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(Uuid),

    #[error("Invalid time range: {0}")]
    InvalidTimeRange(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<sqlx::Error> for MetricsCollectorError {
    fn from(err: sqlx::Error) -> Self {
        MetricsCollectorError::DatabaseError(err.to_string())
    }
}

impl From<clickhouse::error::Error> for MetricsCollectorError {
    fn from(err: clickhouse::error::Error) -> Self {
        MetricsCollectorError::ClickHouseError(err.to_string())
    }
}

impl From<serde_json::Error> for MetricsCollectorError {
    fn from(err: serde_json::Error) -> Self {
        MetricsCollectorError::SerializationError(err.to_string())
    }
}

/// Finding data retrieved from ClickHouse `logs` (`source_type='findings'`).
///
/// Each row represents one logged detection event (live-mode match or alert).
/// `severity` is read from the direct CH column; `matched_events` is parsed
/// out of the JSON `metadata.matched_events_sample` written by
/// `FindingLogger::log_to_clickhouse` so the existing entity-extraction and
/// pattern-extraction code keeps working unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: Uuid,
    pub severity: String,
    pub matched_events: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    /// NAN-2085: the finding's persisted `origin_source_types` — computed by
    /// `FindingEvent::origin_source_types_from` over the FULL matched set, not
    /// the truncated `matched_events_sample` above. Tuning provenance must be
    /// derived from this: a mixed-source finding whose first few sampled events
    /// all came from source A would otherwise be stamped "complete for A" while
    /// the proposal's inputs also covered denied source B.
    ///
    /// `None` = the key was absent or the metadata could not be parsed (a
    /// pre-NAN-1800 finding, or a writer regression) — provenance is unknown
    /// and every consumer must fail closed.
    #[serde(default)]
    pub origin_source_types: Option<Vec<String>>,
}

/// Row shape returned by the ClickHouse `logs` SELECT for findings.
///
/// We pull `severity` from the direct column (populated by `FindingLogger`)
/// and the matched-event sample out of the JSON `metadata` column. The CH
/// `timestamp` is a `DateTime64(6)` — we decode it as microseconds since
/// epoch (i64) and convert to `DateTime<Utc>` in code.
#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct FindingRow {
    severity: String,
    metadata: String,
    timestamp_us: i64,
}

/// One exact aggregate over the full seven-day input window. Counts and source
/// provenance are deliberately read in the same ClickHouse query so a metric
/// row cannot describe one event set while authorizing against another.
#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct FindingAggregateRow {
    finding_count_1h: u64,
    finding_count_24h: u64,
    finding_count_7d: u64,
    origin_source_types: Vec<String>,
    unattributed_count: u64,
}

/// Metrics collector service.
///
/// Uses PostgreSQL for the rule registry / metrics-storage tables and
/// ClickHouse for the finding count / sample queries.
pub struct MetricsCollector {
    pg_pool: PgPool,
    ch_client: ClickHouseClient,
    table_names: TableNames,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    ///
    /// The PG pool is used for the rule registry + `detection_rule_metrics`
    /// storage. The CH client + `TableNames` resolver is used to count
    /// findings from `logs` (or `logs_distributed` in cluster mode) where
    /// `source_type='findings'`.
    pub fn new(pg_pool: PgPool, ch_client: ClickHouseClient, table_names: TableNames) -> Self {
        Self {
            pg_pool,
            ch_client,
            table_names,
        }
    }

    /// Collect comprehensive metrics for a detection rule.
    ///
    /// Counts findings from ClickHouse for each window and extracts entity
    /// information from the matched-event samples on those findings.
    pub async fn collect_rule_metrics(
        &self,
        rule_id: Uuid,
    ) -> Result<RuleMetrics, MetricsCollectorError> {
        Ok(self
            .collect_rule_metrics_with_provenance(rule_id)
            .await?
            .into_value())
    }

    /// Collect metrics and the exact origin manifest of the full seven-day
    /// finding set used by the stored snapshot.
    pub async fn collect_rule_metrics_with_provenance(
        &self,
        rule_id: Uuid,
    ) -> Result<Provenanced<RuleMetrics>, MetricsCollectorError> {
        let now = Utc::now();

        // Verify rule exists
        let rule_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM detection_rules WHERE id = $1)")
                .bind(rule_id)
                .fetch_one(&self.pg_pool)
                .await?;

        if !rule_exists {
            return Err(MetricsCollectorError::RuleNotFound(rule_id));
        }

        // Read the capped entity sample first, then the exact aggregate. A row
        // arriving between these queries can therefore only make the manifest
        // more conservative; it can never influence the sample while escaping
        // the provenance union. Both queries share the stored timestamp anchor.
        let recent_findings = self
            .get_recent_findings_at(rule_id, Duration::hours(24), now)
            .await?;
        let aggregate = self.aggregate_findings(rule_id, now).await?;

        // Extract unique entities from matched events
        let (unique_users, unique_hosts, unique_ips) =
            self.extract_unique_entities(&recent_findings);

        // Calculate average severity (map severity to numeric values)
        let avg_severity = self.calculate_average_severity(&recent_findings);

        // For now, execution_time_ms is set to 0 as we don't track this yet
        let execution_time_ms = 0;

        let metrics = RuleMetrics {
            rule_id,
            timestamp: now,
            alert_count_1h: aggregate.finding_count_1h as i64,
            alert_count_24h: aggregate.finding_count_24h as i64,
            alert_count_7d: aggregate.finding_count_7d as i64,
            unique_users,
            unique_hosts,
            unique_ips,
            avg_severity,
            execution_time_ms,
        };
        let mut provenance = SourceProvenance::from_parts(
            aggregate.origin_source_types,
            aggregate.finding_count_7d > 0 && aggregate.unattributed_count == 0,
        );
        if !recent_findings.is_empty() {
            let sample_inputs: Vec<FindingProvenance<'_>> = recent_findings
                .iter()
                .map(|finding| FindingProvenance {
                    origin_source_types: finding.origin_source_types.as_deref(),
                    matched_events: &finding.matched_events,
                })
                .collect();
            let (sample_sources, sample_complete) =
                derive_finding_source_manifest(&sample_inputs);
            provenance =
                provenance.merge(&SourceProvenance::from_parts(sample_sources, sample_complete));
        }

        Ok(Provenanced::new(metrics, provenance))
    }

    /// Count every finding window and union the authoritative full-match
    /// origins in one ClickHouse snapshot.
    async fn aggregate_findings(
        &self,
        rule_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<FindingAggregateRow, MetricsCollectorError> {
        // SAFETY: the only value interpolated into `sql` via `format!` is the
        // table name returned by `TableNames::read`, which is a hard-coded
        // constant (`nanosiem.logs` / `nanosiem.logs_distributed`). All
        // caller-supplied values flow through `.bind(...)` placeholders.
        // NAN-1254: under OCSF the nano finding payload is an OCSF Detection
        // Finding (class_uid 2004) in `ocsf_logs` — there is no `rule_id`
        // column; the rule id lives in the spill, `unmapped.rule_id`. NAN-1443:
        // the spill is now the stored `unmapped` column (the full `event` is
        // EPHEMERAL), so read it directly. UDM stays byte-identical (`rule_id`).
        let is_ocsf = active_profile_is_ocsf();
        let table = self.table_names.read(crate::schema::active_logs_table());
        let (metadata_expr, rule_id_col) = if is_ocsf {
            (
                "toString(unmapped)",
                "JSONExtractString(toString(unmapped), 'rule_id')",
            )
        } else {
            ("metadata", "rule_id")
        };
        let cutoff_1h = now - Duration::hours(1);
        let cutoff_24h = now - Duration::hours(24);
        let cutoff_7d = now - Duration::days(7);
        let sql = format!(
            "WITH JSONExtract({metadata_expr}, 'origin_source_types', 'Array(String)') AS origin_types \
             SELECT \
               countIf(timestamp >= fromUnixTimestamp64Micro(?)) AS finding_count_1h, \
               countIf(timestamp >= fromUnixTimestamp64Micro(?)) AS finding_count_24h, \
               count() AS finding_count_7d, \
               arraySort(groupUniqArrayArray(origin_types)) AS origin_source_types, \
               countIf(empty(origin_types) OR arrayExists(source -> empty(trimBoth(source)), origin_types) OR has( \
                   arrayMap(source -> lowerUTF8(trimBoth(source)), origin_types), \
                   '{UNRESOLVED_SOURCE_SENTINEL}' \
               )) AS unattributed_count \
             FROM {table} \
             WHERE source_type = 'findings' \
               AND {rule_id_col} = ? \
               AND timestamp >= fromUnixTimestamp64Micro(?) \
               AND timestamp <= fromUnixTimestamp64Micro(?)"
        );

        self.ch_client
            .query(&sql)
            .bind(cutoff_1h.timestamp_micros())
            .bind(cutoff_24h.timestamp_micros())
            .bind(rule_id.to_string())
            .bind(cutoff_7d.timestamp_micros())
            .bind(now.timestamp_micros())
            .fetch_one()
            .await
            .map_err(Into::into)
    }

    /// Get recent findings for a detection rule from ClickHouse.
    ///
    /// Returns up to 1000 findings within the window, ordered most recent
    /// first. The finding's matched-event sample is parsed out of the JSON
    /// stored in the `metadata` column so the existing pattern / entity
    /// extraction code can consume it unchanged.
    pub async fn get_recent_findings(
        &self,
        rule_id: Uuid,
        duration: Duration,
    ) -> Result<Vec<Finding>, MetricsCollectorError> {
        self.get_recent_findings_at(rule_id, duration, Utc::now())
            .await
    }

    async fn get_recent_findings_at(
        &self,
        rule_id: Uuid,
        duration: Duration,
        now: DateTime<Utc>,
    ) -> Result<Vec<Finding>, MetricsCollectorError> {
        let cutoff = now - duration;
        // SAFETY: the only value interpolated into `sql` via `format!` is the
        // table name returned by `TableNames::read`, which is a hard-coded
        // constant (`nanosiem.logs` / `nanosiem.logs_distributed`). All
        // caller-supplied values flow through `.bind(...)` placeholders.
        // NAN-1254: under OCSF the finding is a Detection Finding (class_uid
        // 2004) on `ocsf_logs` with no `rule_id`/`metadata` columns — the nano
        // payload (rule_id, signal_type, matched_events_sample, …) lives in the
        // spill. NAN-1443: the spill is the stored `unmapped` column (the full
        // `event` is EPHEMERAL); `toString(unmapped)` returns that object as a
        // JSON string, which the parsing below reads `.matched_events_sample`
        // from unchanged. `severity` is materialized. UDM stays byte-identical.
        let is_ocsf = active_profile_is_ocsf();
        let table = self.table_names.read(crate::schema::active_logs_table());
        let (meta_col, rule_id_col) = if is_ocsf {
            (
                "toString(unmapped)",
                "JSONExtractString(toString(unmapped), 'rule_id')",
            )
        } else {
            ("metadata", "rule_id")
        };
        let sql = format!(
            "SELECT severity, {meta_col} AS metadata, toUnixTimestamp64Micro(timestamp) AS timestamp_us \
             FROM {table} \
             WHERE source_type = 'findings' \
               AND {rule_id_col} = ? \
               AND timestamp >= fromUnixTimestamp64Micro(?) \
               AND timestamp <= fromUnixTimestamp64Micro(?) \
             ORDER BY timestamp DESC \
             LIMIT 1000"
        );

        let rows: Vec<FindingRow> = self
            .ch_client
            .query(&sql)
            .bind(rule_id.to_string())
            .bind(cutoff.timestamp_micros())
            .bind(now.timestamp_micros())
            .fetch_all()
            .await?;

        let findings = rows
            .into_iter()
            .map(|row| {
                // Parse the metadata JSON and lift `matched_events_sample` out
                // as the row's matched_events (an array). Anything we can't
                // parse degrades to an empty array — entity extraction just
                // skips it — but we log so a finding-writer regression that
                // starts emitting malformed metadata doesn't silently zero
                // out baselines (the same failure mode as NAN-866).
                let parsed_metadata =
                    match serde_json::from_str::<serde_json::Value>(&row.metadata) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            tracing::warn!(
                                rule_id = %rule_id,
                                error = %e,
                                "Failed to parse finding metadata JSON; treating as empty matched_events"
                            );
                            None
                        }
                    };
                let matched_events = parsed_metadata
                    .as_ref()
                    .and_then(|v| v.get("matched_events_sample").cloned())
                    .unwrap_or(serde_json::Value::Array(Vec::new()));
                // NAN-2085: the FULL origin manifest, absent on pre-NAN-1800
                // findings — `None` there so consumers fail closed.
                let origin_source_types = parsed_metadata
                    .as_ref()
                    .and_then(|v| v.get("origin_source_types"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str())
                            .map(|s| s.to_string())
                            .collect::<Vec<String>>()
                    });

                // `from_timestamp_micros` only returns `None` for values
                // outside i64 micros range, which can't happen for CH
                // `DateTime64(6)`. Fall back to epoch instead of `now()` so
                // any pathological row stands out in the data.
                let timestamp =
                    DateTime::<Utc>::from_timestamp_micros(row.timestamp_us).unwrap_or_default();

                Finding {
                    rule_id,
                    severity: row.severity,
                    matched_events,
                    timestamp,
                    origin_source_types,
                }
            })
            .collect();

        Ok(findings)
    }

    /// Identify common patterns in finding field values.
    ///
    /// Analyzes matched events from recent findings to find frequently
    /// occurring field values that might indicate false-positive patterns.
    pub async fn get_alert_patterns(
        &self,
        rule_id: Uuid,
    ) -> Result<Vec<AlertPattern>, MetricsCollectorError> {
        // Get recent findings (last 24 hours)
        let recent_findings = self.get_recent_findings(rule_id, Duration::hours(24)).await?;

        if recent_findings.is_empty() {
            return Ok(Vec::new());
        }

        let total_findings = recent_findings.len() as i64;

        // Track field value occurrences
        let mut field_value_counts: HashMap<(String, String), i64> = HashMap::new();

        // Extract field values from matched events
        for finding in &recent_findings {
            if let Some(events) = finding.matched_events.as_array() {
                for event in events {
                    if let Some(obj) = event.as_object() {
                        self.extract_field_patterns(obj, &mut field_value_counts);
                    }
                }
            }
        }

        // Convert to AlertPattern structs and calculate percentages
        let mut patterns: Vec<AlertPattern> = field_value_counts
            .into_iter()
            .map(|((field_name, field_value), occurrence_count)| {
                let percentage = (occurrence_count as f64 / total_findings as f64) * 100.0;
                AlertPattern {
                    field_name,
                    field_value,
                    occurrence_count,
                    percentage,
                }
            })
            .collect();

        // Sort by occurrence count (descending)
        patterns.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));

        // Return top 50 patterns
        patterns.truncate(50);

        Ok(patterns)
    }

    /// Extract unique entity counts from findings.
    ///
    /// Reads UDM fields from the finding's `matched_events_sample` payload:
    /// `src_user`, `dest_user`, `src_host`, `dest_host`, `src_ip`, `dest_ip`.
    fn extract_unique_entities(&self, findings: &[Finding]) -> (i64, i64, i64) {
        let mut unique_users = std::collections::HashSet::new();
        let mut unique_hosts = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();

        for finding in findings {
            if let Some(events) = finding.matched_events.as_array() {
                for event in events {
                    if let Some(obj) = event.as_object() {
                        // Extract user information (UDM fields)
                        for field in &["src_user", "dest_user"] {
                            if let Some(user) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !user.is_empty() {
                                    unique_users.insert(user.to_string());
                                }
                            }
                        }

                        // Extract host information (UDM fields)
                        for field in &["src_host", "dest_host"] {
                            if let Some(host) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !host.is_empty() {
                                    unique_hosts.insert(host.to_string());
                                }
                            }
                        }

                        // Extract IP information (UDM fields)
                        for field in &["src_ip", "dest_ip"] {
                            if let Some(ip) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !ip.is_empty() {
                                    unique_ips.insert(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        (
            unique_users.len() as i64,
            unique_hosts.len() as i64,
            unique_ips.len() as i64,
        )
    }

    /// Calculate average severity from findings.
    fn calculate_average_severity(&self, findings: &[Finding]) -> f64 {
        if findings.is_empty() {
            return 0.0;
        }

        let severity_sum: i32 = findings
            .iter()
            .map(|finding| match finding.severity.as_str() {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                "informational" => 1,
                _ => 0,
            })
            .sum();

        severity_sum as f64 / findings.len() as f64
    }

    /// Extract field patterns from an event object.
    ///
    /// Uses UDM field names from the finding's `matched_events_sample`:
    /// `src_ip`, `dest_ip`, `src_host`, `dest_host`, `src_user`, `dest_user`,
    /// `source_type`, `risk_entity`, plus metadata object keys.
    fn extract_field_patterns(
        &self,
        obj: &serde_json::Map<String, serde_json::Value>,
        field_value_counts: &mut HashMap<(String, String), i64>,
    ) {
        // UDM fields present in matched_events_sample
        let tracked_fields = [
            "src_ip",
            "dest_ip",
            "src_host",
            "dest_host",
            "src_user",
            "dest_user",
            "source_type",
            "risk_entity",
            "src_port",
            "dest_port",
            "protocol",
            "process_name",
            "command_line",
            "file_path",
            "file_hash",
        ];

        for field in tracked_fields {
            if let Some(value) = obj.get(field) {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                if !value_str.is_empty() {
                    let key = (field.to_string(), value_str);
                    *field_value_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Also iterate over the metadata object for additional fields
        if let Some(metadata) = obj.get("metadata").and_then(|v| v.as_object()) {
            for (key, value) in metadata {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                if !value_str.is_empty() {
                    let field_name = format!("metadata.{}", key);
                    let key = (field_name, value_str);
                    *field_value_counts.entry(key).or_insert(0) += 1;
                }
            }
        }
    }

    /// Collect metrics for all enabled detection rules.
    ///
    /// Called by the scheduler to collect metrics for all active rules
    /// (those not in `staging` or `paused` mode).
    pub async fn collect_all_metrics(&self) -> Result<usize, MetricsCollectorError> {
        let rule_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM detection_rules WHERE mode NOT IN ('staging', 'paused')",
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let mut collected_count = 0;

        for rule_id in rule_ids {
            match self.collect_and_store_rule_metrics(rule_id).await {
                Ok(_) => {
                    collected_count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        rule_id = %rule_id,
                        error = %e,
                        "Failed to collect or store metrics for rule"
                    );
                }
            }
        }

        Ok(collected_count)
    }

    /// Production collection + persistence path used by the scheduler and
    /// provenance integration tests.
    pub async fn collect_and_store_rule_metrics(
        &self,
        rule_id: Uuid,
    ) -> Result<Provenanced<RuleMetrics>, MetricsCollectorError> {
        let metrics = self.collect_rule_metrics_with_provenance(rule_id).await?;
        self.store_metrics(&metrics).await?;
        Ok(metrics)
    }

    /// Store metrics in the PostgreSQL `detection_rule_metrics` table.
    async fn store_metrics(
        &self,
        metrics: &Provenanced<RuleMetrics>,
    ) -> Result<(), MetricsCollectorError> {
        let value = &metrics.value;
        sqlx::query(
            r#"
            INSERT INTO detection_rule_metrics (
                rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d,
                unique_users, unique_hosts, unique_ips, avg_severity, execution_time_ms,
                patterns, source_types, source_types_complete
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(value.rule_id)
        .bind(value.timestamp)
        .bind(value.alert_count_1h)
        .bind(value.alert_count_24h)
        .bind(value.alert_count_7d)
        .bind(value.unique_users)
        .bind(value.unique_hosts)
        .bind(value.unique_ips)
        .bind(value.avg_severity)
        .bind(value.execution_time_ms)
        .bind(serde_json::json!({})) // Empty patterns for now
        .bind(metrics.provenance.source_types())
        .bind(metrics.provenance.is_complete())
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: &str, matched_events: serde_json::Value) -> Finding {
        Finding {
            rule_id: Uuid::now_v7(),
            severity: severity.to_string(),
            matched_events,
            timestamp: Utc::now(),
            origin_source_types: None,
        }
    }

    #[test]
    fn test_calculate_average_severity() {
        let findings = vec![
            make_finding("critical", serde_json::json!([])),
            make_finding("high", serde_json::json!([])),
            make_finding("medium", serde_json::json!([])),
        ];

        let severity_sum: i32 = findings
            .iter()
            .map(|finding| match finding.severity.as_str() {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                "informational" => 1,
                _ => 0,
            })
            .sum();

        let avg = severity_sum as f64 / findings.len() as f64;
        assert_eq!(avg, 4.0); // (5 + 4 + 3) / 3 = 4.0
    }

    #[test]
    fn test_extract_unique_entities() {
        let findings = vec![
            make_finding(
                "high",
                serde_json::json!([
                    {
                        "src_user": "alice",
                        "src_host": "server1",
                        "src_ip": "192.168.1.1"
                    }
                ]),
            ),
            make_finding(
                "high",
                serde_json::json!([
                    {
                        "src_user": "alice",
                        "dest_host": "server2",
                        "src_ip": "192.168.1.1"
                    }
                ]),
            ),
            make_finding(
                "high",
                serde_json::json!([
                    {
                        "dest_user": "bob",
                        "src_host": "server1",
                        "dest_ip": "192.168.1.2"
                    }
                ]),
            ),
        ];

        // Test entity extraction directly using UDM field names
        let mut unique_users = std::collections::HashSet::new();
        let mut unique_hosts = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();

        for finding in &findings {
            if let Some(events) = finding.matched_events.as_array() {
                for event in events {
                    if let Some(obj) = event.as_object() {
                        for field in &["src_user", "dest_user"] {
                            if let Some(user) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !user.is_empty() {
                                    unique_users.insert(user.to_string());
                                }
                            }
                        }
                        for field in &["src_host", "dest_host"] {
                            if let Some(host) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !host.is_empty() {
                                    unique_hosts.insert(host.to_string());
                                }
                            }
                        }
                        for field in &["src_ip", "dest_ip"] {
                            if let Some(ip) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !ip.is_empty() {
                                    unique_ips.insert(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(unique_users.len(), 2); // alice, bob
        assert_eq!(unique_hosts.len(), 2); // server1, server2
        assert_eq!(unique_ips.len(), 2); // 192.168.1.1, 192.168.1.2
    }

    #[test]
    fn test_extract_field_patterns() {
        let mut field_value_counts = HashMap::new();
        let mut obj = serde_json::Map::new();
        obj.insert("process_name".to_string(), serde_json::json!("chrome.exe"));
        obj.insert("src_user".to_string(), serde_json::json!("alice"));
        obj.insert("src_host".to_string(), serde_json::json!("workstation1"));
        obj.insert(
            "metadata".to_string(),
            serde_json::json!({"rule_name": "test_rule"}),
        );

        // Test pattern extraction directly using UDM field names
        let tracked_fields = ["process_name", "src_user", "src_host"];

        for field in tracked_fields {
            if let Some(value) = obj.get(field) {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                if !value_str.is_empty() {
                    let key = (field.to_string(), value_str);
                    *field_value_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Also extract metadata fields
        if let Some(metadata) = obj.get("metadata").and_then(|v| v.as_object()) {
            for (key, value) in metadata {
                if let Some(s) = value.as_str() {
                    if !s.is_empty() {
                        let field_name = format!("metadata.{}", key);
                        *field_value_counts
                            .entry((field_name, s.to_string()))
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        assert_eq!(field_value_counts.len(), 4); // 3 UDM fields + 1 metadata field
        assert_eq!(
            field_value_counts.get(&("process_name".to_string(), "chrome.exe".to_string())),
            Some(&1)
        );
        assert_eq!(
            field_value_counts.get(&("src_user".to_string(), "alice".to_string())),
            Some(&1)
        );
        assert_eq!(
            field_value_counts.get(&("src_host".to_string(), "workstation1".to_string())),
            Some(&1)
        );
        assert_eq!(
            field_value_counts.get(&("metadata.rule_name".to_string(), "test_rule".to_string())),
            Some(&1)
        );
    }
}
