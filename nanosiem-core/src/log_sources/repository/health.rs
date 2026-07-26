// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health metrics and ClickHouse-backed statistics for log sources

use clickhouse::Client as ClickHouseClient;
use uuid::Uuid;

use super::super::types::{
    HealthStatus, HistoryPoint, IngestionHistoryPoint, IngestionTrend, ListParams, LogSource,
    LogSourceHealth, LogSourceHealthSummary,
};
use super::helpers::parse_json_i64;
use super::{LogSourceRepository, LogSourceRepositoryError};
use crate::auth::ScopeSet;
use crate::search::service::source_scope_sql_predicate;

/// The detail page is a live-health surface. Its visible metrics are all 24h
/// or shorter, so a longer raw-table scan only adds latency and read load.
const DETAIL_HEALTH_WINDOW_HOURS: i64 = 24;

/// NAN-2059: render the caller's deny-set as an `AND`-able predicate over the
/// `source_type` column of whatever logs/rollup table is being read.
///
/// Returns an empty string for an unrestricted caller, so the emitted SQL stays
/// byte-identical to the pre-scoping form. Uses the ONE canonical builder
/// (NAN-1801) rather than a re-derived copy, so this gate keeps the same
/// lowercased shape as the nPL injector.
fn scope_and(scope: &ScopeSet) -> String {
    source_scope_sql_predicate("source_type", scope.deny_set())
        .map(|p| format!(" AND {p}"))
        .unwrap_or_default()
}

/// Scope suffix for the profile-aware source rollup. The display key may differ
/// from the raw authorization key under OCSF, so restricted reads use only the
/// preserved raw key and reject rows with incomplete provenance.
fn rollup_scope_and(scope: &ScopeSet) -> String {
    if !scope.is_restricted() {
        return String::new();
    }
    let predicate = source_scope_sql_predicate("scope_source_type", scope.deny_set())
        .expect("a restricted ScopeSet always renders a predicate");
    format!(" AND scope_source_type_complete = 1 AND {predicate}")
}

/// Derive parser rates from the pre-sampling production counters.
fn parse_health_rates(attempts: i64, parse_errors_24h: i64) -> (f64, Option<f64>) {
    let error_rate = if attempts > 0 {
        (parse_errors_24h as f64 / attempts as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let success_rate = (attempts > 0).then_some(1.0 - error_rate);
    (error_rate, success_rate)
}

/// Is `s` usable as a bare ClickHouse column identifier in generated SQL?
///
/// NAN-2055 (codex round 9) introduced this here; NAN-2158 promoted the rule
/// itself to [`crate::sql_hygiene::is_safe_sql_identifier`] so the whole
/// codebase shares ONE definition of "safe identifier" — a local copy is how
/// this class kept recurring. This alias stays because the sink below and its
/// regression tests read better with the column-specific name.
///
/// Mirrors `log_telemetry::repository::is_safe_source_type`, which applies the
/// same defense to source-type VALUES.
fn is_safe_column_identifier(s: &str) -> bool {
    crate::sql_hygiene::is_safe_sql_identifier(s)
}

/// The OCSF rollup's display key, replicated for the raw-table fallback.
///
/// `ocsf_logs_per_source_5m_mv` groups direct-writer events (raw `source_type`
/// left at its `'unknown'` DEFAULT) under `metadata.product.name`, so
/// source-health shows a real product instead of one opaque bucket. When a
/// restricted OCSF caller is diverted onto the raw table, the SAME expression
/// has to drive display/grouping — otherwise those sources collapse into
/// `unknown` and effectively vanish from ingestion history.
///
/// Authorization does NOT use this: the deny-set is applied to the raw
/// `source_type` column, which is what canonical search filters.
///
/// This remains only for raw reads whose window exceeds the rollup's seven-day
/// retention. In-retention OCSF reads use the durable profile-aware rollup.
const OCSF_DISPLAY_KEY_EXPR: &str = "if(source_type != '' AND source_type != 'unknown', lower(source_type), if(`metadata.product.name` != '', lower(`metadata.product.name`), 'unknown'))";

impl LogSourceRepository {
    /// Get health summary for all log sources
    pub async fn get_all_health_summary(
        &self,
        scope: &ScopeSet,
    ) -> Result<Vec<(Uuid, LogSourceHealthSummary)>, LogSourceRepositoryError> {
        // Get all log sources
        let log_sources = self.list(&ListParams::default()).await?;

        // Query ClickHouse for actual metrics if available
        if let Some(ref ch_client) = self.ch_client {
            return self
                .get_all_health_summary_clickhouse(ch_client, &log_sources, scope)
                .await;
        }

        // Fallback: basic health based on enabled/deployed status
        Ok(log_sources
            .iter()
            .map(|ls| {
                let status = if !ls.enabled {
                    HealthStatus::Disabled
                } else if !ls.deployed {
                    HealthStatus::NoData
                } else {
                    HealthStatus::Healthy
                };

                (
                    ls.id,
                    LogSourceHealthSummary {
                        total_events: 0,
                        events_last_24h: 0,
                        last_event_at: None,
                        health_status: status,
                    },
                )
            })
            .collect())
    }

    /// Get health summary for all log sources from ClickHouse.
    ///
    /// Reads from the `logs_per_source_5m` rollup (NAN-734) — replaces the
    /// previous un-scoped `count(*) * 10 SAMPLE 0.1 FROM logs` over the
    /// 90-day TTL window with a single tiny aggregated read against the
    /// 7-day rollup. Numbers are now exact rather than sampled estimates.
    ///
    /// **`total_events` semantics change:** the rollup retains 7 days, so
    /// what's reported here is the 7-day sum, not a 90-day "ever-seen"
    /// total. The badge logic uses `events_last_24h` directly to decide
    /// `NoData` vs `Stale` vs `Healthy`, which is more accurate than the
    /// previous `total_events == 0` check (a source dormant for >24h used
    /// to show as `Healthy`; now correctly shows `NoData`).
    async fn get_all_health_summary_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        log_sources: &[LogSource],
        scope: &ScopeSet,
    ) -> Result<Vec<(Uuid, LogSourceHealthSummary)>, LogSourceRepositoryError> {
        let rollup = self.table_names.read("logs_per_source_5m_v2");
        let profile = crate::schema::active_log_telemetry_profile();
        // One scoped query against the rollup. The rollup MV writes
        // lowercased source_type, so reads compare against lowercased names
        // without runtime `lower()` overhead.
        //
        // NAN-2059: a denied source simply produces no row in `stats_map`, so
        // the loop below reports it as 0 events / `NoData` — identical to an
        // allowed source that has not ingested anything.
        //
        let sql = format!(
            "SELECT \
                source_type AS source_type_lc, \
                sum(events) AS total_events, \
                sumIf(events, bucket_start >= now() - INTERVAL 24 HOUR) AS events_last_24h, \
                sumIf(events, bucket_start >= now() - INTERVAL 1 HOUR) AS events_last_hour, \
                max(last_event_at) AS last_event_at \
             FROM {} \
             WHERE bucket_start >= now() - INTERVAL 7 DAY \
               AND schema_profile = '{}'{} \
             GROUP BY source_type",
            rollup,
            profile,
            rollup_scope_and(scope)
        );

        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;

        // Parse results into a map
        let mut stats_map: std::collections::HashMap<
            String,
            (i64, i64, i64, Option<chrono::DateTime<chrono::Utc>>),
        > = std::collections::HashMap::new();

        for line in response_str.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let source_type = json
                    .get("source_type_lc")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let total = parse_json_i64(&json, "total_events");
                let last_24h = parse_json_i64(&json, "events_last_24h");
                let last_hour = parse_json_i64(&json, "events_last_hour");
                let last_event = json
                    .get("last_event_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                            .or_else(|_| {
                                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                            })
                            .ok()
                    })
                    .map(|dt| dt.and_utc());

                stats_map.insert(source_type, (total, last_24h, last_hour, last_event));
            }
        }

        // Build results for all log sources. Health badge now derives from
        // events_last_24h instead of total_events — see the function-level
        // doc comment for the contract change.
        let mut results = Vec::new();
        for ls in log_sources {
            let source_key = ls.source_type.to_lowercase();
            let (total_events, events_last_24h, events_last_hour, last_event_at) = stats_map
                .get(&source_key)
                .cloned()
                .unwrap_or((0, 0, 0, None));

            let health_status = if !ls.enabled {
                HealthStatus::Disabled
            } else if !ls.deployed {
                HealthStatus::NoData
            } else if ls.validation_error.is_some() {
                HealthStatus::Error
            } else if events_last_24h == 0 {
                HealthStatus::NoData
            } else if events_last_hour == 0 {
                HealthStatus::Stale
            } else {
                HealthStatus::Healthy
            };

            results.push((
                ls.id,
                LogSourceHealthSummary {
                    total_events,
                    events_last_24h,
                    last_event_at,
                    health_status,
                },
            ));
        }

        Ok(results)
    }

    /// Get detailed health metrics for a specific log source
    pub async fn get_health(
        &self,
        id: Uuid,
        scope: &ScopeSet,
    ) -> Result<LogSourceHealth, LogSourceRepositoryError> {
        let log_source = self.find_by_id(id).await?;

        // Query ClickHouse for actual metrics if available
        if let Some(ref ch_client) = self.ch_client {
            return self
                .get_health_clickhouse(ch_client, &log_source, scope)
                .await;
        }

        // Fallback: basic health based on enabled/deployed status
        let health_status = if !log_source.enabled {
            HealthStatus::Disabled
        } else if !log_source.deployed {
            HealthStatus::NoData
        } else if log_source.validation_error.is_some() {
            HealthStatus::Error
        } else {
            HealthStatus::Healthy
        };

        Ok(LogSourceHealth {
            log_source_id: log_source.id,
            log_source_name: log_source.name,
            total_events: 0,
            events_last_24h: 0,
            events_last_hour: 0,
            avg_events_per_hour: 0.0,
            last_event_at: None,
            first_event_at: None,
            data_freshness_hours: None,
            ingestion_rate_trend: IngestionTrend::Unknown,
            health_status,
            total_size_bytes: 0,
            avg_event_size_bytes: 0.0,
            error_rate_24h: 0.0,
            parse_errors_24h: 0,
            parse_attempts_24h: 0,
            parse_success_rate_24h: None,
        })
    }

    /// Get health metrics from ClickHouse
    async fn get_health_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        log_source: &LogSource,
        scope: &ScopeSet,
    ) -> Result<LogSourceHealth, LogSourceRepositoryError> {
        let logs_table = crate::schema::active_logs_table();
        let logs_read = self.table_names.read_bare(logs_table);
        let rollup = self.table_names.read("logs_per_source_5m_v2");
        let sql = Self::build_detail_health_query(
            log_source,
            scope,
            logs_table,
            crate::schema::active_log_telemetry_profile(),
            &logs_read,
            &rollup,
        );

        // Execute query and parse results as JSON
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;

        let (
            total_events,
            events_last_24h,
            events_last_hour,
            last_event_at,
            first_event_at,
            total_size_bytes,
        ) = if let Some(line) = response_str.lines().next() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let total = parse_json_i64(&json, "total_events");
                let last_24h = parse_json_i64(&json, "events_last_24h");
                let last_hour = parse_json_i64(&json, "events_last_hour");
                let size_bytes = parse_json_i64(&json, "total_size_bytes");

                let last_event = json
                    .get("last_event_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok()
                    })
                    .map(|dt| dt.and_utc());

                let first_event = json
                    .get("first_event_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok()
                    })
                    .map(|dt| dt.and_utc());

                (
                    total,
                    last_24h,
                    last_hour,
                    last_event,
                    first_event,
                    size_bytes,
                )
            } else {
                (0, 0, 0, None, None, 0)
            }
        } else {
            (0, 0, 0, None, None, 0)
        };

        // Determine health status based on actual data
        let health_status = if !log_source.enabled {
            HealthStatus::Disabled
        } else if !log_source.deployed {
            HealthStatus::NoData
        } else if log_source.validation_error.is_some() {
            HealthStatus::Error
        } else if total_events == 0 {
            HealthStatus::NoData
        } else if events_last_hour == 0 && events_last_24h > 0 {
            HealthStatus::Stale
        } else {
            HealthStatus::Healthy
        };

        // Calculate data freshness
        let data_freshness_hours = last_event_at.map(|t| {
            let now = chrono::Utc::now();
            let diff = now.signed_duration_since(t);
            diff.num_minutes() as f64 / 60.0
        });

        // Calculate average events per hour
        let avg_events_per_hour = if let (Some(first), Some(last)) = (first_event_at, last_event_at)
        {
            let hours = last.signed_duration_since(first).num_hours().max(1) as f64;
            total_events as f64 / hours
        } else {
            0.0
        };

        // Determine trend
        let ingestion_rate_trend = if events_last_hour == 0 && events_last_24h == 0 {
            IngestionTrend::Unknown
        } else if (events_last_hour as f64) > (events_last_24h as f64 / 24.0) * 1.2 {
            IngestionTrend::Increasing
        } else if (events_last_hour as f64) < (events_last_24h as f64 / 24.0) * 0.8 {
            IngestionTrend::Decreasing
        } else {
            IngestionTrend::Stable
        };

        // Calculate average event size
        let avg_event_size_bytes = if total_events > 0 {
            total_size_bytes as f64 / total_events as f64
        } else {
            0.0
        };

        // NAN-2164: static VRL validation only proves that the program compiles.
        // Production runtime failures are preserved by the generated Vector
        // parser under metadata.parse_failure / metadata.parse_error and tagged
        // with the immutable parser UUID. A narrow Vector branch counts every
        // output before optional sampling; the Null-engine ClickHouse ingress
        // retains only five-minute aggregates.
        let (parse_attempts_24h, parse_errors_24h) = self
            .get_parse_health_counts_clickhouse(ch_client, log_source, scope)
            .await?;
        let (error_rate_24h, parse_success_rate_24h) =
            parse_health_rates(parse_attempts_24h, parse_errors_24h);

        Ok(LogSourceHealth {
            log_source_id: log_source.id,
            log_source_name: log_source.name.clone(),
            total_events,
            events_last_24h,
            events_last_hour,
            avg_events_per_hour,
            last_event_at,
            first_event_at,
            data_freshness_hours,
            ingestion_rate_trend,
            health_status,
            total_size_bytes,
            avg_event_size_bytes,
            error_rate_24h,
            parse_errors_24h,
            parse_attempts_24h,
            parse_success_rate_24h,
        })
    }

    /// Build the bounded event-health query used by the detail page.
    ///
    /// Most log sources match on `source_type`, which the five-minute telemetry
    /// rollup carries directly. Matchers on arbitrary event columns cannot be
    /// answered by that rollup, and a restricted OCSF caller cannot safely use
    /// its re-keyed/shared source dimension. Those exceptional cases retain an
    /// exact raw-table fallback, but it is limited to the same 24-hour window
    /// shown in the UI and protected by a hard execution limit.
    fn build_detail_health_query(
        log_source: &LogSource,
        scope: &ScopeSet,
        logs_table: &str,
        rollup_profile: &str,
        logs_read: &str,
        rollup: &str,
    ) -> String {
        if let Some(source_filter) = Self::rollup_log_source_where_clause(log_source) {
            return format!(
                "SELECT \
                    sum(events) AS total_events, \
                    sum(events) AS events_last_24h, \
                    sumIf(events, bucket_start >= now() - INTERVAL 1 HOUR) AS events_last_hour, \
                    max(last_event_at) AS last_event_at, \
                    min(first_event_at) AS first_event_at, \
                    sum(bytes + events * (length(source_type) + 100)) AS total_size_bytes \
                 FROM {rollup} \
                 WHERE bucket_start >= now() - INTERVAL {DETAIL_HEALTH_WINDOW_HOURS} HOUR \
                   AND schema_profile = '{rollup_profile}' \
                   AND ({source_filter}){scope_predicate} \
                 SETTINGS max_execution_time = 5, max_threads = 2",
                scope_predicate = rollup_scope_and(scope),
            );
        }

        // NAN-1241/1443: under OCSF the arriving `event` JSON is ephemeral, but
        // its original length is retained in `event_bytes`. UDM keeps the
        // message/metadata estimate. NAN-1728 routes `logs_read` through the
        // distributed wrapper in cluster mode.
        let size_expr = if logs_table == "ocsf_logs" {
            "event_bytes + length(source_type) + 100"
        } else {
            "length(message) + length(metadata) + length(source_type) + 100"
        };
        let where_clause = Self::scoped_log_source_where_clause(log_source, scope);
        format!(
            "SELECT \
                count(*) AS total_events, \
                count(*) AS events_last_24h, \
                countIf(timestamp >= now() - INTERVAL 1 HOUR) AS events_last_hour, \
                max(timestamp) AS last_event_at, \
                min(timestamp) AS first_event_at, \
                sum({size_expr}) AS total_size_bytes \
             FROM {logs_read} \
             WHERE timestamp >= now() - INTERVAL {DETAIL_HEALTH_WINDOW_HOURS} HOUR \
               AND ({where_clause}) \
             SETTINGS max_execution_time = 5, max_threads = 2"
        )
    }

    /// Return the configured match clause when it can be evaluated against the
    /// rollup's deliberately small schema.
    fn rollup_log_source_where_clause(log_source: &LogSource) -> Option<String> {
        let has_explicit_match = log_source
            .match_values
            .as_ref()
            .is_some_and(|values| !values.is_empty())
            || log_source
                .match_pattern
                .as_ref()
                .is_some_and(|pattern| !pattern.is_empty());
        let match_field = log_source
            .match_field
            .as_deref()
            .filter(|field| !field.is_empty())
            .filter(|field| is_safe_column_identifier(field))
            .unwrap_or("source_type");

        if has_explicit_match && match_field != "source_type" {
            None
        } else {
            Some(Self::build_log_source_where_clause(log_source))
        }
    }

    /// Count production events and runtime failures for one deployed parser
    /// over a fixed 24h window. The parser UUID is assigned after parser-authored
    /// VRL executes, so neither an event payload nor custom parser code can spoof
    /// attribution.
    async fn get_parse_health_counts_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        log_source: &LogSource,
        scope: &ScopeSet,
    ) -> Result<(i64, i64), LogSourceRepositoryError> {
        let rollup = self.table_names.read_bare("parser_health_5m");
        let sql = Self::build_parse_health_query(log_source, scope, &rollup);
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => {
                    return Err(LogSourceRepositoryError::ClickHouseError(error.to_string()))
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;
        let counts = response_str
            .lines()
            .next()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .map(|json| {
                (
                    parse_json_i64(&json, "parser_events_24h"),
                    parse_json_i64(&json, "parse_errors_24h"),
                )
            })
            .unwrap_or((0, 0));
        Ok(counts)
    }

    /// Pure SQL builder for production parse health. Keeping this separate makes
    /// the time bound, parser attribution, and source-scope gate unit-testable
    /// without a live ClickHouse instance.
    fn build_parse_health_query(log_source: &LogSource, scope: &ScopeSet, rollup: &str) -> String {
        // When source_type is the configured match key, retain that predicate
        // for primary-key pruning. For arbitrary match fields the immutable
        // parser UUID remains authoritative and avoids assuming the rollup's
        // deliberately small schema has an OCSF-only nested column.
        let source_fast_path = match (
            log_source.match_field.as_deref(),
            log_source.match_values.as_ref(),
        ) {
            (None | Some("") | Some("source_type"), Some(values)) if !values.is_empty() => {
                format!(" AND {}", Self::build_log_source_where_clause(log_source))
            }
            _ => String::new(),
        };
        format!(
            "SELECT sum(events) AS parser_events_24h, \
                    sum(parse_errors) AS parse_errors_24h \
             FROM {rollup} \
             WHERE bucket_start >= now() - INTERVAL 24 HOUR \
               AND parser_id = '{parser_id}'\
             {source_fast_path}{scope_predicate} \
             SETTINGS max_execution_time = 5, max_threads = 2",
            parser_id = log_source.id,
            scope_predicate = scope_and(scope),
        )
    }

    /// The log source's own match clause AND the caller's source-scope gate.
    ///
    /// NAN-2059: the deny-set is ANDed onto the match clause rather than
    /// pre-filtering by log-source name, because a log source can match on an
    /// arbitrary `match_field` / `match_pattern` (not just `source_type = name`)
    /// — only a predicate on the `source_type` COLUMN is correct in every case.
    /// An unrestricted caller appends nothing, leaving the SQL byte-identical.
    fn scoped_log_source_where_clause(log_source: &LogSource, scope: &ScopeSet) -> String {
        format!(
            "{}{}",
            Self::build_log_source_where_clause(log_source),
            scope_and(scope)
        )
    }

    /// Build WHERE clause to match logs to a log source
    ///
    /// Priority:
    /// 1. Use `match_values` if set (exact match on match_field column)
    /// 2. Use `match_pattern` if set (regex match on match_field column)
    /// 3. Fall back to matching source_type = log_source.name
    fn build_log_source_where_clause(log_source: &LogSource) -> String {
        // Determine which column to match against.
        //
        // NAN-2055 (codex round 9): `match_field` is a caller-supplied COLUMN
        // IDENTIFIER, and it is persisted without validation by
        // `NewLogSource`/`UpdateLogSource`. The match VALUES below are escaped;
        // the identifier never was, and it is interpolated verbatim. A caller
        // with `log_sources:edit` could therefore store
        //     source_type) = 'audit' --
        // which closes our `lower(` early and comments out the REST OF THE LINE
        // — including the source-scope predicate this batch appends — turning
        // `/api/log-sources/{id}/health` back into an unscoped read of the audit
        // feed. The injection predates this change; appending a security
        // predicate to the same line is what made it exploitable as a scope
        // bypass rather than only a malformed query.
        //
        // Validated HERE, at the sink, rather than only on write: that also
        // covers rows already persisted with a hostile value, which a
        // write-side fix alone would leave live.
        let field = log_source
            .match_field
            .as_deref()
            .filter(|f| !f.is_empty())
            .filter(|f| {
                let ok = is_safe_column_identifier(f);
                if !ok {
                    tracing::warn!(
                        log_source_id = %log_source.id,
                        match_field = %f,
                        "log source has a non-identifier match_field; \
                         falling back to source_type for the health query"
                    );
                }
                ok
            })
            .unwrap_or("source_type");

        // If match_values is set, use case-insensitive IN clause
        if let Some(ref values) = log_source.match_values {
            if !values.is_empty() {
                let escaped: Vec<String> = values
                    .iter()
                    .map(|v| {
                        format!(
                            "'{}'",
                            crate::sql_hygiene::escape_sql_string(v.to_lowercase())
                        )
                    })
                    .collect();
                return format!("lower({}) IN ({})", field, escaped.join(", "));
            }
        }

        // If match_pattern is set, use case-insensitive regex
        if let Some(ref pattern) = log_source.match_pattern {
            if !pattern.is_empty() {
                let escaped_pattern = pattern.replace('\\', "\\\\").replace('\'', "''");
                return format!("match(lower({}), lower('{}'))", field, escaped_pattern);
            }
        }

        // Default: case-insensitive match by log source name
        format!(
            "lower(source_type) = lower('{}')",
            crate::sql_hygiene::escape_sql_string(&log_source.name)
        )
    }

    /// Get ingestion history for charting
    pub async fn get_ingestion_history(
        &self,
        id: Uuid,
        _hours: i64,
    ) -> Result<Vec<HistoryPoint>, LogSourceRepositoryError> {
        // Verify log source exists
        self.find_by_id(id).await?;

        // In production, query ClickHouse for actual history
        // For now, return empty history
        Ok(Vec::new())
    }

    /// Get ingestion history for all log sources (for area chart)
    pub async fn get_all_ingestion_history(
        &self,
        hours: i64,
        scope: &ScopeSet,
    ) -> Result<Vec<IngestionHistoryPoint>, LogSourceRepositoryError> {
        // Get all deployed log sources to build the WHERE clause
        let log_sources = self.list_deployed().await?;

        if log_sources.is_empty() {
            return Ok(Vec::new());
        }

        let Some(ref ch_client) = self.ch_client else {
            return Ok(Vec::new());
        };

        // Build a combined WHERE clause for all log sources
        let mut all_source_types: Vec<String> = Vec::new();
        for ls in &log_sources {
            if let Some(ref values) = ls.match_values {
                for v in values {
                    all_source_types.push(v.clone());
                }
            } else {
                all_source_types.push(ls.name.clone());
            }
        }

        if all_source_types.is_empty() {
            return Ok(Vec::new());
        }

        let escaped: Vec<String> = all_source_types
            .iter()
            .map(|v| {
                format!(
                    "'{}'",
                    crate::sql_hygiene::escape_sql_string(v.to_lowercase())
                )
            })
            .collect();
        let in_clause = escaped.join(", ");

        // Read from the rollup (NAN-734) when the requested window fits in
        // its 7-day retention; otherwise fall back to scanning raw `logs`.
        // Rollup path uses sum(events) over 5-min buckets re-grouped by hour
        // — equivalent to the previous count() but reads ~7 buckets/hour
        // instead of every row in the 90d TTL window.
        // NAN-2059: the caller's deny-set is ANDed onto BOTH branches — the
        // rollup read and the raw-logs fallback — so a denied source cannot
        // reappear in the series just because the requested window exceeded the
        // rollup's retention and tipped the query onto the other path.
        let raw_scope_sql = scope_and(scope);
        let rollup_retention_hours: i64 = 7 * 24;
        let sql = if hours <= rollup_retention_hours {
            let rollup = self.table_names.read("logs_per_source_5m_v2");
            // Aliased to `display_source` to match the raw branch below, so one
            // parser handles both. (Here the rollup key IS the display key, and
            // there is no shadowing hazard — but keeping the two branches
            // symmetrical is what stops the next edit from reintroducing one.)
            format!(
                "SELECT \
                    source_type AS display_source, \
                    toStartOfHour(bucket_start) AS hour, \
                    sum(events) AS count \
                 FROM {} \
                 WHERE bucket_start >= now() - INTERVAL {} HOUR \
                   AND schema_profile = '{}' \
                   AND source_type IN ({}){} \
                 GROUP BY display_source, hour \
                 ORDER BY hour ASC",
                rollup,
                hours,
                crate::schema::active_log_telemetry_profile(),
                in_clause,
                rollup_scope_and(scope)
            )
        } else {
            // NAN-1728 (H5): route the raw-logs fallback through the
            // `_distributed` wrapper on a cluster so the history covers all
            // shards; bare table name on single-node (byte-identical).
            //
            // NAN-2055 (codex round 1): resolve the ACTIVE events table rather
            // than hardcoding `logs`. Under OCSF this branch was querying a
            // table the deployment does not write to, so the >7-day fallback
            // silently returned an empty series.
            let active = crate::schema::active_logs_table();
            let logs_table = self.table_names.read_bare(active);

            // NAN-2055 (codex round 6): SEPARATE the two keys.
            //
            // Authorization filters the RAW `source_type` — the column
            // canonical search filters and the deny-set is defined over.
            // Display/grouping uses the MV's key, so an OCSF direct-writer
            // source still appears under its product name instead of collapsing
            // into `unknown`.
            //
            // Conflating them is wrong in BOTH directions, and codex caught one
            // of each: filtering the display key drops rows whose raw type the
            // caller may see (round 6), while grouping by the raw key makes
            // those same sources vanish from the chart (round 4).
            let display_key = if active == "ocsf_logs" {
                OCSF_DISPLAY_KEY_EXPR
            } else {
                "lower(source_type)"
            };
            // NAN-2055 (codex round 7): the display expression is aliased to
            // `display_source`, NOT to `source_type`.
            //
            // ClickHouse aliases are visible throughout the query, and with the
            // default `prefer_column_name_to_alias=0` an alias BEATS a
            // same-named base column in the WHERE clause. Aliasing this
            // `AS source_type` therefore silently rebound the authorization
            // predicate — `lower(source_type) != 'unknown'` would have filtered
            // the DISPLAY key, so a row with raw `unknown` shown as product
            // `foo` sailed straight through, re-creating the exact leak the raw
            // branch exists to close.
            //
            // Keeping the alias distinct means `source_type` inside
            // `{scope_sql}` can only ever mean the raw column.
            format!(
                r#"
                SELECT
                    {display_key} AS display_source,
                    toStartOfHour(timestamp) as hour,
                    count(*) as count
                FROM {logs_table}
                WHERE timestamp >= now() - INTERVAL {} HOUR
                  AND {display_key} IN ({}){}
                GROUP BY display_source, hour
                ORDER BY hour ASC
                "#,
                hours, in_clause, raw_scope_sql
            )
        };

        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;

        let mut results = Vec::new();
        for line in response_str.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                // Both branches alias the display key to `display_source`
                // (NAN-2055 codex round 7) so `source_type` in the SQL can only
                // mean the raw, authorization-bearing column.
                let source_type = json
                    .get("display_source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let hour = json
                    .get("hour")
                    .and_then(|v| v.as_str())
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()
                    })
                    .map(|dt| dt.and_utc());

                let count = parse_json_i64(&json, "count");

                if let Some(timestamp) = hour {
                    results.push(IngestionHistoryPoint {
                        source_type,
                        timestamp,
                        count,
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn deny(items: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(items.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>())
    }

    /// A log source with every field populated, so the match-clause variants
    /// below differ only in the three `match_*` columns under test.
    fn log_source(match_json: serde_json::Value) -> LogSource {
        let mut base = serde_json::json!({
            "id": "lsrc_00000000000000000000000000",
            "name": "windows_sysmon",
            "description": null,
            "source_type": "windows_sysmon",
            "parser_vrl": ".",
            "output_fields": null,
            "category": null,
            "vendor": null,
            "product": null,
            "icon": null,
            "color": null,
            "match_field": null,
            "match_pattern": null,
            "match_values": null,
            "validated": true,
            "validation_error": null,
            "deployed": true,
            "deployed_at": null,
            "enabled": true,
            "stale_alert_enabled": false,
            "stale_threshold_minutes": 60,
            "sampling_ratio": null,
            "sampling_exclude_condition": null,
            "source_parser_repository_id": null,
            "source_parser_path": null,
            "created_at": "2026-07-24T00:00:00Z",
            "updated_at": "2026-07-24T00:00:00Z",
        });
        let obj = base.as_object_mut().expect("fixture is an object");
        for (k, v) in match_json.as_object().expect("overrides are an object") {
            obj.insert(k.clone(), v.clone());
        }
        serde_json::from_value(base).expect("LogSource fixture should deserialize")
    }

    /// NAN-2055 (codex round 7). The ingestion-history SQL must never alias any
    /// expression to `source_type`.
    ///
    /// ClickHouse aliases are visible throughout the query and, with the default
    /// `prefer_column_name_to_alias=0`, an alias BEATS a same-named base column
    /// in the WHERE clause. So `SELECT <expr> AS source_type … WHERE
    /// lower(source_type) != 'x'` silently authorizes against `<expr>` rather
    /// than the real column — which is how the raw branch briefly re-created the
    /// very leak it exists to close.
    ///
    /// This scans the emitted SQL rather than the Rust, because the hazard is a
    /// property of the query text and would survive any refactor of the builder.
    #[test]
    fn ingestion_history_sql_never_shadows_the_authorization_column() {
        // Reconstructed exactly as `get_all_ingestion_history` emits them; that
        // function needs a live ClickHouse client, so the shapes are asserted
        // here and the drift risk is the two literals below.
        let scope_sql = scope_and(&deny(&["unknown"]));
        assert!(scope_sql.contains("lower(source_type)"), "got: {scope_sql}");

        for sql in [
            format!(
                "SELECT source_type AS display_source, toStartOfHour(bucket_start) AS hour, \
                 sum(events) AS count FROM r WHERE bucket_start >= now() - INTERVAL 24 HOUR \
                   AND source_type IN ('a'){scope_sql} GROUP BY display_source, hour"
            ),
            format!(
                "SELECT {OCSF_DISPLAY_KEY_EXPR} AS display_source, toStartOfHour(timestamp) as hour, \
                 count(*) as count FROM l WHERE timestamp >= now() - INTERVAL 24 HOUR \
                   AND {OCSF_DISPLAY_KEY_EXPR} IN ('a'){scope_sql} GROUP BY display_source, hour"
            ),
        ] {
            assert!(
                !sql.contains("AS source_type"),
                "aliasing to `source_type` rebinds the authorization predicate: {sql}"
            );
            assert!(
                sql.contains("AS display_source"),
                "display key must use a distinct alias: {sql}"
            );
            // The scope predicate is still present and unqualified, which is
            // only safe BECAUSE nothing shadows the column.
            assert!(sql.contains("lower(source_type) != 'unknown'"), "got: {sql}");
        }
    }

    /// The long-window raw fallback and the MV must retain the same display
    /// rule: non-unknown raw source first, then product name, then unknown.
    /// The MV names normalized subquery columns to avoid ClickHouse alias
    /// shadowing, so assert the equivalent pieces rather than byte identity.
    #[test]
    fn ocsf_display_key_semantics_match_the_materialized_view() {
        let ddl = include_str!("../../../../clickhouse/ocsf/init.sql");
        let mv_start = ddl
            .find("CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_per_source_5m_mv")
            .expect("ocsf_logs_per_source_5m_mv should exist in clickhouse/ocsf/init.sql");
        let mv = &ddl[mv_start..];
        let body_end = mv.find(';').expect("MV statement should terminate");
        let body = &mv[..body_end];

        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let mv_norm = squash(body);
        assert!(
            mv_norm.contains("lower(source_type) AS raw_source_type")
                && mv_norm.contains("lower(`metadata.product.name`) AS product_name")
                && mv_norm.contains(
                    "if(raw_source_type != '' AND raw_source_type != 'unknown', raw_source_type, \
                     if(product_name != '', product_name, 'unknown')) AS source_type"
                ),
            "OCSF display-key semantics drifted in the MV: {mv_norm}"
        );
        assert!(OCSF_DISPLAY_KEY_EXPR.contains("source_type != 'unknown'"));
        assert!(OCSF_DISPLAY_KEY_EXPR.contains("metadata.product.name"));
    }

    #[test]
    fn restricted_rollup_scope_uses_raw_key_and_requires_complete_provenance() {
        let scoped = rollup_scope_and(&deny(&["unknown"]));
        assert!(
            scoped.contains("scope_source_type_complete = 1"),
            "legacy/incomplete rows must fail closed: {scoped}"
        );
        assert!(
            scoped.contains("lower(scope_source_type) != 'unknown'"),
            "scope must use the raw key: {scoped}"
        );
        assert!(!scoped.contains("lower(source_type)"), "got: {scoped}");
        assert_eq!(rollup_scope_and(&ScopeSet::unrestricted()), "");
    }

    #[test]
    fn scope_and_is_empty_for_an_unrestricted_caller() {
        // NAN-2059: an unrestricted caller must produce byte-identical SQL to
        // the pre-scoping form, so nothing is appended at all.
        assert_eq!(scope_and(&ScopeSet::unrestricted()), "");
    }

    #[test]
    fn scope_and_renders_the_canonical_deny_shapes() {
        assert_eq!(
            scope_and(&deny(&["audit"])),
            " AND lower(source_type) != 'audit'"
        );
        let many = scope_and(&deny(&["audit", "windows_sysmon"]));
        assert!(
            many.starts_with(" AND lower(source_type) NOT IN ("),
            "got: {many}"
        );
        assert!(
            many.contains("'audit'") && many.contains("'windows_sysmon'"),
            "got: {many}"
        );
    }

    /// NAN-2055 (codex round 9): a hostile `match_field` must not be able to
    /// comment out the appended source-scope predicate.
    #[test]
    fn hostile_match_field_cannot_comment_out_the_scope_predicate() {
        // codex's exact payload: closes our `lower(` and starts a line comment,
        // so everything appended after it — the scope gate — would vanish.
        let attack = log_source(serde_json::json!({
            "match_field": "source_type) = 'audit' --",
            "match_values": ["anything"]
        }));

        let scoped =
            LogSourceRepository::scoped_log_source_where_clause(&attack, &deny(&["audit"]));

        // The whole clause, asserted exactly: the injected identifier is gone,
        // the column fell back to the safe default, and the scope gate is
        // terminal so nothing preceding it can neutralize it.
        assert_eq!(
            scoped,
            "lower(source_type) IN ('anything') AND lower(source_type) != 'audit'"
        );

        // Spelled out separately so a failure names the property that broke.
        // (Note `!= 'audit'` legitimately contains `= 'audit'`, so the injected
        // predicate has to be matched by its distinctive prefix, not that
        // substring — the first version of this test got that wrong.)
        assert!(!scoped.contains("--"), "comment marker survived: {scoped}");
        assert!(
            !scoped.contains("source_type) = 'audit'"),
            "injected predicate survived: {scoped}"
        );
    }

    #[test]
    fn safe_column_identifier_accepts_real_columns_and_rejects_sql() {
        for ok in ["source_type", "host", "metadata.product.name", "a_b.c1"] {
            assert!(is_safe_column_identifier(ok), "should accept {ok}");
        }
        for bad in [
            "source_type) = 'audit' --",
            "source_type;DROP",
            "source_type'",
            "source type",
            "source_type)",
            "",
            "`source_type`",
            "/*x*/source_type",
        ] {
            assert!(!is_safe_column_identifier(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn health_where_clause_ands_the_deny_set_onto_every_match_variant() {
        // NAN-2059: a log source may match by name, by an explicit value list,
        // or by a regex over an ARBITRARY column. The scope gate has to land on
        // the `source_type` column in all three, ANDed AFTER the match clause —
        // matching on `match_field = host` must not smuggle a denied source's
        // telemetry through.
        let by_name = log_source(serde_json::json!({}));
        let by_values = log_source(serde_json::json!({
            "match_values": ["windows_sysmon", "Windows_Sysmon_Extra"]
        }));
        let by_pattern = log_source(serde_json::json!({
            "match_field": "host",
            "match_pattern": "^ws-.*$"
        }));

        for ls in [&by_name, &by_values, &by_pattern] {
            let scoped = LogSourceRepository::scoped_log_source_where_clause(ls, &deny(&["audit"]));
            let bare = LogSourceRepository::build_log_source_where_clause(ls);
            assert_eq!(
                scoped,
                format!("{bare} AND lower(source_type) != 'audit'"),
                "scope gate must be ANDed after the match clause for {scoped}"
            );
        }

        // ...and an unrestricted caller gets the untouched match clause.
        let bare = LogSourceRepository::build_log_source_where_clause(&by_pattern);
        assert_eq!(
            LogSourceRepository::scoped_log_source_where_clause(
                &by_pattern,
                &ScopeSet::unrestricted()
            ),
            bare
        );
    }

    #[test]
    fn detail_health_uses_the_bounded_rollup_for_source_type_matchers() {
        let ls = log_source(serde_json::json!({
            "match_values": ["limacharlie", "lc_dns"]
        }));
        let sql = LogSourceRepository::build_detail_health_query(
            &ls,
            &deny(&["audit"]),
            "logs",
            "udm",
            "logs_distributed",
            "logs_per_source_5m_distributed",
        );

        assert!(
            sql.contains("FROM logs_per_source_5m_distributed"),
            "source_type health should use the rollup: {sql}"
        );
        assert!(!sql.contains("FROM logs_distributed"), "{sql}");
        assert!(
            sql.contains("bucket_start >= now() - INTERVAL 24 HOUR"),
            "{sql}"
        );
        assert!(
            sql.contains("lower(source_type) IN ('limacharlie', 'lc_dns')"),
            "{sql}"
        );
        assert!(
            sql.contains("lower(scope_source_type) != 'audit'"),
            "rollups must enforce scope on the raw source key: {sql}"
        );
        assert!(sql.contains("scope_source_type_complete = 1"), "{sql}");
        assert!(
            sql.contains("sum(bytes + events * (length(source_type) + 100))"),
            "the rollup path should preserve the UDM size estimate: {sql}"
        );
        assert!(sql.contains("max_execution_time = 5"), "{sql}");
        assert!(!sql.contains("90 DAY"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
        assert_eq!(sql.matches("WHERE").count(), 1, "{sql}");
    }

    #[test]
    fn detail_health_raw_fallback_is_limited_to_the_visible_24h_window() {
        let by_host = log_source(serde_json::json!({
            "match_field": "host",
            "match_pattern": "^dns-.*$"
        }));
        let arbitrary_sql = LogSourceRepository::build_detail_health_query(
            &by_host,
            &ScopeSet::unrestricted(),
            "logs",
            "udm",
            "logs_distributed",
            "logs_per_source_5m_distributed",
        );

        assert!(
            arbitrary_sql.contains("FROM logs_distributed"),
            "{arbitrary_sql}"
        );
        assert!(
            arbitrary_sql.contains("timestamp >= now() - INTERVAL 24 HOUR"),
            "{arbitrary_sql}"
        );
        assert!(
            arbitrary_sql.contains("match(lower(host), lower('^dns-.*$'))"),
            "{arbitrary_sql}"
        );
        assert!(
            arbitrary_sql.contains("max_execution_time = 5"),
            "{arbitrary_sql}"
        );
        assert!(!arbitrary_sql.contains("90 DAY"), "{arbitrary_sql}");
        assert!(!arbitrary_sql.contains("PREWHERE"), "{arbitrary_sql}");
        assert_eq!(arbitrary_sql.matches("WHERE").count(), 1, "{arbitrary_sql}");

        // OCSF source_type matchers use the profile-aware rollup. The display
        // key drives source selection while the preserved raw key drives scope.
        let by_source = log_source(serde_json::json!({
            "match_values": ["limacharlie"]
        }));
        for ocsf_scope in [ScopeSet::unrestricted(), deny(&["audit"])] {
            let ocsf_sql = LogSourceRepository::build_detail_health_query(
                &by_source,
                &ocsf_scope,
                "ocsf_logs",
                "ocsf",
                "ocsf_logs_distributed",
                "logs_per_source_5m_v2_distributed",
            );
            assert!(
                ocsf_sql.contains("FROM logs_per_source_5m_v2_distributed"),
                "{ocsf_sql}"
            );
            assert!(ocsf_sql.contains("schema_profile = 'ocsf'"), "{ocsf_sql}");
            assert!(!ocsf_sql.contains("90 DAY"), "{ocsf_sql}");
            if ocsf_scope.is_restricted() {
                assert!(
                    ocsf_sql.contains("lower(scope_source_type) != 'audit'"),
                    "{ocsf_sql}"
                );
                assert!(
                    ocsf_sql.contains("scope_source_type_complete = 1"),
                    "{ocsf_sql}"
                );
            }
        }
    }

    #[test]
    fn parse_health_query_is_bounded_attributed_and_scoped() {
        let mut ls = log_source(serde_json::json!({
            "match_values": ["limacharlie", "lc_dns"]
        }));
        let sql = LogSourceRepository::build_parse_health_query(
            &ls,
            &deny(&["audit"]),
            "parser_health_5m_distributed",
        );

        assert!(sql.contains("FROM parser_health_5m_distributed"), "{sql}");
        assert!(
            sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"),
            "{sql}"
        );
        assert!(!sql.contains("PREWHERE"), "{sql}");
        assert_eq!(sql.matches("WHERE").count(), 1, "{sql}");
        assert!(sql.contains(&format!("parser_id = '{}'", ls.id)), "{sql}");
        assert!(
            sql.contains("lower(source_type) IN ('limacharlie', 'lc_dns')"),
            "source_type match values should retain primary-key pruning: {sql}"
        );
        assert!(
            sql.contains("lower(source_type) != 'audit'"),
            "the canonical deny-set must gate parser telemetry: {sql}"
        );
        assert!(
            sql.contains("sum(events) AS parser_events_24h"),
            "health reads must use the ingest-time rollup, not raw JSON: {sql}"
        );
        assert!(!sql.contains("JSONExtract"), "{sql}");
        assert!(sql.contains("max_execution_time = 5"), "{sql}");

        // An arbitrary match field may not exist in the UDM dead-letter table.
        // Parser UUID attribution remains exact, while authorization still
        // applies to the raw source_type column.
        ls.match_field = Some("metadata.product.name".to_string());
        let arbitrary = LogSourceRepository::build_parse_health_query(
            &ls,
            &deny(&["audit"]),
            "parser_health_5m",
        );
        assert!(
            !arbitrary.contains("lower(metadata.product.name)"),
            "OCSF-only match fields must not break the UDM failure query: {arbitrary}"
        );
        assert!(
            arbitrary.contains("lower(source_type) != 'audit'"),
            "scope enforcement must survive the missing fast path: {arbitrary}"
        );
    }

    #[test]
    fn parse_health_rates_use_pre_sampling_attempts() {
        let (error_rate, success_rate) = parse_health_rates(100, 4);
        assert!((error_rate - 0.04).abs() < f64::EPSILON);
        assert_eq!(success_rate, Some(0.96));
        assert_eq!(parse_health_rates(0, 0), (0.0, None));
    }
}
