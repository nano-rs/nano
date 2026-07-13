// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenTelemetry trace/metrics fetch glue (NAN-1528).
//!
//! Thin service methods that build the OTLP SQL (via the standalone
//! [`crate::query::otel`] helpers — the spans/metrics tables have their own
//! time columns and are NOT wired through the logs-coupled nPL generator) and
//! execute it as a single SELECT → JSON. These deliberately use
//! `execute_sql_to_json` directly rather than the paginated/count wrappers:
//! both reads are bounded (trace fetch is partition-pruned + `LIMIT 100000`,
//! the metric series is GROUP BY bucket) so the count-companion round trip
//! (NAN-1032) would only double the I/O for no caller benefit.
//!
//! Source scoping (NAN-1801): `otel_spans` / `otel_metrics` have NO
//! `source_type` column — the per-source RBAC deny-set does not apply to them
//! (out of scope by design; the scoping unit is the ingest `source_type`
//! string, which OTLP-native tables never carry). The ONE read in this module
//! that touches a source-scopeable table is
//! [`SearchService::observability_service_security_signals`], which reads the
//! detection `signals` table — that path takes the caller's [`ScopeSet`] and
//! AND-s the deny-set exclusion onto both its signals reads.

use super::*;
use super::lateral::source_scope_sql_predicate;
use crate::auth::ScopeSet;
use crate::query::{
    infra_hosts_sql, metric_names_sql, metric_scalar_sql, metric_tag_keys_sql,
    metric_tag_values_sql, metric_timeseries_sql, metric_timeseries_v2_sql, recent_traces_sql,
    rum_pageviews_series_sql, rum_recent_errors_sql, rum_top_pages_sql, rum_web_vitals_sql,
    security_signals_for_entities_sql, service_endpoints_sql, service_entities_sql,
    service_exemplars_sql, service_red_timeseries_sql, services_overview_sql, services_sparkline_sql,
    slo_compute_sql, synthetic_history_sql, synthetic_summary_sql, trace_by_id_sql,
    InfraHostsFilters, MetricQuery, RumFilters, ServicesOverviewFilters, ServicesSort, SliKind,
    TimeRange, TraceListFilters,
};

impl SearchService {
    /// Fetch every span of one trace, time-ordered for waterfall rendering.
    ///
    /// Returns the ordered span rows as JSON (one object per span). Empty when
    /// the trace id is unknown. The id is lowercased + escaped by
    /// [`trace_by_id_sql`].
    #[instrument(skip(self))]
    pub async fn query_otel_trace_by_id(
        &self,
        trace_id: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = trace_by_id_sql(trace_id, self.table_names.is_clustered());
        debug!("OTEL trace fetch SQL: {}", sql);
        ch_executor.execute_sql_to_json(&sql).await
    }

    /// Fetch a metric time series: one bucketed point per `step_secs` interval
    /// over `time_range`, filtered to `metric_name` (and optionally a single
    /// `service_name`). Returns `(bucket, value)` rows as JSON, bucket-ordered.
    #[instrument(skip(self))]
    pub async fn query_otel_metric_timeseries(
        &self,
        metric_name: &str,
        service_name: Option<&str>,
        time_range: &TimeRange,
        step_secs: u64,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = metric_timeseries_sql(metric_name, service_name, time_range, step_secs, self.table_names.is_clustered());
        debug!("OTEL metric timeseries SQL: {}", sql);
        ch_executor.execute_sql_to_json(&sql).await
    }

    /// Metrics-v2 timeseries (NAN-1540): run [`metric_timeseries_v2_sql`] and
    /// pivot the flat `(series_key, bucket, v)` rows into the PINNED
    /// `series: [{ key, points: [{t, v}] }]` shape. `query.group_by = None`
    /// yields a single series with `key = ""`. Bounded by the window + LIMIT
    /// (no count companion, NAN-1032).
    ///
    /// Returns the `series` vector only — the api layer wraps it with the
    /// echoed `metric_name`, `agg`, `group_by`, and `step_secs` it already holds.
    #[instrument(skip(self))]
    pub async fn query_otel_metric_timeseries_v2(
        &self,
        query: &MetricQuery<'_>,
        time_range: &TimeRange,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = metric_timeseries_v2_sql(query, time_range, self.table_names.is_clustered());
        debug!("OTEL metric timeseries v2 SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;

        // Pivot (series_key, bucket, v) → ordered per-series point arrays.
        // Rows arrive ORDER BY series_key, bucket so a single linear pass keeps
        // points in time order and groups contiguously; a HashMap of insertion
        // order would also work but the linear merge avoids re-sorting.
        let mut series: Vec<serde_json::Value> = Vec::new();
        let mut cur_key: Option<String> = None;
        let mut cur_points: Vec<serde_json::Value> = Vec::new();
        for row in &rows {
            let key = json_str(row, "series_key");
            let point = serde_json::json!({
                "t": json_str(row, "bucket"),
                "v": json_f64(row, "v"),
            });
            match &cur_key {
                Some(k) if *k == key => cur_points.push(point),
                _ => {
                    if let Some(k) = cur_key.take() {
                        series.push(serde_json::json!({
                            "key": k,
                            "points": std::mem::take(&mut cur_points),
                        }));
                    }
                    cur_key = Some(key);
                    cur_points.push(point);
                }
            }
        }
        if let Some(k) = cur_key.take() {
            series.push(serde_json::json!({ "key": k, "points": cur_points }));
        }

        Ok(series)
    }

    /// Distinct tag/attribute KEYS for a metric over `time_range` (NAN-1540) —
    /// the `GET .../metrics/tags` (no `key`) contract. Returns the key strings.
    #[instrument(skip(self))]
    pub async fn list_otel_metric_tag_keys(
        &self,
        metric_name: &str,
        time_range: &TimeRange,
    ) -> Result<Vec<String>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = metric_tag_keys_sql(metric_name, time_range, self.table_names.is_clustered());
        debug!("OTEL metric tag-keys SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;
        Ok(rows.iter().map(|r| json_str(r, "k")).filter(|s| !s.is_empty()).collect())
    }

    /// Distinct VALUES of one tag `key` for a metric over `time_range`
    /// (NAN-1540) — the `GET .../metrics/tags?key=` contract. `key` is validated
    /// by the api layer ([`crate::query::valid_tag_key`]); escaped in the SQL.
    #[instrument(skip(self))]
    pub async fn list_otel_metric_tag_values(
        &self,
        metric_name: &str,
        key: &str,
        time_range: &TimeRange,
    ) -> Result<Vec<String>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = metric_tag_values_sql(metric_name, key, time_range, self.table_names.is_clustered());
        debug!("OTEL metric tag-values SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;
        Ok(rows
            .iter()
            .map(|r| json_str(r, "tag_value"))
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Metric-monitor EVAL (NAN-1540): compute the monitor's aggregate as one
    /// scalar PER SERIES over the window via [`metric_scalar_sql`], returning
    /// `(series_key, value)` pairs where `value` is `Option<f64>`. The jobs
    /// runner compares each `Some(value)` to the monitor threshold per its
    /// comparator and raises on breach. A monitor with no `group_by` yields
    /// exactly one pair with key `""`; an empty result (a group_by series that
    /// vanished) yields an empty vec.
    ///
    /// O13 (NAN-1721): `value` is `None` for a no-data window — either
    /// `row_count == 0` (Contract #1: `metric_scalar_sql` emits
    /// `count() AS row_count`) or a NULL aggregate (avg/min/max/quantile over an
    /// empty set). None is NEVER coerced to 0.0, so the runner treats it as
    /// no-data (no compare, no alert) instead of false-firing an `lt`/`eq 0`
    /// monitor when the metric stops reporting. Bounded by the window + LIMIT
    /// (NAN-1032).
    #[instrument(skip(self))]
    pub async fn evaluate_metric_monitor(
        &self,
        query: &MetricQuery<'_>,
        time_range: &TimeRange,
    ) -> Result<Vec<(String, Option<f64>)>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = metric_scalar_sql(query, time_range, self.table_names.is_clustered());
        debug!("OTEL metric-monitor eval SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;
        Ok(rows
            .iter()
            .map(|r| {
                // Contract #1 (O13/NAN-1721): a no-data window — `row_count == 0`
                // or a NULL aggregate — maps to `None`, NEVER coerced to 0.0, so
                // the runner treats it as no-data (no compare, no alert) instead
                // of false-firing an `lt`/`eq 0` monitor when the metric stops
                // reporting. When `row_count` is absent (SQL not yet carrying it)
                // this still nulls a NULL aggregate but falls through on the
                // count gate — no worse than the pre-fix 0.0 floor.
                let value = match json_f64_opt(r, "row_count") {
                    Some(rc) if rc == 0.0 => None,
                    _ => json_f64_opt(r, "v"),
                };
                (json_str(r, "series_key"), value)
            })
            .collect())
    }

    /// List recent traces over `time_range` for the Traces explorer (NAN-1534).
    ///
    /// One JSON object per trace — `trace_id`, `root_service`, `root_name`,
    /// `span_count`, `error_count`, `duration_ns`, `start_time` — most recent
    /// first. Optional `filters` narrow by root service / errors-only / minimum
    /// root duration and cap the row count (clamped to 1000). Bounded by the
    /// time window + LIMIT, so it uses `execute_sql_to_json` directly (no
    /// count-companion round trip, NAN-1032).
    #[instrument(skip(self))]
    pub async fn list_otel_traces(
        &self,
        time_range: &TimeRange,
        filters: &TraceListFilters<'_>,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = recent_traces_sql(time_range, filters, self.table_names.is_clustered());
        debug!("OTEL recent-traces SQL: {}", sql);
        ch_executor.execute_sql_to_json(&sql).await
    }

    /// List distinct metric names for the Metrics explorer dropdown (NAN-1534).
    ///
    /// Returns one JSON object per distinct `metric_name`, optionally restricted
    /// to a single `service_name`, name-ordered. Bounded by `LIMIT 10000`.
    #[instrument(skip(self))]
    pub async fn list_otel_metric_names(
        &self,
        service_name: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = metric_names_sql(service_name, self.table_names.is_clustered());
        debug!("OTEL metric-names SQL: {}", sql);
        ch_executor.execute_sql_to_json(&sql).await
    }

    // ========================================================================
    // Observability console — services overview / service detail / SLO compute
    // (NAN-1536). Each builds the bounded OTLP SQL (`crate::query::*`), executes
    // via `execute_sql_to_json` (no count companion — every read is window+LIMIT
    // bounded, NAN-1032), then assembles the EXACT JSON shape the api layer hands
    // back to the FE. Scalar derivations the SQL layer can't carry (rate_per_sec
    // needs the window seconds, error_rate/health need both counts) live here.
    // ========================================================================

    /// Services-overview rows for `GET /api/search/services` (NAN-1536/1543).
    ///
    /// One object per `service` with `request_count`, `rate_per_sec`
    /// (= count / window-secs), `error_rate` (0..1), `p50_ms`/`p95_ms`/`p99_ms`,
    /// `health` (`good`|`warn`|`bad` from error_rate + p95 thresholds), and a
    /// `sparkline: [{t, v}]` of per-bucket request volume. Two bounded reads —
    /// the per-service RED aggregate and the `(service, bucket)` sparkline — are
    /// joined in memory keyed by service name. `sparkline_step_secs` is the
    /// bucket width for the sparkline (clamp ≥1 happens in the SQL builder).
    ///
    /// NAN-1543: `filters` (`q` substring + `sort`) are pushed into the SQL;
    /// `health_filter` (`good|warn|bad`) and paging (`offset`/`limit`) are applied
    /// HERE, post-aggregation — the health classification is a derived scalar and
    /// the page must slice the FILTERED + re-sorted set. Returns the `(rows,
    /// total)` tuple where `total` is the count AFTER the health filter (the
    /// has-more signal source) but BEFORE the offset/limit slice. With no filters
    /// + no paging the returned rows are byte-identical to the pre-1543 default.
    #[instrument(skip(self))]
    #[allow(clippy::too_many_arguments)]
    pub async fn observability_services_overview(
        &self,
        time_range: &TimeRange,
        sparkline_step_secs: u64,
        filters: &ServicesOverviewFilters<'_>,
        health_filter: Option<&str>,
        offset: u32,
        limit: Option<u32>,
    ) -> Result<(Vec<serde_json::Value>, usize), SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let window_secs = ((time_range.end - time_range.start).num_seconds().max(1)) as f64;

        let overview_sql = services_overview_sql(time_range, filters, self.table_names.is_clustered());
        debug!("OTEL services-overview SQL: {}", overview_sql);
        let rows = ch_executor.execute_sql_to_json(&overview_sql).await?;

        let spark_sql = services_sparkline_sql(time_range, sparkline_step_secs, self.table_names.is_clustered());
        debug!("OTEL services-sparkline SQL: {}", spark_sql);
        let spark_rows = ch_executor.execute_sql_to_json(&spark_sql).await?;

        // Pivot the flat (service, bucket, v) rows into per-service point arrays.
        let mut sparklines: std::collections::HashMap<String, Vec<serde_json::Value>> =
            std::collections::HashMap::new();
        for row in &spark_rows {
            let svc = json_str(row, "service");
            if svc.is_empty() {
                continue;
            }
            let point = serde_json::json!({
                "t": json_str(row, "bucket"),
                "v": json_f64(row, "v"),
            });
            sparklines.entry(svc).or_default().push(point);
        }

        // Assemble + derive scalars; capture (error_rate, health) for the
        // post-aggregation health filter and the error_rate re-sort.
        let mut assembled: Vec<(f64, &'static str, serde_json::Value)> = rows
            .into_iter()
            .map(|row| {
                let service = json_str(&row, "service");
                let request_count = json_f64(&row, "request_count");
                let error_count = json_f64(&row, "error_count");
                let rate_per_sec = request_count / window_secs;
                let error_rate = if request_count > 0.0 {
                    error_count / request_count
                } else {
                    0.0
                };
                let p95_ms = json_f64(&row, "p95_ms");
                let health = service_health(error_rate, p95_ms);
                let sparkline = sparklines.remove(&service).unwrap_or_default();
                let obj = serde_json::json!({
                    "service": service,
                    "request_count": request_count as i64,
                    "rate_per_sec": rate_per_sec,
                    "error_rate": error_rate,
                    "p50_ms": json_f64(&row, "p50_ms"),
                    "p95_ms": p95_ms,
                    "p99_ms": json_f64(&row, "p99_ms"),
                    "health": health,
                    "sparkline": sparkline,
                });
                (error_rate, health, obj)
            })
            .collect();

        // Post-aggregation health filter (derived scalar — not a SQL column).
        if let Some(h) = health_filter.filter(|s| !s.is_empty()) {
            assembled.retain(|(_, health, _)| *health == h);
        }

        // error_rate sort is a derived scalar the SQL couldn't order on — re-sort
        // worst-first here. Other sorts already came ordered from the SQL.
        if matches!(filters.sort, Some(ServicesSort::ErrorRate)) {
            assembled.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        }

        // `total` is the FILTERED count (drives has-more); slice the page after.
        let total = assembled.len();
        let services: Vec<serde_json::Value> = assembled
            .into_iter()
            .map(|(_, _, obj)| obj)
            .skip(offset as usize)
            .take(limit.map(|l| l as usize).unwrap_or(usize::MAX))
            .collect();

        Ok((services, total))
    }

    /// Service-detail payload for `GET /api/search/services/{service}` (NAN-1536):
    /// the `red` timeseries block (rate / errors / latency p50,p95,p99), the
    /// per-endpoint `endpoints` table, and `exemplars` (click-through trace seeds).
    /// Three bounded reads assembled into the single contract object.
    /// `red_step_secs` is the RED bucket width; `exemplar_limit` caps the
    /// exemplar sample (clamp `[1,200]` in the SQL builder).
    #[instrument(skip(self))]
    pub async fn observability_service_detail(
        &self,
        service: &str,
        time_range: &TimeRange,
        red_step_secs: u64,
        exemplar_limit: Option<u32>,
    ) -> Result<serde_json::Value, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let red_sql = service_red_timeseries_sql(service, time_range, red_step_secs, self.table_names.is_clustered());
        debug!("OTEL service-detail RED SQL: {}", red_sql);
        let red_rows = ch_executor.execute_sql_to_json(&red_sql).await?;

        let mut rate = Vec::with_capacity(red_rows.len());
        let mut errors = Vec::with_capacity(red_rows.len());
        let mut latency = Vec::with_capacity(red_rows.len());
        for row in &red_rows {
            let t = json_str(row, "bucket");
            rate.push(serde_json::json!({ "t": t, "v": json_f64(row, "rate_count") }));
            errors.push(serde_json::json!({ "t": t, "v": json_f64(row, "error_count") }));
            latency.push(serde_json::json!({
                "t": t,
                "p50": json_f64(row, "p50_ms"),
                "p95": json_f64(row, "p95_ms"),
                "p99": json_f64(row, "p99_ms"),
            }));
        }

        let endpoints_sql = service_endpoints_sql(service, time_range, self.table_names.is_clustered());
        debug!("OTEL service-detail endpoints SQL: {}", endpoints_sql);
        let endpoint_rows = ch_executor.execute_sql_to_json(&endpoints_sql).await?;
        let endpoints: Vec<serde_json::Value> = endpoint_rows
            .into_iter()
            .map(|row| {
                let request_count = json_f64(&row, "request_count");
                let error_count = json_f64(&row, "error_count");
                let error_rate = if request_count > 0.0 {
                    error_count / request_count
                } else {
                    0.0
                };
                serde_json::json!({
                    "span_name": json_str(&row, "span_name"),
                    "request_count": request_count as i64,
                    "error_rate": error_rate,
                    "p95_ms": json_f64(&row, "p95_ms"),
                })
            })
            .collect();

        let exemplars_sql = service_exemplars_sql(service, time_range, exemplar_limit, self.table_names.is_clustered());
        debug!("OTEL service-detail exemplars SQL: {}", exemplars_sql);
        let exemplar_rows = ch_executor.execute_sql_to_json(&exemplars_sql).await?;
        let exemplars: Vec<serde_json::Value> = exemplar_rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "trace_id": json_str(&row, "trace_id"),
                    "duration_ms": json_f64(&row, "duration_ms"),
                    "error": json_bool(&row, "error"),
                    "start_time": json_str(&row, "start_time"),
                    "span_name": json_str(&row, "span_name"),
                })
            })
            .collect();

        Ok(serde_json::json!({
            "service": service,
            "red": { "rate": rate, "errors": errors, "latency": latency },
            "endpoints": endpoints,
            "exemplars": exemplars,
        }))
    }

    /// Compute one SLO's spans-based attainment over `time_range` (NAN-1536).
    ///
    /// Returns `(current, total_spans, no_data)` where `current` is the SLI
    /// attainment in `0..1`: availability = `good_non_error / total`, latency =
    /// `under_threshold / total`. `latency_threshold_ms` is required for
    /// [`SliKind::Latency`] (the SQL builder degrades to availability if absent).
    /// The api/PG slice owns the SLO record + the budget/burn/status math on top
    /// of `current`.
    ///
    /// O17 (NAN-1721 / Contract #2): `total = 0` (no spans in window) still
    /// yields `current = 1.0` numerically, but `no_data = true` flags it so
    /// callers do NOT treat a zero-traffic window as "attained". A hard-down
    /// service or a stopped collector produces exactly this, and the rolling
    /// window sliding past old errors would otherwise make the SLO *improve*
    /// while the service is dead. The api surfaces status `"no_data"` and the
    /// scheduler does not alert (neither breach nor recovery) on it.
    #[instrument(skip(self))]
    pub async fn observability_slo_compute(
        &self,
        service: &str,
        sli_kind: SliKind,
        latency_threshold_ms: Option<f64>,
        time_range: &TimeRange,
    ) -> Result<(f64, i64, bool), SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = slo_compute_sql(service, sli_kind, latency_threshold_ms, time_range, self.table_names.is_clustered());
        debug!("OTEL SLO-compute SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;

        let row = match rows.first() {
            Some(r) => r,
            // No row (empty result) → no traffic → NO DATA (Contract #2 / O17).
            None => return Ok((1.0, 0, true)),
        };
        let total = json_f64(row, "total");
        let good = json_f64(row, "good");
        let current = if total > 0.0 { good / total } else { 1.0 };
        // Contract #2 (O17): a zero-span window is NOT attained — flag no_data.
        let no_data = total <= 0.0;
        Ok((current, total as i64, no_data))
    }

    // ========================================================================
    // Observability console — Infra host inventory (NAN-1537)
    // ========================================================================

    /// Host inventory for `GET /api/search/infra/hosts` (NAN-1537).
    ///
    /// One object per host with the latest CPU/mem/load/net gauges over
    /// `time_range`, derived from `otel_metrics`:
    ///   - `cpu_pct`  — `system.cpu.utilization` ×100 (OTLP reports 0..1)
    ///   - `mem_pct`  — `system.memory.utilization` ×100
    ///   - `load`     — `system.cpu.load_average.1m` (as-is)
    ///   - `net_bytes_per_sec` — `system.network.io` (as-is)
    ///   - `group`    — `host.group` resource attr, else `service_name`
    ///   - `status`   — `good`|`warn`|`bad` from cpu/mem thresholds
    ///
    /// A gauge a host never reported comes back 0 from `argMaxIf`; O52 (NAN-1721)
    /// disambiguates that ABSENT reading from a genuine reported 0.0 via the
    /// per-metric count companions (`cpu_n`/`mem_n`/`load_n`/`net_n` =
    /// `countIf(metric_name = …)`): a gauge with zero data points → `null`, a
    /// reported 0.0 stays 0.0 (an idle host at 0% CPU no longer renders "–").
    /// Until the SQL carries those companions the glue falls back to the legacy
    /// "null a bare 0.0" heuristic (see [`gauge_or_null`]). Bounded single read.
    #[instrument(skip(self))]
    pub async fn observability_infra_hosts(
        &self,
        time_range: &TimeRange,
        filters: &InfraHostsFilters<'_>,
        status_filter: Option<&str>,
        offset: u32,
        limit: Option<u32>,
    ) -> Result<(Vec<serde_json::Value>, usize), SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = infra_hosts_sql(time_range, filters, self.table_names.is_clustered());
        debug!("OTEL infra-hosts SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;

        // Assemble + derive status; `status` is a derived scalar (cpu/mem
        // thresholds), so the optional status filter is applied here, post-read.
        let mut assembled: Vec<(&'static str, serde_json::Value)> = rows
            .into_iter()
            .map(|row| {
                let host = json_str(&row, "host");
                let group = json_str(&row, "host_group");
                // OTLP utilization is a 0..1 fraction → percent.
                let cpu_pct = json_f64(&row, "cpu_util") * 100.0;
                let mem_pct = json_f64(&row, "mem_util") * 100.0;
                let load = json_f64(&row, "load_1m");
                let net = json_f64(&row, "net_io");
                let status = host_status(cpu_pct, mem_pct);
                let obj = serde_json::json!({
                    "host": host,
                    "group": if group.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(group) },
                    "cpu_pct": gauge_or_null(&row, cpu_pct, "cpu_n"),
                    "mem_pct": gauge_or_null(&row, mem_pct, "mem_n"),
                    "load": gauge_or_null(&row, load, "load_n"),
                    "net_bytes_per_sec": gauge_or_null(&row, net, "net_n"),
                    "status": status,
                });
                (status, obj)
            })
            .collect();

        if let Some(s) = status_filter.filter(|s| !s.is_empty()) {
            assembled.retain(|(status, _)| *status == s);
        }

        // `total` = filtered count (has-more source); slice the page after.
        let total = assembled.len();
        let hosts: Vec<serde_json::Value> = assembled
            .into_iter()
            .map(|(_, obj)| obj)
            .skip(offset as usize)
            .take(limit.map(|l| l as usize).unwrap_or(usize::MAX))
            .collect();

        Ok((hosts, total))
    }

    // ========================================================================
    // Observability console — RUM (real user monitoring) (NAN-1537)
    // ========================================================================

    /// RUM summary for `GET /api/search/rum` (NAN-1537).
    ///
    /// Assembles the single RUM contract from four bounded reads:
    ///   - `web_vitals` — p75 LCP/INP/CLS from `otel_metrics` (a vital with no
    ///     data points → `null`, told apart from a true 0 by the `*_n` count
    ///     companions);
    ///   - `page_views` + `page_views_series` — page-view spans from
    ///     `otel_spans`, bucketed per `series_step_secs` and summed for the total;
    ///   - `js_errors` — JS-error spans (summed across the same series read);
    ///   - `top_pages` — busiest pages with per-page p75 LCP;
    ///   - `recent_errors` — most recent JS-error span sample.
    #[instrument(skip(self))]
    pub async fn observability_rum_summary(
        &self,
        time_range: &TimeRange,
        series_step_secs: u64,
        filters: &RumFilters<'_>,
    ) -> Result<serde_json::Value, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        // Web vitals (p75), with count companions to distinguish "no data" from 0.
        let vitals_sql = rum_web_vitals_sql(time_range, filters, self.table_names.is_clustered());
        debug!("OTEL RUM web-vitals SQL: {}", vitals_sql);
        let vitals_rows = ch_executor.execute_sql_to_json(&vitals_sql).await?;
        let web_vitals = match vitals_rows.first() {
            Some(r) => serde_json::json!({
                "lcp_ms": vital_or_null(r, "lcp_ms", "lcp_n"),
                "inp_ms": vital_or_null(r, "inp_ms", "inp_n"),
                "cls": vital_or_null(r, "cls", "cls_n"),
            }),
            None => serde_json::json!({ "lcp_ms": null, "inp_ms": null, "cls": null }),
        };

        // Page views + JS errors, bucketed.
        let series_sql = rum_pageviews_series_sql(time_range, series_step_secs, filters, self.table_names.is_clustered());
        debug!("OTEL RUM page-views series SQL: {}", series_sql);
        let series_rows = ch_executor.execute_sql_to_json(&series_sql).await?;
        let mut page_views: i64 = 0;
        let mut js_errors: i64 = 0;
        let mut page_views_series = Vec::with_capacity(series_rows.len());
        for row in &series_rows {
            let v = json_f64(row, "views");
            page_views += v as i64;
            js_errors += json_f64(row, "js_errors") as i64;
            page_views_series.push(serde_json::json!({
                "t": json_str(row, "bucket"),
                "v": v,
            }));
        }

        // Top pages with per-page p75 LCP.
        let top_pages_sql = rum_top_pages_sql(time_range, None, filters, self.table_names.is_clustered());
        debug!("OTEL RUM top-pages SQL: {}", top_pages_sql);
        let top_rows = ch_executor.execute_sql_to_json(&top_pages_sql).await?;
        let top_pages: Vec<serde_json::Value> = top_rows
            .into_iter()
            .map(|row| {
                let lcp = json_opt_f64(&row, "lcp_ms");
                serde_json::json!({
                    "page": json_str(&row, "page"),
                    "views": json_f64(&row, "views") as i64,
                    "lcp_ms": lcp,
                })
            })
            .collect();

        // Recent JS-error sample.
        let errors_sql = rum_recent_errors_sql(time_range, None, filters, self.table_names.is_clustered());
        debug!("OTEL RUM recent-errors SQL: {}", errors_sql);
        let error_rows = ch_executor.execute_sql_to_json(&errors_sql).await?;
        let recent_errors: Vec<serde_json::Value> = error_rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "message": json_str(&row, "message"),
                    "page": json_str(&row, "page"),
                    "ts": json_str(&row, "ts"),
                    // NAN-1553: promoted entity overlay for the enterprise
                    // RUM→investigation pivot (empty string when absent).
                    "user": json_str(&row, "user"),
                    "src_ip": json_str(&row, "src_ip"),
                    "session": json_str(&row, "session"),
                })
            })
            .collect();

        Ok(serde_json::json!({
            "web_vitals": web_vitals,
            "page_views": page_views,
            "page_views_series": page_views_series,
            "js_errors": js_errors,
            "top_pages": top_pages,
            "recent_errors": recent_errors,
        }))
    }

    // ========================================================================
    // Observability console — Synthetics results summaries (NAN-1538)
    // ========================================================================

    /// Per-check result summaries over `time_range`, keyed by `check_id`
    /// (NAN-1538). Returns a map `check_id -> { uptime_pct, p50_latency_ms }`
    /// for every check that has at least one run in the window. The api layer
    /// reads the check *definitions* from PG (`SyntheticCheckRepository`), looks
    /// up its UUID-string here, and defaults a missing entry to `0% / null`
    /// (no runs yet). One bounded GROUP BY check_id read.
    #[instrument(skip(self))]
    pub async fn observability_synthetics_summary(
        &self,
        time_range: &TimeRange,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = synthetic_summary_sql(time_range, self.table_names.is_clustered());
        debug!("OTEL synthetics-summary SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;

        let mut out = std::collections::HashMap::new();
        for row in &rows {
            let check_id = json_str(row, "check_id");
            if check_id.is_empty() {
                continue;
            }
            let total = json_f64(row, "total");
            let good = json_f64(row, "good");
            let uptime_pct = if total > 0.0 {
                good / total * 100.0
            } else {
                0.0
            };
            out.insert(
                check_id,
                serde_json::json!({
                    "uptime_pct": uptime_pct,
                    "p50_latency_ms": json_opt_f64(row, "p50_latency_ms"),
                }),
            );
        }
        Ok(out)
    }

    /// The last-N run history of one synthetic check (NAN-1538), chronological,
    /// for the uptime-bar sparkline. Returns `[{success, latency_ms, ts}]`
    /// oldest-first (the SQL takes the newest `limit` DESC; this reverses to
    /// chronological for the bar). `check_id` is the def's UUID stringified.
    #[instrument(skip(self))]
    pub async fn observability_synthetic_history(
        &self,
        check_id: &str,
        time_range: &TimeRange,
        limit: Option<u32>,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let sql = synthetic_history_sql(check_id, time_range, limit, self.table_names.is_clustered());
        debug!("OTEL synthetic-history SQL: {}", sql);
        let rows = ch_executor.execute_sql_to_json(&sql).await?;

        // SQL returns newest-first; reverse to chronological for the bar.
        let mut history: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "success": json_bool(row, "success"),
                    "latency_ms": json_f64(row, "latency_ms"),
                    "ts": json_str(row, "ts"),
                })
            })
            .collect();
        history.reverse();
        Ok(history)
    }

    // ========================================================================
    // Observability ↔ Security convergence — service security signals (NAN-1542)
    // ========================================================================

    /// Security detection signals firing against a service's hosts/IPs over
    /// `time_range` (NAN-1542) — the cross-link that powers the service detail's
    /// "security signals" panel.
    ///
    /// Three bounded reads: (1) resolve the service's distinct entities (src_ip +
    /// host) from `otel_spans`, capped at `SERVICE_ENTITY_CAP`; (2) find
    /// detection signals whose `risk_entity` is one of those entities, over the
    /// same window (bounded by `limit`); (3) O54 (NAN-1721): a companion `count()`
    /// over the SAME entity predicate + window for the TRUE range total (the
    /// sample is capped by `limit`, so `signals.len()` under-counts). Returns
    /// `(host_count, signal_count, signal_total, signals)` where:
    ///   - `host_count`   — distinct entities resolved for the service;
    ///   - `signal_count` — signals returned in the sample (bounded by `limit`);
    ///   - `signal_total` — TRUE count of matching signals over the window
    ///     (`>= signal_count`); the FE header + "+N more in range" use this;
    ///   - `signals`      — `[{ ts, rule_name, src_host, src_ip, severity }]`,
    ///     most recent first. The matched `risk_entity` is mapped to `src_ip`
    ///     (when it is one of the resolved IPs) or `src_host` (when it is one of
    ///     the resolved hosts), else surfaced as `src_host` (best-effort label).
    ///
    /// When the service has no entities in the window the signal reads are skipped
    /// entirely (no point querying `signals IN ()`), returning empty. All reads
    /// use `execute_sql_to_json` directly; the count companion (3) is a deliberate
    /// exception to the NAN-1032 "no companion" default because the `limit` cap
    /// makes the true total unrecoverable from the bounded sample rows.
    ///
    /// NAN-1801 (P3 side-doors): the `signals` table is source-scopeable
    /// (`source_type`, migration 164), and this hand-built path bypasses the P1
    /// nPL search-path gate — so the caller's `ScopeSet` is threaded down here
    /// and its deny-set exclusion is AND-ed onto BOTH signals reads (the bounded
    /// sample (2) AND the count companion (3) — they must agree or
    /// `signal_total` would leak the existence of hidden-source signals). The
    /// entity-resolution read (1) is `otel_spans`, which has no `source_type`
    /// column and stays unscoped by design. An empty deny set emits
    /// byte-identical SQL to the pre-scoping form. Residual: pre-rollout MV rows
    /// carry `source_type = 'unknown'` (migration 164 DEFAULT) and stay visible
    /// until the supervised backfill — accepted (NAN-1801).
    #[instrument(skip(self, scope))]
    pub async fn observability_service_security_signals(
        &self,
        service: &str,
        time_range: &TimeRange,
        limit: Option<u32>,
        scope: &ScopeSet,
    ) -> Result<(usize, usize, u64, Vec<serde_json::Value>), SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        // 1) Resolve the service's distinct entities (src_ip + host).
        let entities_sql = service_entities_sql(service, time_range, self.table_names.is_clustered());
        debug!("OTEL service-entities SQL: {}", entities_sql);
        let entity_rows = ch_executor.execute_sql_to_json(&entities_sql).await?;
        let entities: Vec<String> = entity_rows
            .iter()
            .map(|r| json_str(r, "entity"))
            .filter(|s| !s.is_empty())
            .collect();

        let host_count = entities.len();
        if entities.is_empty() {
            return Ok((0, 0, 0, Vec::new()));
        }

        // Set membership to map a matched risk_entity back to ip vs host. An
        // entity can be either (the span src_ip column or the host column); when
        // it isn't a recognizable IP we treat it as a host label.
        let ip_set: std::collections::HashSet<&str> = entities
            .iter()
            .filter(|e| e.parse::<std::net::IpAddr>().is_ok())
            .map(|s| s.as_str())
            .collect();

        // NAN-1801: render the caller's source-scope deny-set ONCE — it gates
        // both the sample read below and the count companion, which must stay
        // predicate-identical. `None` (unrestricted) leaves both reads
        // byte-identical to the pre-scoping form.
        let scope_predicate = source_scope_sql_predicate("source_type", scope.deny_set());

        // 2) Find detection signals against those entities.
        let mut signals_sql = security_signals_for_entities_sql(
            &entities,
            time_range,
            limit,
            self.table_names.is_clustered(),
        );
        if let Some(pred) = scope_predicate.as_deref() {
            // NAN-1801: `security_signals_for_entities_sql` does not (yet) take
            // a scope predicate, so splice the conjunct into its WHERE ahead of
            // the ORDER BY. The marker is pinned by the builder's format string;
            // if the builder's shape ever drifts, FAIL CLOSED (error out) rather
            // than run the read unscoped for a restricted caller.
            const ORDER_BY_MARKER: &str = "\nORDER BY timestamp DESC";
            match signals_sql.find(ORDER_BY_MARKER) {
                Some(idx) => signals_sql.insert_str(idx, &format!("\n  AND ({pred})")),
                None => {
                    return Err(SearchError::SqlGenError(
                        "security-signals SQL shape changed; cannot inject source scope"
                            .to_string(),
                    ));
                }
            }
        }
        debug!("OTEL service-security-signals SQL: {}", signals_sql);
        let signal_rows = ch_executor.execute_sql_to_json(&signals_sql).await?;

        let signals: Vec<serde_json::Value> = signal_rows
            .iter()
            .map(|row| {
                let entity = json_str(row, "risk_entity");
                // Map the matched entity to src_ip when it parses as an IP (or is
                // in the resolved ip set), else to src_host.
                let is_ip = ip_set.contains(entity.as_str())
                    || entity.parse::<std::net::IpAddr>().is_ok();
                let (src_ip, src_host) = if is_ip {
                    (
                        serde_json::Value::String(entity.clone()),
                        serde_json::Value::Null,
                    )
                } else {
                    (
                        serde_json::Value::Null,
                        serde_json::Value::String(entity.clone()),
                    )
                };
                serde_json::json!({
                    "ts": json_str(row, "ts"),
                    "rule_name": json_str(row, "rule_name"),
                    "src_host": src_host,
                    "src_ip": src_ip,
                    "severity": json_str(row, "severity"),
                })
            })
            .collect();

        let signal_count = signals.len();

        // 3) O54 (NAN-1721 / Contract #4): the sample above is capped by `limit`,
        // so `signals.len()` is NOT the range total. Issue a dedicated UNBOUNDED
        // count over the SAME entity predicate + window so the FE header
        // ("N on K hosts · +M more in range") reflects the true total, not the
        // page. Built inline (the sample's SQL builder bakes a `LIMIT`, so it
        // can't be reused for the count); entities are escaped via the shared
        // `sql_hygiene::escape_sql_string` — byte-identical to the builder's
        // `escape_string` — and `entities` is non-empty here (early-returned).
        let entity_list = entities
            .iter()
            .map(|e| format!("'{}'", crate::sql_hygiene::escape_sql_string(e)))
            .collect::<Vec<_>>()
            .join(", ");
        let sig_table = self.table_names.read("signals");
        let sig_ref = self.table_names.read_bare("signals");
        // NAN-1801: the count carries the SAME source-scope conjunct as the
        // sample — otherwise "+N more in range" would count hidden-source
        // signals a restricted viewer can't see. Empty deny → empty splice
        // (byte-identical SQL).
        let scope_and = scope_predicate
            .as_deref()
            .map(|pred| format!("\n  AND ({pred})"))
            .unwrap_or_default();
        let count_sql = format!(
            "SELECT count() AS signal_total\n\
             FROM {sig_table}\n\
             WHERE {sig_ref}.timestamp BETWEEN '{start}' AND '{end}'\n  \
               AND (risk_entity IN ({entity_list})){scope_and}",
            start = crate::sql_hygiene::format_ch_bound_micros(&time_range.start),
            end = crate::sql_hygiene::format_ch_bound_micros(&time_range.end),
        );
        debug!("OTEL service-security-signals count SQL: {}", count_sql);
        let count_rows = ch_executor.execute_sql_to_json(&count_sql).await?;
        let signal_total = count_rows
            .first()
            .map(|r| json_f64(r, "signal_total") as u64)
            .unwrap_or(signal_count as u64);

        Ok((host_count, signal_count, signal_total, signals))
    }
}

// ----------------------------------------------------------------------------
// JSON cell extractors — ClickHouse `execute_sql_to_json` returns one object per
// row keyed by column alias; numeric columns may surface as JSON numbers OR as
// strings (driver-dependent), so the f64 reader tolerates both. Kept module-local
// (NAN-1536); they encode no SQL, only result-shape parsing.
// ----------------------------------------------------------------------------

fn json_str(row: &serde_json::Value, key: &str) -> String {
    match row.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) if !v.is_null() => v.to_string(),
        _ => String::new(),
    }
}

fn json_f64(row: &serde_json::Value, key: &str) -> f64 {
    match row.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(serde_json::Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Read a numeric cell that may be SQL NULL (e.g. a `quantile…` over an empty
/// set, or a `toFloat64OrNull` miss) → `null` JSON. A present non-numeric or
/// absent key also maps to `null` (NAN-1537/1538). Distinct from [`json_f64`]
/// which floors everything to 0.0 — used where the contract field is nullable.
fn json_opt_f64(row: &serde_json::Value, key: &str) -> serde_json::Value {
    match row.get(key) {
        Some(serde_json::Value::Number(n)) => n
            .as_f64()
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
        Some(serde_json::Value::String(s)) => s
            .trim()
            .parse::<f64>()
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
        _ => serde_json::Value::Null,
    }
}

/// Read a numeric cell as a Rust `Option<f64>` — `None` for SQL NULL, an absent
/// key, or a non-numeric value; `Some(v)` for a real number (NAN-1721). Unlike
/// [`json_f64`] (floors everything to 0.0) and [`json_opt_f64`] (returns a JSON
/// value), this yields the `Option<f64>` the no-data decision paths need so a
/// reported 0.0 is never conflated with "no data" (O13 breach gate, O52 gauge
/// count companion).
fn json_f64_opt(row: &serde_json::Value, key: &str) -> Option<f64> {
    match row.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_f64(),
        Some(serde_json::Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn json_bool(row: &serde_json::Value, key: &str) -> bool {
    match row.get(key) {
        Some(serde_json::Value::Bool(b)) => *b,
        // CH boolean / UInt8 comes back as 0/1 (number or string).
        Some(serde_json::Value::Number(n)) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
        Some(serde_json::Value::String(s)) => {
            let t = s.trim();
            t == "1" || t.eq_ignore_ascii_case("true")
        }
        _ => false,
    }
}

/// Service-health classification from the RED signals (NAN-1536), mirroring the
/// design's `healthOf` thresholds (obs-data.jsx) re-expressed against the
/// contract's fractional `error_rate` (the design used whole-percent `errPct`):
///   - `bad`  — error_rate ≥ 5% OR p95 ≥ 1000 ms
///   - `warn` — error_rate ≥ 1% OR p95 ≥ 600 ms
///   - `good` — otherwise
fn service_health(error_rate: f64, p95_ms: f64) -> &'static str {
    if error_rate >= 0.05 || p95_ms >= 1000.0 {
        "bad"
    } else if error_rate >= 0.01 || p95_ms >= 600.0 {
        "warn"
    } else {
        "good"
    }
}

/// Host-status classification from the CPU/memory percentages (NAN-1537),
/// mirroring the design's "hot host" framing (obs-data.jsx — CPU≳72 / mem≳64
/// on hot hosts). `bad` at ≥90% on either, `warn` at ≥75%, else `good`.
fn host_status(cpu_pct: f64, mem_pct: f64) -> &'static str {
    if cpu_pct >= 90.0 || mem_pct >= 90.0 {
        "bad"
    } else if cpu_pct >= 75.0 || mem_pct >= 75.0 {
        "warn"
    } else {
        "good"
    }
}

/// Map a `0.0` gauge to JSON `null` (the contract's `*|null` fields), else the
/// value (NAN-1537). `argMaxIf` returns 0 for a metric a host never reported, so
/// a 0 is indistinguishable from "no reading" in the raw row — we surface `null`
/// rather than a misleading 0 in the inventory. A real 0% CPU is vanishingly
/// rare and harmless to render as "–".
fn null_if_zero(v: f64) -> serde_json::Value {
    if v == 0.0 {
        serde_json::Value::Null
    } else {
        serde_json::json!(v)
    }
}

/// A host gauge cell (O52, NAN-1721): distinguish an ABSENT reading — the host
/// never reported the metric, so its count companion `*_n` == 0 — from a genuine
/// reported `0.0`. Returns `null` only when the companion says there were no
/// data points; a reported `0.0` stays `0.0` (an idle host at 0% CPU is real,
/// not "–"). `value` is the already-derived reading (e.g. cpu_util × 100); the
/// companion counts the raw metric's data points, so the scaling is irrelevant.
///
/// When the count companion column is NOT present in the row (the SQL has not
/// yet been extended to emit `cpu_n`/`mem_n`/`load_n`/`net_n`) this FALLS BACK
/// to the legacy [`null_if_zero`] behavior so a reading is never silently
/// zeroed-out wholesale — the fix activates once the companion columns land.
fn gauge_or_null(row: &serde_json::Value, value: f64, count_key: &str) -> serde_json::Value {
    match json_f64_opt(row, count_key) {
        // Companion present: 0 data points → absent → null; else the real value.
        Some(n) if n <= 0.0 => serde_json::Value::Null,
        Some(_) => serde_json::json!(value),
        // Companion absent (SQL not updated yet): preserve legacy behavior.
        None => null_if_zero(value),
    }
}

/// A web-vital p75 cell: `null` when the count companion (`*_n`) is 0 (no data
/// points in the window), else the value (NAN-1537). Distinguishes a true 0.0
/// p75 from "no vitals reported".
fn vital_or_null(row: &serde_json::Value, value_key: &str, count_key: &str) -> serde_json::Value {
    if json_f64(row, count_key) <= 0.0 {
        serde_json::Value::Null
    } else {
        serde_json::json!(json_f64(row, value_key))
    }
}
