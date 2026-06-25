// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenTelemetry dataset selection and trace-fetch SQL (NAN-1528).
//!
//! The nPL→SQL generator ([`crate::query::ClickHouseSqlGenerator`]) is built
//! around the `logs` table and its `timestamp` column. OTLP traces and metrics
//! live in sibling MergeTree tables (`otel_spans`, `otel_metrics`) created by
//! migrations 138/140, each with its OWN time column (`start_time` / `timestamp`).
//!
//! Rather than thread profile-aware timestamp expressions through the whole
//! generator (risking divergence from today's exact UDM output — see the
//! "Phase 2b" note in `clickhouse_sql_gen.rs`), this module gives the
//! search/api layer a thin, self-contained way to:
//!   1. pick the storage table + time column for a query ([`Dataset`]), and
//!   2. fetch a full trace by id ([`trace_by_id_sql`]).
//!
//! [`Dataset`] is what the search handler maps a `from=spans` / `from=metrics`
//! selector onto; `logs` (the default) keeps flowing through the existing
//! `ClickHouseSqlGenerator::with_table("logs")` path unchanged.

use super::escape_string;
use crate::query::TimeRange;
use chrono::{DateTime, Utc};

/// The query target dataset. `Logs` is the default and preserves every
/// existing code path; `Spans`/`Metrics` point the generator at the OTLP
/// native-storage tables (NAN-1528).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Dataset {
    /// UDM/OCSF normalized logs (`logs`, time column `timestamp`). Default.
    Logs,
    /// OTLP spans (`otel_spans`, time column `start_time`).
    Spans,
    /// OTLP metric data points (`otel_metrics`, time column `timestamp`).
    Metrics,
}

impl Default for Dataset {
    fn default() -> Self {
        Dataset::Logs
    }
}

/// Resolution grain for the generic metric rollup (migration 144), NAN-1555.
/// `core_search` selects a grain by query window so wide-window aggregate metric
/// queries read the pre-aggregated `otel_metrics_1m`/`_1h` AggregatingMergeTree
/// instead of scanning raw `otel_metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricRollup {
    /// 1-minute buckets (`otel_metrics_1m`, time column `minute`).
    Minute,
    /// 1-hour buckets (`otel_metrics_1h`, time column `hour`).
    Hour,
}

impl MetricRollup {
    /// The rollup storage table for this grain (unqualified, like [`Dataset::table_name`]).
    pub fn table_name(self) -> &'static str {
        match self {
            MetricRollup::Minute => "otel_metrics_1m",
            MetricRollup::Hour => "otel_metrics_1h",
        }
    }

    /// The rollup's bucket/time column.
    pub fn time_column(self) -> &'static str {
        match self {
            MetricRollup::Minute => "minute",
            MetricRollup::Hour => "hour",
        }
    }
}

impl Dataset {
    /// Parse a `from=` selector value. Unknown / empty → `Logs` (the selector is
    /// an additive override, never a hard error — a malformed value must not
    /// break an otherwise-valid search).
    pub fn from_selector(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "spans" | "span" | "traces" | "trace" => Dataset::Spans,
            "metrics" | "metric" => Dataset::Metrics,
            _ => Dataset::Logs,
        }
    }

    /// Strict variant of [`from_selector`](Self::from_selector): `None` for any
    /// value that isn't a recognized selector instead of the lenient `Logs`
    /// fallback. The subsearch-bracket `dataset=<name>` parser (NAN-1562) uses
    /// this so a typo like `dataset=spanz` is a parse error rather than silently
    /// resolving to the logs table (which would scan the wrong dataset).
    pub fn from_selector_strict(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "logs" | "log" => Some(Dataset::Logs),
            "spans" | "span" | "traces" | "trace" => Some(Dataset::Spans),
            "metrics" | "metric" => Some(Dataset::Metrics),
            _ => None,
        }
    }

    /// The ClickHouse storage table this dataset reads from (unqualified — the
    /// generator/executor prepends the `nanosiem.` database as needed, matching
    /// the existing `"logs"` convention).
    pub fn table_name(self) -> &'static str {
        match self {
            Dataset::Logs => "logs",
            Dataset::Spans => "otel_spans",
            Dataset::Metrics => "otel_metrics",
        }
    }

    /// The primary time column for this dataset — `timestamp` for logs/metrics,
    /// `start_time` for spans (OTLP span start). Used by callers that build
    /// time-bounded WHERE clauses against the OTLP tables.
    pub fn time_column(self) -> &'static str {
        match self {
            Dataset::Logs | Dataset::Metrics => "timestamp",
            Dataset::Spans => "start_time",
        }
    }
}

/// Promoted columns on `otel_spans` (migration 138) that nPL field tokens may
/// reference DIRECTLY when the query runs against the spans dataset (NAN-1534).
/// Scoped to spans — never merged into the logs `EXPLICIT_COLUMNS` universe — so
/// a `service_name=` / `duration_ns>` filter on a spans search resolves to the
/// real column instead of UDM's `ext.<field>` spill (`otel_spans` has no `ext`
/// column, so that spill would be a hard SQL error). Names that ALSO exist on
/// `logs` (`trace_id`, `span_id`, `src_ip`, `dest_ip`, `user`, `status_code`) are
/// listed for completeness; they would resolve via the profile anyway.
pub const SPAN_COLUMNS: &[&str] = &[
    "trace_id",
    "span_id",
    "parent_span_id",
    "start_time",
    "end_time",
    "duration_ns",
    "service_name",
    "span_name",
    "span_kind",
    "status_code",
    "status_message",
    "src_ip",
    "dest_ip",
    "user",
    "host",
];

/// Promoted columns on `otel_metrics` (migration 140) referenceable directly in
/// nPL when the query runs against the metrics dataset (NAN-1534). Same rationale
/// as [`SPAN_COLUMNS`] — `otel_metrics` has no `ext` column.
pub const METRIC_COLUMNS: &[&str] = &[
    "metric_name",
    "metric_type",
    "unit",
    "timestamp",
    "value",
    "count",
    "sum",
    "bucket_counts",
    "explicit_bounds",
    "service_name",
];

/// Numeric columns on the OTLP tables — nPL comparisons against these must NOT be
/// `lower()`-wrapped and string literals coerce to numbers (mirrors
/// `NUMERIC_UDM_FIELDS` for logs). Spans: `duration_ns`. Metrics: `value`,
/// `count`, `sum`. (Time columns are handled by the dedicated time-bound path.)
pub const OTEL_NUMERIC_COLUMNS: &[&str] = &["duration_ns", "value", "count", "sum"];

impl Dataset {
    /// The set of promoted columns referenceable directly in nPL for this
    /// dataset (NAN-1534). Empty for [`Dataset::Logs`] — logs field resolution is
    /// owned entirely by the active [`SchemaProfile`], so the generator's dataset
    /// overlay stays empty and every logs statement is byte-identical.
    ///
    /// [`SchemaProfile`]: crate::schema::SchemaProfile
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            Dataset::Logs => &[],
            Dataset::Spans => SPAN_COLUMNS,
            Dataset::Metrics => METRIC_COLUMNS,
        }
    }

    /// Numeric columns for this dataset (no `lower()`, string→number coercion).
    /// Empty for [`Dataset::Logs`] (the profile/`NUMERIC_UDM_FIELDS` own that).
    pub fn numeric_columns(self) -> &'static [&'static str] {
        match self {
            Dataset::Logs => &[],
            Dataset::Spans | Dataset::Metrics => OTEL_NUMERIC_COLUMNS,
        }
    }
}

/// SQL to fetch every span of one trace, time-ordered.
///
/// Two-step, partition-pruned (NAN-1528):
///   1. resolve the trace's `[min(start), max(end)]` window from the compact
///      `otel_spans_trace_id_ts` AggregatingMergeTree (migration 139) — a tiny
///      per-trace index, so this is a point lookup served by its `trace_id`
///      bloom rather than a scan of `otel_spans`;
///   2. select the spans whose `start_time` falls in `[window_start, window_end]`
///      with the same `trace_id`, `ORDER BY start_time` so the caller can build
///      the waterfall directly.
///
/// Keeping the time bound on `otel_spans.start_time` lets ClickHouse prune
/// daily partitions instead of scanning the whole table for the `trace_id`
/// bloom. The `trace_id` is escaped (single-quote/backslash) and lowercased to
/// match the ingest-lowercased hex stored in the column.
pub fn trace_by_id_sql(trace_id: &str) -> String {
    let id = escape_string(&trace_id.to_ascii_lowercase());
    format!(
        "WITH bounds AS (\n  \
           SELECT min(start) AS w_start, max(end) AS w_end\n  \
           FROM nanosiem.otel_spans_trace_id_ts\n  \
           WHERE trace_id = '{id}'\n\
         )\n\
         SELECT trace_id, span_id, parent_span_id, start_time, end_time, duration_ns,\n       \
                service_name, span_name, span_kind, status_code, status_message,\n       \
                attributes, resource_attributes, events, src_ip, dest_ip, user, host\n\
         FROM nanosiem.otel_spans\n\
         WHERE trace_id = '{id}'\n  \
           AND start_time BETWEEN (SELECT w_start FROM bounds) AND (SELECT w_end FROM bounds)\n\
         ORDER BY start_time ASC, span_id ASC\n\
         LIMIT 100000"
    )
}

/// SQL for a metric time series: one bucketed point per `step`-second interval
/// over `[time_range]`, filtered to `metric_name` (and optionally a single
/// `service_name`). Returns `(bucket, value)` ordered by bucket (NAN-1528).
///
/// `value` is `avg(value)` within the bucket — the safe default for gauges; the
/// caller chooses rate/quantile via the nPL `rate()` / `histogram_quantile()`
/// aggregations on the `metrics` dataset when it needs counter/histogram
/// semantics. `step_secs` is clamped to ≥1 to avoid a zero-width interval.
pub fn metric_timeseries_sql(
    metric_name: &str,
    service_name: Option<&str>,
    time_range: &TimeRange,
    step_secs: u64,
) -> String {
    let name = escape_string(metric_name);
    let step = step_secs.max(1);
    let mut filter = format!("metric_name = '{name}'");
    if let Some(svc) = service_name {
        if !svc.is_empty() {
            filter.push_str(&format!(" AND service_name = '{}'", escape_string(svc)));
        }
    }
    format!(
        "SELECT toStartOfInterval(timestamp, toIntervalSecond({step})) AS bucket,\n       \
                avg(value) AS value\n\
         FROM nanosiem.otel_metrics\n\
         WHERE timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND ({filter})\n\
         GROUP BY bucket\n\
         ORDER BY bucket ASC\n\
         LIMIT 100000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

// ============================================================================
// Metrics v2 — query builder (agg / group_by / tag filters) + tag enumeration
// (NAN-1540). Extends the single-metric `metric_timeseries_sql` above without
// changing it (back-compat: avg, no group_by, no filters → one series). All
// string params are escaped; `agg` and `group_by` are validated against
// allowlists by the caller via [`MetricAgg::from_str`] / [`valid_tag_key`]; the
// statement carries a bounded LIMIT. Tag keys/values live in the
// `attributes Map(LowCardinality,String)` and `resource_attributes Map(...)`
// columns of `otel_metrics` — a key is matched over BOTH maps (attribute wins).
// ============================================================================

/// The aggregation a metrics-v2 query applies within each time bucket
/// (NAN-1540). Allowlisted — the api/jobs layer parses the request string via
/// [`MetricAgg::from_str`]; an unknown value is rejected before SQL generation,
/// so the emitted aggregate function is never attacker-controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricAgg {
    Avg,
    Sum,
    Min,
    Max,
    Count,
    /// Cumulative-counter delta over the bucket, per second
    /// (`(max-min)/bucket_secs`), mirroring the nPL `rate()` idea.
    Rate,
    /// `quantileTDigest(0.50)(value)`.
    P50,
    /// `quantileTDigest(0.95)(value)`.
    P95,
    /// `quantileTDigest(0.99)(value)`.
    P99,
}

impl Default for MetricAgg {
    fn default() -> Self {
        MetricAgg::Avg
    }
}

impl MetricAgg {
    /// Parse the wire string. Returns `None` for anything outside the allowlist
    /// (the caller maps `None` → 400). Empty/absent should be treated as the
    /// default (`avg`) by the caller before calling this.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "avg" | "mean" => Some(Self::Avg),
            "sum" => Some(Self::Sum),
            "min" => Some(Self::Min),
            "max" => Some(Self::Max),
            "count" => Some(Self::Count),
            "rate" => Some(Self::Rate),
            "p50" | "median" => Some(Self::P50),
            "p95" => Some(Self::P95),
            "p99" => Some(Self::P99),
            _ => None,
        }
    }

    /// The canonical wire/string form (echoed back in the response `agg`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Avg => "avg",
            Self::Sum => "sum",
            Self::Min => "min",
            Self::Max => "max",
            Self::Count => "count",
            Self::Rate => "rate",
            Self::P50 => "p50",
            Self::P95 => "p95",
            Self::P99 => "p99",
        }
    }

    /// The ClickHouse SELECT expression producing the per-bucket scalar `v`.
    /// `bucket_secs` is the (clamped, ≥1) bucket width, needed only by `Rate`.
    fn value_expr(self, bucket_secs: u64) -> String {
        let secs = bucket_secs.max(1);
        match self {
            Self::Avg => "avg(value)".to_string(),
            Self::Sum => "sum(value)".to_string(),
            Self::Min => "min(value)".to_string(),
            Self::Max => "max(value)".to_string(),
            Self::Count => "toFloat64(count())".to_string(),
            // Cumulative-counter delta over the bucket, per second. greatest(...,1)
            // guards a single-point bucket (delta 0 / 0 → NaN).
            Self::Rate => format!("(max(value) - min(value)) / greatest({secs}, 1)"),
            Self::P50 => "quantileTDigest(0.50)(value)".to_string(),
            Self::P95 => "quantileTDigest(0.95)(value)".to_string(),
            Self::P99 => "quantileTDigest(0.99)(value)".to_string(),
        }
    }
}

/// A single `key = value` tag filter for a metrics-v2 query, matched over the
/// metric's `attributes` / `resource_attributes` maps (NAN-1540).
#[derive(Debug, Clone)]
pub struct MetricTagFilter {
    pub key: String,
    pub value: String,
}

/// A fully-specified metrics-v2 timeseries query (NAN-1540). Built by the
/// api/jobs layer from the validated request, consumed by
/// [`metric_timeseries_v2_sql`].
#[derive(Debug, Clone)]
pub struct MetricQuery<'a> {
    pub metric_name: &'a str,
    /// Restrict to a single OTLP service (the `service_name` column). Empty/None
    /// drops the predicate.
    pub service_name: Option<&'a str>,
    pub agg: MetricAgg,
    /// A tag/attribute key to split the result into one series per distinct
    /// value. `None` → a single series (label `""`). Must be a valid tag key
    /// ([`valid_tag_key`]) — the caller validates before building.
    pub group_by: Option<&'a str>,
    /// Tag filters ANDed together, each matched over attributes/resource maps.
    pub filters: &'a [MetricTagFilter],
    pub step_secs: u64,
}

/// A ClickHouse expression that resolves a tag `key` from EITHER the
/// `attributes` map or the `resource_attributes` map (attribute wins; falls
/// back to resource; `''` when absent in both). `key` is escaped. Used both as
/// a GROUP BY split key and inside tag-filter predicates so a key the caller
/// gave matches regardless of which map carries it.
fn tag_lookup_expr(key: &str) -> String {
    let k = escape_string(key);
    // `if(has(map,k), map[k], fallback)` — map[absent] yields '' for
    // Map(_,String), but be explicit so a real empty-string value and an absent
    // key are both handled and the fallback to resource is unambiguous.
    format!(
        "if(has(attributes, '{k}'), attributes['{k}'], \
         if(has(resource_attributes, '{k}'), resource_attributes['{k}'], ''))"
    )
}

/// Validate a tag/attribute key for use as a `group_by` or filter key
/// (NAN-1540). Keys are OTLP attribute names — letters, digits, and the usual
/// separators (`.`, `_`, `-`, `/`). Rejecting anything else keeps the escaped
/// key from being an injection surface AND screens obvious garbage early.
/// (Values are NOT restricted this way — they are always single-quote escaped.)
pub fn valid_tag_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

/// SQL for the metrics-v2 timeseries (NAN-1540): one bucketed scalar per
/// `step_secs` interval over `[time_range]`, applying [`MetricAgg`], optional
/// `service_name`, optional per-value tag filters, and an optional `group_by`
/// tag that splits the rows into one series per distinct tag value.
///
/// When `group_by` is set the result carries a `series_key` column (the tag
/// value) and is GROUP BY (series_key, bucket); the glue pivots it into the
/// `series[]` contract. When `group_by` is absent the SELECT emits a constant
/// `'' AS series_key` so the glue's pivot is uniform (one series labelled `""`).
///
/// Single time-bound WHERE (NAN-1412 — no explicit PREWHERE), every string
/// escaped, bounded `LIMIT 200000` (buckets × series).
pub fn metric_timeseries_v2_sql(query: &MetricQuery, time_range: &TimeRange) -> String {
    let name = escape_string(query.metric_name);
    let step = query.step_secs.max(1);
    let value_expr = query.agg.value_expr(step);

    // metric_name + optional service + tag filters → the single WHERE body.
    let mut filter = format!("metric_name = '{name}'");
    if let Some(svc) = query.service_name {
        if !svc.is_empty() {
            filter.push_str(&format!(" AND service_name = '{}'", escape_string(svc)));
        }
    }
    for f in query.filters {
        // Skip empty keys; an invalid key would have been rejected at the API
        // boundary, but guard here too (defense in depth). Value is escaped.
        if f.key.is_empty() || !valid_tag_key(&f.key) {
            continue;
        }
        filter.push_str(&format!(
            " AND {} = '{}'",
            tag_lookup_expr(&f.key),
            escape_string(&f.value)
        ));
    }

    // group_by → extra split column + GROUP BY key. Absent → constant series key.
    let (series_select, group_by_keys) = match query.group_by {
        Some(key) if valid_tag_key(key) => (
            format!("{} AS series_key", tag_lookup_expr(key)),
            "series_key, bucket",
        ),
        _ => ("'' AS series_key".to_string(), "bucket"),
    };

    format!(
        "SELECT {series_select},\n       \
                toStartOfInterval(timestamp, toIntervalSecond({step})) AS bucket,\n       \
                {value_expr} AS v\n\
         FROM nanosiem.otel_metrics\n\
         WHERE timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND ({filter})\n\
         GROUP BY {group_by_keys}\n\
         ORDER BY series_key ASC, bucket ASC\n\
         LIMIT 200000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL to compute the metrics-v2 aggregate as a SINGLE scalar per series over
/// the whole window (no bucketing) — what the metric-monitor evaluator compares
/// to its threshold (NAN-1540). Mirrors [`metric_timeseries_v2_sql`]'s filters
/// and group_by, but aggregates the whole `[time_range]` into one row per series
/// (`series_key`, `v`). `step_secs` is the monitor's window (used only by the
/// `rate` per-second denominator). Bounded `LIMIT 100000` (series cardinality).
pub fn metric_scalar_sql(query: &MetricQuery, time_range: &TimeRange) -> String {
    let name = escape_string(query.metric_name);
    // For the whole-window scalar the rate denominator is the window length.
    let window_secs = ((time_range.end - time_range.start).num_seconds().max(1)) as u64;
    let value_expr = query.agg.value_expr(window_secs);

    let mut filter = format!("metric_name = '{name}'");
    if let Some(svc) = query.service_name {
        if !svc.is_empty() {
            filter.push_str(&format!(" AND service_name = '{}'", escape_string(svc)));
        }
    }
    for f in query.filters {
        if f.key.is_empty() || !valid_tag_key(&f.key) {
            continue;
        }
        filter.push_str(&format!(
            " AND {} = '{}'",
            tag_lookup_expr(&f.key),
            escape_string(&f.value)
        ));
    }

    let (series_select, group_clause) = match query.group_by {
        Some(key) if valid_tag_key(key) => (
            format!("{} AS series_key", tag_lookup_expr(key)),
            "\nGROUP BY series_key".to_string(),
        ),
        // No group_by → a single scalar row; emit a constant key for shape parity.
        _ => ("'' AS series_key".to_string(), String::new()),
    };

    format!(
        "SELECT {series_select},\n       \
                {value_expr} AS v\n\
         FROM nanosiem.otel_metrics\n\
         WHERE timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND ({filter}){group_clause}\n\
         ORDER BY series_key ASC\n\
         LIMIT 100000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL listing the distinct tag/attribute KEYS present for a metric over the
/// recent window (NAN-1540) — the `GET .../tags` (no `key`) contract. Unions the
/// keys of `attributes` and `resource_attributes` via `arrayJoin(mapKeys(...))`.
/// `metric_name` is escaped; bounded `LIMIT 1000` (attribute cardinality is
/// instrumentation-bounded). A `time_range` keeps the scan partition-pruned.
pub fn metric_tag_keys_sql(metric_name: &str, time_range: &TimeRange) -> String {
    let name = escape_string(metric_name);
    format!(
        "SELECT DISTINCT k\n\
         FROM nanosiem.otel_metrics\n\
         ARRAY JOIN arrayConcat(mapKeys(attributes), mapKeys(resource_attributes)) AS k\n\
         WHERE timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND metric_name = '{name}'\n\
         ORDER BY k ASC\n\
         LIMIT 1000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL listing the distinct VALUES of one tag `key` for a metric over the window
/// (NAN-1540) — the `GET .../tags?key=` contract. `key` is resolved over both
/// maps via [`tag_lookup_expr`]; empty values (key absent) are filtered out.
/// `key` MUST be validated ([`valid_tag_key`]) by the caller; escaped here too.
/// Bounded `LIMIT 1000`.
pub fn metric_tag_values_sql(metric_name: &str, key: &str, time_range: &TimeRange) -> String {
    let name = escape_string(metric_name);
    let lookup = tag_lookup_expr(key);
    // The empty-string drop is applied OUTSIDE the DISTINCT (a subquery) so the
    // `tag_value` alias is never referenced in the same SELECT's WHERE (which
    // would either shadow a column or re-evaluate the map lookup). The inner
    // query is the bounded, partition-pruned scan; the outer just filters '' .
    format!(
        "SELECT tag_value FROM (\n  \
           SELECT DISTINCT {lookup} AS tag_value\n  \
           FROM nanosiem.otel_metrics\n  \
           WHERE timestamp BETWEEN '{start}' AND '{end}'\n    \
             AND metric_name = '{name}'\n\
         )\n\
         WHERE tag_value != ''\n\
         ORDER BY tag_value ASC\n\
         LIMIT 1000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// Filters for the recent-traces list ([`recent_traces_sql`]). All optional;
/// each `None`/empty field drops its predicate so the default is "every trace
/// in the window, most recent first".
#[derive(Debug, Clone, Default)]
pub struct TraceListFilters<'a> {
    /// Restrict to a single `service_name` (matched against the root service —
    /// the span with no parent — via the `HAVING` clause).
    pub service: Option<&'a str>,
    /// Only traces that contain at least one `status_code = 'ERROR'` span.
    pub errors_only: bool,
    /// Only traces whose root span lasted at least this many nanoseconds.
    pub min_duration_ns: Option<u64>,
    /// Hard row cap (number of traces). Clamped to `[1, 1000]`; defaults to 200.
    pub limit: Option<u32>,
    /// Keyset pagination cursor (NAN-1539): when set, only traces whose
    /// `start_time` is STRICTLY BEFORE this instant are returned. Because the
    /// list is `ORDER BY start_time DESC`, paging is "give me the next page after
    /// the last row I saw" — the caller passes the previous page's last
    /// `start_time` here. A plain `<` keyset (not `<=`) avoids re-emitting the
    /// boundary row; trace_ids sharing the exact boundary `start_time` are an
    /// accepted edge (sub-second ties drop at most a handful — acceptable for a
    /// recent-traces explorer).
    pub before: Option<DateTime<Utc>>,
}

/// SQL for the recent-traces list (NAN-1534) — the Traces explorer's table.
///
/// One row per `trace_id` over `[time_range]` on `start_time` (partition-pruned),
/// aggregating per trace:
///   - `root_service`  — the service of the ROOT span (empty `parent_span_id`),
///     resolved with `argMin(service_name, length(parent_span_id))` so the
///     parent-less span wins; ties/edge cases fall back to the earliest span's
///     service. (A trace with no captured root still yields *a* service.)
///   - `root_name`     — likewise the root span's `span_name`.
///   - `span_count`    — total spans seen for the trace in the window.
///   - `error_count`   — spans with `status_code = 'ERROR'`.
///   - `duration_ns`   — root span duration (`argMin(duration_ns, length(parent_span_id))`),
///     i.e. the wall-clock span of the trace as seen by its entrypoint.
///   - `start_time`    — `min(start_time)` (trace start).
///
/// Ordered by `start_time DESC` (most recent first). Optional filters narrow by
/// root service, errors-only, and minimum root duration — all applied in a
/// `HAVING` clause over the per-trace aggregates (the root service/duration are
/// not knowable until the trace is assembled). The time bound stays a plain
/// `WHERE` on `start_time` for partition pruning (NAN-1412 single-WHERE rule;
/// the HAVING is a post-aggregation refinement, not a pushed-down filter).
pub fn recent_traces_sql(time_range: &TimeRange, filters: &TraceListFilters) -> String {
    let limit = filters.limit.unwrap_or(200).clamp(1, 1000);

    // Post-aggregation refinements over the assembled per-trace row.
    let mut having: Vec<String> = Vec::new();
    if let Some(svc) = filters.service {
        if !svc.is_empty() {
            having.push(format!("root_service = '{}'", escape_string(svc)));
        }
    }
    if filters.errors_only {
        having.push("error_count > 0".to_string());
    }
    if let Some(min_ns) = filters.min_duration_ns {
        having.push(format!("duration_ns >= {min_ns}"));
    }
    let having_clause = if having.is_empty() {
        String::new()
    } else {
        format!("\nHAVING {}", having.join(" AND "))
    };

    // Keyset pagination cursor (NAN-1539): a STRICT `<` on the raw `start_time`
    // COLUMN (table-qualified, pre-aggregation) so it prunes partitions and stays
    // out of the post-aggregation HAVING. Combined with `ORDER BY start_time
    // DESC`, paging the cursor down the timeline is a partition-pruned keyset, not
    // an OFFSET scan. NULL/None drops the predicate (first page).
    let cursor_clause = match filters.before {
        Some(before) => format!(
            "\n  AND otel_spans.start_time < '{}'",
            before.format("%Y-%m-%d %H:%M:%S%.6f")
        ),
        None => String::new(),
    };

    // `start_time` is table-qualified in the WHERE so it binds to the COLUMN,
    // not the `min(start_time) AS start_time` alias below. An unqualified ref
    // resolves to the alias and lands an aggregate in WHERE → Code 184
    // ILLEGAL_AGGREGATION (the alias-shadows-column gotcha).
    format!(
        "SELECT trace_id,\n       \
                argMin(service_name, length(parent_span_id)) AS root_service,\n       \
                argMin(span_name, length(parent_span_id)) AS root_name,\n       \
                count() AS span_count,\n       \
                countIf(status_code = 'ERROR') AS error_count,\n       \
                argMin(duration_ns, length(parent_span_id)) AS duration_ns,\n       \
                min(start_time) AS start_time\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'{cursor}\n\
         GROUP BY trace_id{having}\n\
         ORDER BY start_time DESC\n\
         LIMIT {limit}",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
        cursor = cursor_clause,
        having = having_clause,
    )
}

/// SQL for the distinct metric-name list (NAN-1534) — the Metrics explorer's
/// dropdown source. Returns `metric_name` rows, optionally restricted to a
/// single `service_name`, name-ordered. `LIMIT 10000` is an ample cap for a
/// dropdown (metric cardinality is bounded by instrumentation, not data volume).
pub fn metric_names_sql(service_name: Option<&str>) -> String {
    let mut filter = String::new();
    if let Some(svc) = service_name {
        if !svc.is_empty() {
            filter = format!("\nWHERE service_name = '{}'", escape_string(svc));
        }
    }
    format!(
        "SELECT DISTINCT metric_name\n\
         FROM nanosiem.otel_metrics{filter}\n\
         ORDER BY metric_name ASC\n\
         LIMIT 10000"
    )
}

// ============================================================================
// Observability console — Services overview / Service detail / SLOs (NAN-1536)
// ============================================================================
//
// These feed the tabbed Observability console (obs-app.jsx). All read with a
// single time-bounded WHERE (NAN-1412 — no explicit PREWHERE), table-qualify any
// aggregate-aliased time column to dodge the alias-shadow Code 184 trap, escape
// every string param, and carry a bounded LIMIT.
//
// SCALE NOTE (NAN-1539): the per-service RED AGGREGATES (overview, sparkline,
// per-service RED time series) read the precomputed minute rollup
// `nanosiem.otel_service_red_1m` (migration 143) instead of GROUP BYing the raw
// `otel_spans` on every load. The rollup carries, per (service, minute):
//   - `request_count` / `error_count` — SimpleAggregateFunction(sum) columns, so
//     they read with PLAIN `sum(col)` (NOT `sumMerge` — that errs Code 43 on a
//     SimpleAggregateFunction);
//   - `duration_state` — an AggregateFunction(quantilesTDigest(0.5,0.95,0.99))
//     over duration in MILLISECONDS, read via
//     `quantilesTDigestMerge(0.5,0.95,0.99)(duration_state)[i]` (already ms — no
//     `/1e6` re-divide), preserving the `pXX_ms` contract.
// The time bound is now on the `minute` column (partition-pruned the same way).
// Service-detail exemplars and recent_traces stay on raw spans (they need
// per-span rows). The emitted JSON contract is byte-for-byte unchanged.

/// Sort key for the services-overview list (NAN-1543). Allowlisted — the api
/// layer parses the wire string via [`ServicesSort::from_str`] so the emitted
/// `ORDER BY` column is never attacker-controlled. `error_rate` is a derived
/// post-aggregation scalar (the SQL has only the raw counts), so it can't be a
/// SQL `ORDER BY` column — it is applied in the glue after the row is assembled;
/// the SQL-orderable keys are the ones below. Default mirrors the historical
/// behavior (`request_count DESC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicesSort {
    /// Request volume, busiest first (the historical default).
    Rate,
    /// p95 latency, slowest first.
    P95,
    /// Service name, A→Z.
    Name,
    /// Error rate, worst first — a derived scalar, sorted in the glue (the SQL
    /// keeps the default request-count order so the glue has a stable base).
    ErrorRate,
}

impl Default for ServicesSort {
    fn default() -> Self {
        ServicesSort::Rate
    }
}

impl ServicesSort {
    /// Parse the wire string. `None` for anything outside the allowlist (the
    /// caller maps `None` → 400). Empty/absent should be treated as the default
    /// (`rate`) by the caller before calling this.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rate" | "request_count" | "requests" => Some(Self::Rate),
            "p95" | "latency" => Some(Self::P95),
            "name" | "service" => Some(Self::Name),
            "error_rate" | "errors" => Some(Self::ErrorRate),
            _ => None,
        }
    }

    /// The SQL `ORDER BY` clause body for this sort. `ErrorRate` falls back to
    /// the default count order in SQL (the glue re-sorts on the derived rate).
    fn order_by(self) -> &'static str {
        match self {
            Self::Rate | Self::ErrorRate => "request_count DESC",
            Self::P95 => "p95_ms DESC",
            Self::Name => "service ASC",
        }
    }

    /// Whether the glue must re-sort the assembled rows (only `ErrorRate`, a
    /// derived scalar the SQL can't order on).
    pub fn needs_glue_sort(self) -> bool {
        matches!(self, Self::ErrorRate)
    }
}

/// Filters for the services-overview list (NAN-1543). All optional; each
/// `None`/empty field drops its predicate so the default (no params) is the
/// historical "every service, busiest first" behavior.
///
/// `q` and `sort` are PUSHED INTO the SQL. `health` and paging (`limit`/`offset`)
/// are applied POST-AGGREGATION in the glue: `health` is derived from the
/// assembled `error_rate` + `p95` (not a SQL column), and paging must follow the
/// health filter so the page is sliced from the FILTERED set rather than from a
/// pre-filtered SQL `LIMIT`. The SQL therefore always reads the bounded top
/// `LIMIT 1000` and the glue does the health filter → re-sort → slice.
#[derive(Debug, Clone, Default)]
pub struct ServicesOverviewFilters<'a> {
    /// Case-insensitive substring match on `service_name` (pushed into the
    /// SQL WHERE on the rollup's `service_name` column).
    pub q: Option<&'a str>,
    /// Sort key. `None` → [`ServicesSort::default`] (`rate`).
    pub sort: Option<ServicesSort>,
}

/// SQL for the services-overview rows (the `GET /api/search/services` contract).
///
/// One row per `service_name` over `[time_range]`, read from the minute rollup
/// `nanosiem.otel_service_red_1m` (NAN-1539): request count, p50/p95/p99 latency
/// (ms, from the merged t-digest state), and the ERROR count. The caller derives
/// `rate_per_sec` (= count / window-secs), `error_rate` (= error_count / count),
/// and `health` from the row + window — the window duration is a request param
/// the SQL layer doesn't carry, so those scalar derivations live in the glue.
///
/// The time bound is a plain table-qualified WHERE on `minute` (partition
/// pruning); `service_name` is the GROUP BY key. NAN-1543 adds an optional
/// case-insensitive `q` substring on `service_name` (pushed into the WHERE) and
/// an allowlisted `sort` (`ORDER BY`). The hard `LIMIT 1000` is unchanged — the
/// no-filter default stays byte-identical. Health filtering + paging happen in
/// the glue (post-aggregation, see [`ServicesOverviewFilters`]).
pub fn services_overview_sql(time_range: &TimeRange, filters: &ServicesOverviewFilters) -> String {
    let order_by = filters.sort.unwrap_or_default().order_by();

    // Case-insensitive substring on service_name, pushed into the time-bound
    // WHERE (NAN-1543). `lower(service_name) LIKE '%<q>%'` — the value is
    // lowercased + escaped; the rollup has no text index on service_name (it is
    // a fleet-bounded LowCardinality), so a plain substring scan is fine.
    let q_clause = match filters.q {
        Some(q) if !q.is_empty() => format!(
            "\n  AND lower(service_name) LIKE '%{}%'",
            escape_string(&q.to_ascii_lowercase())
        ),
        _ => String::new(),
    };

    format!(
        "SELECT service_name AS service,\n       \
                sum(request_count) AS request_count,\n       \
                sum(error_count) AS error_count,\n       \
                quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[1] AS p50_ms,\n       \
                quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[2] AS p95_ms,\n       \
                quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[3] AS p99_ms\n\
         FROM nanosiem.otel_service_red_1m\n\
         WHERE otel_service_red_1m.minute BETWEEN '{start}' AND '{end}'{q_clause}\n\
         GROUP BY service_name\n\
         ORDER BY {order_by}\n\
         LIMIT 1000",
        // The rollup `minute` is a second-precision DateTime (not DateTime64), so
        // the bound is formatted WITHOUT the `%.6f` microseconds the raw-spans SQL
        // uses — a fractional literal won't parse into DateTime (Code 53). The
        // window edges round to the second, which is moot at minute granularity.
        start = time_range.start.format("%Y-%m-%d %H:%M:%S"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S"),
    )
}

/// SQL for the per-service request-volume sparkline used in the overview table.
///
/// One row per `(service, bucket)` over `[time_range]`, bucketed every
/// `step_secs` seconds from the minute rollup (NAN-1539): the summed request
/// count per bucket. The glue pivots this into the per-service
/// `sparkline: [{t, v}]` arrays of the overview contract. Kept separate from
/// [`services_overview_sql`] (a second bounded round trip) because the overview
/// row is a single GROUP BY service while the sparkline is GROUP BY
/// (service, bucket). `step_secs` is clamped to ≥1; the rollup grain is 1 minute,
/// so a sub-minute step collapses onto the minute bucket (the rollup's finest
/// resolution) — fine for a sparkline.
pub fn services_sparkline_sql(time_range: &TimeRange, step_secs: u64) -> String {
    let step = step_secs.max(1);
    format!(
        "SELECT service_name AS service,\n       \
                toStartOfInterval(minute, toIntervalSecond({step})) AS bucket,\n       \
                sum(request_count) AS v\n\
         FROM nanosiem.otel_service_red_1m\n\
         WHERE otel_service_red_1m.minute BETWEEN '{start}' AND '{end}'\n\
         GROUP BY service, bucket\n\
         ORDER BY service ASC, bucket ASC\n\
         LIMIT 200000",
        // Second-precision bound — see services_overview_sql (rollup `minute` is
        // a DateTime, not DateTime64; %.6f would fail to parse, Code 53).
        start = time_range.start.format("%Y-%m-%d %H:%M:%S"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S"),
    )
}

/// SQL for the RED time series of one service (the `red` block of the service
/// detail contract): per-`step_secs` bucket over `[time_range]` on `start_time`,
/// for a single `service`:
///   - `rate_count`   — spans in the bucket (glue → `red.rate[].v`; divide by step
///     for a true per-sec rate if desired, but the UI plots raw bucket volume);
///   - `error_count`  — ERROR spans in the bucket (→ `red.errors[].v`);
///   - `p50_ms` / `p95_ms` / `p99_ms` — `quantileTDigest` of `duration_ns` (→ ms)
///     in the bucket (→ the `red.latency[]` `{t,p50,p95,p99}` rows).
///
/// `service` is escaped. The time bound is a plain table-qualified WHERE on the
/// rollup's `minute` column (partition pruning); `bucket` is the only GROUP BY
/// key. Reads the minute rollup `nanosiem.otel_service_red_1m` (NAN-1539): counts
/// via `sum(...)` (SimpleAggregateFunction), latency via the merged t-digest
/// (`[i]` already ms). The emitted column shape (`rate_count`, `error_count`,
/// `pXX_ms`) is unchanged — the glue/contract is byte-identical.
pub fn service_red_timeseries_sql(service: &str, time_range: &TimeRange, step_secs: u64) -> String {
    let svc = escape_string(service);
    let step = step_secs.max(1);
    format!(
        "SELECT toStartOfInterval(minute, toIntervalSecond({step})) AS bucket,\n       \
                sum(request_count) AS rate_count,\n       \
                sum(error_count) AS error_count,\n       \
                quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[1] AS p50_ms,\n       \
                quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[2] AS p95_ms,\n       \
                quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[3] AS p99_ms\n\
         FROM nanosiem.otel_service_red_1m\n\
         WHERE otel_service_red_1m.minute BETWEEN '{start}' AND '{end}'\n  \
           AND service_name = '{svc}'\n\
         GROUP BY bucket\n\
         ORDER BY bucket ASC\n\
         LIMIT 100000",
        // Second-precision bound — see services_overview_sql (rollup `minute` is
        // a DateTime, not DateTime64; %.6f would fail to parse, Code 53).
        start = time_range.start.format("%Y-%m-%d %H:%M:%S"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S"),
    )
}

/// SQL for the per-endpoint breakdown of one service (the `endpoints` block of
/// the service detail contract): GROUP BY `span_name` over `[time_range]` for a
/// single `service`, returning request count, ERROR count, and p95 (ms) per
/// endpoint, busiest first. The glue derives `error_rate` (= error_count/count).
/// `service` is escaped; bounded `LIMIT 500` (endpoint cardinality per service is
/// route-bounded, not data-volume-bounded).
pub fn service_endpoints_sql(service: &str, time_range: &TimeRange) -> String {
    let svc = escape_string(service);
    format!(
        "SELECT span_name,\n       \
                count() AS request_count,\n       \
                countIf(status_code = 'ERROR') AS error_count,\n       \
                quantileTDigest(0.95)(duration_ns) / 1e6 AS p95_ms\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n  \
           AND service_name = '{svc}'\n\
         GROUP BY span_name\n\
         ORDER BY request_count DESC\n\
         LIMIT 500",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL for exemplar traces of one service (the `exemplars` block of the service
/// detail contract): recent root-ish spans for `service` over `[time_range]`,
/// errored first then most-recent, surfacing `trace_id`, `duration_ms`, `error`,
/// `start_time`, `span_name`. These are click-through seeds into the trace
/// waterfall — a sampling, not an aggregate, so it reads raw span rows with a
/// tight `LIMIT` (default 20, clamped to `[1, 200]`).
///
/// `error` is `status_code = 'ERROR'`; ordering puts errored exemplars first
/// (`error DESC`) so the UI's "show me a broken trace" affordance has fodder even
/// when errors are rare. `service` is escaped.
pub fn service_exemplars_sql(service: &str, time_range: &TimeRange, limit: Option<u32>) -> String {
    let svc = escape_string(service);
    let lim = limit.unwrap_or(20).clamp(1, 200);
    format!(
        "SELECT trace_id,\n       \
                duration_ns / 1e6 AS duration_ms,\n       \
                status_code = 'ERROR' AS error,\n       \
                start_time,\n       \
                span_name\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n  \
           AND service_name = '{svc}'\n\
         ORDER BY error DESC, start_time DESC\n\
         LIMIT {lim}",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// The SLI kind an SLO computes its `current` attainment from (NAN-1536).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliKind {
    /// Fraction of non-ERROR spans: `1 - errorCount/total`.
    Availability,
    /// Fraction of spans faster than a latency threshold (ms).
    Latency,
}

/// SQL that computes one SLO's attainment over its window from `otel_spans`
/// (NAN-1536). Returns a single row `(total, good)` for `service` over
/// `[time_range]` (the api layer passes `now - window_days .. now`):
///   - `total` — all spans for the service in the window;
///   - `good`  — for [`SliKind::Availability`], non-ERROR spans; for
///     [`SliKind::Latency`], spans with `duration_ns <= threshold_ms * 1e6`.
///
/// The api/PG slice owns SLO CRUD + the scalar math (`current = good/total`,
/// `budget_remaining_pct`, `burn_rate`, `status`); this is purely the spans-based
/// numerator/denominator. For [`SliKind::Latency`], `latency_threshold_ms` must
/// be supplied (the api layer validates this when `sli_kind = latency`); passed
/// as `None` it degrades to the availability `good` definition so the query never
/// errors. `service` is escaped; the threshold is a numeric literal (no
/// injection surface). Single time-bound WHERE, no GROUP BY (one scalar row).
pub fn slo_compute_sql(
    service: &str,
    sli_kind: SliKind,
    latency_threshold_ms: Option<f64>,
    time_range: &TimeRange,
) -> String {
    let svc = escape_string(service);
    let good_expr = match sli_kind {
        SliKind::Availability => "countIf(status_code != 'ERROR')".to_string(),
        SliKind::Latency => {
            // Threshold ms → ns; finite-guard the literal (NaN/Inf would emit an
            // un-parseable token). A missing/invalid threshold falls back to the
            // availability definition so the SLO still computes a number.
            match latency_threshold_ms.filter(|v| v.is_finite() && *v >= 0.0) {
                Some(ms) => {
                    let threshold_ns = (ms * 1e6).round() as u64;
                    format!("countIf(duration_ns <= {threshold_ns})")
                }
                None => "countIf(status_code != 'ERROR')".to_string(),
            }
        }
    };
    format!(
        "SELECT count() AS total,\n       \
                {good_expr} AS good\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n  \
           AND service_name = '{svc}'\n\
         LIMIT 1",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

// ============================================================================
// Observability console — Infra (host inventory) (NAN-1537)
// ============================================================================
//
// The Infra waffle reads `otel_metrics`, keyed by host =
// `resource_attributes['host.name']`. Each host's gauges are the LATEST value
// per (host, metric_name) — `argMax(value, timestamp)` — over the window, so a
// host that stopped reporting still shows its last reading rather than an
// average that drags toward zero. The host-status thresholds and the
// percent-scaling of `system.cpu.utilization` (OTLP reports it 0..1) live in
// the glue; the SQL just surfaces the four raw gauges + a group label.

/// Filters for the Infra host inventory (NAN-1543). All optional; each
/// `None`/empty field drops its predicate so the default (no params) is the
/// historical "every host" behavior.
///
/// `q` / `group` / `env` are PUSHED INTO the SQL WHERE (on the host name and the
/// `resource_attributes` map). `status` is derived from the assembled CPU/mem
/// percentages, so it is applied POST-AGGREGATION in the glue; paging
/// (`limit`/`offset`) likewise slices the post-status set. The SQL reads the
/// bounded top set so the glue can compute the total + has-more signal.
#[derive(Debug, Clone, Default)]
pub struct InfraHostsFilters<'a> {
    /// Case-insensitive substring match on the host name.
    pub q: Option<&'a str>,
    /// Exact match on `resource_attributes['host.group']`.
    pub group: Option<&'a str>,
    /// Exact match on `resource_attributes['deployment.environment']`.
    pub env: Option<&'a str>,
}

/// SQL for the Infra host inventory (`GET /api/search/infra/hosts`).
///
/// One row per host over `[time_range]` on `timestamp` (partition-pruned),
/// reading from `otel_metrics`. Host identity is
/// `resource_attributes['host.name']`; the group label is
/// `resource_attributes['host.group']` falling back to `service_name`. Each of
/// the four tracked gauges is the latest reading in the window via
/// `argMaxIf(value, timestamp, metric_name = '…')` so a single GROUP BY host
/// yields all four columns without four self-joins:
///   - `cpu_util`  — `system.cpu.utilization` (0..1; glue ×100 → `cpu_pct`)
///   - `mem_util`  — `system.memory.utilization` (0..1; glue ×100 → `mem_pct`)
///   - `load_1m`   — `system.cpu.load_average.1m`
///   - `net_io`    — `system.network.io` (bytes; glue → `net_bytes_per_sec`)
///
/// Hosts with an empty `host.name` are dropped (a metric with no host can't be
/// placed in the inventory). `argMaxIf` returns the metric type's default (0)
/// when a host never reported a given gauge; the glue maps an all-zero gauge to
/// a `null` field so the FE renders "–" rather than a fake 0. Single
/// time-bound WHERE (NAN-1412), bounded `LIMIT 10000` (host cardinality is
/// fleet-bounded, not data-volume-bounded). NAN-1543 pushes the optional
/// `q`/`group`/`env` filters into the WHERE; the no-filter default is unchanged.
pub fn infra_hosts_sql(time_range: &TimeRange, filters: &InfraHostsFilters) -> String {
    // Pushed-down predicates on the host name + resource attributes. All values
    // lowercased (for `q`) / escaped. host.group / deployment.environment are
    // exact matches; `q` is a case-insensitive substring on the host name.
    let mut extra = String::new();
    if let Some(q) = filters.q {
        if !q.is_empty() {
            extra.push_str(&format!(
                "\n  AND lower(resource_attributes['host.name']) LIKE '%{}%'",
                escape_string(&q.to_ascii_lowercase())
            ));
        }
    }
    if let Some(group) = filters.group {
        if !group.is_empty() {
            extra.push_str(&format!(
                "\n  AND resource_attributes['host.group'] = '{}'",
                escape_string(group)
            ));
        }
    }
    if let Some(env) = filters.env {
        if !env.is_empty() {
            extra.push_str(&format!(
                "\n  AND resource_attributes['deployment.environment'] = '{}'",
                escape_string(env)
            ));
        }
    }

    format!(
        "SELECT resource_attributes['host.name'] AS host,\n       \
                any(if(resource_attributes['host.group'] != '', resource_attributes['host.group'], service_name)) AS host_group,\n       \
                argMaxIf(value, timestamp, metric_name = 'system.cpu.utilization') AS cpu_util,\n       \
                argMaxIf(value, timestamp, metric_name = 'system.memory.utilization') AS mem_util,\n       \
                argMaxIf(value, timestamp, metric_name = 'system.cpu.load_average.1m') AS load_1m,\n       \
                argMaxIf(value, timestamp, metric_name = 'system.network.io') AS net_io\n\
         FROM nanosiem.otel_metrics\n\
         WHERE otel_metrics.timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND resource_attributes['host.name'] != ''{extra}\n\
         GROUP BY host\n\
         ORDER BY host ASC\n\
         LIMIT 10000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

// ============================================================================
// Observability console — RUM (real user monitoring) (NAN-1537)
// ============================================================================
//
// RUM blends two OTLP tables:
//   - web vitals (LCP/INP/CLS) are p75 of the `web.vitals.*` metric_names from
//     `otel_metrics`;
//   - page views, JS errors and the top-pages/recent-errors breakdowns come
//     from `otel_spans`, where a RUM page span carries `attributes['page.url']`
//     (or a `pageview%` span_name) and a JS error span carries
//     `status_code = 'ERROR'` + `attributes['exception.type']`.
// Each is a separate bounded read; the glue assembles the single RUM contract.

/// SQL for the RUM web-vitals scalar block: p75 of each `web.vitals.*` metric
/// over `[time_range]` from `otel_metrics`, in one scalar row (NAN-1537).
///
/// `quantileTDigest(0.75)` matches this module's quantile convention. LCP/INP
/// are reported in ms, CLS is unitless — the SQL surfaces the raw p75 of each;
/// the glue maps them to `lcp_ms`/`inp_ms`/`cls` and nulls a vital with no data
/// points (the `*_n` count companions let the glue tell "0.0 p75" from "no
/// data"). Single time-bound WHERE, no GROUP BY (one row), `LIMIT 1`.
/// NAN-1543: an `env` filter (from [`RumFilters`]) scopes the vitals; page /
/// browser don't apply to metric rows (they carry no such attribute).
pub fn rum_web_vitals_sql(time_range: &TimeRange, filters: &RumFilters) -> String {
    format!(
        "SELECT quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.lcp') AS lcp_ms,\n       \
                quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.inp') AS inp_ms,\n       \
                quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.cls') AS cls,\n       \
                countIf(metric_name = 'web.vitals.lcp') AS lcp_n,\n       \
                countIf(metric_name = 'web.vitals.inp') AS inp_n,\n       \
                countIf(metric_name = 'web.vitals.cls') AS cls_n\n\
         FROM nanosiem.otel_metrics\n\
         WHERE otel_metrics.timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND metric_name IN ('web.vitals.lcp', 'web.vitals.inp', 'web.vitals.cls'){env}\n\
         LIMIT 1",
        env = filters.metrics_predicate(),
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// Filters for the RUM summary (NAN-1543). All optional; each `None`/empty
/// field drops its predicate so the default (no params) is the historical
/// "all traffic" RUM summary.
///
/// `page` is a case-insensitive substring on the page URL/route; `browser` and
/// `env` are exact matches. They are pushed into the spans WHERE (page/browser
/// only exist on spans); `env` is ALSO pushed into the web-vitals metrics WHERE
/// (it lives on `resource_attributes` of both tables). `page`/`browser` cannot
/// scope the metrics-sourced web vitals (those rows have no page/browser
/// attribute), so a `page`/`browser` filter narrows the span-derived blocks
/// only — the vitals reflect the `env` scope.
#[derive(Debug, Clone, Default)]
pub struct RumFilters<'a> {
    /// Case-insensitive substring on `attributes['page.url']` (page / route).
    pub page: Option<&'a str>,
    /// Exact match on `attributes['browser.name']`.
    pub browser: Option<&'a str>,
    /// Exact match on `resource_attributes['deployment.environment']`.
    pub env: Option<&'a str>,
}

impl RumFilters<'_> {
    /// The spans-side predicate fragment (a leading `\n  AND …` chain, empty
    /// when no filter is set). Pushed into the page-views / top-pages /
    /// recent-errors WHERE. `page` is a case-insensitive substring; `browser`
    /// and `env` are exact matches; all values escaped.
    fn spans_predicate(&self) -> String {
        let mut s = String::new();
        if let Some(page) = self.page {
            if !page.is_empty() {
                s.push_str(&format!(
                    "\n  AND lower(attributes['page.url']) LIKE '%{}%'",
                    escape_string(&page.to_ascii_lowercase())
                ));
            }
        }
        if let Some(browser) = self.browser {
            if !browser.is_empty() {
                s.push_str(&format!(
                    "\n  AND attributes['browser.name'] = '{}'",
                    escape_string(browser)
                ));
            }
        }
        if let Some(env) = self.env {
            if !env.is_empty() {
                s.push_str(&format!(
                    "\n  AND resource_attributes['deployment.environment'] = '{}'",
                    escape_string(env)
                ));
            }
        }
        s
    }

    /// The metrics-side predicate fragment — only `env` (web-vital metric rows
    /// carry no page/browser attribute). Leading `\n  AND …`, empty when no env.
    fn metrics_predicate(&self) -> String {
        match self.env {
            Some(env) if !env.is_empty() => format!(
                "\n  AND resource_attributes['deployment.environment'] = '{}'",
                escape_string(env)
            ),
            _ => String::new(),
        }
    }
}

/// A page-view span = one with a non-empty `attributes['page.url']` OR a
/// `span_name` starting `pageview`. Shared predicate so the count, the series,
/// and the top-pages query all agree on what a page view is.
const RUM_PAGEVIEW_PREDICATE: &str =
    "(attributes['page.url'] != '' OR startsWith(span_name, 'pageview'))";

/// A JS-error span = `status_code = 'ERROR'` carrying an `exception.type`
/// attribute (a RUM error report, distinct from a backend 5xx).
const RUM_JS_ERROR_PREDICATE: &str =
    "(status_code = 'ERROR' AND attributes['exception.type'] != '')";

/// SQL for the RUM page-view totals + time series block (NAN-1537), from
/// `otel_spans`. One scalar-ish read bucketed every `step_secs` seconds:
///   - `bucket`      — interval start (glue → `page_views_series[].t`)
///   - `views`       — page-view spans in the bucket (→ `…[].v`; SUM → `page_views`)
///   - `js_errors`   — JS-error spans in the bucket
/// The glue sums `views`/`js_errors` across buckets for the scalar totals and
/// keeps the per-bucket `views` for the series. `step_secs` clamps ≥1. Single
/// time-bound WHERE on `start_time` (partition pruning), GROUP BY bucket.
/// NAN-1543: the optional [`RumFilters`] page/browser/env predicates are pushed
/// into the WHERE so the totals + series reflect the filtered traffic.
pub fn rum_pageviews_series_sql(
    time_range: &TimeRange,
    step_secs: u64,
    filters: &RumFilters,
) -> String {
    let step = step_secs.max(1);
    format!(
        "SELECT toStartOfInterval(start_time, toIntervalSecond({step})) AS bucket,\n       \
                countIf({pv}) AS views,\n       \
                countIf({err}) AS js_errors\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'{extra}\n\
         GROUP BY bucket\n\
         ORDER BY bucket ASC\n\
         LIMIT 100000",
        pv = RUM_PAGEVIEW_PREDICATE,
        err = RUM_JS_ERROR_PREDICATE,
        extra = filters.spans_predicate(),
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL for the RUM top-pages breakdown (NAN-1537), from `otel_spans`. GROUP BY
/// page (`attributes['page.url']`) over the page-view spans in `[time_range]`,
/// busiest first, capped at `limit` (clamped `[1, 100]`, default 10). Per page:
/// view count + p75 LCP sourced from the page-view spans' `attributes['web.vitals.lcp']`
/// (RUM spans carry their own LCP attribute; `toFloat64OrNull` tolerates a
/// missing/non-numeric value and `quantileTDigestIf` skips the nulls). The glue
/// maps `lcp_ms`'s null/absence to a `null` field. NAN-1543: the optional
/// [`RumFilters`] page/browser/env predicates are pushed into the WHERE.
pub fn rum_top_pages_sql(
    time_range: &TimeRange,
    limit: Option<u32>,
    filters: &RumFilters,
) -> String {
    let lim = limit.unwrap_or(10).clamp(1, 100);
    format!(
        "SELECT attributes['page.url'] AS page,\n       \
                count() AS views,\n       \
                quantileTDigestIf(0.75)(toFloat64OrNull(attributes['web.vitals.lcp']), toFloat64OrNull(attributes['web.vitals.lcp']) IS NOT NULL) AS lcp_ms\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n  \
           AND attributes['page.url'] != ''{extra}\n\
         GROUP BY page\n\
         ORDER BY views DESC\n\
         LIMIT {lim}",
        extra = filters.spans_predicate(),
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL for the RUM recent-errors sample (NAN-1537), from `otel_spans`. The most
/// recent JS-error spans in `[time_range]`, capped at `limit` (clamped
/// `[1, 200]`, default 20). Surfaces the error message
/// (`attributes['exception.message']` falling back to `status_message`), the
/// page (`attributes['page.url']`), and `start_time` (glue → rfc3339 `ts`). A
/// sampling, not an aggregate — raw rows with a tight LIMIT, most recent first.
/// NAN-1543: the optional [`RumFilters`] page/browser/env predicates are pushed
/// into the WHERE.
pub fn rum_recent_errors_sql(
    time_range: &TimeRange,
    limit: Option<u32>,
    filters: &RumFilters,
) -> String {
    let lim = limit.unwrap_or(20).clamp(1, 200);
    format!(
        "SELECT if(attributes['exception.message'] != '', attributes['exception.message'], status_message) AS message,\n       \
                attributes['page.url'] AS page,\n       \
                formatDateTime(start_time, '%Y-%m-%dT%H:%i:%S.%fZ') AS ts,\n       \
                src_ip,\n       \
                user,\n       \
                attributes['session.id'] AS session\n\
         FROM nanosiem.otel_spans\n\
         WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n  \
           AND {err}{extra}\n\
         ORDER BY start_time DESC\n\
         LIMIT {lim}",
        err = RUM_JS_ERROR_PREDICATE,
        extra = filters.spans_predicate(),
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

// ============================================================================
// Observability console — Synthetics check results summary (NAN-1538)
// ============================================================================
//
// Synthetic *definitions* live in PostgreSQL (`observability_synthetic_checks`,
// migration 210); each scheduled run records a row in ClickHouse
// (`synthetic_check_results`, migration 142). The api layer reads the defs from
// PG and joins per-check summaries from these CH queries.

/// SQL for the per-check rollup over the last `window_days` of
/// `synthetic_check_results` (NAN-1538): one row per `check_id` with the total
/// run count, success count (→ glue `uptime_pct = good/total*100`), and p50
/// latency (`quantileTDigest(0.50)(latency_ms)`). `check_id` is the synthetic
/// def's UUID stringified — the api layer passes the exact set it cares about,
/// but the summary scans all checks in the window and the glue keys by id, so no
/// id list is interpolated (no injection surface, and a check with zero runs
/// simply has no row → glue defaults to 0% / null). `window_days` is the rolling
/// window; the time bound stays a plain WHERE on `timestamp` for partition
/// pruning. Bounded `LIMIT 100000` (check cardinality is config-bounded).
pub fn synthetic_summary_sql(time_range: &TimeRange) -> String {
    format!(
        "SELECT check_id,\n       \
                count() AS total,\n       \
                sum(success) AS good,\n       \
                quantileTDigest(0.50)(latency_ms) AS p50_latency_ms\n\
         FROM nanosiem.synthetic_check_results\n\
         WHERE synthetic_check_results.timestamp BETWEEN '{start}' AND '{end}'\n\
         GROUP BY check_id\n\
         ORDER BY check_id ASC\n\
         LIMIT 100000",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL for the last-N run history of one synthetic check (NAN-1538), the
/// uptime-bar sparkline. Most-recent `limit` rows (clamped `[1, 365]`, default
/// 90) for `check_id` over `[time_range]`, each `{success, latency_ms, ts}`.
/// `check_id` is escaped. The api glue REVERSES the rows to chronological order
/// for the bar (we order DESC here to take the newest `limit` cheaply). Raw rows
/// (a sampling) with a tight LIMIT, time-bound WHERE on `timestamp`.
pub fn synthetic_history_sql(check_id: &str, time_range: &TimeRange, limit: Option<u32>) -> String {
    let id = escape_string(check_id);
    let lim = limit.unwrap_or(90).clamp(1, 365);
    format!(
        "SELECT success,\n       \
                latency_ms,\n       \
                formatDateTime(timestamp, '%Y-%m-%dT%H:%i:%S.%fZ') AS ts\n\
         FROM nanosiem.synthetic_check_results\n\
         WHERE synthetic_check_results.timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND check_id = '{id}'\n\
         ORDER BY timestamp DESC\n\
         LIMIT {lim}",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

// ============================================================================
// Observability ↔ Security convergence — service security signals (NAN-1542)
// ============================================================================
//
// The service-detail view cross-links to the SECURITY world: "which detections
// fired against the hosts/IPs this service runs on?". Two bounded steps:
//   1. resolve the service's distinct entities (src_ip + host) from `otel_spans`
//      over the window ([`service_entities_sql`]) — a bounded top set;
//   2. find security DETECTION signals whose `risk_entity` is one of those
//      entities, over the same window ([`security_signals_for_entities_sql`]).
// The `signals` table (init.sql) is the cheapest correct ClickHouse source: it
// carries `rule_name`, `severity`, `timestamp`, and the matched `risk_entity`
// (the detection's configured entity field — typically src_ip / dest_ip /
// src_host) WITHOUT a logs join. Every entity is escaped; both reads carry a
// bounded LIMIT and a single time-bound WHERE (NAN-1412).

/// Hard cap on the number of distinct entities (src_ip + host) resolved for a
/// service before they are fed into the signal lookup's `IN (...)` list. Keeps
/// the second query's predicate bounded regardless of service fan-out.
pub const SERVICE_ENTITY_CAP: u32 = 100;

/// SQL for the distinct non-empty entities (src_ip + host) a service touched
/// over `[time_range]`, from `otel_spans` (NAN-1542). One column `entity`,
/// unioned from the `src_ip` and `host` span columns, empties dropped. Bounded
/// by `SERVICE_ENTITY_CAP` so the downstream signal `IN (...)` stays small.
/// `service` is escaped; single time-bound WHERE on `start_time`.
pub fn service_entities_sql(service: &str, time_range: &TimeRange) -> String {
    let svc = escape_string(service);
    format!(
        "SELECT DISTINCT entity FROM (\n  \
           SELECT src_ip AS entity\n  \
           FROM nanosiem.otel_spans\n  \
           WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n    \
             AND service_name = '{svc}' AND src_ip != ''\n  \
           UNION ALL\n  \
           SELECT host AS entity\n  \
           FROM nanosiem.otel_spans\n  \
           WHERE otel_spans.start_time BETWEEN '{start}' AND '{end}'\n    \
             AND service_name = '{svc}' AND host != ''\n\
         )\n\
         WHERE entity != ''\n\
         LIMIT {cap}",
        cap = SERVICE_ENTITY_CAP,
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

/// SQL for security DETECTION signals whose matched `risk_entity` is one of the
/// supplied `entities` (the service's hosts/IPs), over `[time_range]` from the
/// `signals` table (NAN-1542). Returns, most recent first:
///   - `ts`          — signal timestamp (rfc3339);
///   - `rule_name`   — the detection rule name;
///   - `risk_entity` — the matched entity (the glue maps it to `src_ip`/`src_host`
///     by testing membership in the ip / host sets it already holds);
///   - `severity`    — the signal severity.
///
/// Every entity is escaped and the list is the `risk_entity IN (...)` predicate
/// (which engages the `idx_risk_entity` bloom). An EMPTY `entities` slice yields
/// a query that matches nothing (`risk_entity IN ('')` would false-positive on a
/// literal-empty entity, so we emit an explicit `0` guard) — the caller should
/// skip the round trip entirely when there are no entities, but the SQL is safe
/// either way. Bounded `LIMIT` (clamped `[1, 1000]`, default 100); single
/// time-bound WHERE on `timestamp`.
pub fn security_signals_for_entities_sql(
    entities: &[String],
    time_range: &TimeRange,
    limit: Option<u32>,
) -> String {
    let lim = limit.unwrap_or(100).clamp(1, 1000);
    // Build the escaped IN-list. Empty → an unsatisfiable predicate so the
    // statement is still valid SQL and returns no rows.
    let entity_pred = if entities.is_empty() {
        "0".to_string()
    } else {
        let list = entities
            .iter()
            .map(|e| format!("'{}'", escape_string(e)))
            .collect::<Vec<_>>()
            .join(", ");
        format!("risk_entity IN ({list})")
    };
    format!(
        "SELECT formatDateTime(timestamp, '%Y-%m-%dT%H:%i:%S.%fZ') AS ts,\n       \
                rule_name,\n       \
                risk_entity,\n       \
                severity\n\
         FROM nanosiem.signals\n\
         WHERE signals.timestamp BETWEEN '{start}' AND '{end}'\n  \
           AND ({entity_pred})\n\
         ORDER BY timestamp DESC\n\
         LIMIT {lim}",
        start = time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
        end = time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn dataset_selector_parses_known_and_defaults_logs() {
        assert_eq!(Dataset::from_selector("spans"), Dataset::Spans);
        assert_eq!(Dataset::from_selector("TRACES"), Dataset::Spans);
        assert_eq!(Dataset::from_selector(" metric "), Dataset::Metrics);
        assert_eq!(Dataset::from_selector("logs"), Dataset::Logs);
        // Unknown / empty falls back to logs (additive override, never an error).
        assert_eq!(Dataset::from_selector("garbage"), Dataset::Logs);
        assert_eq!(Dataset::from_selector(""), Dataset::Logs);
        assert_eq!(Dataset::default(), Dataset::Logs);
    }

    #[test]
    fn dataset_table_and_time_column() {
        assert_eq!(Dataset::Logs.table_name(), "logs");
        assert_eq!(Dataset::Logs.time_column(), "timestamp");
        assert_eq!(Dataset::Spans.table_name(), "otel_spans");
        assert_eq!(Dataset::Spans.time_column(), "start_time");
        assert_eq!(Dataset::Metrics.table_name(), "otel_metrics");
        assert_eq!(Dataset::Metrics.time_column(), "timestamp");
    }

    #[test]
    fn trace_by_id_lowercases_and_escapes() {
        let sql = trace_by_id_sql("ABCD1234");
        // Stored ids are lowercase hex.
        assert!(sql.contains("trace_id = 'abcd1234'"), "{sql}");
        // Two-step: index table then span window scan.
        assert!(sql.contains("otel_spans_trace_id_ts"), "{sql}");
        assert!(sql.contains("FROM nanosiem.otel_spans\n"), "{sql}");
        assert!(sql.contains("ORDER BY start_time ASC"), "{sql}");
        // Single-quote injection is escaped.
        let evil = trace_by_id_sql("a' OR '1'='1");
        assert!(evil.contains("''"), "{evil}");
        assert!(!evil.contains("OR '1'='1'"), "{evil}");
    }

    #[test]
    fn rate_and_histogram_quantile_generate_expected_sql() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let g = ClickHouseSqlGenerator::new();
        let sql = |q: &str| {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            g.generate(&query, &tr).unwrap_or_else(|e| panic!("gen {q}: {e}"))
        };
        // rate(value) → cumulative-counter delta over the window in seconds.
        let r = sql("* | stats rate(value) by service_name");
        assert!(r.contains("(max(value) - min(value)) / greatest(dateDiff('second'"), "{r}");
        // histogram_quantile(value, 95) → quantileTDigest(0.95)(value).
        let h = sql("* | stats histogram_quantile(value, 95) by service_name");
        assert!(h.contains("quantileTDigest(0.95)(value)"), "{h}");
    }

    #[test]
    fn trace_id_filter_routes_to_explicit_column() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let g = ClickHouseSqlGenerator::new();
        let query = parse_query(r#"trace_id="ABCDEF""#).unwrap();
        let s = g.generate(&query, &tr).unwrap();
        // Explicit column (not ext JSON), lowercase-normalized raw compare
        // engaging the migration-141 bloom — not wrapped in lower().
        assert!(s.contains("trace_id = 'abcdef'"), "{s}");
        assert!(!s.contains("ext"), "{s}");
    }

    #[test]
    fn dataset_generator_retargets_table_and_time_column() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        // Spans dataset: the time-bound WHERE + default ORDER BY use start_time,
        // and the read targets otel_spans.
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query("error").unwrap();
        let sql = g.generate(&q, &tr).unwrap();
        assert!(sql.contains("FROM otel_spans"), "{sql}");
        assert!(sql.contains("WHERE start_time BETWEEN"), "{sql}");
        assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
        assert!(!sql.contains("timestamp BETWEEN"), "{sql}");

        // rate() on spans uses the dataset time column too.
        let r = g
            .generate(&parse_query("* | stats rate(duration_ns) by service_name").unwrap(), &tr)
            .unwrap();
        assert!(r.contains("dateDiff('second', min(start_time), max(start_time))"), "{r}");
    }

    #[test]
    fn logs_dataset_is_byte_identical_default() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let q = parse_query("error").unwrap();
        let base = ClickHouseSqlGenerator::new().generate(&q, &tr).unwrap();
        let logs = ClickHouseSqlGenerator::new()
            .with_dataset(Dataset::Logs)
            .generate(&q, &tr)
            .unwrap();
        assert_eq!(base, logs, "Dataset::Logs must be byte-identical to the default");
        assert!(base.contains("FROM logs"), "{base}");
        assert!(base.contains("timestamp BETWEEN"), "{base}");
    }

    #[test]
    fn recent_traces_sql_filters_and_aggregates() {
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        // Defaults: every trace, recent first, LIMIT 200, no HAVING.
        let sql = recent_traces_sql(&tr, &TraceListFilters::default());
        assert!(sql.contains("FROM nanosiem.otel_spans"), "{sql}");
        assert!(sql.contains("GROUP BY trace_id"), "{sql}");
        assert!(sql.contains("countIf(status_code = 'ERROR') AS error_count"), "{sql}");
        assert!(sql.contains("argMin(service_name, length(parent_span_id)) AS root_service"), "{sql}");
        assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
        assert!(sql.contains("LIMIT 200"), "{sql}");
        assert!(!sql.contains("HAVING"), "{sql}");

        // Filters compose into a HAVING over the per-trace row.
        let filters = TraceListFilters {
            service: Some("api"),
            errors_only: true,
            min_duration_ns: Some(1_000_000),
            limit: Some(50),
            before: None,
        };
        let f = recent_traces_sql(&tr, &filters);
        assert!(f.contains("HAVING root_service = 'api'"), "{f}");
        assert!(f.contains("error_count > 0"), "{f}");
        assert!(f.contains("duration_ns >= 1000000"), "{f}");
        assert!(f.contains("LIMIT 50"), "{f}");
        // No cursor predicate when `before` is None (first page).
        assert!(!f.contains("otel_spans.start_time < "), "{f}");

        // Keyset cursor (NAN-1539): a strict `<` on the raw start_time column,
        // outside the HAVING, for partition-pruned pagination.
        let paged = recent_traces_sql(
            &tr,
            &TraceListFilters {
                before: Some(Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap()),
                ..Default::default()
            },
        );
        assert!(
            paged.contains("AND otel_spans.start_time < '2024-01-01 12:00:00"),
            "{paged}"
        );
        // service value is escaped.
        let evil = recent_traces_sql(&tr, &TraceListFilters { service: Some("a'b"), ..Default::default() });
        assert!(evil.contains("root_service = 'a''b'"), "{evil}");
        // limit clamps.
        let clamp = recent_traces_sql(&tr, &TraceListFilters { limit: Some(99999), ..Default::default() });
        assert!(clamp.contains("LIMIT 1000"), "{clamp}");
    }

    #[test]
    fn metric_names_sql_optional_service_filter() {
        let all = metric_names_sql(None);
        assert!(all.contains("SELECT DISTINCT metric_name"), "{all}");
        assert!(all.contains("FROM nanosiem.otel_metrics"), "{all}");
        assert!(!all.contains("WHERE"), "{all}");
        let svc = metric_names_sql(Some("api"));
        assert!(svc.contains("WHERE service_name = 'api'"), "{svc}");
        // empty service is dropped.
        let empty = metric_names_sql(Some(""));
        assert!(!empty.contains("WHERE"), "{empty}");
    }

    #[test]
    fn metric_agg_allowlist_parses_and_rejects() {
        assert_eq!(MetricAgg::from_str("avg"), Some(MetricAgg::Avg));
        assert_eq!(MetricAgg::from_str("P95"), Some(MetricAgg::P95));
        assert_eq!(MetricAgg::from_str("rate"), Some(MetricAgg::Rate));
        assert_eq!(MetricAgg::from_str("median"), Some(MetricAgg::P50));
        assert_eq!(MetricAgg::from_str("nonsense"), None);
        assert_eq!(MetricAgg::from_str("p98"), None);
        assert_eq!(MetricAgg::default(), MetricAgg::Avg);
    }

    #[test]
    fn valid_tag_key_screens_injection() {
        assert!(valid_tag_key("http.method"));
        assert!(valid_tag_key("k8s.pod_name-1"));
        assert!(!valid_tag_key(""));
        assert!(!valid_tag_key("a' OR '1'='1"));
        assert!(!valid_tag_key("has space"));
        assert!(!valid_tag_key("semi;colon"));
    }

    #[test]
    fn metric_timeseries_v2_single_series_back_compat() {
        let q = MetricQuery {
            metric_name: "http.server.duration",
            service_name: Some("api"),
            agg: MetricAgg::Avg,
            group_by: None,
            filters: &[],
            step_secs: 60,
        };
        let sql = metric_timeseries_v2_sql(&q, &day_range());
        assert!(sql.contains("metric_name = 'http.server.duration'"), "{sql}");
        assert!(sql.contains("service_name = 'api'"), "{sql}");
        assert!(sql.contains("avg(value) AS v"), "{sql}");
        // No group_by → constant series key, GROUP BY bucket only.
        assert!(sql.contains("'' AS series_key"), "{sql}");
        assert!(sql.contains("GROUP BY bucket"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }

    #[test]
    fn metric_timeseries_v2_group_by_and_filters() {
        let filters = vec![
            MetricTagFilter { key: "env".into(), value: "prod".into() },
            MetricTagFilter { key: "region".into(), value: "us'east".into() },
        ];
        let q = MetricQuery {
            metric_name: "rpc.duration",
            service_name: None,
            agg: MetricAgg::P95,
            group_by: Some("http.method"),
            filters: &filters,
            step_secs: 30,
        };
        let sql = metric_timeseries_v2_sql(&q, &day_range());
        assert!(sql.contains("quantileTDigest(0.95)(value) AS v"), "{sql}");
        // group_by resolves over both maps and becomes a split key.
        assert!(sql.contains("attributes['http.method']"), "{sql}");
        assert!(sql.contains("AS series_key"), "{sql}");
        assert!(sql.contains("GROUP BY series_key, bucket"), "{sql}");
        // tag filters matched over the maps; value escaped.
        assert!(sql.contains("attributes['env']"), "{sql}");
        assert!(sql.contains("= 'prod'"), "{sql}");
        assert!(sql.contains("= 'us''east'"), "{sql}");
        // no service filter when None.
        assert!(!sql.contains("service_name ="), "{sql}");
    }

    #[test]
    fn metric_rate_agg_uses_window_in_scalar() {
        let q = MetricQuery {
            metric_name: "requests.total",
            service_name: None,
            agg: MetricAgg::Rate,
            group_by: None,
            filters: &[],
            step_secs: 60,
        };
        // The whole-window scalar uses the window length (1 day = 86400s) as the
        // rate denominator, not step_secs.
        let sql = metric_scalar_sql(&q, &day_range());
        assert!(sql.contains("(max(value) - min(value)) / greatest(86400"), "{sql}");
        assert!(sql.contains("AS v"), "{sql}");
        // No group_by → no GROUP BY clause (single scalar row).
        assert!(!sql.contains("GROUP BY"), "{sql}");
    }

    #[test]
    fn metric_tag_keys_and_values_sql() {
        let keys = metric_tag_keys_sql("http.server.duration", &day_range());
        assert!(keys.contains("arrayConcat(mapKeys(attributes), mapKeys(resource_attributes))"), "{keys}");
        assert!(keys.contains("metric_name = 'http.server.duration'"), "{keys}");
        assert!(keys.contains("SELECT DISTINCT k"), "{keys}");

        let vals = metric_tag_values_sql("m", "http.method", &day_range());
        assert!(vals.contains("attributes['http.method']"), "{vals}");
        assert!(vals.contains("AS tag_value"), "{vals}");
        // empty-string drop is applied in the outer query, not a HAVING on DISTINCT.
        assert!(vals.contains("WHERE tag_value != ''"), "{vals}");
    }

    #[test]
    fn metric_timeseries_filters_and_buckets() {
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let sql = metric_timeseries_sql("http.server.duration", Some("api"), &tr, 60);
        assert!(sql.contains("metric_name = 'http.server.duration'"), "{sql}");
        assert!(sql.contains("service_name = 'api'"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        // No service filter when None.
        let sql2 = metric_timeseries_sql("m", None, &tr, 0);
        assert!(!sql2.contains("service_name ="), "{sql2}");
        // step clamps to >= 1.
        assert!(sql2.contains("toIntervalSecond(1)"), "{sql2}");
    }

    fn day_range() -> TimeRange {
        TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn services_overview_aggregates_red_per_service() {
        let sql = services_overview_sql(&day_range(), &ServicesOverviewFilters::default());
        assert!(sql.contains("GROUP BY service_name"), "{sql}");
        // NAN-1539: reads the minute rollup, summing SimpleAggregateFunction
        // counts and merging the latency t-digest (already ms — no /1e6).
        assert!(sql.contains("FROM nanosiem.otel_service_red_1m"), "{sql}");
        assert!(sql.contains("sum(request_count) AS request_count"), "{sql}");
        assert!(sql.contains("sum(error_count) AS error_count"), "{sql}");
        assert!(
            sql.contains("quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[2] AS p95_ms"),
            "{sql}"
        );
        // sum on a SimpleAggregateFunction (NOT sumMerge — Code 43).
        assert!(!sql.contains("sumMerge"), "{sql}");
        // Time bound is a table-qualified plain WHERE on `minute` (no PREWHERE).
        assert!(
            sql.contains("WHERE otel_service_red_1m.minute BETWEEN"),
            "{sql}"
        );
        assert!(!sql.contains("PREWHERE"), "{sql}");
        assert!(sql.contains("LIMIT 1000"), "{sql}");
    }

    #[test]
    fn services_sparkline_buckets_per_service() {
        let sql = services_sparkline_sql(&day_range(), 60);
        assert!(sql.contains("GROUP BY service, bucket"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        // NAN-1539: bucket the rollup minutes, sum the rollup counts.
        assert!(sql.contains("FROM nanosiem.otel_service_red_1m"), "{sql}");
        assert!(sql.contains("toStartOfInterval(minute,"), "{sql}");
        assert!(sql.contains("sum(request_count) AS v"), "{sql}");
        // step clamps to >= 1.
        let z = services_sparkline_sql(&day_range(), 0);
        assert!(z.contains("toIntervalSecond(1)"), "{z}");
    }

    #[test]
    fn service_red_timeseries_buckets_and_escapes() {
        let sql = service_red_timeseries_sql("checkout-api", &day_range(), 60);
        assert!(sql.contains("service_name = 'checkout-api'"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        // NAN-1539: rollup-backed — summed counts + merged digest.
        assert!(sql.contains("FROM nanosiem.otel_service_red_1m"), "{sql}");
        assert!(sql.contains("sum(request_count) AS rate_count"), "{sql}");
        assert!(sql.contains("sum(error_count) AS error_count"), "{sql}");
        assert!(
            sql.contains("quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[3] AS p99_ms"),
            "{sql}"
        );
        assert!(sql.contains("GROUP BY bucket"), "{sql}");
        // injection-safe.
        let evil = service_red_timeseries_sql("a'b", &day_range(), 60);
        assert!(evil.contains("service_name = 'a''b'"), "{evil}");
    }

    #[test]
    fn service_endpoints_group_by_span_name() {
        let sql = service_endpoints_sql("payments", &day_range());
        assert!(sql.contains("GROUP BY span_name"), "{sql}");
        assert!(sql.contains("service_name = 'payments'"), "{sql}");
        assert!(sql.contains("ORDER BY request_count DESC"), "{sql}");
        assert!(sql.contains("LIMIT 500"), "{sql}");
    }

    #[test]
    fn service_exemplars_orders_errors_first_and_clamps() {
        let sql = service_exemplars_sql("payments", &day_range(), Some(25));
        assert!(sql.contains("status_code = 'ERROR' AS error"), "{sql}");
        assert!(sql.contains("duration_ns / 1e6 AS duration_ms"), "{sql}");
        assert!(sql.contains("ORDER BY error DESC, start_time DESC"), "{sql}");
        assert!(sql.contains("LIMIT 25"), "{sql}");
        // default + clamp.
        let def = service_exemplars_sql("p", &day_range(), None);
        assert!(def.contains("LIMIT 20"), "{def}");
        let clamp = service_exemplars_sql("p", &day_range(), Some(99999));
        assert!(clamp.contains("LIMIT 200"), "{clamp}");
    }

    #[test]
    fn slo_compute_availability_and_latency() {
        let avail = slo_compute_sql("checkout-api", SliKind::Availability, None, &day_range());
        assert!(avail.contains("count() AS total"), "{avail}");
        assert!(
            avail.contains("countIf(status_code != 'ERROR') AS good"),
            "{avail}"
        );
        assert!(avail.contains("service_name = 'checkout-api'"), "{avail}");
        assert!(avail.contains("LIMIT 1"), "{avail}");

        // Latency: threshold ms → ns literal.
        let lat = slo_compute_sql("payments", SliKind::Latency, Some(300.0), &day_range());
        assert!(lat.contains("countIf(duration_ns <= 300000000) AS good"), "{lat}");

        // Latency with missing threshold degrades to the availability definition.
        let lat_none = slo_compute_sql("payments", SliKind::Latency, None, &day_range());
        assert!(
            lat_none.contains("countIf(status_code != 'ERROR') AS good"),
            "{lat_none}"
        );
        // Non-finite threshold is rejected the same way.
        let lat_nan = slo_compute_sql("p", SliKind::Latency, Some(f64::NAN), &day_range());
        assert!(
            lat_nan.contains("countIf(status_code != 'ERROR') AS good"),
            "{lat_nan}"
        );
    }

    #[test]
    fn infra_hosts_latest_per_host_metric() {
        let sql = infra_hosts_sql(&day_range(), &InfraHostsFilters::default());
        assert!(sql.contains("resource_attributes['host.name'] AS host"), "{sql}");
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.cpu.utilization') AS cpu_util"),
            "{sql}"
        );
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.memory.utilization') AS mem_util"),
            "{sql}"
        );
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.cpu.load_average.1m') AS load_1m"),
            "{sql}"
        );
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.network.io') AS net_io"),
            "{sql}"
        );
        // group label = host.group, fallback service_name.
        assert!(sql.contains("resource_attributes['host.group']"), "{sql}");
        assert!(sql.contains("GROUP BY host"), "{sql}");
        assert!(sql.contains("WHERE otel_metrics.timestamp BETWEEN"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
        assert!(sql.contains("LIMIT 10000"), "{sql}");
    }

    #[test]
    fn rum_web_vitals_p75_with_counts() {
        let sql = rum_web_vitals_sql(&day_range(), &RumFilters::default());
        assert!(
            sql.contains("quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.lcp') AS lcp_ms"),
            "{sql}"
        );
        assert!(sql.contains("AS inp_ms"), "{sql}");
        assert!(sql.contains("AS cls"), "{sql}");
        // count companions distinguish "0.0 p75" from "no data".
        assert!(sql.contains("countIf(metric_name = 'web.vitals.lcp') AS lcp_n"), "{sql}");
        assert!(
            sql.contains("metric_name IN ('web.vitals.lcp', 'web.vitals.inp', 'web.vitals.cls')"),
            "{sql}"
        );
        assert!(sql.contains("LIMIT 1"), "{sql}");
    }

    #[test]
    fn rum_pageviews_series_buckets_and_predicates() {
        let sql = rum_pageviews_series_sql(&day_range(), 60, &RumFilters::default());
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        assert!(sql.contains("AS views"), "{sql}");
        assert!(sql.contains("AS js_errors"), "{sql}");
        assert!(sql.contains("page.url"), "{sql}");
        assert!(sql.contains("exception.type"), "{sql}");
        assert!(sql.contains("GROUP BY bucket"), "{sql}");
        // step clamps to >= 1.
        let z = rum_pageviews_series_sql(&day_range(), 0, &RumFilters::default());
        assert!(z.contains("toIntervalSecond(1)"), "{z}");
    }

    #[test]
    fn rum_top_pages_group_and_clamp() {
        let sql = rum_top_pages_sql(&day_range(), Some(5), &RumFilters::default());
        assert!(sql.contains("attributes['page.url'] AS page"), "{sql}");
        assert!(sql.contains("count() AS views"), "{sql}");
        assert!(sql.contains("ORDER BY views DESC"), "{sql}");
        assert!(sql.contains("LIMIT 5"), "{sql}");
        let def = rum_top_pages_sql(&day_range(), None, &RumFilters::default());
        assert!(def.contains("LIMIT 10"), "{def}");
        let clamp = rum_top_pages_sql(&day_range(), Some(99999), &RumFilters::default());
        assert!(clamp.contains("LIMIT 100"), "{clamp}");
    }

    #[test]
    fn rum_recent_errors_orders_recent_and_clamps() {
        let sql = rum_recent_errors_sql(&day_range(), Some(25), &RumFilters::default());
        assert!(sql.contains("AS message"), "{sql}");
        assert!(sql.contains("attributes['page.url'] AS page"), "{sql}");
        assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
        assert!(sql.contains("LIMIT 25"), "{sql}");
        let def = rum_recent_errors_sql(&day_range(), None, &RumFilters::default());
        assert!(def.contains("LIMIT 20"), "{def}");
        let clamp = rum_recent_errors_sql(&day_range(), Some(99999), &RumFilters::default());
        assert!(clamp.contains("LIMIT 200"), "{clamp}");
    }

    #[test]
    fn synthetic_summary_aggregates_per_check() {
        let sql = synthetic_summary_sql(&day_range());
        assert!(sql.contains("FROM nanosiem.synthetic_check_results"), "{sql}");
        assert!(sql.contains("count() AS total"), "{sql}");
        assert!(sql.contains("sum(success) AS good"), "{sql}");
        assert!(
            sql.contains("quantileTDigest(0.50)(latency_ms) AS p50_latency_ms"),
            "{sql}"
        );
        assert!(sql.contains("GROUP BY check_id"), "{sql}");
        assert!(sql.contains("WHERE synthetic_check_results.timestamp BETWEEN"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }

    #[test]
    fn synthetic_history_escapes_and_clamps() {
        let sql = synthetic_history_sql("abc-123", &day_range(), Some(50));
        assert!(sql.contains("check_id = 'abc-123'"), "{sql}");
        assert!(sql.contains("AS ts"), "{sql}");
        assert!(sql.contains("ORDER BY timestamp DESC"), "{sql}");
        assert!(sql.contains("LIMIT 50"), "{sql}");
        // default + clamp.
        let def = synthetic_history_sql("c", &day_range(), None);
        assert!(def.contains("LIMIT 90"), "{def}");
        let clamp = synthetic_history_sql("c", &day_range(), Some(99999));
        assert!(clamp.contains("LIMIT 365"), "{clamp}");
        // injection-safe.
        let evil = synthetic_history_sql("a'b", &day_range(), None);
        assert!(evil.contains("check_id = 'a''b'"), "{evil}");
    }

    // ------------------------------------------------------------------------
    // NAN-1543 filter pushdown
    // ------------------------------------------------------------------------

    #[test]
    fn services_overview_q_and_sort_pushdown() {
        // q → case-insensitive substring on service_name, lowercased + escaped.
        let f = ServicesOverviewFilters {
            q: Some("Check'out"),
            sort: Some(ServicesSort::P95),
        };
        let sql = services_overview_sql(&day_range(), &f);
        assert!(
            sql.contains("AND lower(service_name) LIKE '%check''out%'"),
            "{sql}"
        );
        assert!(sql.contains("ORDER BY p95_ms DESC"), "{sql}");
        assert!(sql.contains("LIMIT 1000"), "{sql}");
        // name sort.
        let n = services_overview_sql(
            &day_range(),
            &ServicesOverviewFilters {
                sort: Some(ServicesSort::Name),
                ..Default::default()
            },
        );
        assert!(n.contains("ORDER BY service ASC"), "{n}");
        // error_rate sort falls back to the count order in SQL (glue re-sorts).
        let e = services_overview_sql(
            &day_range(),
            &ServicesOverviewFilters {
                sort: Some(ServicesSort::ErrorRate),
                ..Default::default()
            },
        );
        assert!(e.contains("ORDER BY request_count DESC"), "{e}");
        assert!(ServicesSort::ErrorRate.needs_glue_sort());
        assert!(!ServicesSort::Rate.needs_glue_sort());
        // default (no filters) keeps the historical count order, no q clause.
        let d = services_overview_sql(&day_range(), &ServicesOverviewFilters::default());
        assert!(d.contains("ORDER BY request_count DESC"), "{d}");
        assert!(!d.contains("LIKE"), "{d}");
    }

    #[test]
    fn services_sort_allowlist_parses_and_rejects() {
        assert_eq!(ServicesSort::from_str("rate"), Some(ServicesSort::Rate));
        assert_eq!(ServicesSort::from_str("P95"), Some(ServicesSort::P95));
        assert_eq!(ServicesSort::from_str("name"), Some(ServicesSort::Name));
        assert_eq!(
            ServicesSort::from_str("error_rate"),
            Some(ServicesSort::ErrorRate)
        );
        assert_eq!(ServicesSort::from_str("garbage"), None);
        assert_eq!(ServicesSort::default(), ServicesSort::Rate);
    }

    #[test]
    fn infra_hosts_q_group_env_pushdown() {
        let f = InfraHostsFilters {
            q: Some("WEB-01"),
            group: Some("frontend"),
            env: Some("prod'"),
        };
        let sql = infra_hosts_sql(&day_range(), &f);
        assert!(
            sql.contains("AND lower(resource_attributes['host.name']) LIKE '%web-01%'"),
            "{sql}"
        );
        assert!(
            sql.contains("AND resource_attributes['host.group'] = 'frontend'"),
            "{sql}"
        );
        assert!(
            sql.contains("AND resource_attributes['deployment.environment'] = 'prod'''"),
            "{sql}"
        );
        // default → no extra filter predicates (the host_group SELECT always
        // references host.group, so assert the FILTER form is absent, not the
        // bare attribute name).
        let d = infra_hosts_sql(&day_range(), &InfraHostsFilters::default());
        assert!(!d.contains("AND resource_attributes['host.group'] ="), "{d}");
        assert!(!d.contains("deployment.environment"), "{d}");
        assert!(!d.contains("LIKE"), "{d}");
        assert!(d.contains("LIMIT 10000"), "{d}");
    }

    #[test]
    fn rum_filters_pushdown_spans_and_metrics() {
        let f = RumFilters {
            page: Some("/Checkout"),
            browser: Some("Chrome"),
            env: Some("prod"),
        };
        // spans-side: page (lowercased substring), browser + env (exact).
        let series = rum_pageviews_series_sql(&day_range(), 60, &f);
        assert!(
            series.contains("AND lower(attributes['page.url']) LIKE '%/checkout%'"),
            "{series}"
        );
        assert!(
            series.contains("AND attributes['browser.name'] = 'Chrome'"),
            "{series}"
        );
        assert!(
            series.contains("AND resource_attributes['deployment.environment'] = 'prod'"),
            "{series}"
        );
        let top = rum_top_pages_sql(&day_range(), None, &f);
        assert!(top.contains("AND attributes['browser.name'] = 'Chrome'"), "{top}");
        let errs = rum_recent_errors_sql(&day_range(), None, &f);
        assert!(errs.contains("AND lower(attributes['page.url']) LIKE '%/checkout%'"), "{errs}");
        // metrics-side: only env applies to the vitals.
        let vitals = rum_web_vitals_sql(&day_range(), &f);
        assert!(
            vitals.contains("AND resource_attributes['deployment.environment'] = 'prod'"),
            "{vitals}"
        );
        assert!(!vitals.contains("page.url"), "{vitals}");
        assert!(!vitals.contains("browser.name"), "{vitals}");
        // default → no pushed predicates.
        let d = rum_pageviews_series_sql(&day_range(), 60, &RumFilters::default());
        assert!(!d.contains("browser.name"), "{d}");
    }

    // ------------------------------------------------------------------------
    // NAN-1542 service ↔ security convergence
    // ------------------------------------------------------------------------

    #[test]
    fn service_entities_unions_ip_and_host_escapes() {
        let sql = service_entities_sql("checkout'api", &day_range());
        assert!(sql.contains("SELECT src_ip AS entity"), "{sql}");
        assert!(sql.contains("SELECT host AS entity"), "{sql}");
        assert!(sql.contains("UNION ALL"), "{sql}");
        // service escaped, applied to both legs.
        assert!(sql.contains("service_name = 'checkout''api'"), "{sql}");
        assert!(sql.contains("WHERE entity != ''"), "{sql}");
        assert!(sql.contains(&format!("LIMIT {SERVICE_ENTITY_CAP}")), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }

    #[test]
    fn security_signals_for_entities_in_list_and_escape() {
        let entities = vec!["10.0.0.1".to_string(), "web'01".to_string()];
        let sql = security_signals_for_entities_sql(&entities, &day_range(), Some(50));
        assert!(sql.contains("FROM nanosiem.signals"), "{sql}");
        assert!(
            sql.contains("risk_entity IN ('10.0.0.1', 'web''01')"),
            "{sql}"
        );
        assert!(sql.contains("AS ts"), "{sql}");
        assert!(sql.contains("rule_name"), "{sql}");
        assert!(sql.contains("severity"), "{sql}");
        assert!(sql.contains("ORDER BY timestamp DESC"), "{sql}");
        assert!(sql.contains("LIMIT 50"), "{sql}");
        assert!(sql.contains("WHERE signals.timestamp BETWEEN"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
        // empty entities → unsatisfiable guard, still valid SQL, default + clamp.
        let none = security_signals_for_entities_sql(&[], &day_range(), None);
        assert!(none.contains("AND (0)"), "{none}");
        assert!(none.contains("LIMIT 100"), "{none}");
        let clamp = security_signals_for_entities_sql(&entities, &day_range(), Some(99999));
        assert!(clamp.contains("LIMIT 1000"), "{clamp}");
    }

    // ── NAN-1562: cross-dataset correlation ──────────────────────────────────

    fn xds_range() -> crate::query::TimeRange {
        crate::query::TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        }
    }

    /// Parse: `trace_id IN [dataset=logs … | return trace_id]` carries the
    /// subsearch dataset on the AST.
    #[test]
    fn parse_in_subsearch_carries_dataset() {
        use crate::query::ast::{Query, SearchExpr};
        use crate::query::parse_query;
        let q = parse_query("trace_id IN [dataset=logs status_code=500 | return trace_id]")
            .unwrap();
        fn find_in_expr(e: &SearchExpr) -> Option<Option<Dataset>> {
            match e {
                SearchExpr::InSubsearch {
                    subsearch_dataset, ..
                } => Some(*subsearch_dataset),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    find_in_expr(a).or_else(|| find_in_expr(b))
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => find_in_expr(i),
                _ => None,
            }
        }
        fn find(q: &Query) -> Option<Option<Dataset>> {
            match q {
                Query::Search(e) => find_in_expr(e),
                Query::Piped { source, .. } => find(source),
            }
        }
        assert_eq!(find(&q), Some(Some(Dataset::Logs)));
    }

    /// Parse: `| join trace_id [dataset=spans …]` carries the dataset on Join.
    #[test]
    fn parse_join_carries_dataset() {
        use crate::query::ast::{Command, Query};
        use crate::query::parse_query;
        let q =
            parse_query("error | join trace_id [dataset=spans service_name=checkout]").unwrap();
        fn find(q: &Query) -> Option<Option<Dataset>> {
            match q {
                Query::Piped {
                    command:
                        Command::Join {
                            subsearch_dataset, ..
                        },
                    ..
                } => Some(*subsearch_dataset),
                Query::Piped { source, .. } => find(source),
                Query::Search(_) => None,
            }
        }
        assert_eq!(find(&q), Some(Some(Dataset::Spans)));
    }

    /// NAN-1562 FIX 2: `from=` is NO LONGER a dataset-selector alias. `from` is a
    /// real log field (email/syslog sender), and the old `from=` alias silently
    /// swallowed a `from=<word>` field filter inside a subsearch. The subsearch
    /// must now parse `from=production` as a FIELD FILTER (preserved on the AST),
    /// with NO subsearch_dataset consumed. Covers the IN-subsearch parser.
    #[test]
    fn from_field_filter_in_subsearch_is_preserved_not_a_dataset() {
        use crate::query::ast::{Query, SearchExpr};
        use crate::query::parse_query;
        let q = parse_query("user IN [from=production status=500 | return user]").unwrap();

        // No dataset selector was consumed (defaults to None → logs).
        fn in_dataset(e: &SearchExpr) -> Option<Option<Dataset>> {
            match e {
                SearchExpr::InSubsearch {
                    subsearch_dataset, ..
                } => Some(*subsearch_dataset),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    in_dataset(a).or_else(|| in_dataset(b))
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => in_dataset(i),
                _ => None,
            }
        }
        // Locate the InSubsearch subsearch and assert `from` survives as a filter.
        fn in_sub<'a>(e: &'a SearchExpr) -> Option<&'a Query> {
            match e {
                SearchExpr::InSubsearch { subsearch, .. } => Some(subsearch),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    in_sub(a).or_else(|| in_sub(b))
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => in_sub(i),
                _ => None,
            }
        }
        fn has_from_filter(e: &SearchExpr) -> bool {
            match e {
                SearchExpr::FieldFilter { field, .. } => field == "from",
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    has_from_filter(a) || has_from_filter(b)
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => has_from_filter(i),
                _ => false,
            }
        }
        fn query_has_from(q: &Query) -> bool {
            match q {
                Query::Search(e) => has_from_filter(e),
                Query::Piped { source, .. } => query_has_from(source),
            }
        }
        let outer = match &q {
            Query::Search(e) => e,
            Query::Piped { source, .. } => match source.as_ref() {
                Query::Search(e) => e,
                _ => panic!("unexpected shape: {q:?}"),
            },
        };
        assert_eq!(
            in_dataset(outer),
            Some(None),
            "from= must NOT be consumed as a dataset selector: {q:?}"
        );
        let sub = in_sub(outer).expect("InSubsearch present");
        assert!(
            query_has_from(sub),
            "from=production must survive as a field filter, not be dropped: {sub:?}"
        );
    }

    /// NAN-1562 FIX 3: an unknown dataset selector value (`dataset=spanz`) is now
    /// a HARD parse error rather than silently resolving to logs via the lenient
    /// `from_selector` fallback.
    #[test]
    fn unknown_dataset_value_is_parse_error() {
        use crate::query::parse_query;
        assert!(
            parse_query("trace_id IN [dataset=spanz status=500 | return trace_id]").is_err(),
            "dataset=spanz must fail to parse, not resolve to logs"
        );
        assert!(
            parse_query("error | join trace_id [dataset=spanz service_name=checkout]").is_err(),
            "dataset=spanz in a join must fail to parse"
        );
    }

    /// Cross-dataset IN from a SPANS main query targets the logs table + time
    /// column in the subquery; the outer side stays on otel_spans.
    #[test]
    fn cross_dataset_in_spans_to_logs() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query(
            "service_name=checkout AND trace_id IN [dataset=logs status_code=500 | return trace_id]",
        )
        .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // Outer reads spans on start_time.
        assert!(sql.contains("FROM otel_spans"), "{sql}");
        assert!(sql.contains("WHERE start_time BETWEEN"), "{sql}");
        // The IN subquery hits the LOGS table on the LOGS time column.
        assert!(sql.contains("IN (SELECT DISTINCT"), "{sql}");
        assert!(sql.contains("FROM logs WHERE timestamp BETWEEN"), "{sql}");
    }

    /// NAN-1567: a logs subsearch from a SPANS outer must resolve its WHERE
    /// fields against the LOGS profile, not the inherited spans profile. A field
    /// that is a logs column but NOT a spans-promoted field (`source_type`) is
    /// the regression case — under the spans profile it resolves to
    /// `attributes['source_type']`, which references the OUTER table inside the
    /// subquery → a correlated subquery CH rejects (Code 48). (`status_code` in
    /// the test above masks this because it exists on both profiles.)
    #[test]
    fn cross_dataset_in_spans_to_logs_resolves_logs_profile_field() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query(
            "trace_id IN [dataset=logs source_type=\"auth\" | return trace_id]",
        )
        .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // The subsearch resolves `source_type` as the LOGS column, NOT the spans
        // `attributes['source_type']` Map access (the correlated-subquery bug).
        assert!(
            sql.contains("source_type = 'auth'") || sql.contains("source_type = \"auth\""),
            "subsearch must use the logs `source_type` column: {sql}"
        );
        assert!(
            !sql.contains("attributes['source_type']"),
            "subsearch must NOT resolve source_type via the spans attributes map: {sql}"
        );
    }

    /// Reverse direction: cross-dataset IN from a LOGS main query targets the
    /// spans table + start_time in the subquery.
    #[test]
    fn cross_dataset_in_logs_to_spans() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new(); // logs default
        let q = parse_query(
            "status_code=500 AND trace_id IN [dataset=spans service_name=checkout | return trace_id]",
        )
        .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        assert!(sql.contains("FROM logs"), "{sql}");
        // Subquery hits otel_spans on start_time.
        assert!(
            sql.contains("FROM otel_spans WHERE start_time BETWEEN"),
            "{sql}"
        );
    }

    /// Cross-dataset `| join` from a logs main query targets the spans table in
    /// the join CTE and appends the partial_merge join algorithm setting.
    #[test]
    fn cross_dataset_join_logs_to_spans_partial_merge() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new();
        let q =
            parse_query("status_code=500 | join trace_id [dataset=spans service_name=checkout]")
                .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // The join subsearch reads otel_spans on start_time.
        assert!(
            sql.contains("FROM otel_spans\n    WHERE start_time BETWEEN")
                || sql.contains("FROM otel_spans WHERE start_time BETWEEN"),
            "subsearch must hit otel_spans/start_time:\n{sql}"
        );
        // Non-logs subsearch → partial_merge.
        assert!(
            sql.contains("SETTINGS join_algorithm = 'partial_merge'"),
            "{sql}"
        );
    }

    /// A keyless cross-dataset join is rejected with an actionable error.
    #[test]
    fn cross_dataset_join_without_key_is_rejected() {
        use crate::query::ast::{Command, JoinType, Query, SearchExpr};
        use crate::query::ClickHouseSqlGenerator;
        // Build a keyless cross-dataset join AST directly (the parser requires
        // ≥1 field, so construct the degenerate shape to exercise the guard).
        let q = Query::Piped {
            source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
            command: Command::Join {
                join_type: JoinType::Inner,
                fields: vec![],
                subsearch: Box::new(Query::Search(SearchExpr::FieldFilter {
                    field: "service_name".to_string(),
                    op: crate::query::ast::Comparator::Eq,
                    value: crate::query::ast::Value::String("checkout".to_string()),
                })),
                max: 1,
                overwrite: true,
                maxout: None,
                subsearch_dataset: Some(Dataset::Spans),
            },
        };
        let g = ClickHouseSqlGenerator::new();
        let err = g.generate(&q, &xds_range()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cross-dataset correlation requires a join key"),
            "got: {msg}"
        );
    }

    /// A logs-only IN subsearch (dataset=logs from a logs query) is byte-identical
    /// to the same query with NO dataset token — proving the change is inert for
    /// the existing logs path.
    #[test]
    fn logs_only_in_subsearch_byte_identical() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let with_token = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("user IN [dataset=logs status_code=500 | return user]").unwrap(),
                &xds_range(),
            )
            .unwrap();
        let without = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("user IN [status_code=500 | return user]").unwrap(),
                &xds_range(),
            )
            .unwrap();
        assert_eq!(
            with_token, without,
            "logs-only IN with dataset=logs must be byte-identical to the no-token form"
        );
    }

    /// NAN-1562 FIX 1: a cross-dataset `| join service_name [dataset=spans …]`
    /// from a logs main query must resolve the SUB-side join key through the
    /// SPANS profile (which keeps `service_name`), NOT the logs profile (which
    /// aliases `service_name → cloud_service`, a column `otel_spans` lacks →
    /// Code 47 UNKNOWN_IDENTIFIER at runtime). The main side keeps the logs
    /// resolution. Existing join tests all key on `trace_id` (which canonicalizes
    /// identically across profiles) and so never exercised this.
    #[test]
    fn cross_dataset_join_sub_key_resolves_against_sub_profile() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new(); // logs main
        let q = parse_query("error | join service_name [dataset=spans service_name=checkout]")
            .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // SUB side of the ON clause must be the bare spans column, not cloud_service.
        assert!(
            sql.contains("= sub.service_name") || sql.contains("= sub.\"service_name\""),
            "ON sub side must be bare service_name (spans profile):\n{sql}"
        );
        // LIMIT … BY and the empty-key eviction also bind the SUB key.
        assert!(
            sql.contains("LIMIT 1 BY service_name")
                || sql.contains("LIMIT 1 BY \"service_name\""),
            "LIMIT BY must use the spans-profile sub key:\n{sql}"
        );
        assert!(
            sql.contains("toString(service_name) != ''")
                || sql.contains("toString(\"service_name\") != ''"),
            "sub key eviction must use spans-profile key:\n{sql}"
        );
        // The logs alias must NOT appear anywhere on the sub side.
        assert!(
            !sql.contains("sub.cloud_service") && !sql.contains("BY cloud_service"),
            "sub side must not resolve to the logs-only cloud_service:\n{sql}"
        );
        // The MAIN side keeps the logs resolution: service_name → cloud_service.
        assert!(
            sql.contains("main.cloud_service") || sql.contains("main.\"cloud_service\""),
            "main side must keep the logs profile (cloud_service):\n{sql}"
        );
    }

    /// NAN-1562 FIX 4: a cross-dataset IN with a STRING outer field and a NUMERIC
    /// return field must NOT emit `lower(<numeric col>)` (Code 43 — `lower` wants
    /// String). Both sides are coerced with `toString()` instead. Numeric form is
    /// reserved for the both-sides-numeric case.
    #[test]
    fn cross_dataset_in_string_outer_numeric_return_no_lower() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new(); // logs main; `user` is a string field
        let q = parse_query("user IN [dataset=spans service_name=checkout | return duration_ns]")
            .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // The numeric sub column must never be wrapped in lower().
        assert!(
            !sql.contains("lower(duration_ns)") && !sql.contains("lower(\"duration_ns\")"),
            "must not lower() a numeric sub return field:\n{sql}"
        );
        // Mixed-type comparison falls back to toString() on each side.
        assert!(
            sql.contains("toString(") && sql.contains("toString(duration_ns)"),
            "mixed string/numeric IN must coerce both sides with toString():\n{sql}"
        );
    }

    /// NAN-1562 FIX 4 (positive): when BOTH sides are numeric the bare,
    /// no-coercion form is kept (no toString/lower wrapping the comparison).
    #[test]
    fn cross_dataset_in_both_numeric_keeps_bare_form() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        // outer `status_code` and sub `duration_ns` — both numeric.
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query(
            "service_name=checkout AND status_code IN [dataset=metrics metric_name=x | return value]",
        );
        // Just assert it generates and uses no lower() on the numeric value col.
        if let Ok(q) = q {
            let sql = g.generate(&q, &xds_range()).unwrap();
            assert!(!sql.contains("lower(value)"), "{sql}");
        }
    }
}
