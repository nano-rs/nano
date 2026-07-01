// SPDX-License-Identifier: AGPL-3.0-or-later

export interface TimeRange {
  start: string;
  end: string;
}

export interface SearchRequest {
  query: string;
  time_range: TimeRange;
  limit?: number;
  offset?: number;
  use_cache?: boolean;
  skip_field_stats?: boolean;
  /** Skip histogram generation. Set true on surfaces that don't render
   * a time-bucketed histogram (detection rule tester, dashboard panels).
   * The /api/search handler always honors this flag (default false). */
  skip_histogram?: boolean;
  /** Table view mode - fetch minimal columns, full data fetched on row expand */
  table_view?: boolean;
  /** Request ID for query tracking and cancellation */
  request_id?: string;
  /** Run query asynchronously - returns job_id for polling */
  async_mode?: boolean;
  /** Query priority for admission control: "interactive" (default) or "analytics" (long-running) */
  priority?: 'interactive' | 'analytics';
  /**
   * Observability dataset selector (NAN-1534). The nPL search terms + pipeline
   * run against the selected ClickHouse table. Omitted/"logs" = the UDM logs
   * lane (default); "spans" = otel_spans; "metrics" = otel_metrics. Unknown
   * values fall back to logs server-side (never an error).
   */
  dataset?: SearchDataset;
}

/** Observability dataset a search runs against (NAN-1534). */
export type SearchDataset = 'logs' | 'spans' | 'metrics';

// ============================================================================
// Async Search Types
// ============================================================================

/** Response when starting an async search (async_mode=true) */
export interface AsyncSearchResponse {
  /** Job ID for polling status */
  job_id: string;
  /** Initial status (always "running") */
  status: 'running';
}

/** Progress information for a running search job */
export interface SearchJobProgress {
  /** Number of rows scanned so far */
  rows_scanned: number;
  /** Estimated total rows to scan */
  rows_total: number;
  /** Completion percentage (0-100) */
  percent: number;
  /** Time elapsed since job started (milliseconds) */
  elapsed_ms: number;
}

/** Status of an async search job */
export type SearchJobStatusValue = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

/** Priority level for search queries */
export type QueryPriority = 'detection' | 'near_realtime' | 'interactive' | 'analytics';

/** Full status response for an async search job */
export interface SearchJobStatus {
  /** Job ID */
  job_id: string;
  /** Current status */
  status: SearchJobStatusValue;
  /** Progress information (when running) */
  progress?: SearchJobProgress;
  /** Search results (when completed) */
  result?: SearchResponse;
  /** Error message (when failed) */
  error?: string;
  /** Queue position (1-based, when queued) */
  queue_position?: number;
  /** Estimated wait time in seconds (when queued) */
  estimated_wait_seconds?: number;
}

/** Summary of a search job for the active searches panel */
export interface SearchJobSummary {
  job_id: string;
  status: SearchJobStatusValue;
  query: string;
  created_at_ms: number;
  elapsed_ms: number;
  queue_position?: number;
  priority: QueryPriority;
}

/** Summary of a search job for the admin view (includes user_id) */
export interface AdminSearchJobSummary {
  job_id: string;
  status: SearchJobStatusValue;
  user_id: string | null;
  query: string;
  created_at_ms: number;
  elapsed_ms: number;
  queue_position?: number;
  priority: QueryPriority;
}

/** Admission control statistics */
export interface AdmissionStats {
  active_adhoc: number;
  queued: number;
  per_user_counts: [string, number][];
}

/** Admin list search jobs response */
export interface AdminSearchJobsResponse {
  jobs: AdminSearchJobSummary[];
  stats: AdmissionStats;
}

/** Admin-configurable search admission control settings */
export interface SearchAdmissionConfig {
  global_adhoc_limit: number;
  per_user_limit: number;
  max_queue_depth: number;
  queue_timeout_seconds: number;
  interactive_max_execution_time: number;
  interactive_max_memory_gb: number;
  analytics_max_execution_time: number;
  analytics_max_memory_gb: number;
  realtime_max_execution_time: number;
  realtime_max_memory_gb: number;
}

/** Admin-configurable search query safety limits */
export interface SearchQueryLimitsConfig {
  max_group_array_size: number;
  max_mvexpand_rows: number;
  max_post_processing_groups: number;
  max_streaming_cache_rows: number;
  block_on_cost_errors: boolean;
}

// ============================================================================
// Streaming Search SSE Types
// ============================================================================

/** Callbacks for SSE streaming search events */
export interface SearchStreamCallbacks {
  onQueued?: (data: { queue_position: number; estimated_wait_seconds: number }) => void;
  onStarted?: (data: { job_id: string; query_id: string; is_streaming: boolean }) => void;
  onProgress?: (data: SearchJobProgress) => void;
  onRows?: (data: { rows: Record<string, unknown>[]; batch_index: number; cumulative_count: number }) => void;
  onMetadata?: (data: SearchStreamMetadata) => void;
  onCompleted?: (data: { total_rows_delivered: number }) => void;
  onError?: (data: { code: string; message: string }) => void;
  // NAN-1595: server cache status parsed from the stream response headers.
  onCacheMeta?: (meta: import('./index').CacheMeta) => void;
}

/** Metadata delivered after all rows (or with single batch for non-streaming queries) */
export interface SearchStreamMetadata {
  total_count: number;
  execution_time_ms: number;
  fields: FieldInfo[];
  histogram?: HistogramBucket[];
  warnings?: QueryWarning[];
  cost_score?: number;
  display_type?: DisplayType;
  column_order?: string[];
  generated_sql?: string;
}

export interface RawSqlRequest {
  sql: string;
  time_range: TimeRange;
  limit?: number;
  offset?: number;
}

export interface HistogramBucket {
  time: string;
  count: number;
}

// Query warning from cost analysis (query cost analysis)
export interface QueryWarning {
  severity: 'info' | 'warning' | 'error';
  code: string;
  message: string;
  suggestion?: string;
  impact?: string;
}

/**
 * Display type hint from backend for frontend visualization selection.
 * Determined by the terminal command in the query AST.
 */
export type DisplayType =
  | 'events'      // Raw log events with infinite scroll
  | 'table'       // Paginated table (stats, table after aggregation)
  | 'timechart'   // Time-series chart (timechart command)
  | 'ranked_bar'  // Horizontal bar chart (top, rare commands)
  | 'transaction' // Transaction cards (transaction command)
  | 'flow'        // Flow/funnel diagram (sequence, funnel commands)
  | 'tree'        // Hierarchical tree visualization (tree command)
  | 'asset'       // Asset-centric view with identity resolution (asset command)
  | 'cloud'       // Cloud investigation view with faceted summaries (cloud command)
  | 'lateral'     // Lateral movement trace with hop-by-hop paths (lateral command)
  | 'services'    // OTLP services overview (services command) — reuses ServicesTab
  | 'service'     // OTLP service RED drill-in (service command) — reuses ServiceDetail
  | 'trace'       // OTLP distributed-trace waterfall (trace command) — reuses TraceWaterfall
  | 'metric'      // OTLP metrics explorer (metric command) — reuses MetricsExplorer
  | 'retro';      // IOC retro-hunt view (`ioc=… | retro`, NAN-1580) — reuses RetroView

// ============================================================================
// IOC retro-hunt (NAN-1580)
//
// `ioc=<value> | retro` (summary), `ioc in [..]|feed() | retro` (campaign list),
// `… | retro by asset|user` (pivot rollup). The initial /api/search response is a
// MARKER carrying the parsed retro request (`_retro_*` fields on results[0].fields);
// the real data is fetched from POST /api/search/retro. Verdict bands reuse the
// prevalence rarity logic — ratio = distinct_hosts_touched / total_hosts_in_env;
// rare ≤ 0.02, uncommon ≤ 0.15, else common.
// ============================================================================

/** Retro hunt submode, derived from the nPL `| retro` shape. */
export type RetroSubmode = 'summary' | 'list' | 'pivot';

/** Retro hunt pivot axis. host/ip/entity/account all normalize to "asset". */
export type RetroAxis = 'indicator' | 'asset' | 'user';

/** Prevalence verdict band (rarest = rare). */
export type RetroVerdict = 'rare' | 'uncommon' | 'common';

export interface RetroRequest {
  query: string;
  time_range: TimeRange;
  /** "indicator" | "asset" | "user" — drives the submode/projection server-side. */
  axis: string;
  offset?: number;
  limit?: number;
  sort?: string;
}

/** One [field, count] pair for the summary's matched-fields breakdown. */
export type RetroMatchedField = [string, number];

/** A pivot/entity target the indicator landed on (summary top_entities). */
export interface RetroTopEntity {
  id: string;
  hits: number;
  kind: string;
}

/** Single-indicator summary payload (summary submode). */
export interface RetroIndicator {
  value: string;
  type: string;
  source: string | null;
  campaign: string | null;
  confidence: number;
  hits: number;
  first_seen: string | null;
  last_seen: string | null;
  matched_fields: RetroMatchedField[];
  distinct_hosts: number;
  total_hosts: number;
  verdict: RetroVerdict;
  top_entities: RetroTopEntity[];
}

/** One row of the campaign list (list submode). */
export interface RetroListRow {
  value: string;
  type: string;
  hits: number;
  hosts: number;
  total_hosts: number;
  first_seen: string | null;
  last_seen: string | null;
  field: string;
  verdict: RetroVerdict;
}

/** One row of the asset/user pivot rollup (pivot submode). */
export interface RetroPivotRow {
  id: string;
  name: string;
  sub: string | null;
  iocs: number;
  indicators: string[];
  first_seen: string | null;
  last_seen: string | null;
  worst_verdict: RetroVerdict;
}

export interface RetroResponse {
  submode: RetroSubmode;
  axis: RetroAxis;
  total_hosts: number;
  generated_sql?: string;
  // summary submode
  indicator?: RetroIndicator;
  // list submode
  total_indicators?: number;
  rows?: RetroListRow[] | RetroPivotRow[];
  no_hits?: string[];
  // pivot submode — backend serializes pivot rows under a distinct field
  // (a single struct can't carry two typed `rows`); useRetro normalizes
  // these into `rows` so the views read one field. (NAN-1580)
  pivot_rows?: RetroPivotRow[];
  offset?: number;
  limit?: number;
  has_more?: boolean;
}

// ============================================================================
// OpenTelemetry observability (NAN-1528)
//
// Spans/metrics are stored RAW/native in ClickHouse (otel_spans, otel_metrics)
// — OTLP semconv attributes preserved losslessly in Map columns, with a thin
// security-correlation entity overlay promoted to indexed columns. Logs ride
// the existing UDM/OCSF lane and only gain trace_id/span_id correlation cols.
// ============================================================================

/** One OTLP span, flattened to the otel_spans row shape (lowercased-hex ids). */
export interface OtelSpan {
  trace_id: string;
  span_id: string;
  parent_span_id: string;
  start_time: string;   // RFC3339 / ISO-8601 (DateTime64(9))
  end_time: string;
  duration_ns: number;
  service_name: string;
  span_name: string;
  span_kind: string;    // INTERNAL | SERVER | CLIENT | PRODUCER | CONSUMER
  status_code: string;  // UNSET | OK | ERROR
  status_message: string;
  attributes: Record<string, string>;
  resource_attributes: Record<string, string>;
  // thin security-correlation entity overlay
  src_ip: string;
  dest_ip: string;
  user: string;
  host: string;
}

/** GET trace-by-id → spans ordered by start_time, plus the resolved window. */
export interface TraceResponse {
  trace_id: string;
  spans: OtelSpan[];
  start_time: string;
  end_time: string;
  duration_ns: number;
}

/**
 * One point in a metric timeseries (value already aggregated server-side).
 *
 * NAN-1534: reconciled with the real backend `MetricTimeseriesResponse` shape —
 * the backend emits `{bucket, value}` per point (bucket = ISO-8601 interval
 * start from `toStartOfInterval`), NOT `{timestamp, value}`. `timestamp` is kept
 * as an optional alias so any older callers keep type-checking; readers should
 * prefer `bucket ?? timestamp`.
 */
export interface MetricPoint {
  /** ISO-8601 bucket start (backend field). */
  bucket?: string;
  /** Legacy alias for `bucket` — prefer `bucket`. */
  timestamp?: string;
  value: number;
}

/**
 * Request for an OTLP metric time series.
 * Matches backend `MetricTimeseriesRequest` (POST /api/search/metrics/timeseries):
 * `{ metric_name, service_name?, time_range, step_secs? }`. The backend buckets
 * by `step_secs` (default 60) and returns `avg(value)` per bucket.
 */
export interface MetricsQueryRequest {
  metric_name: string;
  time_range: TimeRange;
  /** Optional service_name filter. */
  service_name?: string;
  /** Bucket width in seconds (clamped to >= 1 server-side; defaults to 60). */
  step_secs?: number;
}

/**
 * Response for a metric time series.
 * Matches backend `MetricTimeseriesResponse`: `{ metric_name, points, step_secs }`.
 */
export interface MetricsQueryResponse {
  metric_name: string;
  /** Bucketed points (`{bucket, value}`), ordered by bucket. */
  points: MetricPoint[];
  /** Bucket width applied (after the >= 1 clamp). */
  step_secs: number;
}

// ---------------------------------------------------------------------------
// Metrics v2 (NAN-1540) — multi-series timeseries with agg / group_by / filters
// ---------------------------------------------------------------------------

/** Aggregation applied per bucket. Validated server-side against an allowlist. */
export type MetricAgg =
  | 'avg'
  | 'sum'
  | 'min'
  | 'max'
  | 'count'
  | 'rate'
  | 'p50'
  | 'p95'
  | 'p99';

/** A single attribute/resource-attribute equality filter. */
export interface MetricFilter {
  key: string;
  value: string;
}

/** One time-bucketed scalar point. `t` is RFC3339, `v` the aggregated value. */
export interface MetricSeriesPoint {
  t: string;
  v: number;
}

/** One series in a metrics-v2 response. `key` is "" when no group_by. */
export interface MetricSeries {
  key: string;
  points: MetricSeriesPoint[];
}

/**
 * Request for a metrics-v2 timeseries (POST /api/search/metrics/timeseries).
 * Superset of the legacy single-series request: `agg` defaults to "avg" and an
 * absent `group_by` yields a single series, so omitting both is back-compatible.
 */
export interface MetricTimeseriesV2Request {
  metric_name: string;
  time_range: TimeRange;
  service_name?: string;
  /** Bucket width in seconds (clamped to >= 1 server-side; defaults to 60). */
  step_secs?: number;
  /** Aggregation; defaults to "avg" server-side. */
  agg?: MetricAgg;
  /** A tag/attribute key that splits the result into one series per value. */
  group_by?: string;
  /** Attribute/resource-attribute equality filters (ANDed). */
  filters?: MetricFilter[];
}

/** Response for a metrics-v2 timeseries — one or more aligned series. */
export interface MetricTimeseriesV2Response {
  metric_name: string;
  agg: MetricAgg;
  group_by?: string;
  series: MetricSeries[];
  step_secs: number;
}

/**
 * GET /api/search/metrics/tags — distinct tag keys (key omitted) or the distinct
 * values for one key (key given) present on a metric over the window.
 */
export interface MetricTagsResponse {
  tag_keys?: string[];
  tag_values?: string[];
}

// ---------------------------------------------------------------------------
// Metric monitors (NAN-1540) — saved metrics-v2 query + breach test, evaluated
// by the jobs runner. CRUD lives on the main api service
// (GET/POST/PUT/DELETE /api/observability/metric-monitors).
// ---------------------------------------------------------------------------

/** Breach comparator: `value <comparator> threshold`. */
export type MetricMonitorComparator = 'gt' | 'gte' | 'lt' | 'lte';

/** A stored metric-monitor definition. Breach *state* is not part of the row. */
export interface MetricMonitor {
  /** typeid (`mon_<base32>`). */
  id: string;
  name: string;
  metric_name: string;
  agg: MetricAgg;
  /** Splits the evaluation into one series per value of this tag key. */
  group_by?: string;
  filters: MetricFilter[];
  comparator: MetricMonitorComparator;
  threshold: number;
  /** Trailing window (seconds) the aggregate is computed over. */
  window_secs: number;
  /** Runner cadence in seconds (30..=3600). */
  eval_interval_secs: number;
  enabled: boolean;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

/** Create/update payload (server-derived fields like id/timestamps are never sent). */
export interface MetricMonitorRequest {
  name: string;
  metric_name: string;
  agg: MetricAgg;
  group_by?: string;
  filters: MetricFilter[];
  comparator: MetricMonitorComparator;
  threshold: number;
  /** 1..=86400. */
  window_secs: number;
  /** 30..=3600. */
  eval_interval_secs: number;
  enabled: boolean;
}

export interface MetricMonitorListResponse {
  monitors: MetricMonitor[];
}

/** Filters for the recent-traces list (GET /api/search/traces, NAN-1534). */
export interface ListTracesRequest {
  time_range: TimeRange;
  /** Optional substring/exact service_name filter. */
  service?: string;
  /** Only return traces that contain at least one ERROR span. */
  errors_only?: boolean;
  /** Minimum root/span duration in nanoseconds. */
  min_duration_ns?: number;
  /** Max traces to return (page size; backend clamps to 1000, default 200). */
  limit?: number;
  /**
   * Keyset pagination cursor (NAN-1539, RFC3339). When set, only traces whose
   * `start_time` is strictly before this instant are returned. Pass the last
   * row's `start_time` from the previous page to load the next page (the list
   * is most-recent-first).
   */
  before?: string;
}

/**
 * One row in the recent-traces list. Aggregated per trace_id from otel_spans.
 * Field names match the backend `list_traces` response verbatim (reconciled in
 * the NAN-1534 verify stage): the SQL builder emits `root_service` / `root_name`
 * (via argMin on the parent-less span), not `service_name` / `root_span_name`.
 */
export interface RecentTrace {
  trace_id: string;
  /** Root (parent-less) span's service.name. */
  root_service: string;
  /** Root span name. */
  root_name: string;
  span_count: number;
  error_count: number;
  /** Root-span duration in nanoseconds (the trace's wall-clock span). */
  duration_ns: number;
  /** Trace start_time (ISO-8601). */
  start_time: string;
}

export interface ListTracesResponse {
  traces: RecentTrace[];
  /** Number of traces returned (mirrors backend `count`). */
  count?: number;
}

/** One row in the metric-names list — backend emits `{metric_name}` objects. */
export interface MetricName {
  metric_name: string;
}

/** Distinct metric names for the Metrics explorer dropdown (GET /api/search/metrics/names). */
export interface MetricNamesResponse {
  names: MetricName[];
  /** Number of distinct metric names returned (mirrors backend `count`). */
  count?: number;
}

export interface SearchResponse {
  results: Record<string, unknown>[];
  total_count: number;
  execution_time_ms: number;
  fields: FieldInfo[];
  generated_sql?: string;
  histogram?: HistogramBucket[];
  warnings?: QueryWarning[];
  cost_score?: number;
  /** Display type hint from backend for visualization selection */
  display_type?: DisplayType;
  /** Column order from | table command (preserves user-specified order) */
  column_order?: string[];
}

export interface FieldInfo {
  name: string;
  field_type: string;
  count: number;
  top_values: [string, number][];
  cardinality?: number;  // Total unique values across ALL matching events (from server-side topK)
}

// Active schema profile's field universe (GET /api/schema/fields). Profile-aware
// (OCSF Phase 7, NAN-1241) — the shape is identical for UDM and OCSF; only the
// discriminator + field set differ.
export interface SchemaFieldInfo {
  name: string;
  type: string;
  category: string;
  entity_type?: string;
  prewhere: boolean;
  search: boolean;
}

export interface SchemaFieldsResponse {
  schema: string;            // active discriminator: "udm" | "ocsf"
  fields: SchemaFieldInfo[];
}

// Async field stats request/response (loaded separately from main search)
export interface FieldStatsRequest {
  query: string;
  start: string;
  end: string;
  /** Search request id — the server derives `{request_id}-fstats` so cancelling the search kills the stats query too (NAN-1428) */
  request_id?: string;
  /** Column subset to compute stats for; omit for the full table inventory (NAN-1427) */
  columns?: string[];
  /** Per-query dataset; must match the search's dataset so stats enumerate the right table/columns (NAN-1559) */
  dataset?: SearchDataset;
}

export interface FieldStatsResponse {
  fields: FieldInfo[];
  total_events: number;
}

// On-demand field values (Kibana-style, loaded when user expands a field)
export interface FieldValuesRequest {
  field: string;
  query: string;
  start: string;
  end: string;
  limit?: number;
  /** Per-query dataset; must match the search's dataset so drill-in reads the right table/column (NAN-1559) */
  dataset?: SearchDataset;
}

export interface FieldValueInfo {
  value: string;
  count: number;
  percentage: number;
}

export interface FieldValuesResponse {
  field: string;
  values: FieldValueInfo[];
  total_count: number;
}

// ============================================================================
// Asset Events Pagination Types
// ============================================================================

/** Facet counts for asset view filtering */
export interface AssetFacets {
  /** Source type facet: [value, count][] */
  source_type: [string, number][];
  /** Event type facet: [value, count][] */
  event_type: [string, number][];
  /** User facet: [value, count][] */
  user: [string, number][];
}

/** Pagination metadata for asset events */
export interface AssetPagination {
  /** Total number of events matching the query */
  total_count: number;
  /** Current offset (events already returned) */
  offset: number;
  /** Page size limit */
  limit: number;
  /** Whether more events are available */
  has_more: boolean;
  /** Facet counts for filtering UI */
  facets: AssetFacets;
}

/** Filters for paginated asset event queries */
export interface AssetEventFilters {
  /** Filter by source types (OR) */
  source_types?: string[];
  /** Filter by event types (OR) - note: computed from fields, not stored */
  event_types?: string[];
  /** Filter by users (OR) */
  users?: string[];
  /** Text search across message, process, file_path, etc. */
  search_text?: string;
}

/** Request for fetching paginated asset events */
export interface AssetEventsRequest {
  /** Identifier field (e.g., "src_host", "src_ip") */
  identifier_field: string;
  /** Identifier value (e.g., "workstation-01.corp.local") */
  identifier_value: string;
  /** Resolved identities from the initial asset query */
  identities: Record<string, unknown>[];
  /** Time range for the search */
  time_range: TimeRange;
  /** Offset for pagination */
  offset?: number;
  /** Limit for pagination (default 500) */
  limit?: number;
  /** Optional filters */
  filters?: AssetEventFilters;
}

/** Request for fetching true first/last seen timestamps for an asset */
export interface AssetTrueTimeRangeRequest {
  /** Identifier field (e.g., "src_host", "src_ip") */
  identifier_field: string;
  /** Identifier value (e.g., "workstation-01.corp.local") */
  identifier_value: string;
  /** Resolved identities from the initial asset query */
  identities: Record<string, unknown>[];
}

/** Response with true first/last seen timestamps */
export interface AssetTrueTimeRangeResponse {
  first_seen: string | null;
  last_seen: string | null;
}

/** Request for fetching artifact occurrences with server-side prevalence filtering */
export interface AssetArtifactsRequest {
  /** Identifier field (e.g., "src_host", "src_ip") */
  identifier_field: string;
  /** Identifier value (e.g., "workstation-01.corp.local") */
  identifier_value: string;
  /** Resolved identities from the initial asset query */
  identities: Record<string, unknown>[];
  /** Time range for the search */
  time_range: TimeRange;
  /** Max host count filter — only return artifacts seen on <= this many hosts (default 10) */
  max_host_count?: number;
  /** Prevalence time window: "1h", "24h", "7d", "30d" (default "24h") */
  prevalence_window?: string;
}

/** A single artifact occurrence with its event timestamp */
export interface ArtifactOccurrence {
  artifact: string;
  timestamp: string;
}

/** Prevalence info for a unique artifact */
export interface ArtifactPrevalence {
  artifact: string;
  host_count: number;
  is_rare: boolean;
  prevalence_score: number;
  total_occurrences: number;
  first_seen: string;
}

/** Response with per-event artifact occurrences and prevalence metadata */
export interface AssetArtifactsResponse {
  hashes: ArtifactOccurrence[];
  domains: ArtifactOccurrence[];
  /** Prevalence data for each unique hash */
  hash_prevalence: ArtifactPrevalence[];
  /** Prevalence data for each unique domain */
  domain_prevalence: ArtifactPrevalence[];
  /** Rarity threshold from prevalence settings */
  rarity_threshold: number;
}

/** Response for paginated asset events */
export interface AssetEventsResponse {
  /** The events for this page */
  events: Record<string, unknown>[];
  /** Total count of matching events */
  total_count: number;
  /** Facet counts for filtering UI */
  facets: AssetFacets;
  /** Current offset */
  offset: number;
  /** Page size limit */
  limit: number;
  /** Whether more events are available */
  has_more: boolean;
}

// ============================================================================
// Cloud Events Pagination Types
// ============================================================================

/** Facet counts for cloud view filtering */
export interface CloudFacets {
  /** Cloud provider facet: [value, count][] */
  cloud_provider: [string, number][];
  /** Cloud service facet: [value, count][] */
  cloud_service: [string, number][];
  /** Cloud region facet: [value, count][] */
  cloud_region: [string, number][];
  /** Cloud account ID facet: [value, count][] */
  cloud_account_id: [string, number][];
  /** Resource type facet: [value, count][] */
  resource_type: [string, number][];
  /** Change type facet: [value, count][] */
  change_type: [string, number][];
}

/** Filters for paginated cloud event queries */
export interface CloudEventFilters {
  /** Filter by cloud providers (OR) */
  cloud_providers?: string[];
  /** Filter by cloud services (OR) */
  cloud_services?: string[];
  /** Filter by cloud regions (OR) */
  cloud_regions?: string[];
  /** Filter by cloud account IDs (OR) */
  cloud_account_ids?: string[];
  /** Filter by resource types (OR) */
  resource_types?: string[];
  /** Filter by change types (OR) */
  change_types?: string[];
  /** Text search across action, user, src_ip, resource_id, resource_name, message, http_user_agent */
  search_text?: string;
}

/** Request for fetching paginated cloud events */
export interface CloudEventsRequest {
  /** The original nPL query string */
  query: string;
  /** Time range for the search */
  time_range: TimeRange;
  /** Offset for pagination */
  offset?: number;
  /** Limit for pagination (default 200) */
  limit?: number;
  /** Optional filters */
  filters?: CloudEventFilters;
}

/** Response for paginated cloud events */
export interface CloudEventsResponse {
  /** The events for this page */
  events: Record<string, unknown>[];
  /** Total count of matching events */
  total_count: number;
  /** Facet counts for filtering UI */
  facets: CloudFacets;
  /** Current offset */
  offset: number;
  /** Page size limit */
  limit: number;
  /** Whether more events are available */
  has_more: boolean;
  /** Filtered resources (only present when offset=0 and filters active) */
  resources?: Record<string, unknown>[];
  /** Filtered user activity (only present when offset=0 and filters active) */
  user_activity?: CloudUserActivity[];
}

// ============================================================================
// Cloud User Timeline Types
// ============================================================================

/** Request for fetching a cloud user's activity timeline */
export interface CloudUserTimelineRequest {
  /** The original nPL query string */
  query: string;
  /** Time range for the search */
  time_range: TimeRange;
  /** The user to get timeline for */
  user: string;
}

/** Session summary for a single user's cloud activity */
export interface CloudUserSessionSummary {
  /** Cloud services accessed */
  services: string[];
  /** Cloud regions accessed */
  regions: string[];
  /** Source IPs used */
  ips: string[];
  /** Total event count */
  event_count: number;
  /** Failed API calls */
  fail_count: number;
  /** Permission/IAM change operations */
  permission_change_count: number;
  /** Delete operations */
  delete_count: number;
  /** Whether any request lacked MFA */
  has_no_mfa: boolean;
  /** Computed risk indicators */
  risk_indicators: string[];
}

/** Response for cloud user timeline */
export interface CloudUserTimelineResponse {
  /** Chronological events for this user */
  events: Record<string, unknown>[];
  /** Session summary with risk indicators */
  summary: CloudUserSessionSummary;
}

// ============================================================================
// Cloud Entity Pivot Types
// ============================================================================

/** Request for fetching entity cross-references */
export interface CloudEntityPivotRequest {
  /** The original nPL query string */
  query: string;
  /** Time range for the search */
  time_range: TimeRange;
  /** Entity type: "user", "ip", or "resource" */
  entity_type: string;
  /** Entity value to pivot on */
  entity_value: string;
}

/** Cross-referenced entity */
export interface EntityCrossReference {
  /** Entity type (e.g. "user", "ip", "resource") */
  entity_type: string;
  /** Entity value */
  entity_value: string;
  /** Number of events involving this entity */
  event_count: number;
}

/** Response for entity pivot */
export interface CloudEntityPivotResponse {
  /** Chronological events involving this entity */
  events: Record<string, unknown>[];
  /** Cross-referenced related entities */
  cross_references: EntityCrossReference[];
  /** Entity summary */
  entity_summary: Record<string, unknown>;
}

/** Pre-aggregated cloud user activity */
export interface CloudUserActivity {
  user: string;
  event_count: number;
  distinct_services: number;
  distinct_regions: number;
  distinct_ips: number;
  fail_count: number;
  permission_change_count: number;
  delete_count: number;
  mfa_count: number;
  no_mfa_count: number;
  risk_indicators: string[];
}

// AI triage hints for guiding automated alert analysis
export interface AiTriageHints {
  ignore_when: string[];  // Conditions indicating benign/expected activity
  suspicious_when: string[];  // Conditions indicating especially suspicious activity
  context?: string;  // Additional context for the AI about this detection
}

export interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  query: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  mode: 'staging' | 'live' | 'alerting' | 'paused';
  detection_mode?: 'real-time' | 'scheduled';
  materialized_view_name?: string;
  schedule_cron?: string;
  lookback_minutes?: number;
  // NAN-1561: dataset this rule queries ('logs' default; 'spans'/'metrics' are
  // scheduled-only). Mirrors the search dataset selector.
  dataset?: SearchDataset;
  mitre_tactics: string[];
  mitre_techniques: string[];
  narrative?: string;
  reference_url?: string;
  author?: string;
  tags: string[];
  ai_generated?: boolean;
  realtime_enabled?: boolean;
  risk_score?: number;
  risk_entity_field?: string;
  risk_modifiers?: RiskModifier[];
  ai_triage_hints?: AiTriageHints;
  archived?: boolean;
  folder?: string;
  created_at: string;
  updated_at: string;
  last_run_at?: string;
  last_match_at?: string;
  match_count: number;
  live_match_count?: number;
  // Case permissions - inherited by cases created from this rule
  case_visibility?: 'public' | 'group' | 'private';
  case_groups?: SharedGroup[];
  case_assigned_group?: string;
  // Alert mode: grouped (all matches → 1 alert) or per_event (each match → 1 alert)
  alert_mode?: 'grouped' | 'per_event';
  // NAN-452: playbook to auto-attach when this rule fires and produces a case
  playbook_selector_mode?: 'none' | 'specific' | 'adaptive';
  playbook_id?: string | null;
}

// Response type for create/update operations that may include warnings
export interface DetectionResponse extends DetectionRule {
  warning?: string; // Warning message from backend (e.g., auto-correction)
}

export interface CreateDetectionRequest {
  name: string;
  description?: string;
  query: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  mode: 'staging' | 'live' | 'alerting';
  detection_mode?: 'real-time' | 'scheduled';
  schedule_cron?: string;
  lookback_minutes?: number; // Custom lookback period in minutes
  // NAN-1561: dataset this rule queries ('logs' default; 'spans'/'metrics' are
  // scheduled-only).
  dataset?: SearchDataset;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  narrative?: string;
  reference_url?: string;
  author?: string;
  tags?: string[];
  ai_generated?: boolean;
  realtime_enabled?: boolean;
  risk_score?: number;
  risk_entity_field?: string;
  risk_modifiers?: RiskModifier[];
  ai_triage_hints?: AiTriageHints;
  archived?: boolean;
  folder?: string;
  // Case permissions - inherited by cases created from this rule
  case_visibility?: 'public' | 'group' | 'private';
  case_group_ids?: string[];
  case_assigned_group?: string | null;
  // Alert mode: grouped (all matches → 1 alert) or per_event (each match → 1 alert)
  alert_mode?: 'grouped' | 'per_event';
  // NAN-452: playbook to auto-attach when this rule fires and produces a case.
  // Server enforces: mode='specific' requires playbook_id; other modes must leave it null.
  playbook_selector_mode?: 'none' | 'specific' | 'adaptive';
  playbook_id?: string | null;
}

export type UpdateDetectionRequest = Partial<CreateDetectionRequest>;

export interface Alert {
  id: string;
  // NAN-1356: absent when the source detection rule was deleted
  // (FK ON DELETE SET NULL); the API omits it via skip_serializing_if.
  rule_id?: string;
  rule_name?: string;
  rule_query?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  status: 'new' | 'acknowledged' | 'closed';
  disposition?: 'true_positive' | 'false_positive' | 'benign';
  matched_events: Record<string, unknown>[];
  matched_event_count?: number;
  risk_score?: number;
  assigned_to?: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  closed_by?: string;
  closed_at?: string;
  triage_status?: 'pending' | 'running' | 'in_progress' | 'completed' | 'failed';
  triage_verdict?: 'true_positive' | 'false_positive' | 'likely_true_positive' | 'likely_false_positive' | 'needs_investigation' | 'benign';
  created_at: string;
  // NAN-1541 alert-spine discriminator — what produced this alert. The backend
  // always serializes it (defaulting legacy rows to `detection`).
  kind?: AlertKind;
  // NAN-1541 producer id as text — the detection rule UUID for `detection`
  // alerts, or the monitor/check typeid for observability (monitor) alerts.
  source_id?: string;
}

/** NAN-1541 alert-spine kinds. `detection` → SIEM; the rest → Observability. */
export type AlertKind = 'detection' | 'metric_monitor' | 'slo' | 'synthetic';

export interface AlertCounts {
  total: number;
  new: number;
  acknowledged: number;
  closed: number;
  by_severity: Record<string, number>;
}

/** NAN-1019: one hourly bucket from /api/alerts/velocity. */
export interface AlertVelocityBucket {
  bucket_start: string;
  count: number;
}

export interface CloseAlertRequest {
  disposition: 'true_positive' | 'false_positive' | 'benign';
  notes?: string;
}

export interface BulkAlertRequest {
  alert_ids: string[];
  action: 'acknowledge' | 'close' | 'assign';
  disposition?: 'true_positive' | 'false_positive' | 'benign';
  assigned_to?: string;
}

export interface BulkUpdateRulesRequest {
  rule_ids: string[];
  mode: string;
}

export interface BulkUpdateRulesResponse {
  updated: number;
  skipped: number;
  failed: Array<{
    rule_id: string;
    error: string;
  }>;
}

export interface SavedSearch {
  id: string;
  name: string;
  query: string;
  query_mode: 'piped' | 'sql';
  time_range?: TimeRange;
  created_at: string;
  updated_at: string;
  user_id?: string;
  visibility?: 'private' | 'public' | 'group';
}

export interface SharedGroup {
  id: string;
  name: string;
}

export interface SavedSearchWithContext extends SavedSearch {
  is_owner: boolean;
  owner_name?: string;
  shared_groups: SharedGroup[];
  visibility: 'private' | 'public' | 'group';
}

export interface CreateSavedSearchRequest {
  name: string;
  query: string;
  query_mode: 'piped' | 'sql';
  time_range?: TimeRange;
  visibility?: 'private' | 'public' | 'group';
  group_ids?: string[];
}

export interface UpdateSavedSearchRequest {
  name?: string;
  query?: string;
  time_range?: TimeRange;
}

export interface ShareSavedSearchRequest {
  visibility: 'private' | 'public' | 'group';
  group_ids?: string[];
}

export interface SharedSearchResponse {
  id: string;
  query: string;
  query_mode: string;
  time_range_type: string;
  time_range_preset?: string;
  time_range_start?: string;
  time_range_end?: string;
}

export interface CreateSharedSearchRequest {
  query: string;
  query_mode: string;
  time_range_type: string;
  time_range_preset?: string;
  time_range_start?: string;
  time_range_end?: string;
}

export interface CreateSharedSearchResponse {
  id: string;
  short_url: string;
}

// Query explanation types (AI reasoning cache)
export interface StoreQueryExplanationRequest {
  query: string;
  query_mode: string;
  natural_language_prompt?: string;
  explanation?: string;
  reasoning_steps?: ReasoningStep[];
  fields_used?: string[];
  generated_sql?: string;
  complexity?: string;
  suggested_time_range?: string;
}

export interface QueryExplanationResponse {
  query_hash: string;
  query: string;
  query_mode: string;
  natural_language_prompt?: string;
  explanation?: string;
  reasoning_steps?: ReasoningStep[];
  fields_used?: string[];
  generated_sql?: string;
  complexity?: string;
  suggested_time_range?: string;
}

export interface TimeBucket {
  bucket_start: string;
  count: number;
}

export interface TestDetectionResult {
  rule_id: string;
  rule_name: string;
  time_range: TimeRange;
  total_matches: number;
  sample_events: Record<string, unknown>[];
  matches_by_day: { date: string; count: number }[];
  /**
   * Match counts at sub-daily granularity. Computed from the pre-aggregation
   * filter, so aggregated rules (e.g. `... | stats count by src_ip`) still get
   * a meaningful histogram. Empty when the backend can't bucket (parse error,
   * etc.) — fall back to `matches_by_day` or sample events.
   */
  matches_by_bucket?: TimeBucket[];
  /** Bucket size used for `matches_by_bucket`, in seconds. `0` when unbucketed. */
  bucket_size_seconds?: number;
  execution_time_ms: number;
}

export interface ValidateDetectionResult {
  valid: boolean;
  effective_mode: string;
  creates_materialized_view: boolean;
  mode_reason: string;
  warning?: string;
  errors: string[];
  referenced_fields: string[];
}

export interface DetectionMatch {
  id: string;
  detected_at: string;
  severity: string;
  status: string;
  event_count: number;
  events: Record<string, unknown>[];
  /** Whether the match has been reviewed by an analyst (NAN-494). */
  reviewed?: boolean;
  /** When the match was last reviewed, RFC 3339 (NAN-494). */
  reviewed_at?: string;
}

/** Response from POST/DELETE /api/matches/{id}/review (NAN-494). */
export interface MatchReviewResponse {
  reviewed: boolean;
  reviewed_at?: string | null;
  reviewed_by?: string | null;
  note?: string | null;
}

/** Disposition values for a match (NAN-498). Mirrors the Postgres CHECK. */
export type MatchDisposition =
  | 'unclassified'
  | 'true_positive'
  | 'false_positive'
  | 'benign';

/** Rule-level disposition rollup over a time window (NAN-498). */
export interface DispositionStatsResponse {
  total: number;
  unclassified: number;
  true_positive: number;
  false_positive: number;
  benign: number;
  window_start: string;
  window_end: string;
}

/** Response from POST /api/matches/{id}/disposition (NAN-498). */
export interface MatchDispositionResponse {
  disposition: MatchDisposition;
}

/** Predicate kind discriminant on `Predicate` (NAN-501). */
export type PredicateKind =
  | 'keyword'
  | 'field_filter'
  | 'in_list'
  | 'in_subsearch'
  | 'function'
  | 'boolean_function'
  | 'literal';

/** A leaf predicate from the parsed nPL search expression (NAN-501). */
export interface Predicate {
  kind: PredicateKind;
  field?: string | null;
  operator?: string | null;
  value?: string | null;
  values?: string[];
  negated: boolean;
  /** "AND" / "OR" — null on the first predicate. */
  connector?: string | null;
}

/** A pipe stage downstream of the search term (NAN-501). */
export interface PipeStage {
  command: string;
  args: string;
}

/** Response from GET /api/rules/{id}/predicates (NAN-501). */
export interface RulePredicatesResponse {
  raw_query: string;
  parsed: boolean;
  parse_error?: string | null;
  predicates: Predicate[];
  pipe_stages: PipeStage[];
}

export interface DetectionMatchesResponse {
  total: number;
  matches: DetectionMatch[];
}

export interface DailyStat {
  date: string;
  match_count: number;
  alert_count: number;
}

export interface ApiError {
  code: string;
  message: string;
  details?: ParseErrorDetails;
  /** Original warning severity — 'info' warnings render as subtle hints, not alert banners */
  warningSeverity?: 'info' | 'warning' | 'error';
}

export interface ParseErrorDetails {
  position: number;
  line: number;
  column: number;
  token?: string;
  expected: string[];
  suggestions: ErrorSuggestion[];
  formatted: string;
  impact?: string; // For warnings
}

export interface ErrorSuggestion {
  description: string;
  replacement: string;
  /**
   * For AI query-correction suggestions only: the corrected query could not be
   * validated (syntax/runtime), so it is surfaced as "unverified" (NAN-1496).
   */
  unverified?: boolean;
}

export interface EnrichmentSource {
  id: string;
  name: string;
  source_type: string;
  description?: string;
  download_url?: string;
  enabled: boolean;
  last_sync_at?: string;
  last_sync_status?: string;
  record_count: number;
  config?: Record<string, unknown>;
}

export interface EnrichmentSyncResult {
  success: boolean;
  records_loaded: number;
  duration_ms: number;
  error?: string;
}

/** Response from async sync endpoints (202 Accepted or 409 Conflict) */
export interface AsyncSyncResponse {
  source_id: string;
  status: 'in_progress' | 'success' | 'failed';
  message: string;
}

export interface EnrichmentSourceStats {
  total: number;
  last_updated?: string;
}

export interface EnrichmentStats {
  enabled_sources: number;
  total_ip_records: number;
  /** Per-source statistics keyed by source type */
  sources?: Record<string, EnrichmentSourceStats>;
}

export interface IpLookupResult {
  ip: string;
  found: boolean;
  country?: string;
  country_code?: string;
  continent?: string;
  continent_code?: string;
  asn?: string;
  as_name?: string;
  as_domain?: string;
}

export interface AutoSyncConfig {
  source_id: string;
  auto_sync_enabled: boolean;
  sync_interval_hours: number;
  next_sync_at?: string;
}

// NAN-1111: IocLookupResult, IocStats, ThreatFoxConfig, and
// TorExitNodesConfig used to live here. Both providers and the shared
// IOC lookup/stats endpoints moved to the marketplace + Deno
// (nano-rs/nano-enrichments). See project_ipinfo_lite_stays_native for
// why IPinfo Lite stays native.

export interface Feed {
  id: string;
  name: string;
  description?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  category?: string;
  vendor?: string;
  product?: string;
  icon?: string;
  color?: string;
  enabled: boolean;
  stale_alert_enabled: boolean;
  stale_threshold_minutes: number;
  created_at: string;
  updated_at: string;
}

export interface CreateFeedRequest {
  name: string;
  description?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  category?: string;
  vendor?: string;
  product?: string;
  icon?: string;
  color?: string;
}

export interface UpdateFeedRequest extends Partial<CreateFeedRequest> {
  enabled?: boolean;
  stale_alert_enabled?: boolean;
  stale_threshold_minutes?: number;
}

export interface FeedStats {
  feed_id: string;
  feed_name: string;
  event_count: number;
  last_event_at?: string;
}

export interface FeedHealthMetrics {
  feed_id: string;
  feed_name: string;
  total_events: number;
  events_last_24h: number;
  events_last_hour: number;
  avg_events_per_hour: number;
  last_event_at?: string;
  first_event_at?: string;
  data_freshness_hours?: number;
  ingestion_rate_trend: string;
  health_status: string;
  total_size_bytes: number;
  avg_event_size_bytes: number;
  error_rate_24h: number;
  parse_errors_24h: number;
  storage_errors_24h: number;
}

export interface FeedHistoryPoint {
  time: string;
  event_count: number;
  hour_label: string;
}

export interface DiscoveredSourcetype {
  name: string;
  count: number;
  has_feed: boolean;
}

// Cloud Credential types
export type CredentialEnvironment = 'prod' | 'staging' | 'dev';

export interface CloudCredential {
  id: string;
  name: string;
  provider: 'aws_s3' | 'gcp_pubsub' | 'kafka';
  description?: string;
  region?: string;
  environment?: CredentialEnvironment | null;
  expires_at?: string | null;
  last_used_at?: string | null;
  active_version: number;
  created_at: string;
  updated_at: string;
}

export interface CreateCloudCredentialRequest {
  name: string;
  provider: 'aws_s3' | 'gcp_pubsub' | 'kafka';
  credentials: AwsS3Credentials | GcpPubSubCredentials | KafkaCredentials;
  description?: string;
  region?: string;
  environment?: CredentialEnvironment;
  expires_at?: string;
}

/** Metadata-only update — to replace the secret material use `rotateCredential`. */
export interface UpdateCloudCredentialRequest {
  name?: string;
  description?: string;
  region?: string;
  environment?: CredentialEnvironment;
  expires_at?: string;
}

export interface RotateCredentialRequest {
  credentials: AwsS3Credentials | GcpPubSubCredentials | KafkaCredentials;
  note?: string;
}

export interface RollbackCredentialRequest {
  version: number;
  note?: string;
}

export interface CloudCredentialVersion {
  id: string;
  credential_id: string;
  version_number: number;
  created_at: string;
  created_by?: string | null;
  note?: string | null;
  is_active: boolean;
  reverted_from_version?: number | null;
}

export interface CredentialRotationResponse {
  credential: CloudCredential;
  version: CloudCredentialVersion;
}

export interface CredentialVersionListResponse {
  versions: CloudCredentialVersion[];
  total: number;
}

export interface AwsS3Credentials {
  access_key_id: string;
  secret_access_key: string;
  session_token?: string;
  assume_role_arn?: string;
}

export interface GcpPubSubCredentials {
  credentials_json: string;
}

export interface KafkaCredentials {
  sasl_mechanism?: 'PLAIN' | 'SCRAM-SHA-256' | 'SCRAM-SHA-512';
  sasl_username?: string;
  sasl_password?: string;
  tls_enabled?: boolean;
  tls_ca_cert?: string;
}

// ============================================================================
// Source Configuration Types (for wizard and log source configuration)
// ============================================================================

/** TLS configuration for source types */
export interface TlsSourceConfig {
  enabled: boolean;
  /** CA certificate content (PEM format) - for verifying client certificates */
  ca_content?: string;
  /** Server certificate content (PEM format) */
  crt_content?: string;
  /** Private key content (PEM format) */
  key_content?: string;
}

export interface CredentialListResponse {
  credentials: CloudCredential[];
  total: number;
}

// Parser types
export interface Parser {
  id: string;
  name: string;
  description?: string;
  source_type: string;
  source_config: Record<string, unknown>;
  parser_vrl: string;
  output_fields?: Record<string, unknown>;
  feed_id?: string;
  credential_id?: string;
  enabled: boolean;
  validated: boolean;
  validation_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateParserRequest {
  name: string;
  description?: string;
  source_type: string;
  source_config: Record<string, unknown>;
  parser_vrl: string;
  output_fields?: Record<string, unknown>;
  feed_id?: string;
  credential_id?: string;
}

export interface UpdateParserRequest extends Partial<CreateParserRequest> {
  enabled?: boolean;
}

export interface VrlValidationResult {
  valid: boolean;
  error?: string;
  warnings: string[];
}

export interface ParserTestResult {
  success: boolean;
  input: string;
  output?: Record<string, unknown>;
  error?: string;
  duration_ms: number;
}

export interface VectorConfigResponse {
  config: string;
}

export interface DeployParsersResponse {
  success: boolean;
  message: string;
  enabled_parsers: number;
}

export interface ParserDeployment {
  id: string;
  parser_id: string;
  action: string;
  status: string;
  error_message?: string;
  config_snapshot?: string;
  deployed_at: string;
}

export interface EnhancedDeploymentResponse {
  success: boolean;
  parser_id: string;
  action: string;
  message: string;
  validation_result?: {
    success: boolean;
    errors: string[];
    warnings: string[];
    raw_output: string;
  };
  deployment_id?: string;
  recent_deployments: ParserDeployment[];
}

// AI Provider Credentials types (LiteLLM multi-provider support)
export interface ProviderCredentials {
  provider: string;
  display_name: string;
  enabled: boolean;
  has_credentials: boolean;
  config: Record<string, unknown>;
  last_validated_at?: string;
  validation_error?: string;
}

export interface UpdateProviderCredentialsRequest {
  api_key?: string;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

// Agent Model Configuration types
export interface AgentModelConfig {
  agent_id: string;
  display_name: string;
  model_id: string;
  max_tokens: number;
  temperature: number;
  timeout_seconds: number;
  enabled: boolean;
}

export interface UpdateAgentModelConfigRequest {
  model_id?: string;
  max_tokens?: number;
  temperature?: number;
  timeout_seconds?: number;
  enabled?: boolean;
}

// Available Models types
export interface AvailableModel {
  model_id: string;
  provider: string;
  display_name: string;
  context_window?: number;
  input_price_per_million?: number;
  output_price_per_million?: number;
  supports_vision: boolean;
  supports_function_calling: boolean;
  deprecated: boolean;
}

export interface CreateAvailableModelRequest {
  model_id: string;
  provider: string;
  display_name: string;
  context_window?: number;
  input_price_per_million?: number;
  output_price_per_million?: number;
  supports_vision: boolean;
  supports_function_calling: boolean;
}

export interface UpdateAvailableModelRequest {
  display_name?: string;
  context_window?: number | null;
  input_price_per_million?: number | null;
  output_price_per_million?: number | null;
  supports_vision?: boolean;
  supports_function_calling?: boolean;
  deprecated?: boolean;
}

// Model Catalog Sync types
export interface ModelCatalogSyncResult {
  status: string;
  models_deprecated: number;
  models_total: number;
  commit?: string | null;
}

export interface ModelCatalogStatus {
  url: string;
  branch: string;
  last_synced_at?: string | null;
  last_sync_status?: string | null;
  last_sync_commit?: string | null;
  last_sync_error?: string | null;
}

// Organizational Context types (Custom Prompt Data)
export interface OrganizationalContext {
  organization_name: string | null;
  industry: string | null;
  environment: string | null;
  attack_vectors: string | null;
  compliance_frameworks: string[];
  custom_context: string | null;
  enable_for_chat: boolean;
  enable_for_query: boolean;
  enable_for_detection: boolean;
  enable_for_parser: boolean;
  enable_for_dashboard: boolean;
}

export interface UpdateOrganizationalContextRequest {
  organization_name?: string | null;
  industry?: string | null;
  environment?: string | null;
  attack_vectors?: string | null;
  compliance_frameworks?: string[];
  custom_context?: string | null;
  enable_for_chat?: boolean;
  enable_for_query?: boolean;
  enable_for_detection?: boolean;
  enable_for_parser?: boolean;
  enable_for_dashboard?: boolean;
}

// Retention Settings types
export interface RetentionConfig {
  enabled: boolean;
  retention_days: number;
  job_id: number | null;
}

export interface UpdateRetentionRequest {
  enabled: boolean;
  retention_days: number;
}

export interface StorageStats {
  total_size_bytes: number;
  total_size_pretty: string;
  chunk_count: number;
  compressed_chunks: number;
  oldest_log: string | null;
  newest_log: string | null;
  log_count: number;
}

// ClickHouse Storage Stats types
export interface ClickHouseStorageStats {
  total_size_bytes: number;
  total_size_pretty: string;
  row_count: number;
  partition_count: number;
  parts_count: number;
  oldest_log: string | null;
  newest_log: string | null;
  compression_ratio: number;
  uncompressed_size_bytes: number;
  ttl_days: number | null;
}

export interface DiskPressureStatus {
  usage_fraction: number;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  level: 'normal' | 'elevated' | 'critical' | 'emergency';
  estimated_retention_days: number | null;
  partitions_dropped: number;
  ingestion_paused: boolean;
  high_watermark: number;
  low_watermark: number;
  critical_threshold: number;
  emergency_threshold: number;
}

export interface StorageOverview {
  clickhouse_enabled: boolean;
  postgres: StorageStats | null;
  clickhouse: ClickHouseStorageStats | null;
  disk_pressure: DiskPressureStatus | null;
}

export interface UpdateClickHouseRetentionRequest {
  retention_days: number;
}

// Storage Tiering types
export type TieringStatus = 'unconfigured' | 'pending' | 'applying' | 'active' | 'error';

export interface TieringConfig {
  enabled: boolean;
  s3_endpoint: string | null;
  s3_bucket: string | null;
  s3_region: string;
  s3_path_style: boolean;
  has_credentials: boolean;
  retention_days: number;
  move_factor: number;
  status: TieringStatus;
  status_message: string | null;
  last_applied_at: string | null;
}

export interface UpdateTieringRequest {
  enabled?: boolean;
  s3_endpoint?: string;
  s3_bucket?: string;
  s3_region?: string;
  s3_path_style?: boolean;
  retention_days?: number;
  move_factor?: number;
}

export interface SetTieringCredentialsRequest {
  access_key_id: string;
  secret_access_key: string;
}

export interface TierInfo {
  size_bytes: number;
  size_pretty: string;
  row_count: number;
}

export interface TierStats {
  hot: TierInfo;
  warm: TierInfo;
  total_size_bytes: number;
  total_size_pretty: string;
  total_row_count: number;
  last_updated: string;
}

export interface TieringConnectionTestResult {
  success: boolean;
  message: string;
  latency_ms: number | null;
}

// Risk Settings types
export interface RiskConfig {
  risk_weight: number;
}

export interface UpdateRiskConfigRequest {
  risk_weight: number;
}

// Risk Modifier type for detection rules
export interface RiskModifier {
  condition: string;
  score: number;
}

// Risk Analytics types
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface EntityRiskSummary {
  entity: string;
  entity_type: string;
  risk_score: number;
  finding_count: number;
  last_finding_at?: string;
  last_rule_name?: string;
  last_severity?: string;
  risk_level: RiskLevel;
}

export interface RiskAnalyticsOverview {
  total_entities: number;
  critical_entities: number;
  high_entities: number;
  medium_entities: number;
  low_entities: number;
  total_findings: number;
  avg_risk_score: number;
}

export interface EntityTypeCount {
  entity_type: string;
  count: number;
}

export interface RiskOverviewResponse {
  overview_24h: RiskAnalyticsOverview;
  overview_7d: RiskAnalyticsOverview;
  entity_types: EntityTypeCount[];
}

export interface RiskEntitiesResponse {
  entities: EntityRiskSummary[];
  total: number;
}

export interface ClearEntityRiskRequest {
  entity: string;
  entity_type?: string;
  reason?: string;
}

export interface ClearRiskResponse {
  success: boolean;
  cleared_count: number;
}

export interface RiskEntitiesQuery {
  window?: '24h' | '7d' | 'all';
  entity_type?: string;
  min_score?: number;
  limit?: number;
  offset?: number;
}

// Entity context types
export interface EntityAlertSummary {
  id: string;
  alert_id: string;
  rule_id?: string;
  rule_name?: string;
  severity: string;
  status: string;
  disposition?: string;
  matched_event_count?: number;
  created_at: string;
  added_at: string;
  is_primary: boolean;
  triage_verdict?: string;
  triage_confidence?: number;
  /**
   * Per-alert risk-score contribution (0–100) sourced from the firing rule's
   * `risk_score`. Used by the Risk page to render a per-alert weight bar.
   */
  score_contribution?: number;
  /**
   * MITRE ATT&CK tactic IDs from the firing rule (e.g. `["TA0006", "TA0001"]`).
   * Empty array when the rule has no tactics tagged.
   */
  mitre_tactics?: string[];
}

export interface EntityCaseSummary {
  id: string;
  case_number: number;
  title: string;
  severity: string;
  status: string;
  alert_count: number;
  created_at: string;
  last_activity_at?: string;
}

/**
 * Recent detection-rule firing for an entity. Sourced from ClickHouse
 * `logs WHERE source_type = 'findings'` — a superset of `EntityAlertSummary`
 * because it includes matches from rules in `live`/`staging` mode that never
 * produce alerts.
 */
export interface EntitySignalSummary {
  id: string;
  timestamp: string;
  /** Detection rule UUID. May be an empty string for ad-hoc findings. */
  rule_id: string;
  rule_name: string;
  severity: string;
  risk_score: number;
  /** e.g. `detection_match`, `alert` — stored on the finding row's `action` column. */
  signal_type: string;
}

export interface EntityContextResponse {
  entity: string;
  entity_type: string;
  risk: EntityRiskSummary | null;
  alerts: EntityAlertSummary[];
  alert_count: number;
  matches: EntitySignalSummary[];
  match_count: number;
  cases: EntityCaseSummary[];
  case_count: number;
}

// meloD Agent types
export interface GeneratedParser {
  vrl_code: string;
  description: string;
  output_fields: Record<string, string>;
  test_results?: {
    passed: number;
    failed: number;
    samples: Array<{ input: string; output: Record<string, unknown>; success: boolean }>;
  };
  udm_validation?: {
    valid: boolean;
    valid_fields: Array<{ field_name: string; data_type: string; category: string }>;
    invalid_fields: string[];
    semantic_issues: Array<{ field_name: string; issue: string; suggestion: string; severity: string }>;
    summary: string;
  };
}

export interface SuggestedTimeRange {
  preset?: string;
  description: string;
  duration_seconds?: number;
}

export interface GeneratedQuery {
  npl_query: string;
  sql_query: string;
  explanation: string;
  fields_used?: string[];
  estimated_complexity?: string;
  suggested_time_range?: SuggestedTimeRange;
  reasoning_steps?: ReasoningStep[];
}

export interface ReasoningStep {
  step_type: 'parse_request' | 'source_discovery' | 'field_analysis' | 'query_generation' | 'validation';
  title: string;
  description: string;
  details?: Record<string, unknown>;
}

// Detection validation result
export interface DetectionValidation {
  syntax_valid: boolean;
  syntax_errors: string[];
  execution_valid: boolean;
  execution_errors: string[];
  valid_fields: string[];
  invalid_fields: string[];
}

// Noise level classification
export type NoiseLevel = 'very_low' | 'low' | 'moderate' | 'high' | 'very_high' | 'unknown';

// Alert fatigue risk level
export type AlertFatigueRisk = 'low' | 'medium' | 'high' | 'critical';

// Threshold suggestion for tuning
export interface ThresholdSuggestion {
  description: string;
  modified_query: string;
  estimated_reduction_percent: number;
}

// Noise assessment for a detection
export interface NoiseAssessment {
  level: NoiseLevel;
  daily_average: number;
  peak_daily_matches: number;
  estimated_daily_alerts: number;
  alert_fatigue_risk: AlertFatigueRisk;
  explanation: string;
  threshold_suggestions: ThresholdSuggestion[];
}

// Recommended action for a detection
export type RecommendedAction = 'proceed' | 'proceed_with_tuning' | 'review_first' | 'not_recommended' | 'unable_to_assess';

// Overall recommendation for a detection
export interface DetectionRecommendation {
  action: RecommendedAction;
  confidence: number;
  reasoning: string;
  alternatives: string[];
}

// Historical analysis result
export interface HistoricalAnalysisResult {
  total_matches: number;
  days_analyzed: number;
  daily_average: number;
}

// Tuning suggestion
export interface TuningSuggestion {
  issue: string;
  suggestion: string;
  modified_query?: string;
}

export interface GeneratedDetection {
  name: string;
  description: string;
  query: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  mitre_tactics: string[];
  mitre_techniques: string[];
  tags?: string[];
  historical_analysis?: HistoricalAnalysisResult;
  tuning_suggestions?: TuningSuggestion[];
  validation?: DetectionValidation;
  noise_assessment?: NoiseAssessment;
  recommendation?: DetectionRecommendation;
}

export interface MelodChatRequest {
  session_id?: string;
  message: string;
}

export interface MelodCreateParserRequest {
  session_id?: string;
  /** Feed ID is required when fetching logs from database, optional when sample_logs is provided */
  feed_id?: string;
  message?: string;
  /** Optional sample logs to use instead of fetching from database.
   * Use this when logs haven't been ingested yet (e.g., S3/cloud sources). */
  sample_logs?: string[];
  /** Log source type name (e.g., "nginx", "apache", "sysmon", "cloudtrail").
   * Helps the AI select the correct parsing strategy. */
  log_source_type?: string;
}

// Query output mode for meloD query generation
export type QueryOutputMode = 'standard' | 'advanced';

/** A single turn in the AI search conversation */
export interface ConversationTurn {
  /** The user's natural language request */
  user_message: string;
  /** The query that was generated */
  generated_query: string;
  /** Brief summary of results (e.g., "Found 42 events") */
  result_summary?: string;
  /** Key fields/values from the results for context */
  key_context?: string;
}

export interface MelodBuildQueryRequest {
  session_id?: string;
  message: string;
  time_range: TimeRange;
  /** Query output mode: 'standard' (nPL) or 'advanced' (SQL) */
  query_mode?: QueryOutputMode;
  /** Previous conversation turns for context in follow-up queries */
  conversation_history?: ConversationTurn[];
}

/** Request to correct a failed search query using AI */
export interface CorrectQueryRequest {
  query: string;
  error_message: string;
  error_code: string;
  field_suggestions?: string[];
}

/** Response containing the AI-suggested corrected query */
export interface CorrectQueryResponse {
  corrected_query: string;
  explanation: string;
  /**
   * Whether the corrected query passed all available validation checks. When
   * false, the suggestion could not be verified and is surfaced as
   * "unverified" (NAN-1496).
   */
  validated: boolean;
}

/** Request to review a successful query for best practices */
export interface ReviewQueryRequest {
  query: string;
}

/** A single optimization suggestion */
export interface ReviewQuerySuggestion {
  description: string;
  optimized_query: string;
}

/** Response containing query optimization suggestions */
export interface ReviewQueryResponse {
  suggestions: ReviewQuerySuggestion[];
}

export interface MelodCreateDetectionRequest {
  session_id?: string;
  description: string;
  run_historical?: boolean;
}

export interface FetchUrlForDetectionResponse {
  url: string;
  title?: string;
  content: string;
  extracted_indicators?: {
    command_lines?: string[];
    user_agents?: string[];
    file_paths?: string[];
    registry_keys?: string[];
    process_names?: string[];
    techniques?: string[];
  };
}

// Request for generating AI triage hints for a new detection
export interface GenerateDetectionHintsRequest {
  query: string;
  description?: string;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  narrative?: string;
  severity: string;
}

// Response containing generated AI triage hints
export interface GenerateDetectionHintsResponse {
  ignore_when: string[];
  suspicious_when: string[];
  context?: string;
}

export interface MelodTuneDetectionRequest {
  session_id?: string;
  rule_id: string;
  feedback?: string;
}

export interface MelodSummarizeRequest {
  query: string;
  query_mode: string;
  results: Record<string, unknown>[];
  total_count: number;
  time_range: TimeRange;
  histogram?: Array<{ time: string; count: number }>;
}

export interface MelodEditParserRequest {
  parser_id: string;
  current_vrl: string;
  message: string;
  sample_logs?: string[];
  session_id?: string;
  /**
   * Optional OOTB parser VRL shown read-only when editing a parser extension (NAN-874).
   * When present, `current_vrl` is the extension overlay and the agent switches into
   * "edit overlay only" mode.
   */
  base_parser_vrl?: string;
}

// Edit operation types for AI parser editing
export type EditOperation =
  | { type: 'replace'; find: string; with: string }
  | { type: 'insert_after'; marker: string; code: string }
  | { type: 'insert_before'; marker: string; code: string }
  | { type: 'append'; code: string }
  | { type: 'prepend'; code: string };

export interface MelodEditParserResponse {
  session_id: string;
  message: string;
  updated_vrl?: string;
  edits_applied?: EditOperation[];
  validation?: {
    valid: boolean;
    errors: string[];
  };
  test_results?: Array<{
    input: string;
    success: boolean;
    output?: Record<string, unknown>;
    error?: string;
  }>;
}

// System metrics types
export interface ActivityPoint {
  time: string;
  event_count: number;
  alert_count: number;
}

export interface SystemOverview {
  events_24h: number;
  events_1h: number;
  events_trend: number;
  alerts_24h: number;
  alerts_1h: number;
  alerts_trend: number;
  critical_alerts_24h: number;
  critical_alerts_trend: number;
  active_rules: number;
  total_rules: number;
  active_rules_trend: number;
  activity: ActivityPoint[];
}

export interface SystemConfig {
  deployment_mode: "managed" | "self-hosted";
  settings_editable: boolean;
  api_keys_editable: boolean;
  ai_providers_editable: boolean;
  /** True when this install runs air-gapped (no outbound internet). The
   *  marketplace uses this to badge connectivity-required items, hide egress
   *  actions, and promote import-from-file. */
  air_gap: boolean;
}

export interface SearchSummary {
  narrative: string;
  key_findings: KeyFinding[];
  suspicious_items: SuspiciousItem[];
  suggested_queries: SuggestedQuery[];
  risk_assessment?: RiskAssessment;
}

export interface KeyFinding {
  category: string;
  title: string;
  description: string;
  importance: 'low' | 'medium' | 'high' | 'critical';
  related_fields: string[];
}

/** Anomalies detected in field distributions - potential needles in the haystack */
export interface SuspiciousItem {
  field: string;
  anomaly_type: 'dominance' | 'outlier' | 'rare_value' | 'pattern';
  title: string;
  description: string;
  value: string;
  percentage: number;
  severity: 'low' | 'medium' | 'high';
}

export interface SuggestedQuery {
  description: string;
  query: string;
  rationale: string;
  priority: 'low' | 'medium' | 'high';
}

export interface RiskAssessment {
  level: 'none' | 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
  indicators: Array<{ indicator: string; description: string; severity: string }>;
}

export interface MelodApiResponse {
  session_id: string;
  message: string;
  parser?: GeneratedParser;
  query?: GeneratedQuery;
  detection?: GeneratedDetection;
  /** Multiple detections (e.g., from threat intel URL) */
  detections?: GeneratedDetection[];
}

// Parser progress event types for streaming
export type ParserProgressEvent = 
  | { type: 'started'; feed_name: string; sample_count: number }
  | { type: 'generating_parser'; attempt: number; max_attempts: number }
  | { type: 'validating_syntax' }
  | { type: 'syntax_validation_result'; valid: boolean; errors: string[] }
  | { type: 'testing_parser'; sample_index: number; total_samples: number }
  | { type: 'test_result'; sample_index: number; success: boolean; error?: string }
  | { type: 'retrying_with_feedback'; attempt: number; max_attempts: number; reason: string }
  | { type: 'udm_validation_result'; valid: boolean; invalid_fields: string[]; semantic_issues_summary: string[]; summary: string }
  | { type: 'completed'; success: boolean; message: string }
  | { type: 'error'; message: string };

// Upload types
export type FileFormat = 'csv' | 'json' | 'ndjson' | 'tsv';

export interface UploadConfig {
  format?: FileFormat;
  destination_type: 'lookup';
  destination_name: string;
  primary_key?: string;
  mode?: 'replace' | 'append';
  csv_delimiter?: string;
  csv_has_headers?: boolean;
}

export interface UploadResponse {
  upload_id: string;
  records_processed: number;
  records_ingested: number;
  errors: string[];
  duration_ms: number;
}

export interface ColumnInfo {
  name: string;
  detected_type: string;
  sample_values: string[];
  null_count: number;
}

export interface PreviewResult {
  format: FileFormat;
  columns: ColumnInfo[];
  rows: Record<string, unknown>[];
  total_rows_estimate: number;
}

export interface UploadRecord {
  id: string;
  filename: string;
  file_size: number;
  file_format: string;
  destination_type: string;
  destination_name: string;
  records_total: number;
  records_success: number;
  records_failed: number;
  status: string;
  error_message?: string;
  created_at: string;
  completed_at?: string;
}

export interface UploadHistoryFilter {
  destination_type?: string;
  destination_name?: string;
  status?: string;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
}

// Lookup table types
export interface LookupColumn {
  name: string;
  data_type: string;
  nullable: boolean;
}

/**
 * Summary of the user who created a lookup table. Hydrated by the backend
 * via LEFT JOIN on the users table from `lookup_tables_registry.created_by_user_id`.
 *
 * `null` / absent for legacy tables (created before NAN-514) and tables
 * whose creator has been deleted — UI renders these as `—`.
 */
export interface LookupTableCreator {
  id: string;
  name: string;
  email: string;
}

export interface LookupTable {
  id: string;
  name: string;
  description?: string;
  table_name: string;
  columns: LookupColumn[];
  primary_key?: string;
  row_count: number;
  size_bytes: number;
  created_at: string;
  updated_at: string;
  /** User who created the table; null for legacy rows or deleted users. */
  created_by?: LookupTableCreator | null;
}

/**
 * A detection rule that references a lookup table.
 *
 * Returned by `GET /api/lookup-tables/{name}/usage`. Powers the Usage section
 * of the LookupTableView Details inspector (NAN-509 / NAN-510 / NAN-511).
 *
 * NOTE: `hits_24h` and `last_hit` are currently stubbed server-side (0 / null)
 * pending follow-up work to wire signal-table counts. See backend TODO.
 */
export interface LookupUsage {
  rule_id: string;
  rule_name: string;
  tactic?: string | null;
  hits_24h: number;
  last_hit?: string | null;
  /** Substring of the rule's nPL query containing the lookup reference */
  sample_join: string;
}

/**
 * A single activity entry on a lookup table.
 *
 * Returned by `GET /api/lookup-tables/{name}/ingestion-history`. Powers the
 * History tab on the redesigned LookupTableView (NAN-510 slice 3 PR 3 /
 * NAN-512). Each entry represents either an automated refresh run or a
 * user-driven edit/upload event from the audit log.
 */
export interface LookupHistoryEntry {
  /** When the activity happened (ISO 8601 UTC). */
  when: string;
  /** Who performed the action — `"scheduler"` for refresh, audit user (or `"system"`) for edits. */
  actor: string;
  /** Kind of activity. */
  kind: 'refresh' | 'edit' | 'upload';
  /** Server-rendered short description (e.g. `"completed"`, `"rows added"`, `"table created"`). */
  note: string;
}

export interface CreateLookupTableConfig {
  name: string;
  description?: string;
  primary_key?: string;
  format?: FileFormat;
  csv_delimiter?: string;
  csv_has_headers?: boolean;
  mode?: 'replace' | 'append';
  column_types?: { column: string; data_type: string }[];
  flatten_json?: boolean;
}

export interface CreateLookupTableResponse {
  table: LookupTable;
  records_inserted: number;
  /**
   * Columns whose original CSV/JSON header was sanitized to a SQL-safe
   * identifier on upload (e.g. `Customer Id → customer_id`). Empty/omitted
   * if all original headers were already valid identifiers. See NAN-513.
   */
  renamed_columns?: RenamedColumn[];
}

export interface RenamedColumn {
  original: string;
  sanitized: string;
}

export interface LookupQueryRequest {
  table_name: string;
  key_field: string;
  key_value?: unknown;
  key_values?: unknown[];
  output_fields?: string[];
  case_insensitive?: boolean;
}

export interface LookupResult {
  fields?: Record<string, unknown>;
  found: boolean;
}

export interface BatchLookupResult {
  results: Record<string, Record<string, unknown>>;
  matched_count: number;
  total_count: number;
}

// Lookup table inline data management types
export interface LookupRowsPage {
  rows: Record<string, unknown>[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface CreateLookupTableFromSchemaRequest {
  name: string;
  description?: string;
  columns: { name: string; data_type: string; nullable?: boolean }[];
  primary_key?: string;
}

export interface AddRowsRequest {
  rows: Record<string, unknown>[];
}

export interface AddRowsResponse {
  inserted: number;
  row_ids: number[];
}

export interface UpdateRowRequest {
  fields: Record<string, unknown>;
}

// Dashboard visibility type
export type DashboardVisibility = 'public' | 'group' | 'private';

// Dashboard types
export interface Dashboard {
  id: string;
  name: string;
  description?: string;
  layout: DashboardLayout;
  panels: PanelConfig[];
  refresh_interval?: number;
  owner_id?: string;
  owner_name?: string;
  /** Visibility: 'public', 'group', or 'private' */
  visibility: DashboardVisibility;
  /** Groups this dashboard is shared with (when visibility = 'group') */
  shared_groups?: SharedGroup[];
  /** Whether the requesting user is the owner */
  is_owner?: boolean;
  created_at: string;
  updated_at: string;
}

export interface DashboardSummary {
  id: string;
  name: string;
  description?: string;
  panel_count: number;
  owner_id?: string;
  owner_name?: string;
  /** Visibility: 'public', 'group', or 'private' */
  visibility: DashboardVisibility;
  /** Groups this dashboard is shared with (when visibility = 'group') */
  shared_groups?: SharedGroup[];
  created_at: string;
  updated_at: string;
}

/**
 * Serialized form of a TimeRangeValue suitable for persistence in JSON
 * (Date objects flattened to ISO strings). Hydrate back via
 * `hydrateDashboardTimeRange` in `@/lib/dashboard-time-range`.
 */
export type SerializedTimeRange =
  | { type: 'preset'; preset: string }
  | { type: 'custom'; start: string; end: string };

export interface DashboardLayout {
  columns: number;
  rowHeight: number;
  items: LayoutItem[];
  variables?: DashboardVariable[];
  /** Default time range applied when the dashboard is first opened. */
  defaultTimeRange?: SerializedTimeRange;
  /**
   * NAN-711: when true, panels fire automatically on dashboard open with the
   * default variable values. When absent or false (the default for new
   * dashboards), the dashboard opens empty and waits for the user to click
   * Run. SIEM workloads tend to have heavy panels (`| prevalence`, `| lookup`,
   * wide ranges) where firing N queries on every open is wasteful — most
   * users want to narrow variables first and then run.
   */
  autoRun?: boolean;
}

export interface LayoutItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
}

export type VisualizationType =
  | 'bar'
  | 'line'
  | 'area'
  | 'pie'
  | 'table'
  | 'single_value'
  | 'timeline'
  | 'tree'
  | 'ranked_bar'
  | 'transaction'
  | 'flow'
  // NAN-1540: an OTel-metrics-backed widget. Its data comes from the metrics
  // timeseries endpoint (driven by `PanelConfig.metricConfig`), NOT the nPL/SQL
  // panel-query path, and it renders via the observability charts module.
  | 'obs_metric';

/** How an `obs_metric` widget renders its series (NAN-1540). */
export type MetricWidgetViz = 'timeseries' | 'toplist' | 'query_value';

/**
 * Config for an `obs_metric` dashboard widget (NAN-1540). When present on a
 * `PanelConfig` (with `visualizationType === 'obs_metric'`), the dashboard
 * fetches via the metrics timeseries endpoint instead of running `query`.
 */
export interface MetricWidgetConfig {
  metric_name: string;
  agg: MetricAgg;
  /** Splits into one series per value of this tag/attribute key. */
  group_by?: string;
  filters?: MetricFilter[];
  /** Optional service_name filter. */
  service_name?: string;
  /** How to render the returned series. Defaults to "timeseries". */
  viz: MetricWidgetViz;
  /** Bucket width in seconds; defaults to a range-derived value when absent. */
  step_secs?: number;
  /** Display unit (e.g. "ms", "req/s"); cosmetic. */
  unit?: string;
}

export interface VisualizationConfig {
  orientation?: 'horizontal' | 'vertical';
  stacked?: boolean;
  showPoints?: boolean;
  smooth?: boolean;
  fillOpacity?: number;
  showLabels?: boolean;
  donut?: boolean;
  columns?: TableColumnConfig[];
  pageSize?: number;
  unit?: string;
  thresholds?: ThresholdConfig[];
  showTrend?: boolean;
  bucketSize?: string;
  // Tree visualization config
  parentField?: string;
  childField?: string;
  labelField?: string;
  // Ranked bar config
  showPercent?: boolean;
  // Transaction config
  maxEventsShown?: number;
  // Flow visualization config
  flowType?: 'auto' | 'funnel' | 'sequence';
}

export interface TableColumnConfig {
  field: string;
  label: string;
  sortable: boolean;
  width?: number;
}

export interface ThresholdConfig {
  value: number;
  color: string;
  label?: string;
}

export interface PanelConfig {
  id: string;
  title: string;
  query: string;
  queryMode: 'piped' | 'sql';
  visualizationType: VisualizationType;
  visualizationConfig: VisualizationConfig;
  timeRangeMode: 'dashboard' | 'custom';
  customTimeRange?: TimeRange;
  drilldownEnabled: boolean;
  drilldownTemplate?: string;
  /**
   * NAN-1540: present only when `visualizationType === 'obs_metric'`. Carries
   * the OTel-metrics query (metric_name / agg / group_by / filters / viz). For
   * metric widgets `query` is left empty and the panel data is fetched from the
   * metrics timeseries endpoint instead of the nPL/SQL panel-query path.
   */
  metricConfig?: MetricWidgetConfig;
}

export interface CreateDashboardRequest {
  name: string;
  description?: string;
  layout: DashboardLayout;
  panels: PanelConfig[];
  refresh_interval?: number;
  /** Visibility: 'public', 'group', or 'private' (defaults to 'public') */
  visibility?: DashboardVisibility;
}

export interface UpdateDashboardRequest {
  name?: string;
  description?: string;
  layout?: DashboardLayout;
  panels?: PanelConfig[];
  refresh_interval?: number;
}

export interface ShareDashboardRequest {
  /** Visibility: 'public', 'group', or 'private' */
  visibility: DashboardVisibility;
  /** Group IDs to share with (required when visibility = 'group') */
  group_ids?: string[];
}

export interface DashboardAffectedUser {
  user_id: string;
  user_name: string;
  user_email: string;
}

export interface DashboardShareResult {
  dashboard: Dashboard;
  users_who_lost_access: DashboardAffectedUser[];
}

export interface PanelQueryRequest {
  query: string;
  query_mode: string;
  time_range: TimeRange;
  variables?: Record<string, string>;
}

export interface PanelQueryResponse {
  results: Record<string, unknown>[];
  total_count: number;
  execution_time_ms: number;
}

export interface DashboardExport {
  version: string;
  exported_at: string;
  dashboard: CreateDashboardRequest;
}

export interface ImportDashboardRequest {
  json: string;
}

// Scheduled job types
export type JobStatus = 'success' | 'failed' | 'running';

export interface RetryPolicy {
  max_retries: number;
  retry_delay_secs: number;
}

export interface UploadDestination {
  type: 'lookup';
  table_name: string;
  primary_key?: string;
  mode?: 'replace' | 'append';
}

export interface ParserConfig {
  format: FileFormat;
  csv_delimiter?: string;
  csv_has_headers?: boolean;
  custom_headers?: string[];
  encoding?: string;
  max_records?: number;
  skip_invalid?: boolean;
}

export interface ScheduledJob {
  id: string;
  name: string;
  description?: string;
  cron_expression: string;
  url: string;
  auth_headers?: Record<string, string>;
  destination: UploadDestination;
  parser_config: ParserConfig;
  retry_policy: RetryPolicy;
  enabled: boolean;
  last_run_at?: string;
  last_run_status?: JobStatus;
  last_run_error?: string;
  next_run_at?: string;
  lookup_table_name: string;
  created_at: string;
  updated_at: string;
}

export interface NewScheduledJob {
  name: string;
  description?: string;
  cron_expression: string;
  url: string;
  auth_headers?: Record<string, string>;
  destination: UploadDestination;
  parser_config: ParserConfig;
  retry_policy?: RetryPolicy;
  enabled?: boolean;
}

export interface UpdateScheduledJob {
  name?: string;
  description?: string | null;
  cron_expression?: string;
  url?: string;
  auth_headers?: Record<string, string> | null;
  destination?: UploadDestination;
  parser_config?: ParserConfig;
  retry_policy?: RetryPolicy;
  enabled?: boolean;
}

export interface JobExecution {
  job_id: string;
  started_at: string;
  completed_at?: string;
  status: JobStatus;
  records_processed?: number;
  records_ingested?: number;
  error?: string;
  duration_ms?: number;
}

export interface JobFilter {
  enabled?: boolean;
  destination_type?: string;
  limit?: number;
  offset?: number;
}

export interface JobStats {
  total_jobs: number;
  enabled_jobs: number;
  jobs_run_24h: number;
  successful_runs_24h: number;
  failed_runs_24h: number;
}

export interface ValidateCronRequest {
  expression: string;
  preview_count?: number;
}

export interface ValidateCronResponse {
  valid: boolean;
  description?: string;
  next_runs: string[];
  error?: string;
}

export interface UpsertLookupIngestionRequest {
  url: string;
  cron_expression: string;
  auth_headers?: Record<string, string>;
  parser_config: ParserConfig;
  retry_policy?: RetryPolicy;
  enabled?: boolean;
  mode?: 'replace' | 'append';
}

// ============================================================================
// Authentication Types
// ============================================================================

export interface AuthResponse {
  user: CurrentUser;
  tokens: TokenPairResponse;
}

// MFA types
export interface MfaChallengeResponse {
  status: 'mfa_required';
  mfa_required: true;
  challenge_token: string;
}

export interface MfaSetupRequiredResponse {
  status: 'mfa_setup_required';
  mfa_setup_required: true;
  challenge_token: string;
}

export interface MfaSetupResponse {
  secret: string;
  otpauth_uri: string;
  qr_code_base64: string;
}

export interface MfaSetupCompleteResponse {
  backup_codes: string[];
}

export interface MfaStatusResponse {
  mfa_enabled: boolean;
  mfa_setup_pending: boolean;
  mfa_required_globally: boolean;
}

export type LoginApiResponse = AuthResponse | MfaChallengeResponse | MfaSetupRequiredResponse;

export interface TokenPairResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface CurrentUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  is_api_key?: boolean;
}

export interface OidcProviderInfo {
  id: string;
  name: string;
  slug: string;
}

// OIDC Provider Management Types
export interface OidcProviderSummary {
  id: string;
  name: string;
  slug: string;
  issuer: string;
  enabled: boolean;
  scopes: string[];
  group_claim?: string;
  created_at: string;
  updated_at: string;
}

export interface OidcProviderListResponse {
  providers: OidcProviderSummary[];
  total: number;
}

export interface CreateOidcProviderRequest {
  name: string;
  slug: string;
  issuer: string;
  client_id: string;
  client_secret: string;
  scopes?: string[];
  group_claim?: string;
  enabled?: boolean;
}

export interface UpdateOidcProviderRequest {
  name?: string;
  issuer?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  group_claim?: string;
  enabled?: boolean;
}

export interface OidcGroupMapping {
  id: string;
  provider_id: string;
  oidc_group: string;
  local_group_id: string;
  local_group_name?: string;
}

export interface OidcGroupMappingsResponse {
  mappings: OidcGroupMapping[];
}

export interface UpdateOidcGroupMappingsRequest {
  mappings: Array<{
    oidc_group: string;
    local_group_id: string;
  }>;
}

export interface OidcUserGroups {
  user_id: string;
  email: string;
  name: string;
  last_login_at: string | null;
  groups: string[];
}

export interface OidcTokenGroupsResponse {
  groups: string[];
  users: OidcUserGroups[];
}

export interface OidcAuthUrlResponse {
  url: string;
  state: string;
}

export interface OidcCallbackResponse {
  user: CurrentUser;
  tokens: TokenPairResponse;
}

// User Management Types
export interface UserDetail {
  id: string;
  email: string;
  name: string;
  status: 'active' | 'locked' | 'disabled';
  groups: GroupSummary[];
  oidc_provider?: string;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
}

export interface UserListResponse {
  users: UserDetail[];
  total: number;
}

export interface CreateUserRequest {
  email: string;
  name: string;
  password: string;
  group_ids?: string[];
}

export interface UpdateUserRequest {
  email?: string;
  name?: string;
  password?: string;
  group_ids?: string[];
}

// Group Management Types
export interface GroupSummary {
  id: string;
  name: string;
  is_system: boolean;
}

export interface GroupDetail {
  id: string;
  name: string;
  description?: string;
  is_system: boolean;
  roles: RoleSummary[];
  member_count: number;
  created_at: string;
  updated_at: string;
}

export interface GroupListResponse {
  groups: GroupDetail[];
  total: number;
}

export interface CreateGroupRequest {
  name: string;
  description?: string;
  role_ids?: string[];
}

export interface UpdateGroupRequest {
  name?: string;
  description?: string;
  role_ids?: string[];
}

// Role Management Types
export interface RoleSummary {
  id: string;
  name: string;
  is_system: boolean;
}

export interface RoleDetail {
  id: string;
  name: string;
  description?: string;
  is_system: boolean;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface RoleListResponse {
  roles: RoleDetail[];
  total: number;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permissions: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

export interface PermissionInfo {
  id: string;
  name: string;
  description: string;
  category: string;
}

// API Key Types
export interface ApiKeySummary {
  id: string;
  name: string;
  description?: string;
  key_prefix: string;
  permissions: string[];
  enabled: boolean;
  expires_at?: string;
  rate_limit?: number;
  last_used_at?: string;
  created_at: string;
}

export interface ApiKeyListResponse {
  api_keys: ApiKeySummary[];
  total: number;
}

export interface CreateApiKeyRequest {
  name: string;
  description?: string;
  permissions: string[];
  expires_at?: string;
  rate_limit?: number;
}

// Tri-state partial update: omit a field to leave it unchanged, send `null`
// to clear it, or send a value to set it. (`name`/`permissions` are
// non-nullable, so only omit-vs-value applies there.)
export interface UpdateApiKeyRequest {
  name?: string;
  description?: string | null;
  permissions?: string[];
  expires_at?: string | null;
  rate_limit?: number | null;
}

export interface ApiKeyCreatedResponse {
  id: string;
  key: string;
  name: string;
  created_at: string;
}

/** One UTC day's count of audited actions for a key. */
export interface ApiKeyUsagePoint {
  date: string; // YYYY-MM-DD
  count: number;
}

/**
 * Per-key call volume. Counts audited actions (mutations + authorization
 * denials) attributed to the key — not raw request volume. Read-only traffic
 * is not audited and is not reflected here.
 */
export interface ApiKeyUsageResponse {
  days: number;
  total: number;
  series: ApiKeyUsagePoint[];
}

// Session Types
export interface SessionInfo {
  id: string;
  user_id: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  last_used_at: string;
  expires_at: string;
  is_current: boolean;
}

export interface SessionListResponse {
  sessions: SessionInfo[];
  total: number;
}

// Audit Log Types
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_id?: string;
  user_name?: string;
  action?: string;
  source?: string;
  resource_type?: string;
  resource_id?: string;
  resource_name?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  user_agent?: string;
  success: boolean;
  message?: string;
}

export interface AuditLogResponse {
  logs: AuditLogEntry[];
  total: number;
}

export interface AuditLogQuery {
  user_id?: string;
  action?: string;
  resource_type?: string;
  source?: string;
  start_time?: string;
  end_time?: string;
  success?: boolean;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Prevalence Tracking Types
// ============================================================================

export type PrevalenceArtifactType = 'hash_md5' | 'hash_sha256' | 'hash_unknown' | 'domain' | 'subdomain' | 'ip_address' | 'ip_address_private';

export interface PrevalenceData {
  artifact: string;
  artifact_type: PrevalenceArtifactType;
  host_count: number;
  total_occurrences: number;
  first_seen: string;
  last_seen: string;
  is_rare: boolean;
  prevalence_score: number;
}

export interface PrevalenceResponse {
  data: PrevalenceData;
}

export interface BulkPrevalenceRequest {
  artifacts: string[];
  window?: string;
}

export interface BulkPrevalenceResponse {
  data: PrevalenceData[];
  total: number;
}

export interface RareArtifactsQuery {
  window?: string;
  type?: string;
  limit?: number;
  offset?: number;
}

export interface NewArtifactsQuery {
  since?: string;
  type?: string;
  limit?: number;
  offset?: number;
}

export interface ArtifactListResponse {
  artifacts: PrevalenceData[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface ScatterPlotRequest {
  artifacts: {
    hashes: string[];
    domains: string[];
    ips: string[];
  };
  window?: string;
}

export interface PrevalenceScatterPoint {
  artifact: string;
  artifact_type: PrevalenceArtifactType;
  host_count: number;
  first_seen: string;
  last_seen: string;
  total_occurrences: number;
  is_rare: boolean;
  prevalence_score: number;
}

export interface PrevalenceScatterDataResponse {
  hash_points: PrevalenceScatterPoint[];
  domain_points: PrevalenceScatterPoint[];
  ip_points: PrevalenceScatterPoint[];
  rarity_threshold: number;
}

export interface PrevalenceSettingsResponse {
  rarity_threshold: number;
  enable_hash_tracking: boolean;
  enable_domain_tracking: boolean;
  enable_ip_tracking: boolean;
  retention_days: number;
  cache_ttl_seconds: number;
}

// Artifact Explorer Types
// ============================================================================

export interface ArtifactExplorerItem {
  artifact: string;
  artifact_type: PrevalenceArtifactType;
  host_count: number;
  total_occurrences: number;
  first_seen: string;
  last_seen: string;
  is_rare: boolean;
  prevalence_score: number;
  /** Packed dense daily counts, oldest first. Index `i` is `daily_start + i` days. */
  daily_counts: number[];
  /** Date of `daily_counts[0]` in YYYY-MM-DD format. */
  daily_start: string;
  /** Inline-subtitle context (NAN-849). Optional — older API responses omit it. */
  context?: ArtifactInlineContext;
}

/** Inline subtitle data populated on every prevalence list row (NAN-849).
 *  Fields are tuned per artifact_type; renderers fall back gracefully when
 *  any individual field is missing. */
export interface ArtifactInlineContext {
  /** Hash artifacts: top observed on-disk file name. */
  top_file_name?: string;
  /** Hash artifacts: top running image name. */
  top_process_name?: string;
  /** Hash artifacts: short command-line excerpt for the top process. */
  top_command_line?: string;
  /** Hash artifacts: true when top_process_name is a wrapper binary. */
  top_process_is_wrapper?: boolean;
  /** IP artifacts: country name. */
  country?: string;
  /** IP artifacts: ASN number string. */
  asn?: string;
  /** IP artifacts: AS organization. */
  asn_org?: string;
  /** Total distinct users associated with the artifact. */
  user_count?: number;
  /** Top source_type by event count. */
  top_source_type?: string;
}

export interface ArtifactExplorerResponse {
  artifacts: ArtifactExplorerItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  rarity_threshold: number;
  rare_count: number;
  new_count: number;
  high_risk_asset_count: number;
}

export interface ArtifactHostEntry {
  host: string;
  count: number;
  last_seen: string;
}

export interface ArtifactUserEntry {
  user: string;
  count: number;
}

export interface ArtifactSourceEntry {
  source_type: string;
  count: number;
}

export interface ArtifactProcessEntry {
  process_name: string;
  command_line: string;
  count: number;
  /** NAN-849: true when process_name matches a known wrapper binary. */
  is_wrapper?: boolean;
}

/** On-disk file name observed for a hash artifact (NAN-849). */
export interface ArtifactFileNameEntry {
  file_name: string;
  count: number;
}

/** Threat-intel verdict from an enrichment source (NAN-849). */
export interface ArtifactThreatIntelEntry {
  source: string;
  verdict: string;
  score?: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  details?: any;
}

export interface ArtifactNetworkEntry {
  dest_port: number;
  protocol: string;
  count: number;
}

export interface ArtifactGeoEntry {
  country: string;
  asn: string;
  count: number;
}

export interface ArtifactDetailResponse {
  artifact: string;
  artifact_type: PrevalenceArtifactType;
  top_hosts: ArtifactHostEntry[];
  top_users: ArtifactUserEntry[];
  source_types: ArtifactSourceEntry[];
  processes?: ArtifactProcessEntry[];
  /** NAN-849: top on-disk file names for hash artifacts. */
  top_file_names?: ArtifactFileNameEntry[];
  network?: ArtifactNetworkEntry[];
  geo?: ArtifactGeoEntry[];
  /** NAN-849: threat-intel verdicts from configured enrichment sources. */
  threat_intel?: ArtifactThreatIntelEntry[];
}

export interface ArtifactExplorerQuery {
  window?: string;
  type?: string;
  risk_level?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

// Health Monitoring Settings
export interface HealthMonitoringSettings {
  /** AI provider monitoring (costs API credits to check) */
  ai_monitoring_enabled: boolean;
  /** Feed staleness monitoring (free - just DB queries) */
  feed_monitoring_enabled: boolean;
  /** Legacy field for backwards compatibility */
  enabled: boolean;
}

export interface UpdateHealthMonitoringSettingsRequest {
  /** Legacy field - if provided alone, updates ai_monitoring_enabled */
  enabled?: boolean;
  /** AI provider monitoring (costs API credits) */
  ai_monitoring_enabled?: boolean;
  /** Feed staleness monitoring (free) */
  feed_monitoring_enabled?: boolean;
}

export interface UpdatePrevalenceSettingsRequest {
  rarity_threshold?: number;
  enable_hash_tracking?: boolean;
  enable_domain_tracking?: boolean;
  enable_ip_tracking?: boolean;
  retention_days?: number;
  cache_ttl_seconds?: number;
}

// Detection rule version history — returned from GET /api/rules/:id/versions
export interface RuleVersionResponse {
  id: number;
  rule_id: string;
  version_number: number;
  query: string;
  name: string;
  description?: string;
  severity: string;
  enabled: boolean;
  is_active: boolean;
  created_at: string;
  created_by?: string;
  created_by_name?: string;
  change_reason?: string;
  tuning_proposal_id?: string;
  reverted_from_version?: number;
}

// Auto-Tuning Settings
export interface TuningSettings {
  auto_tuning_enabled: boolean;
  auto_tuning_min_confidence: number;
  auto_tuning_critical: boolean;
  auto_tuning_disabled_until?: string;
  auto_apply_enabled: boolean;
}

// Auto-Tuning Proposal Types
export type ProposalType = 'query_tuning' | 'hint_update';

export type TuningStatus =
  | 'proposed'
  | 'testing'
  | 'test_passed'
  | 'test_failed'
  | 'staging'
  | 'promoted'
  | 'reverted'
  | 'manually_approved'
  | 'rejected';

export interface AlertPattern {
  field_name: string;
  field_value: string;
  occurrence_count: number;
  percentage: number;
}

export interface SafetyCheck {
  check_name: string;
  passed: boolean;
  details: string;
}

export interface SafetyValidation {
  is_safe: boolean;
  critical_indicators_preserved: boolean;
  validation_checks: SafetyCheck[];
  warnings: string[];
}

export interface HintsDiff {
  added_ignore: string[];
  removed_ignore: string[];
  added_suspicious: string[];
  removed_suspicious: string[];
  context_changed: boolean;
  old_context?: string;
  new_context?: string;
}

export interface TuningProposal {
  id: string;
  rule_id: string;
  created_at: string;
  proposal_type: ProposalType;
  original_query: string;
  proposed_query: string;
  rationale: string;
  confidence_score: number;
  changes_summary: string[];
  affected_patterns: AlertPattern[];
  safety_validation: SafetyValidation;
  status: TuningStatus;
  // Hint proposal fields
  current_hints?: AiTriageHints;
  proposed_hints?: AiTriageHints;
  hints_diff?: HintsDiff;
}

export interface TuningProposalListParams {
  rule_id?: string;
  status?: TuningStatus;
  proposal_type?: ProposalType;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Cases
// ============================================================================

export type CaseStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed';
export type CaseDisposition = 'true_positive' | 'false_positive' | 'benign' | 'inconclusive' | 'merged';
// NAN-1251: AI Tier-1 triage verdict. Mirrors CaseDisposition plus
// `needs_investigation` (no human-disposition equivalent).
export type AiDisposition =
  | 'true_positive'
  | 'false_positive'
  | 'benign'
  | 'inconclusive'
  | 'needs_investigation';
export type CaseEntityType = 'user' | 'host' | 'ip' | 'domain' | 'hash' | 'url' | 'file' | 'process' | 'email';
export type CaseWallEntryType = 'comment' | 'status_change' | 'assignment_change' | 'alert_added' | 'alert_removed' | 'ai_analysis' | 'action_taken';
export type CaseRelationType = 'related' | 'parent' | 'child' | 'duplicate';
export type GroupingType = 'host' | 'user' | 'rule' | 'ip' | 'manual';

export interface AiRecommendation {
  action: string;
  reasoning: string;
  priority: number;
  automated: boolean;
}

export type CaseVisibility = 'public' | 'group' | 'private';

export interface Case {
  id: string;
  case_number: number;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  status: CaseStatus;
  disposition?: CaseDisposition;
  priority: number;
  assigned_to?: string;
  assigned_at?: string;
  assigned_group?: string;
  assigned_group_at?: string;
  ai_summary?: string;
  ai_recommendations?: AiRecommendation[];
  ai_summary_generated_at?: string;
  // NAN-1251: AI Tier-1 triage verdict, surfaced on list rows + the
  // elevated-case verdict strip.
  ai_disposition?: AiDisposition;
  ai_confidence?: number; // 0.0–1.0
  ai_recommended_action?: string;
  // NAN-1297: AI-recommended severity. Drives symmetric re-triage — when more
  // severe than `severity` it's a pending escalation (recommend-only); when it
  // equals `severity` the escalation was already applied (auto mode).
  ai_recommended_severity?: string;
  ai_key_evidence?: string[];
  ai_triaged_at?: string;
  // NAN-1251 (P3): set when a later case escalated a shared entity this case
  // had closed as FP/benign — suggests re-review.
  needs_review?: boolean;
  needs_review_reason?: string;
  needs_review_at?: string;
  // NAN-1251 (P4): true when the AI Tier-1 triage auto-closed this case.
  ai_closed?: boolean;
  grouping_key?: string;
  grouping_type?: GroupingType;
  mitre_tactics: string[];
  mitre_techniques: string[];
  visibility: CaseVisibility;
  created_by?: string;
  created_at: string;
  updated_at: string;
  first_activity_at?: string;
  last_activity_at?: string;
  resolved_at?: string;
  closed_at?: string;
  // SLA tracking timestamps
  first_response_at?: string;
  triage_completed_at?: string;
}

// NAN-417: Incidents — lightweight parent container grouping related cases.
export interface Incident {
  id: string;
  incident_number: number;
  title: string;
  severity: string;
  status: 'active' | 'resolved' | 'closed';
  source: 'manual' | 'agent_detected';
  detector?: string | null;
  confidence?: number | null;
  signature?: string | null;
  tags: string[];
  opened_at: string;
  closed_at?: string | null;
  closed_by?: string | null;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
}

export interface IncidentSummary {
  id: string;
  incident_number: number;
  title: string;
  severity: string;
  status: string;
  source: string;
}

export interface CreateIncidentRequest {
  title: string;
  severity: string;
  source: 'manual' | 'agent_detected';
  detector?: string | null;
  confidence?: number | null;
  signature?: string | null;
  tags?: string[];
  case_ids: string[];
}

export interface IncidentWithCases {
  incident: Incident;
  cases: CaseWithDetails[];
}

export interface IncidentListResponse {
  incidents: Incident[];
  total_count: number;
  limit: number;
  offset: number;
}

export interface AddCaseToIncidentRequest {
  case_id: string;
}

export interface CaseWithDetails extends Case {
  alert_count: number;
  entity_count: number;
  assignee_name?: string;
  assigned_group_name?: string;
  creator_name?: string;
  shared_groups: SharedGroup[];
  is_creator: boolean;
  // NAN-417: incident grouping
  incident_id?: string | null;
  incident?: IncidentSummary | null;
  // NAN-420: workflow / collab indicators surfaced on the list payload so
  // the Cases page can render handoff pills + presence badges per row.
  pending_state?: CasePendingState | null;
  active_handoff?: ActiveHandoffSummary | null;
  collab_presence?: CollabPresenceSummary;
}

// NAN-420: summary of the latest open handoff for a case (pending/offered
// states). `null` on the list response when no handoff is in flight.
export interface ActiveHandoffSummary {
  id: string;
  to_user_id?: string | null;
  to_user_name?: string | null;
  target_label: string;
  initiated_at: string;
  state: 'pending' | 'accepted' | 'bounced' | 'canceled';
}

// NAN-420: compact collab-presence summary for the Cases list. viewer_count
// excludes the caller — it's "how many OTHER analysts are on this case".
export interface CollabPresenceSummary {
  viewer_count: number;
}

// NAN-420: response shape from `POST /api/cases/:id/presence` heartbeats.
export interface PresenceHeartbeatResponse {
  viewer_count: number;
}

export interface CaseListResponse {
  cases: CaseWithDetails[];
  total_count: number;
  limit: number;
  offset: number;
}

// NAN-1072: case saved searches
export interface CaseSavedSearch {
  id: string;
  owner_id: string;
  name: string;
  query: string;
  is_shared: boolean;
  /** NAN-1075: 'structured' | 'free' — restored on load. */
  mode: string;
  /** NAN-1075: time-window id (e.g. '24h'). Matched against the page's
   *  TIME_WINDOWS table; unknown values fall back to '24h'. */
  time_window: string;
  created_at: string;
  updated_at: string;
}

export interface CaseSavedSearchWithContext {
  id: string;
  owner_id: string;
  owner_name: string | null;
  name: string;
  query: string;
  is_shared: boolean;
  mode: string;
  time_window: string;
  is_owner: boolean;
  created_at: string;
  updated_at: string;
}

export interface NewCaseSavedSearch {
  name: string;
  query: string;
  is_shared?: boolean;
  mode?: string;
  time_window?: string;
}

export interface UpdateCaseSavedSearch {
  name?: string;
  query?: string;
  is_shared?: boolean;
  mode?: string;
  time_window?: string;
}

export interface ShareCaseRequest {
  visibility: CaseVisibility;
  group_ids?: string[];
}

export interface CaseShareResult {
  case: CaseWithDetails;
  users_who_lost_access: CaseAffectedUser[];
}

export interface CaseAffectedUser {
  user_id: string;
  user_name: string;
  user_email: string;
}

export interface CaseSummary {
  id: string;
  case_number: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  status: CaseStatus;
  alert_count: number;
  created_at: string;
  last_activity_at?: string;
}

export interface CaseEntity {
  id: string;
  case_id: string;
  entity_type: CaseEntityType;
  entity_value: string;
  occurrence_count: number;
  risk_score?: number;
  is_primary: boolean;
  enrichment_data?: Record<string, unknown>;
  enrichment_updated_at?: string;
  created_at: string;
}

export interface EntityTypeSummary {
  entity_type: string;
  count: number;
  entities: CaseEntity[];
}

export interface CaseWallEntry {
  id: string;
  case_id: string;
  entry_type: CaseWallEntryType;
  content?: string;
  metadata: Record<string, unknown>;
  is_internal: boolean;
  created_by?: string;
  creator_name?: string;
  created_at: string;
}

export interface CaseRelation {
  source_case_id: string;
  target_case_id: string;
  relation_type: CaseRelationType;
  confidence?: number;
  reason?: string;
  shared_entities?: string[];
  created_at: string;
}

export interface RelatedCaseSummary {
  // NAN-431: field is `id` (matches the Rust `RelatedCaseSummary.id`, not
  // `case_id`). The previous `case_id` name produced undefined in the
  // popover navigation — the bug was latent because the seed DB had no
  // rows; manual linking now surfaces them so the type is aligned here.
  id: string;
  case_number: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  status: CaseStatus;
  relation_type: CaseRelationType;
  confidence?: number;
  shared_entity_count: number;
  /**
   * User id that manually linked this relation. `null`/undefined for
   * auto-detected (entity-intersection) relations.
   */
  created_by?: string | null;
  /**
   * Free-form rationale — analyst-written for manual links, or the
   * auto-detector's "N shared entities" string.
   */
  reason?: string | null;
}

export interface CaseAlertDetail {
  id: string;
  alert_id: string;
  rule_name?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  status: string;
  disposition?: string;
  matched_event_count?: number;
  created_at: string;
  added_at: string;
  is_primary: boolean;
  triage_verdict?: string;
  triage_confidence?: number;
  /**
   * Per-alert risk-score contribution (0–100) sourced from the firing rule's
   * `risk_score`. Used by the Risk page to render a per-alert weight bar.
   */
  score_contribution?: number;
  /**
   * MITRE ATT&CK tactic IDs from the firing rule (e.g. `["TA0006", "TA0001"]`).
   * Empty array when the rule has no tactics tagged.
   */
  mitre_tactics?: string[];
}

export interface CaseStats {
  total: number;
  open: number;
  in_progress: number;
  pending: number;
  resolved: number;
  closed: number;
  by_severity: Record<string, number>;
  avg_resolution_time_hours?: number;
}

export interface CaseFullResponse {
  case: CaseWithDetails;
  alerts: CaseAlertDetail[];
  entities: EntityTypeSummary[];
  related_cases: RelatedCaseSummary[];
  stats: {
    alert_count: number;
    entity_count: number;
    comment_count: number;
    time_open_hours?: number;
  };
  playbook?: CasePlaybookState | null;
  // NAN-415: first-class workflow persistence fields
  close_note?: CaseCloseNote | null;
  pending_state?: CasePendingState | null;
  escalations?: CaseEscalation[];
  handoffs?: CaseHandoff[];
  workflow_events?: CaseWorkflowEvent[];
  // NAN-422: pre-resolved lookup from `case_*` typeid → compact case ref.
  // Keyed by the canonical typeid string (e.g. `case_01hk...`). Missing
  // entries mean the referenced case was deleted or inaccessible — the UI
  // falls back to a non-interactive pill in that case.
  linked_cases_index?: Record<string, LinkedCaseRef>;
}

// NAN-422: compact case reference used in `linked_cases_index`.
export interface LinkedCaseRef {
  /** Typeid (`case_<base32>`). */
  id: string;
  /** Display serial (rendered as `CASE-<n>`). */
  case_number: number;
  title: string;
  /** Free-form case status string (`open`, `in_progress`, `closed`, …). */
  status: string;
  /** Free-form severity string (`critical`, `high`, …). */
  severity: string;
}

// NAN-415: Case workflow persistence types
export type CaseCloseReason = 'tp' | 'fp' | 'btp' | 'dup' | 'esc' | 'info' | 'inconc';
export type CasePendingKind = 'await-user' | 'await-approval' | 'await-vendor' | 'snoozed' | 'scheduled' | 'hold';

export interface CaseCloseNote {
  id: string;
  case_id: string;
  created_by?: string | null;
  close_reason: CaseCloseReason;
  title: string;
  summary: string;
  emits: string[];
  tuning_action?: string | null;
  escalation_target?: string | null;
  duplicate_primary_case_number?: number | null;
  duplicate_primary_case_id?: string | null;
  ack_audit: boolean;
  audit_id?: string | null;
  superseded_at?: string | null;
  created_at: string;
}

export interface CasePendingState {
  kind: CasePendingKind;
  target?: string | null;
  since?: string | null;
}

export interface CaseEscalation {
  id: string;
  case_id: string;
  source_user_id?: string | null;
  target_user_id?: string | null;
  target_group_id?: string | null;
  target_label: string;
  reason: string;
  previous_assigned_to?: string | null;
  previous_assigned_group?: string | null;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  created_at: string;
}

export interface CaseHandoff {
  id: string;
  case_id: string;
  source_user_id: string;
  target_user_id?: string | null;
  target_group_id?: string | null;
  target_label: string;
  reason?: string | null;
  context_payload: Record<string, unknown>;
  state: 'pending' | 'accepted' | 'bounced' | 'canceled';
  accepted_at?: string | null;
  accepted_by?: string | null;
  bounced_at?: string | null;
  bounced_by?: string | null;
  bounce_reason?: string | null;
  canceled_at?: string | null;
  created_at: string;
}

export interface CaseWorkflowEvent {
  id: string;
  case_id: string;
  actor_id?: string | null;
  event_kind:
    | 'status_changed'
    | 'pending_set'
    | 'pending_cleared'
    | 'escalated'
    | 'closed'
    | 'reopened'
    | 'handoff_sent'
    | 'handoff_accepted'
    | 'handoff_bounced'
    | 'handoff_canceled'
    // NAN-422: emitted on first @-mention per (case, user) — see
    // nanosiem-core/src/db/repository/cases/workflow.rs::insert_mention_added.
    | 'mention_added';
  from_status?: string | null;
  to_status?: string | null;
  reason?: string | null;
  metadata: Record<string, unknown>;
  close_note_id?: string | null;
  escalation_id?: string | null;
  handoff_id?: string | null;
  created_at: string;
}

export interface CasePlaybookState {
  title: string;
  summary?: string;
  status: string;
  source: string;
  started_at?: string;
  updated_at?: string;
  evidence_count: number;
  suggested_queries: string[];
  steps: CasePlaybookStep[];
}

export interface CasePlaybookStep {
  title: string;
  status: string;
}

export interface CaseGroupingRule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  match_type: string;
  time_window_minutes: number;
  max_alerts: number;
  case_title_template?: string;
  case_severity_rule: string;
  auto_assign_to?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateCaseRequest {
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  priority?: number;
  assigned_to?: string;
  grouping_key?: string;
  grouping_type?: GroupingType;
}

export interface UpdateCaseRequest {
  title?: string;
  description?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  priority?: number;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
}

export interface CaseFilter {
  status?: CaseStatus[];
  severity?: string[];
  assigned_to?: string;
  assigned_group?: string;
  /** NAN-1093: multi-group filter for the Signal Inbox Escalations tab —
   *  cases whose `assigned_group` matches any of these. Empty array is
   *  treated as no filter by the backend. */
  assigned_groups?: string[];
  search?: string;
  /** NAN-1074: free-text mode — server ILIKE against case
   *  title/description AND joined alert content. Slower than `search`
   *  (which scans only case columns); pair with a tight `created_after`. */
  free_text?: string;
  created_after?: string;
  created_before?: string;
  limit?: number;
  offset?: number;
  /** NAN-1093: filter to cases with NULL (true) or NOT-NULL (false)
   *  `incident_id`. The Signal Inbox sets `true` for the loose list so
   *  paginated tabs don't double-count cases inside an incident pill. */
  incident_id_is_null?: boolean;
  /** NAN-1093: result ordering. `mine_first` keys off the authenticated
   *  user; other variants are caller-controlled. Defaults to `newest`. */
  sort?: CaseSort;
  /** NAN-1251: restrict to the "Must Investigate" bucket — cases the AI
   *  flagged as actionable (true_positive / needs_investigation) that a
   *  human hasn't dispositioned yet. */
  ai_escalated_only?: boolean;
}

/** NAN-1093: Signal Inbox sort options. Matches the Rust `CaseSortParam`.
 *  NAN-1095 added `'sla'` — server resolves the per-severity SLA targets
 *  from `case_settings` and orders by least remaining time. */
export type CaseSort = 'newest' | 'oldest' | 'severity' | 'mine_first' | 'sla' | 'ai_priority';

/** NAN-1093: Per-tab counts for the Signal Inbox. `loose` are cases not
 *  attached to an incident (rendered in the tab list); `grouped` are
 *  cases inside an incident pill — the inbox surfaces this as `+N` next
 *  to the tab label. */
export interface InboxTabCount {
  loose: number;
  grouped: number;
}

export interface InboxCountsResponse {
  active: InboxTabCount;
  triage: InboxTabCount;
  escalations: InboxTabCount;
  all: InboxTabCount;
  mine: InboxTabCount;
  // NAN-1251: "Must Investigate" — AI-actionable, not yet human-dispositioned.
  must_investigate: InboxTabCount;
}

/** NAN-1093: Incident pill + its case children, returned by
 *  `/api/cases/inbox-incidents`. Children are eagerly fetched (no
 *  pagination) — typical SOC queues have far fewer grouped cases than
 *  loose cases. */
export interface InboxIncidentGroup {
  incident: IncidentSummary;
  cases: CaseWithDetails[];
}

export interface InboxIncidentsResponse {
  incidents: InboxIncidentGroup[];
}

export interface AddAlertToCaseRequest {
  alert_id: string;
  is_primary?: boolean;
}

export interface AddWallEntryRequest {
  entry_type: CaseWallEntryType;
  content?: string;
  metadata?: Record<string, unknown>;
  is_internal?: boolean;
}

export interface ChangeCaseStatusRequest {
  status: CaseStatus;
  disposition?: CaseDisposition;
  // NAN-415: structured workflow payloads written through alongside status change
  close_note?: CloseNoteInputRequest | null;
  pending_kind?: CasePendingKind | null;
  pending_target?: string | null;
}

export interface CloseNoteInputRequest {
  close_reason: CaseCloseReason;
  title: string;
  summary: string;
  emits: string[];
  tuning_action?: string | null;
  escalation_target?: string | null;
  duplicate_primary_case_number?: number | null;
  duplicate_primary_case_id?: string | null;
  ack_audit: boolean;
}

export interface CreateHandoffRequest {
  target_user_id?: string | null;
  target_group_id?: string | null;
  target_label: string;
  reason?: string | null;
  context_payload?: Record<string, unknown>;
}

export interface BounceHandoffRequest {
  reason: string;
}

export interface EscalateCaseRequest {
  assigned_to?: string | null;
  assigned_group?: string | null;
  reason: string;
}

export interface BulkChangeCaseStatusRequest {
  case_ids: string[];
  status: CaseStatus;
  disposition?: CaseDisposition;
  reason?: string;
}

export interface BulkChangeCaseStatusResponse {
  success_count: number;
  failed_count: number;
  failed_cases: Array<{
    case_id: string;
    error: string;
  }>;
}

// NAN-421: single-call bulk assign. Replaces the client-side Promise.allSettled
// fan-out the Cases list page used to do.
export interface BulkAssignRequest {
  case_ids: string[];
  assigned_to?: string | null;
  assigned_group?: string | null;
}

export interface BulkAssignFailure {
  id: string;
  reason: string;
}

export interface BulkAssignResponse {
  updated: number;
  failed: BulkAssignFailure[];
}

// NAN-421: duplicate-candidate detector response. Pulled lazily from the
// row-level `dup?` hint on the Cases list page (hover -> fetch -> popover).
export interface DuplicateCandidate {
  case_id: string;
  case_number: number;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  reason: string;
}

export interface MergeCasesRequest {
  source_case_ids: string[];
}

export interface MergeCasesResponse {
  message: string;
  alerts_moved: number;
  entities_moved: number;
  cases_merged: number;
}

export interface CreateGroupingRuleRequest {
  name: string;
  description?: string;
  enabled?: boolean;
  priority?: number;
  match_type: string;
  time_window_minutes?: number;
  max_alerts?: number;
  case_title_template?: string;
  case_severity_rule?: string;
  auto_assign_to?: string;
}

export interface UpdateGroupingRuleRequest {
  name?: string;
  description?: string;
  enabled?: boolean;
  priority?: number;
  match_type?: string;
  time_window_minutes?: number;
  max_alerts?: number;
  case_title_template?: string;
  case_severity_rule?: string;
  auto_assign_to?: string;
}

// SLA tier settings for a single severity level (times in minutes)
export interface SlaTierSettings {
  response_minutes: number;
  triage_minutes: number;
  resolution_minutes: number;
}

// SLA settings for all severity levels
export interface SlaSettings {
  enabled: boolean;
  critical: SlaTierSettings;
  high: SlaTierSettings;
  medium: SlaTierSettings;
  low: SlaTierSettings;
  informational: SlaTierSettings;
}

// NAN-1251: AI Tier-1 triage autonomy. `recommend_only` is the default and a
// permanent first-class state; `auto_close` is explicit opt-in.
export type AutonomyMode = 'off' | 'recommend_only' | 'auto_close';

export interface CaseSettings {
  auto_grouping_enabled: boolean;
  auto_investigate_enabled: boolean;
  max_alerts_per_case: number;
  default_time_window_minutes: number;
  default_assigned_group?: string;
  sla: SlaSettings;
  autonomy_mode: AutonomyMode;
  auto_close_min_confidence: number; // 0.0–1.0
  auto_close_max_severity: string;
}

export interface UpdateCaseSettingsRequest {
  auto_grouping_enabled?: boolean;
  auto_investigate_enabled?: boolean;
  max_alerts_per_case?: number;
  default_time_window_minutes?: number;
  default_assigned_group?: string | null;
  sla?: SlaSettings;
  autonomy_mode?: AutonomyMode;
  auto_close_min_confidence?: number;
  auto_close_max_severity?: string;
}

// ============================================================================
// Notebooks
// ============================================================================

export type NotebookVisibility = 'private' | 'shared' | 'public';
export type NotebookStatus = 'active' | 'paused' | 'closed' | 'merged';
export type SharePermission = 'view' | 'edit';
export type ReferenceType = 'alert' | 'detection' | 'saved_search' | 'case';
export type NotebookEntryType =
  | 'manual_note'
  | 'search_executed'
  | 'search_refined'
  | 'alert_viewed'
  | 'alert_actioned'
  | 'detection_viewed'
  | 'detection_modified'
  | 'ai_suggestion'
  | 'ai_summary'
  | 'entity_reference'
  | 'ioc_marker'
  | 'timeline_marker'
  | 'linked_alert'
  | 'linked_detection'
  | 'ai_query'
  | 'pivot_suggestions'
  | 'user_mention'
  | 'case_event'
  | 'investigation_timeline'
  // AI chat types (NAN-48)
  | 'ai_chat_message'
  | 'ai_chat_response'
  | 'ai_search_result';

// ============================================================================
// Notebook AI Chat Types (NAN-48)
// ============================================================================

export interface NotebookChatRequest {
  message: string;
  thread_id?: string;
  time_range?: TimeRange;
  /** NAN-859: explicit @mention user_ids picked from the case Thread composer's popover. */
  mentioned_user_ids?: string[];
}

export interface NotebookChatSuggestion {
  suggestion_type: string;
  label: string;
  payload: Record<string, unknown>;
}

export interface NotebookChatResponse {
  thread_id: string;
  response_text: string;
  entry_ids: string[];
  suggestions: NotebookChatSuggestion[];
}

/** Callbacks for SSE streaming notebook chat */
export interface NotebookChatStreamCallbacks {
  onThread?: (threadId: string) => void;
  onProgress?: (message: string) => void;
  onSearchResult?: (result: { query: string; query_mode?: string; result_count: number; execution_time_ms?: number }) => void;
  onContent?: (text: string) => void;
  onDone?: (response: NotebookChatResponse) => void;
  onError?: (message: string) => void;
}

export interface Notebook {
  id: string;
  title: string;
  owner_id: string;
  case_id?: string;
  merged_into_id?: string;
  visibility: NotebookVisibility;
  status: NotebookStatus;
  summary?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

export interface NotebookWithOwner extends Notebook {
  owner_name?: string;
}

export interface NotebookSummary extends NotebookWithOwner {
  entry_count: number;
}

export interface MatchedEntity {
  entity_type: string;
  value: string;
}

export interface RelatedNotebook extends NotebookSummary {
  matched_entities: MatchedEntity[];
}

export interface NotebookResponse extends NotebookWithOwner {
  entry_count: number;
  can_edit: boolean;
}

export interface NotebookEntry {
  id: string;
  notebook_id: string;
  entry_type: NotebookEntryType;
  content: Record<string, unknown>;
  source_url?: string;
  created_by: string;
  created_at: string;
  /** Source of entry: 'analyst' (default) or 'shadow_investigation' */
  source?: string;
  // Merge tracking fields
  merged_from_notebook_id?: string;
  merged_from_notebook_title?: string;
  original_created_at?: string;
}

export interface NotebookEntryWithCreator extends NotebookEntry {
  creator_name?: string;
}

// Merge request/response types
export interface MergeNotebooksRequest {
  source_notebook_ids: string[];
}

export interface MergeNotebooksResponse {
  entries_merged: number;
  merged_notebook_ids: string[];
}

export interface LinkNotebookRequest {
  notebook_id: string;
}

export interface NotebookShare {
  id: string;
  notebook_id: string;
  shared_with_user_id?: string;
  shared_with_group_id?: string;
  permission: SharePermission;
  created_at: string;
}

export interface NotebookShareWithNames extends NotebookShare {
  user_name?: string;
  group_name?: string;
}

export interface NotebookReference {
  id: string;
  notebook_id: string;
  reference_type: ReferenceType;
  reference_id: string;
  reference_name?: string;
  created_at: string;
}

export interface CreateNotebookRequest {
  title: string;
  visibility?: NotebookVisibility;
}

export interface UpdateNotebookRequest {
  title?: string;
  visibility?: NotebookVisibility;
  status?: NotebookStatus;
  summary?: string;
}

export interface AddEntryRequest {
  entry_type: NotebookEntryType;
  content: Record<string, unknown>;
  source_url?: string;
  original_created_at?: string;
  /**
   * Side-channel metadata processed at the handler (not persisted on the
   * entry). NAN-479: when the entry lands on a case-bound notebook,
   * `metadata.mentioned_user_ids[]` fires CaseMention notifications and
   * emits a `mention_added` workflow event on first mention per (case, user).
   */
  metadata?: Record<string, unknown>;
}

export interface AddShareRequest {
  user_id?: string;
  group_id?: string;
  permission?: SharePermission;
}

export interface ShareNotebookRequest {
  /** Visibility: 'public', 'shared', or 'private' */
  visibility: NotebookVisibility;
  /** Group IDs to share with (required when visibility = 'shared') */
  group_ids?: string[];
}

export interface NotebookAffectedUser {
  user_id: string;
  user_name: string;
  user_email: string;
}

export interface NotebookSharedGroup {
  id: string;
  name: string;
}

export interface NotebookShareResult {
  notebook: NotebookSummary;
  shared_groups: NotebookSharedGroup[];
  users_who_lost_access: NotebookAffectedUser[];
}

export interface AddReferenceRequest {
  reference_type: ReferenceType;
  reference_id: string;
  reference_name?: string;
}

export interface NotebookAISummary {
  summary: string;
  key_findings: string[];
  entities_investigated: string[];
  queries_run: number;
  alerts_reviewed: number;
  suggested_next_steps: string[];
}

export interface QuerySuggestion {
  query: string;
  description: string;
  rationale: string;
}

export interface NotebookQuerySuggestions {
  suggestions: QuerySuggestion[];
  context_summary: string;
}

export interface GenerateQuerySuggestionsRequest {
  context_type: 'alert' | 'detection';
  context_id: string;
  rule_name: string;
  rule_query?: string;
  severity?: string;
  sample_events: Record<string, unknown>[];
}

export interface AnalyzeNoteRequest {
  note_text: string;
  recent_context?: Array<{ entry_type: string; summary: string }>;
}

// ============================================================================
// Notebook Tabs
// ============================================================================

export interface NotebookTab {
  id: string;
  user_id: string;
  notebook_id: string;
  is_pinned: boolean;
  is_active: boolean;
  tab_order: number;
  last_accessed_at: string;
  created_at: string;
}

export interface NotebookTabWithDetails extends NotebookTab {
  notebook_title: string;
  notebook_status: NotebookStatus;
  entry_count: number;
  case_id?: string;
}

export interface OpenTabRequest {
  notebook_id: string;
}

export interface UpdateTabRequest {
  is_pinned?: boolean;
}

export interface ReorderTabsRequest {
  tab_ids: string[];
}

// ============================================================================
// Log Sources
// ============================================================================

export interface LogSource {
  id: string;
  name: string;
  description?: string;
  /** Network namespace for identity resolution (e.g., "aws:123456789012:vpc-abc", "onprem:dc-east") */
  namespace: string;
  /** IANA timezone name for timestamps without offset info (e.g., "America/New_York") */
  timezone: string;
  source_type: string;
  source_config: Record<string, unknown>;
  credential_id?: string;
  /**
   * NAN-928: deployed source-configuration whose routing transform feeds
   * events into this parser. Set when the user picked a fetch-source config
   * (Kafka / S3 / GCP Pub/Sub) in the parser-import "DISPATCH FROM" UI.
   */
  dispatch_source_config_id?: string | null;
  /**
   * NAN-1084: derived transport label (e.g. "kafka", "gcp_pubsub") sourced
   * from the joined source_configurations row. Populated by list/detail
   * endpoints that join source_configurations; absent for legacy parser-
   * owned sources, in which case the UI falls back to `source_type`.
   */
  dispatch_source_config_type?: string | null;
  parser_vrl: string;
  output_fields?: Record<string, unknown>;
  category?: string;
  vendor?: string;
  product?: string;
  icon?: string;
  color?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  validated: boolean;
  validation_error?: string;
  deployed: boolean;
  deployed_at?: string;
  enabled: boolean;
  stale_alert_enabled: boolean;
  stale_threshold_minutes: number;
  /** Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). null = no sampling. */
  sampling_ratio?: number | null;
  /** VRL condition for events that are NEVER sampled. null = no exclusions. */
  sampling_exclude_condition?: string | null;
  /** Optional VRL overlay chained after _parse, before _output (NAN-874). */
  extension_vrl?: string | null;
  /** When false, extension_vrl is persisted but not deployed (NAN-874). */
  extension_enabled?: boolean;
  parser_only: boolean;
  source_parser_repository_id?: string;
  source_parser_path?: string;
  source_parser_linked: boolean;
  created_at: string;
  updated_at: string;
}

export interface NewLogSource {
  name: string;
  description?: string;
  /** Network namespace for identity resolution (e.g., "aws:123456789012:vpc-abc", "onprem:dc-east") */
  namespace?: string;
  /** IANA timezone for timestamps without offset info. Defaults to "UTC". */
  timezone?: string;
  source_type: string;
  source_config: Record<string, unknown>;
  credential_id?: string;
  parser_vrl: string;
  output_fields?: Record<string, unknown>;
  category?: string;
  vendor?: string;
  product?: string;
  icon?: string;
  color?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  /** Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). */
  sampling_ratio?: number | null;
  /** VRL condition for events that are NEVER sampled. */
  sampling_exclude_condition?: string | null;
}

export interface UpdateLogSource {
  name?: string;
  description?: string;
  /** Network namespace for identity resolution */
  namespace?: string;
  /** IANA timezone for timestamps without offset info */
  timezone?: string;
  source_type?: string;
  source_config?: Record<string, unknown>;
  credential_id?: string;
  parser_vrl?: string;
  output_fields?: Record<string, unknown>;
  category?: string;
  vendor?: string;
  product?: string;
  icon?: string;
  color?: string;
  match_field?: string;
  match_pattern?: string;
  match_values?: string[];
  stale_alert_enabled?: boolean;
  stale_threshold_minutes?: number;
  /** Sample ratio 0.0-1.0 (e.g., 0.1 = keep 10%). */
  sampling_ratio?: number | null;
  /** VRL condition for events that are NEVER sampled. */
  sampling_exclude_condition?: string | null;
  /** Parser extension VRL (NAN-874). Empty string clears the extension; undefined leaves unchanged. */
  extension_vrl?: string;
  /** Toggle whether extension_vrl is included in deploys (NAN-874). */
  extension_enabled?: boolean;
}

export interface LogSourceHealth {
  log_source_id: string;
  log_source_name: string;
  total_events: number;
  events_last_24h: number;
  events_last_hour: number;
  avg_events_per_hour: number;
  last_event_at?: string;
  first_event_at?: string;
  data_freshness_hours?: number;
  ingestion_rate_trend: 'increasing' | 'stable' | 'decreasing' | 'unknown';
  health_status: 'healthy' | 'stale' | 'no_data' | 'disabled' | 'error';
  total_size_bytes: number;
  avg_event_size_bytes: number;
  error_rate_24h: number;
  parse_errors_24h: number;
}

export interface IngestionHistoryPoint {
  source_type: string;
  timestamp: string;
  count: number;
}

export interface LogSourceDeployment {
  id: string;
  log_source_id: string;
  action: string;
  status: string;
  error_message?: string;
  config_snapshot?: string;
  deployed_at: string;
}

/**
 * A single diagnostic returned by the VRL validator.
 * Severity, position, optional code, message and optional hint.
 */
export interface VrlDiagnostic {
  severity: 'error' | 'warn' | 'info';
  line?: number;
  col?: number;
  code?: string;
  message: string;
  hint?: string;
}

export interface LogSourceVrlValidationResult {
  valid: boolean;
  errors: string[];
  /** Optional structured diagnostics (severity, line/col, hint). Backend may omit. */
  diagnostics?: VrlDiagnostic[];
}

export interface LogSourceTestResult {
  input: string;
  success: boolean;
  output?: Record<string, unknown>;
  error?: string;
  /** Optional count of fields the parser extracted from this sample. */
  extracted_field_count?: number;
}

/** NAN-522: namespace validation response. */
export interface NamespaceValidationResult {
  valid: boolean;
  error?: string;
}

/** NAN-522: routing-rule reachability response. */
export interface RoutingRuleReachability {
  reachable: boolean;
  source_config_enabled: boolean;
  source_config_deployed: boolean;
  target_log_source_exists: boolean;
  /**
   * NAN-884 K-4: TCP-dial result for broker-bound configs (Kafka).
   * `true` if at least one `bootstrap_servers` entry accepted a connection,
   * `false` if every entry failed, `undefined` for non-broker source types
   * or when no bootstrap_servers were parseable.
   */
  broker_reachable?: boolean;
  /** One line per probed broker — `host:port → ok` or `host:port → <reason>`. */
  broker_reachable_details?: string[];
  warnings: string[];
}

/** NAN-522: shape of the body for routing-rule reachability check. */
export interface RoutingRuleReachabilityRequest {
  target_source_type: string;
  match_field: string;
  match_type: string;
  match_value?: string;
}

export interface LiveTestResult {
  input: string;
  new_parse: LogSourceTestResult;
  current_parse?: LogSourceTestResult;
}

export interface LogSourceVersion {
  id: number;
  log_source_id: string;
  version_number: number;
  parser_vrl: string;
  output_fields?: Record<string, unknown>;
  is_active: boolean;
  created_at: string;
  created_by?: string;
  change_reason: string;
  reverted_from_version?: number;
  /** Snapshot of extension_vrl at publish time (NAN-874). */
  extension_vrl?: string | null;
  /** Snapshot of extension_enabled at publish time (NAN-874). */
  extension_enabled?: boolean;
}

export interface LogSourceWithDraftStatus extends LogSource {
  has_draft_changes: boolean;
  active_version_number?: number;
  active_parser_vrl?: string;
}

// ============================================================================
// Source Configurations (Infrastructure + Routing)
// ============================================================================

export type SourceConfigType = 'http' | 'kafka' | 'aws_s3' | 'gcp_pubsub' | 'splunk_hec' | 'vector' | 'otlp';
export type MatchType = 'exact' | 'prefix' | 'suffix' | 'regex' | 'contains' | 'default';

export interface RoutingRule {
  id: string;
  source_configuration_id: string;
  priority: number;
  match_field: string;
  match_type: string;
  match_value?: string;
  target_source_type: string;
  created_at: string;
  /**
   * NAN-531: best-effort 24h event count credited to this rule.
   * `null`/missing when ClickHouse is unavailable or telemetry was not requested.
   *
   * Per-rule attribution uses first-rule-wins: the first rule per
   * (source_configuration_id, target_source_type) gets the full count;
   * later rules sharing the same target see `0`.
   */
  fires_24h?: number | null;
  /**
   * NAN-531: best-effort timestamp of the most recent event credited to this
   * rule under the same first-rule-wins attribution as `fires_24h`.
   */
  last_fired_at?: string | null;
}

export interface NewRoutingRule {
  priority?: number;
  match_field: string;
  match_type: string;
  match_value?: string;
  target_source_type: string;
}

export interface UpdateRoutingRule {
  priority?: number;
  match_field?: string;
  match_type?: string;
  match_value?: string;
  target_source_type?: string;
}

export interface SourceConfiguration {
  id: string;
  name: string;
  description?: string;
  config_type: SourceConfigType;
  connection_config: Record<string, unknown>;
  credential_id?: string;
  enabled: boolean;
  deployed: boolean;
  deployed_at?: string;
  created_at: string;
  updated_at: string;
  /** NAN-522: rolling 24h event count routed through this transport (null if unknown). */
  events_24h?: number | null;
  /**
   * NAN-531: best-effort sum of received bytes (proxy:
   * `length(message) + length(metadata)`) across log sources targeted by
   * this config's routing rules over the last 24h. `null`/missing when
   * ClickHouse is unavailable or telemetry was not requested. Only populated
   * on `/full` or when listing with `?include=telemetry`.
   */
  bytes_per_day_24h?: number | null;
  /**
   * NAN-531: best-effort timestamp of the most recent event matched to any
   * of this config's routing rules in the last 24h. Same gating as
   * `bytes_per_day_24h`.
   */
  last_event_at?: string | null;
}

export interface SourceConfigurationWithRules extends SourceConfiguration {
  routing_rules: RoutingRule[];
}

export interface NewSourceConfiguration {
  name: string;
  description?: string;
  config_type: string;
  connection_config: Record<string, unknown>;
  credential_id?: string;
  routing_rules?: NewRoutingRule[];
}

export interface UpdateSourceConfiguration {
  name?: string;
  description?: string;
  config_type?: string;
  connection_config?: Record<string, unknown>;
  credential_id?: string;
  enabled?: boolean;
}

export interface SourceConfigDeployment {
  id: string;
  source_configuration_id: string;
  action: string;
  status: string;
  error_message?: string;
  config_snapshot?: string;
  deployed_at: string;
}

/**
 * NAN-649: a per-driver `match_field` preset surfaced to the routing-rule UI.
 *
 * Lets the UI pre-populate the dropdown with the canonical paths for a
 * given pull source (e.g. `attributes.source_type` for Pub/Sub) instead of
 * making users invent the right VRL path themselves.
 */
export interface MatchFieldPreset {
  /** Short human-readable label for the dropdown row. */
  label: string;
  /** VRL path stored as `match_field` (no leading dot). */
  path: string;
  /** One-line description shown beneath the label. */
  description: string;
}

/**
 * NAN-649: descriptive metadata for a single source-config driver. The UI
 * uses `is_pull_source` to decide between the push-style (one config, N
 * source_types via header) and pull-style (single vs. multiple source_types
 * per binding) routing UIs.
 */
export interface SourceConfigTypeInfo {
  config_type: string;
  label: string;
  description: string;
  requires_credentials: boolean;
  is_pull_source: boolean;
  default_match_field: string;
  match_field_presets: MatchFieldPreset[];
}

export interface SourceConfigDeploymentResult {
  success: boolean;
  source_configuration_id: string;
  action: string;
  message: string;
  deployment_id?: string;
}

// ============================================================================
// Risk Analytics
// ============================================================================

export interface RiskDecayConfig {
  decay_0_24h: number;
  decay_1_3d: number;
  decay_3_5d: number;
  decay_5_7d: number;
}

export interface UpdateRiskDecayConfigRequest {
  decay_0_24h: number;
  decay_1_3d: number;
  decay_3_5d: number;
  decay_5_7d: number;
}

export interface TimeWindowedRiskScore {
  entity: string;
  entity_type: string;
  risk_score_24h: number;
  risk_score_7d: number;
  decayed_score_24h: number;
  decayed_score_7d: number;
  finding_count_24h: number;
  finding_count_7d: number;
  last_finding_at?: string;
  last_rule_name?: string;
  last_severity?: string;
}

export interface TimeWindowedRiskResponse {
  entities: TimeWindowedRiskScore[];
  total: number;
}

export interface TimeWindowedRiskQuery {
  min_score_24h?: number;
  min_score_7d?: number;
  limit?: number;
}

export interface EntityDailyCount {
  date: string;
  count: number;
}

export interface EntityActivityResponse {
  activity: Record<string, EntityDailyCount[]>;
}

// ============================================================================
// Dashboard Variables
// ============================================================================

export type DashboardVariableType = 'dropdown' | 'text' | 'query';

export interface DashboardVariable {
  name: string;           // Variable name (used as $name in queries)
  label: string;          // Display label
  type: DashboardVariableType;
  defaultValue?: string;
  // For dropdown type - static options
  options?: string[];
  // For query type - dynamic options from search
  query?: string;         // Query to fetch options
  queryField?: string;    // Field from results to use as options
  multi?: boolean;        // Allow multiple selections
}

// ============================================================================
// Dashboard Generation (AI)
// ============================================================================

export type DashboardTemplate =
  | 'windows_security'
  | 'network_monitoring'
  | 'web_application_security'
  | 'cloud_security_aws'
  | 'endpoint_detection'
  | 'authentication_audit'
  | 'firewall_analysis';

export interface GeneratedPanel {
  id: string;
  title: string;
  query: string;
  query_mode: 'piped' | 'sql';
  visualization_type: string;
  visualization_config: Record<string, unknown>;
  rationale?: string;
}

export interface GeneratedVariable {
  name: string;
  label: string;
  variable_type: 'dropdown' | 'text' | 'query';
  default_value?: string;
  options?: string[];
  query?: string;
  query_field?: string;
  multi?: boolean;
  rationale?: string;
}

export interface GeneratedLayoutItem {
  panel_id: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface GeneratedLayout {
  columns: number;
  row_height: number;
  items: GeneratedLayoutItem[];
}

export type QuestionType = 'single_choice' | 'multi_choice' | 'free_text' | 'yes_no';

export interface ClarifyingQuestion {
  id: string;
  question: string;
  question_type: QuestionType;
  options?: string[];
  default_answer?: string;
  required: boolean;
}

export interface GeneratedDashboard {
  name: string;
  description: string;
  panels: GeneratedPanel[];
  layout: GeneratedLayout;
  variables: GeneratedVariable[];
  explanation: string;
  refresh_interval?: number;
  clarifying_questions?: ClarifyingQuestion[];
  is_complete: boolean;
}

export interface GenerateDashboardRequest {
  session_id?: string;
  description: string;
  template?: DashboardTemplate;
  time_range?: TimeRange;
  answers?: Record<string, string | string[]>;
}

export interface RefineDashboardCurrentState {
  name: string;
  description?: string;
  panels: GeneratedPanel[];
  variables: GeneratedVariable[];
  layout?: GeneratedLayout;
  explanation?: string;
  is_complete?: boolean;
}

export interface RefineDashboardRequest {
  session_id?: string;
  current_dashboard: RefineDashboardCurrentState;
  refinement: string;
}

export interface GenerateDashboardResponse {
  session_id: string;
  message: string;
  dashboard?: GeneratedDashboard;
  clarifying_questions?: ClarifyingQuestion[];
  is_complete: boolean;
}

// Generic meloD async job types (all AI endpoints use this pattern)
export type MelodJobStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface MelodJobStartResponse {
  job_id: string;
  status: 'running';
}

export interface MelodJobStatusResponse {
  job_id: string;
  status: MelodJobStatus;
  result?: unknown;
  error?: string;
  /** Human-readable progress message (while running) */
  progress?: string;
}

// Legacy aliases (kept for backward compat with dashboard wizard)
export type DashboardJobStatus = MelodJobStatus;
export type DashboardJobStartResponse = MelodJobStartResponse;
export type DashboardJobStatusResponse = MelodJobStatusResponse;

// ============================================================================
// Investigation Timeline (for notebooks)
// ============================================================================

export interface InvestigationTimelineEvent {
  id: string;
  sequence: number;
  phase: string;
  title: string;
  description: string;
  timestamp?: string;
  duration?: string;
  severity?: string;
  related_entries: string[];
  entities: Array<{ type: string; value: string }>;
}

export interface GenerateInvestigationTimelineRequest {
  notebook_id: string;
  entries: Array<{
    id: string;
    entry_type: NotebookEntryType;
    content: Record<string, unknown>;
    created_at: string;
  }>;
}

export interface GenerateInvestigationTimelineResponse {
  events: InvestigationTimelineEvent[];
  summary: string;
  generated_at: string;
}

// ============================================================================
// Notifications
// ============================================================================

export type NotificationType =
  | 'case_mention'
  | 'case_assigned'
  | 'case_status_change'
  | 'case_shared'
  | 'alert_assigned'
  | 'ai_provider_down'
  | 'data_feed_stale'
  | 'search_access_removed'
  | 'case_access_removed'
  | 'system'
  | 'tuning_triggered'
  | 'tuning_validation_complete'
  | 'tuning_staging_deployed'
  | 'tuning_promoted'
  | 'tuning_reverted'
  | 'search_completed'
  | 'search_failed'
  | 'notebook_mention'
  | 'model_deprecated';

export interface Notification {
  id: string;
  user_id: string;
  notification_type: NotificationType;
  title: string;
  message?: string;
  link?: string;
  is_read: boolean;
  read_at?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface NotificationListResponse {
  notifications: Notification[];
}

export interface UnreadCountResponse {
  count: number;
}

export interface MarkAllReadResponse {
  marked_count: number;
}

// ============================================================================
// Feedback
// ============================================================================

export type FeedbackCategory = 'bug' | 'enhancement' | 'general';
export type FeedbackStatus = 'open' | 'in_progress' | 'resolved' | 'closed';

export interface Feedback {
  id: string;
  user_id: string;
  category: FeedbackCategory;
  title: string;
  description: string;
  status: FeedbackStatus;
  admin_notes?: string;
  created_at: string;
  updated_at: string;
}

export interface FeedbackWithUser extends Feedback {
  user_name?: string;
  user_email?: string;
}

export interface CreateFeedbackRequest {
  category: FeedbackCategory;
  title: string;
  description: string;
}

export interface UpdateFeedbackRequest {
  status?: FeedbackStatus;
  admin_notes?: string;
}

export interface FeedbackListResponse {
  feedback: FeedbackWithUser[];
  total: number;
}

export interface FeedbackResponse {
  feedback: Feedback;
}

// ============================================================================
// Agent Enrichment
// ============================================================================

export type ArtifactType =
  | 'hash_md5'
  | 'hash_sha256'
  | 'domain'
  | 'ip_address'
  | 'url'
  | 'email';

export type ProviderType =
  | 'virustotal'
  | 'abuseipdb'
  | 'shodan'
  | 'greynoise'
  | 'otx'
  | 'urlhaus'
  | 'threatfox'
  | 'malwarebazaar'
  | 'custom';

export interface AgentEnrichmentProvider {
  id: string;
  name: string;
  provider_type: ProviderType;
  enabled: boolean;
  supported_artifacts: ArtifactType[];
  config: Record<string, unknown>;
  priority: number;
  rate_limit_per_minute: number;
  rate_limit_per_day: number;
  has_api_key: boolean;
  last_error?: string;
  requests_today: number;
  created_at: string;
  updated_at: string;
}

export interface ListAgentEnrichmentProvidersResponse {
  providers: AgentEnrichmentProvider[];
}

export interface CreateAgentEnrichmentProviderRequest {
  id: string;
  name: string;
  provider_type: ProviderType;
  enabled?: boolean;
  supported_artifacts?: ArtifactType[];
  config?: Record<string, unknown>;
  priority?: number;
  rate_limit_per_minute?: number;
  rate_limit_per_day?: number;
  api_key?: string;
}

export interface UpdateAgentEnrichmentProviderRequest {
  name?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  priority?: number;
  rate_limit_per_minute?: number;
  rate_limit_per_day?: number;
}

export interface EnrichmentSource {
  id: string;
  name: string;
  source_type: string;
  enabled: boolean;
  config?: Record<string, unknown>;
  last_sync?: string;
  stats?: {
    total_records?: number;
    last_error?: string;
  };
}

export interface IpinfoConfig {
  token?: string;
  download_url?: string;
}

export interface AutoSyncConfig {
  enabled: boolean;
  interval_hours: number;
  last_sync?: string;
  next_sync?: string;
}

export interface IpLookupResult {
  ip: string;
  city?: string;
  region?: string;
  country?: string;
  loc?: string;
  org?: string;
  postal?: string;
  timezone?: string;
}

// AI Failure Tracking
export type AiAgentType = 'query' | 'dashboard' | 'detection' | 'parser' | 'summarize';

export interface AiFailure {
  id: string;
  agent_type: AiAgentType;
  user_request: string;
  generated_query?: string;
  error_message: string;
  error_type: string;
  retry_count: number;
  was_resolved: boolean;
  input_context?: Record<string, unknown>;
  stack_trace?: string;
  model_version?: string;
  created_at: string;
}

export interface AiFailureStats {
  agent_type: AiAgentType;
  total_failures: number;
  resolved_count: number;
  avg_retries: number;
  last_failure?: string;
}

export interface AiFailuresResponse {
  failures: AiFailure[];
  stats: AiFailureStats[];
  total_count: number;
}

export interface GetAiFailuresRequest {
  agent_type?: AiAgentType;
  limit?: number;
  offset?: number;
}


// User Preferences
export type QueryMode = 'standard' | 'advanced';

export type TimeRangePreset =
  | 'last_15_minutes'
  | 'last_hour'
  | 'last_4_hours'
  | 'last_24_hours'
  | 'last_7_days'
  | 'last_30_days';

export type SearchHubStyle = 'popover' | 'drawer';

export type LandingPage = 'search' | 'home' | 'cases' | 'dashboards' | 'rules';

export interface UserPreferences {
  preferred_query_mode: QueryMode;
  default_time_range: TimeRangePreset;
  search_hub_style: SearchHubStyle;
  landing_page: LandingPage;
}

export interface UpdateUserPreferencesRequest {
  preferred_query_mode?: QueryMode;
  default_time_range?: TimeRangePreset;
  search_hub_style?: SearchHubStyle;
  landing_page?: LandingPage;
}

// Developer Settings (Scheduler Control)
export interface DeveloperSettings {
  detection_scheduler_enabled: boolean;
  tuning_scheduler_enabled: boolean;
  enrichment_sync_scheduler_enabled: boolean;
  custom_enrichment_scheduler_enabled: boolean;
  ai_monitoring_enabled: boolean;
  feed_monitoring_enabled: boolean;
  model_catalog_sync_scheduler_enabled: boolean;
}

export interface UpdateDeveloperSettingsRequest {
  detection_scheduler_enabled?: boolean;
  tuning_scheduler_enabled?: boolean;
  enrichment_sync_scheduler_enabled?: boolean;
  custom_enrichment_scheduler_enabled?: boolean;
  ai_monitoring_enabled?: boolean;
  feed_monitoring_enabled?: boolean;
  model_catalog_sync_scheduler_enabled?: boolean;
}

// ============================================================================
// Recent Activity (Continue Working)
// ============================================================================

export type RecentItemType = 'detection' | 'alert' | 'case' | 'dashboard';

export interface RecentActivityItem {
  item_type: RecentItemType;
  item_id: string;
  title: string;
  metadata: Record<string, unknown>;
  accessed_at: string;
}

export interface RecentActivityResponse {
  items: RecentActivityItem[];
}

export interface RecordActivityRequest {
  item_type: RecentItemType;
  item_id: string;
  item_title?: string;
  item_metadata?: Record<string, unknown>;
}

// ============================================================================
// Webhook Types
// ============================================================================

export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  has_headers: boolean;
  has_secret: boolean;
  severity_filter: string[] | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateWebhookRequest {
  name: string;
  url: string;
  headers?: Record<string, string>;
  secret?: string;
  severity_filter?: string[];
  enabled?: boolean;
}

export interface UpdateWebhookRequest {
  name?: string;
  url?: string;
  headers?: Record<string, string>;
  secret?: string;
  severity_filter?: string[];
  enabled?: boolean;
}

export interface WebhookDeliveryLog {
  id: string;
  webhook_id: string;
  alert_id: string | null;
  event_type: string;
  status_code: number | null;
  response_body: string | null;
  success: boolean;
  error_message: string | null;
  duration_ms: number | null;
  delivered_at: string;
}

export interface WebhookTestResult {
  success: boolean;
  status_code: number | null;
  error: string | null;
  duration_ms: number;
}

// =============================================================================
// Identity Provider Types
// =============================================================================

export type IdentityProviderType =
  | 'entra_id'
  | 'google_workspace'
  | 'okta'
  | 'workday'
  | 'active_directory';

export interface IdentityProviderSummary {
  id: string;
  name: string;
  provider_type: IdentityProviderType;
  enabled: boolean;
  has_credentials: boolean;
  config?: Record<string, unknown>;
  sync_status?: string;
  last_sync_at?: string;
  last_sync_error?: string;
  last_sync_duration_ms?: number;
  user_count?: number;
  created_at: string;
  updated_at: string;
}

export interface ListIdentityProvidersResponse {
  providers: IdentityProviderSummary[];
}

export interface CreateIdentityProviderRequest {
  id: string;
  name: string;
  provider_type: IdentityProviderType;
  enabled?: boolean;
  config?: Record<string, unknown>;
}

export interface UpdateIdentityProviderRequest {
  name?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
}

export interface IdentityConnectionTestResponse {
  success: boolean;
  response_time_ms?: number;
  error?: string;
  user_count_sample?: number;
}

export interface IdentitySyncTriggerResponse {
  message: string;
  provider_id: string;
}

export interface IdentityUser {
  // NAN-1117: the user_registry payload moved PG -> ClickHouse; the synthetic
  // BIGSERIAL id is replaced by a stable composite key "provider_id|external_id".
  id: string;
  provider_id: string;
  external_id: string;
  username?: string;
  upn?: string;
  email?: string;
  display_name?: string;
  first_name?: string;
  last_name?: string;
  department?: string;
  title?: string;
  manager_upn?: string;
  manager_display_name?: string;
  company?: string;
  office_location?: string;
  city?: string;
  country?: string;
  groups?: string[];
  account_enabled?: boolean;
  account_status?: string;
  mfa_enabled?: boolean;
  last_sign_in_at?: string;
  created_in_directory_at?: string;
  phone?: string;
  employee_id?: string;
  employee_type?: string;
  last_synced_at?: string;
  // NAN-1117: created_at dropped (CH has no row trigger); updated_at derived
  // from last_synced_at and now optional.
  updated_at?: string;
}

export interface IdentityUserListResponse {
  users: IdentityUser[];
  total: number;
  page: number;
  page_size: number;
}

export interface IdentityStats {
  total_users: number;
  active_users: number;
  disabled_users: number;
  providers: IdentityProviderStatsSummary[];
}

export interface IdentityProviderStatsSummary {
  provider_id: string;
  provider_name: string;
  provider_type: string;
  user_count: number;
  last_sync_at?: string;
  sync_status?: string;
}

// ============================================================================
// Identity Resolve Types
// ============================================================================

export interface IdentityResolveMatch {
  hostname?: string;
  user?: string;
  department?: string;
  title?: string;
  confidence: 'high' | 'medium' | 'low' | 'stale' | 'none';
  source?: string;
  last_seen?: string;
}

export interface IdentityResolveResponse {
  ip: string;
  match?: IdentityResolveMatch;
}

// ============================================================================
// GDPR Anonymization Types
// ============================================================================

export type GdprIdentifierType = 'username' | 'email' | 'ip';

export type GdprAnonymizationStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface GdprSubmitRequest {
  identifier_type: GdprIdentifierType;
  identifier_value: string;
  justification?: string;
}

export interface GdprAnonymizationPreview {
  request_id: string;
  identifier_type: GdprIdentifierType;
  status: GdprAnonymizationStatus;
  estimated_logs: number;
  estimated_identity_observations: number;
  estimated_cloud_activity: number;
  estimated_user_registry: number;
  limitations: string[];
}

export interface GdprAnonymizationRequest {
  id: string;
  identifier_type: GdprIdentifierType;
  identifier_hash: string;
  status: GdprAnonymizationStatus;
  logs_affected: number;
  identity_observations_affected: number;
  cloud_activity_affected: number;
  user_registry_affected: number;
  mutation_ids: unknown;
  justification?: string;
  error_message?: string;
  requested_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface GdprAnonymizationListResponse {
  requests: GdprAnonymizationRequest[];
  total: number;
}

// ============================================================================
// Organization Tier Types
// ============================================================================

export type OrganizationTier = 'unrestricted' | 'hobby' | 'startup' | 'growth' | 'team' | 'starter' | 'pro' | 'enterprise';
export type ApiAccessLevel = 'none' | 'readonly' | 'full';
export type AiModelTier = 'economy' | 'standard' | 'full';

export interface TierLimits {
  tier: OrganizationTier;
  max_data_sources: number | null;
  max_detection_rules: number | null;
  max_team_members: number | null;
  max_daily_gb: number | null;
  max_eps: number | null;
  api_access: ApiAccessLevel;
  sso_enabled: boolean;
  ha_enabled: boolean;
  ai_credits_per_month: number | null;
  ai_model_tier: AiModelTier;
}

export interface AiUsage {
  credits_used: number;
  credits_limit: number | null;
  model_tier: AiModelTier;
}

// AI usage ledger detail (NAN-1519)
export interface AgentUsage {
  agent: string;
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  cached_tokens: number;
  cache_creation_tokens: number;
  credits: number;
}

export interface DailyAiUsage {
  date: string;
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  cached_tokens: number;
  credits: number;
}

export interface AiUsageEvent {
  occurred_at: string;
  agent: string;
  model_id: string;
  provider: string;
  prompt_tokens: number;
  completion_tokens: number;
  cached_tokens: number;
  cache_creation_tokens: number;
  credits: number;
}

export interface AiUsageDetail {
  credits_used: number;
  credits_limit: number | null;
  model_tier: AiModelTier;
  from: string;
  to: string;
  by_agent: AgentUsage[];
  daily: DailyAiUsage[];
  recent: AiUsageEvent[];
}

export interface DailyUsage {
  date: string;
  bytes_ingested: number;
  events_ingested: number;
  peak_eps: number;
}

export interface TierUsage {
  data_sources: number;
  detection_rules: number;
  team_members: number;
  today: DailyUsage;
}

export interface TierWarning {
  resource: string;
  current: number;
  limit: number;
  percent_used: number;
  message: string;
}

export interface TierStatus {
  limits: TierLimits;
  usage: TierUsage;
  ai_usage: AiUsage;
  warnings: TierWarning[];
}

export interface SetTierRequest {
  tier: string;
}

export interface UpdateTierLimitsRequest {
  max_data_sources?: number;
  max_detection_rules?: number;
  max_team_members?: number;
  max_daily_gb?: number;
  max_eps?: number;
}

// ============================================================================
// Home page aggregates (NAN-370)
// ============================================================================

export interface DetectionHealthSummary {
  needs_tuning: number;
  noisy_count: number;
  silent_count: number;
}

export interface NoisyRule {
  rule_id: string;
  rule_name: string;
  match_count: number;
  alert_count: number;
  fp_rate: number;
  /** 'up' | 'flat' | 'down' — direction of the 24h match count trend */
  trend: string;
}

export interface NoisyRulesResponse {
  rules: NoisyRule[];
}

// ============================================================================
// Fleet health (NAN-612)
// ============================================================================

/**
 * Fleet-health rollup over the schedulable detection rule fleet
 * (Live/Alerting + scheduled mode + has cron). Drives the "Fleet health"
 * cell of the /rules overview strip.
 *
 * `healthy + slow + errors` may be less than `total` when a rule is in the
 * fleet but has not yet had its first scheduled run — the difference is shown
 * implicitly as the empty section of the bar.
 */
export interface FleetHealthSummary {
  /** Total schedulable rules in the fleet */
  total: number;
  /** Ran on schedule, recent p95 duration under threshold */
  healthy: number;
  /** Ran on schedule, recent p95 duration at or over threshold */
  slow: number;
  /** next_run_at is past due — scheduler stuck or rule is repeatedly timing out */
  errors: number;
}

// ============================================================================
// NAN-393 Asset dossier (redesigned Asset view)
// Aggregates populating the new entity dossier UI: identity header, activity
// timeline, processes/network/auth/files/dns cards. Backed by
// POST /api/search/asset-dossier.
// ============================================================================

/** Request for the asset dossier aggregate */
export interface AssetDossierRequest {
  identifier_field: string;
  identifier_value: string;
  identities: Record<string, unknown>[];
  time_range: TimeRange;
}

export interface AssetLogSource {
  name: string;
  event_count: number;
  last_event: string;
}

export interface AssetDossierIdentity {
  hostname: string | null;
  ip: string | null;
  mac: string | null;
  user: string | null;
  vendor_product: string | null;
  first_seen_in_range: string | null;
  last_seen_in_range: string | null;
  log_sources: AssetLogSource[];
  domain: string | null;
}

export interface AssetDossierTimeline {
  /** Number of buckets in the timeline (default 28) */
  buckets: number;
  /** Lane ordering — ["auth","proc","net","file","alert"] */
  lanes: string[];
  /** Sparse points: [bucket_index, lane_index, weight] — weight in {1,2,3} */
  points: [number, number, number][];
}

export interface DossierProcessTop {
  name: string;
  count: number;
  /** Fleet prevalence (0-100) */
  prev: number;
}

export interface DossierProcessRare {
  name: string;
  hash: string | null;
  prev: number;
  cmd: string | null;
  flags: string[];
}

export interface AssetDossierProcesses {
  unique: number;
  rare: number;
  unsigned: number;
  from_office: number;
  top: DossierProcessTop[];
  rare_list: DossierProcessRare[];
}

export interface DossierNetworkDest {
  host: string;
  ip: string | null;
  country: string | null;
  bytes: number;
  conns: number;
  /** known-good | new-domain | suspicious | unknown */
  rep: string;
}

export interface DossierNetworkRareCountry {
  country: string;
  conns: number;
}

export interface AssetDossierNetwork {
  total_conns: number;
  bytes_in: number;
  bytes_out: number;
  unique_dsts: number;
  new_domains: number;
  top_dsts: DossierNetworkDest[];
  rare_countries: DossierNetworkRareCountry[];
}

export interface DossierAuthRecent {
  ts: string;
  auth_type: string;
  user: string | null;
  src: string | null;
  /** success | failure */
  result: string;
  reason: string | null;
}

export interface AssetDossierAuth {
  success: number;
  failure: number;
  interactive: number;
  network: number;
  lateral: number;
  recent: DossierAuthRecent[];
}

export interface DossierFileRecent {
  ts: string;
  path: string;
  size_bytes: number;
  action: string;
  proc: string | null;
}

export interface AssetDossierFiles {
  writes: number;
  sensitive: number;
  exec: number;
  recent: DossierFileRecent[];
}

export interface DossierDnsTop {
  domain: string;
  count: number;
  nx: number;
}

export interface AssetDossierDns {
  queries: number;
  unique: number;
  nx: number;
  rare_tlds: number;
  top: DossierDnsTop[];
}

export interface AssetDossierResponse {
  identity: AssetDossierIdentity;
  timeline: AssetDossierTimeline;
  processes: AssetDossierProcesses;
  network: AssetDossierNetwork;
  auth: AssetDossierAuth;
  files: AssetDossierFiles;
  dns: AssetDossierDns;
}

// ============================================================================
// NAN-394 Cloud overview — aggregates for the redesigned `| cloud` landing view
// (org / account-wide posture, no single-principal scope). Backed by
// POST /api/search/cloud-overview.
// ============================================================================

export interface CloudOverviewRequest {
  /** Optional provider filter ("aws", "gcp", "azure") — omit for all */
  provider?: string | null;
  /** Optional account scope (AWS account id or gcp project id) — omit for all */
  account?: string | null;
  /** Time window for all aggregates */
  time_range: TimeRange;
}

export interface CloudOverviewProviderBreakdown {
  id: string;
  label: string;
  events: number;
}

export interface CloudOverviewOpenAlerts {
  critical: number;
  high: number;
  medium: number;
}

export interface CloudOverviewHeader {
  /** Display label for the org (uses tenant name when available) */
  org: string;
  /** Org id / tenant id / customer id — shown as mono chip */
  org_id: string;
  /** Human label for the window (e.g. "last 24h") */
  window_label: string;
  accounts: number;
  principals: number;
  regions: number;
  providers: CloudOverviewProviderBreakdown[];
  events_total: number;
  events_failed: number;
  events_denied: number;
  open_alerts: CloudOverviewOpenAlerts;
  /** 0..100 — higher = worse */
  posture_score: number;
  /** Change vs prior equal-length window */
  posture_delta: number;
  /** Short natural-language summary under the posture score (e.g. "driven by acme-prod") */
  posture_reason: string | null;
}

export type CloudRiskBand = 'critical' | 'high' | 'medium' | 'low';

export interface CloudOverviewAccount {
  id: string;
  name: string;
  provider: string;
  events: number;
  risk: number;
  band: CloudRiskBand;
  delta: number;
  alerts: number;
  principals: number;
  regions: number;
  top_principal: string | null;
  top_principal_risk: number;
}

export interface CloudOverviewPrincipal {
  id: string;
  /** "iam_user" | "role" | "service_account" | other provider-specific string */
  type: string;
  account: string;
  risk: number;
  band: CloudRiskBand;
  delta: number;
  events_24h: number;
  reasons: string[];
  last_seen: string | null;
  /** 12-bucket sparkline of event counts across the window (most recent last) */
  sparkline: number[];
}

export interface CloudOverviewTimelineLane {
  id: string;
  label: string;
  /** OKLCH color hint picked by the backend per account */
  accent: string;
}

export interface CloudOverviewTimelineMarker {
  /** Bucket index the marker sits on */
  at: number;
  label: string;
  severity: CloudRiskBand;
}

export interface CloudOverviewTimeline {
  label: string;
  buckets: number;
  lanes: CloudOverviewTimelineLane[];
  /** Sparse [bucket_index, lane_id, weight] triples */
  points: [number, string, number][];
  markers: CloudOverviewTimelineMarker[];
}

export interface CloudOverviewAnomaly {
  id: string;
  /** HH:MM label */
  at: string;
  severity: CloudRiskBand;
  /** Short kind slug, e.g. "privilege-escalation" / "impossible-travel" */
  kind: string;
  title: string;
  detail: string;
  principal: string | null;
  account: string | null;
  service: string | null;
}

export type CloudServiceHealthStatus = 'ok' | 'warn' | 'bad';

export interface CloudOverviewServiceHealth {
  id: string;
  label: string;
  events: number;
  errors: number;
  /** 0..1 */
  error_rate: number;
  /** Delta in error_rate vs prior window (absolute, not relative) */
  delta: number;
  accent: string;
  status: CloudServiceHealthStatus;
  top_error: string | null;
  /** 12-bucket trend (most recent last) */
  trend: number[];
}

export interface CloudOverviewChange {
  /** HH:MM label */
  at: string;
  /** kind slug (iam-policy, security-group, s3-bucket, …) */
  kind: string;
  severity: CloudRiskBand;
  account: string;
  actor: string;
  action: string;
  target: string;
  detail: string | null;
}

export interface CloudOverviewResponse {
  header: CloudOverviewHeader;
  accounts: CloudOverviewAccount[];
  risky_principals: CloudOverviewPrincipal[];
  timeline: CloudOverviewTimeline;
  anomalies: CloudOverviewAnomaly[];
  service_health: CloudOverviewServiceHealth[];
  changes: CloudOverviewChange[];
}

// ============================================================================
// NAN-395 Cloud principal dossier — aggregates for `| cloud principal=X`.
// Backed by POST /api/search/cloud-dossier. Structurally analogous to
// asset-dossier but scoped to an IAM principal (user / role / service account).
// ============================================================================

export interface CloudDossierRequest {
  /** Required — scope to a single IAM principal id (user / role / service account) */
  principal: string;
  /** Optional account scope (AWS account id / GCP project id) */
  account?: string | null;
  /** Optional provider scope ("aws", "gcp", "azure") */
  provider?: string | null;
  /** Additional facet filters — applied to every subquery. Empty arrays (or
   * omitted) mean "no filter". Clicking a facet chip in the dossier toggles
   * entries in these arrays so all sections re-aggregate in lockstep. */
  services?: string[];
  regions?: string[];
  accounts?: string[];
  resource_types?: string[];
  change_types?: string[];
  /** Time window for all aggregates */
  time_range: TimeRange;
}

export interface CloudDossierUserAgent {
  ua: string;
  /** Rough classification: "cli" | "terraform" | "sdk" | "console" | "browser" | other */
  kind: string;
  count: number;
}

export interface CloudDossierIp {
  ip: string;
  first_seen: string | null;
  last_seen: string | null;
  event_count: number;
  geo: string | null;
  asn: string | null;
  /** "new-geo" | "impossible-travel" | null */
  anomaly: string | null;
  risk: CloudRiskBand | null;
}

export interface CloudDossierIdentity {
  /** Principal id (contractor-acme, DevOpsRole, etc.) */
  id: string;
  /** "iam_user" | "role" | "service_account" | "assumed_role" */
  principal_type: string;
  arn: string | null;
  account: string | null;
  account_name: string | null;
  first_seen: string | null;
  last_seen: string | null;
  /** The principal that created this one, when inferrable (e.g. CreateAccessKey) */
  created_by: string | null;
  key_age_days: number | null;
  /** `null` for roles (MFA doesn't apply). `true`/`false` for users. */
  mfa: boolean | null;
  mfa_policy_required: boolean;
  console: boolean;
  api_only: boolean;
  assumed_roles: string[];
  groups: string[];
  tags: string[];
  user_agents: CloudDossierUserAgent[];
  ips: CloudDossierIp[];
}

export interface CloudDossierRiskFactor {
  /** Weight contribution (points) */
  w: number;
  label: string;
  detail: string;
}

export interface CloudDossierRisk {
  score: number;
  band: CloudRiskBand;
  /** Delta vs the previous equal-length window */
  delta: number;
  factors: CloudDossierRiskFactor[];
}

export interface CloudDossierFacetItem {
  name: string;
  count: number;
  /** Optional friendly label (account name, region name) */
  label?: string | null;
  /** Flagged as anomalous for this principal (first-seen, denied-only, etc.) */
  anomaly?: boolean;
}

export interface CloudDossierFacets {
  provider: CloudDossierFacetItem[];
  service: CloudDossierFacetItem[];
  region: CloudDossierFacetItem[];
  account: CloudDossierFacetItem[];
  resource_type: CloudDossierFacetItem[];
  change_type: CloudDossierFacetItem[];
}

export interface CloudDossierAssumeHop {
  /** Timestamp of the AssumeRole call */
  at: string;
  session_name: string;
  /** Usually "sts:AssumeRole" */
  via: string;
  /** Role label (short id) */
  to_label: string;
  to_account: string | null;
  /** Summary permissions (from attached policies) */
  permissions: string[];
  /** Calls made under this role session */
  calls: number;
  /** Optional analyst-readable note (why this hop is interesting) */
  note: string | null;
  /** Whether the role carries privileged permissions */
  sensitive: boolean;
}

export interface CloudDossierKeyAction {
  at: string;
  role: string;
  action: string;
  target: string;
  severity: CloudRiskBand;
  detail: string | null;
}

export interface CloudDossierAssumeChain {
  /** The starting principal label (usually same as identity.id) */
  origin_label: string;
  origin_account: string | null;
  origin_ip: string | null;
  origin_first_at: string | null;
  origin_note: string | null;
  hops: CloudDossierAssumeHop[];
  /** Notable actions taken along the chain, ranked by severity */
  key_actions: CloudDossierKeyAction[];
}

export interface CloudDossierTimelineLane {
  id: string;
  label: string;
  accent: string;
}

export interface CloudDossierTimelineMarker {
  at: number;
  label: string;
  severity: CloudRiskBand;
}

export interface CloudDossierTimeline {
  label: string;
  buckets: number;
  lanes: CloudDossierTimelineLane[];
  /** Sparse [bucket_index, lane_id, weight] triples (weight in 1..3) */
  points: [number, string, number][];
  markers: CloudDossierTimelineMarker[];
}

export interface CloudDossierRegion {
  id: string;
  label: string | null;
  count: number;
  /** "impossible-travel" | "new-for-principal" | null */
  anomaly: string | null;
  new_for_principal: boolean;
}

export interface CloudDossierActionRow {
  name: string;
  count: number;
  errors: number;
  service: string;
  /** Principal that actually invoked this action (origin or assumed role) */
  principal: string | null;
  sensitive: boolean;
  anomaly: boolean;
}

export interface CloudDossierResource {
  arn: string;
  type: string;
  account: string;
  changes: number;
  last_at: string;
  severity: CloudRiskBand;
  /** 8-bucket activity sparkline */
  spark: number[];
  /** Actions the principal took against this resource */
  touched: string[];
}

export interface CloudDossierPosturePrincipal {
  name: string;
  mfa: boolean | null;
  privileged: boolean;
  key_age_days: number | null;
  last_call: string | null;
  privileged_calls: number;
  anomaly: boolean;
  is_role: boolean;
}

export interface CloudDossierAuthPosture {
  total_principals: number;
  with_mfa: number;
  without_mfa: number;
  privileged_without_mfa: number;
  privileged_calls_without_mfa: number;
  console_logins: number;
  console_logins_without_mfa: number;
  api_key_only_principals: number;
  oldest_key_days: number;
  principals: CloudDossierPosturePrincipal[];
}

export interface CloudDossierErrorCode {
  code: string;
  count: number;
  pct: number;
  severity: CloudRiskBand;
}

export interface CloudDossierErrorRate {
  events_total: number;
  events_allowed: number;
  events_failed: number;
  events_denied: number;
  top_errors: CloudDossierErrorCode[];
}

export interface CloudDossierStreamEvent {
  id: string;
  ts: string;
  /** "AUTH" | "READ" | "WRITE" | "PERM" */
  type: string;
  event_name: string;
  service: string;
  user: string;
  account: string;
  region: string;
  source_ip: string;
  resource: string;
  error_code: string | null;
  /** Compact key-value summary for the one-line row — small JSON object */
  summary: Record<string, unknown>;
  /** Full CloudTrail detail JSON, rendered on row expand */
  detail: Record<string, unknown>;
  interesting: boolean;
}

export interface CloudDossierResponse {
  identity: CloudDossierIdentity;
  risk: CloudDossierRisk;
  facets: CloudDossierFacets;
  assume_chain: CloudDossierAssumeChain;
  timeline: CloudDossierTimeline;
  regions: CloudDossierRegion[];
  top_actions: CloudDossierActionRow[];
  top_resources: CloudDossierResource[];
  auth_posture: CloudDossierAuthPosture;
  error_rate: CloudDossierErrorRate;
  stream: CloudDossierStreamEvent[];
  /** Echo of the window label the backend chose ("last 7d", etc.) */
  window_label: string;
}

// NAN-426 / NAN-427 — Queues + queue routing rules.
//
// Queues are thin wrappers over existing groups. Membership flows through the
// backing group (who can claim work), while the queue row carries metadata:
// kind (triage/tier1/.../specialty), SLA tier, Slack channel, routing priority,
// icon, color, description.
//
// The SignalInbox sidebar surfaces "my queues" with live unclaimed counts; the
// admin Settings page (NAN-429) handles queue CRUD + routing-rule CRUD and
// preview. Both pages import this type set.

export type QueueKind = 'triage' | 'tier1' | 'tier2' | 'tier3' | 'specialty';

export interface Queue {
  id: string;
  group_id: string;
  kind: QueueKind;
  default_sla_tier: string | null;
  slack_channel: string | null;
  routing_priority: number;
  icon: string | null;
  color: string | null;
  is_default_landing: boolean;
  description: string | null;
  created_at: string;
  updated_at: string;
}

/// Queue joined with the backing group's display name + system flag + member
/// and unclaimed-case counts. What the list / detail endpoints return.
///
/// Backend flattens `Queue` into this shape via `#[serde(flatten)]`, so the
/// wire format is a single object — not `{ queue: {...}, name, ... }`.
export interface QueueWithMembership extends Queue {
  /** Display name lifted from `groups.name`. */
  name: string;
  /** True when the backing group has `is_system=true`. Admin UI uses this to
   *  hide the "delete queue" control — removing the group would break seeded
   *  defaults. */
  is_system: boolean;
  /** Number of users on the backing group (who can claim work). */
  member_count: number;
  /** Count of cases on this queue with no individual assignee. Primary
   *  "unclaimed work" indicator the SignalInbox sidebar renders per queue. */
  unclaimed_count: number;
}

export interface NewQueue {
  group_id: string;
  kind: QueueKind;
  default_sla_tier?: string | null;
  slack_channel?: string | null;
  routing_priority?: number;
  icon?: string | null;
  color?: string | null;
  is_default_landing?: boolean;
  description?: string | null;
}

/// Update shape. `kind` and `group_id` are immutable on the backend.
export interface QueueUpdate {
  default_sla_tier?: string | null;
  slack_channel?: string | null;
  routing_priority?: number;
  icon?: string | null;
  color?: string | null;
  is_default_landing?: boolean;
  description?: string | null;
}

/// Typed view of the `conditions` JSON blob carried on a queue routing rule.
/// Backend persists it as free-form JSON (see migration 155); this shape is
/// what the admin UI reads/writes after `normalizeConditions()`.
export interface QueueRoutingConditions {
  source_types?: string[];
  severity?: string[];
  rule_ids?: string[];
  /** Prefix-match against `cases.group_by_hash` from the auto-grouper. */
  group_by_hash_prefix?: string;
}

/// A rule evaluated on case-create to pick a landing queue. Conditions is a
/// free-form JSON blob — see migration 155 for shape. The admin UI lays it out
/// as (source_types[], severity[], rule_ids[], group_by_hash[]).
export interface QueueRoutingRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  queue_id: string;
  conditions: QueueRoutingConditions;
  created_at: string;
  updated_at: string;
}

export interface NewQueueRoutingRule {
  name: string;
  enabled?: boolean;
  priority?: number;
  queue_id: string;
  conditions?: QueueRoutingConditions;
}

export interface QueueRoutingRuleUpdate {
  name?: string;
  enabled?: boolean;
  priority?: number;
  queue_id?: string;
  conditions?: QueueRoutingConditions;
}

/// Dry-run request — lets admins see which queue a synthetic case would land
/// on given current rules.
export interface QueueRoutingPreviewRequest {
  source_types?: string[];
  severity: string;
  rule_ids?: string[];
  /** Optional grouping hash from the auto-grouper. */
  group_by_hash?: string | null;
}

export interface QueueRoutingPreviewResponse {
  /** First matched rule, or null when nothing matched (→ case lands on the
   *  `is_default_landing` queue instead). */
  matched_rule: QueueRoutingRule | null;
  /** Resolved queue name — saves the UI a lookup. */
  matched_queue_name: string | null;
}

export interface GroupMemberSummary {
  id: string;
  email: string;
  name: string;
}

export interface GroupMembersResponse {
  members: GroupMemberSummary[];
  total: number;
}

// ============================================================================
// NAN-443 Playbooks — library read-only types (Phase 2).
//
// Shapes mirror `nanosiem-core/src/playbooks/models.rs`. The Rust serde layer
// passes JSON through as-is (snake_case), so the TypeScript types use
// snake_case for field names and lowercase/snake_case literal unions for enums
// (matching the `#[serde(rename_all = "...")]` attributes in models.rs).
// ============================================================================

/** Category of a playbook; maps to PlaybookCategory in Rust. */
export type PlaybookCategory =
  | 'identity'
  | 'endpoint'
  | 'cloud'
  | 'data'
  | 'network'
  | 'email';

/** Lifecycle status. `pending_review` is snake-case from Rust. */
export type PlaybookStatus =
  | 'draft'
  | 'pending_review'
  | 'live'
  | 'archived';

/** Scope — tenant-wide vs per-environment. */
export type PlaybookScope = 'tenant' | 'environment';

/** Step kind — the six slash-commands the parser recognises. */
export type PlaybookStepKind =
  | 'query'
  | 'pivot'
  | 'enrichment'
  | 'decision'
  | 'action'
  | 'review'
  | 'note';

/** Per-danger-level policy (e.g. `{"action:high": "approval"}`). */
export type DangerPolicy = Record<string, string>;

/** Adaptive metadata — which case + reasoning composed this playbook. */
export interface AdaptiveSource {
  case_id?: string | null;
  composed_at?: string | null;
  composed_by?: string | null;
  based_on?: string[];
}

/** Parsed `when:` clause (rendered for conditional steps). */
export interface PlaybookWhenClause {
  ref: string;
  op: '=' | 'in';
  values: string[];
}

/** A single step in a parsed playbook tree. */
export interface PlaybookStep {
  id: string;
  kind: PlaybookStepKind | string;
  label: string;
  params: Record<string, unknown>;
  auto_result?: unknown;
  suggested?: unknown;
  suggested_conf?: number;
  note_required_on?: string | null;
  options?: unknown[];
  decision_id?: string;
  when?: PlaybookWhenClause;
}

/** A phase (H2 heading) grouping steps. */
export interface PlaybookPhase {
  heading: string;
  body: string[];
  steps: PlaybookStep[];
}

/** Parsed step tree — stored on the playbook row as JSONB. */
export interface ParsedStepTree {
  title: string;
  intro: string[];
  phases: PlaybookPhase[];
  steps?: PlaybookStep[];
}

/** A playbook row (typeid `pb_*`). */
export interface Playbook {
  id: string;
  title: string;
  subtitle?: string | null;
  category: string; // PlaybookCategory stored as string in the DB
  doc: string;
  parsed_steps?: ParsedStepTree | null;
  match_signals: string[];
  danger_policy: DangerPolicy;
  review_cadence: string;
  scope: string; // PlaybookScope
  tags: string[];
  owner_team?: string | null;
  maintainer_user_id?: string | null;
  status: string; // PlaybookStatus
  current_version: number;
  adaptive: boolean;
  adaptive_source?: AdaptiveSource | null;
  promoted: boolean;
  source_repository_id?: string | null;
  source_playbook_path?: string | null;
  source_linked: boolean;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
  last_reviewed_at?: string | null;
  next_review_due_at?: string | null;
}

/** A single version row from the playbook history table. */
export interface PlaybookVersion {
  id: string;
  playbook_id: string;
  version: number;
  doc: string;
  metadata: unknown;
  note?: string | null;
  diff_added: number;
  diff_removed: number;
  author_id?: string | null;
  author_name?: string | null;
  promoted_from_case_id?: string | null;
  created_at: string;
}

/** A single run (attach event) of a playbook on a case. */
export interface PlaybookRun {
  id: string;
  playbook_id: string;
  playbook_version: number;
  case_id: string;
  started_at: string;
  finished_at?: string | null;
  status: string;
  operator_user_id?: string | null;
  operator_label?: string | null;
  outcome?: string | null;
  ttr_minutes?: number | null;
  /** NAN-463 — map of step_id → StepCompletionEntry. */
  step_completion?: Record<string, StepCompletionEntry> | null;
  /** NAN-462 — frozen run_context snapshot. Null for legacy / manual-attach. */
  run_context?: unknown | null;
  created_at: string;
}

/** NAN-463 — a single step's completion entry inside `step_completion`. */
export interface StepCompletionEntry {
  completed_at?: string | null;
  operator_user_id?: string | null;
  skipped?: boolean | null;
  note?: string | null;
}

/** NAN-463 — body for `PATCH /api/playbook-runs/{run_id}/steps/{step_id}`. */
export interface UpdateStepCompletionRequest {
  completed?: boolean;
  skipped?: boolean;
  note?: string;
}

/** NAN-462 — resolved run tree response. */
export interface ResolvedRunResponse {
  has_context: boolean;
  tree: ParsedStepTree;
  unresolved: string[];
}

/** NAN-473 — request body for `POST /api/playbooks/dry-resolve`.
 *  Exactly one of `alert_id` / `sample_alert` must be set. */
export interface DryResolveRequest {
  /** Raw playbook markdown (the doc-as-authored, before save). */
  doc: string;
  /** TypeID (`alert_01hz...`) or bare UUID for an existing alert. */
  alert_id?: string | null;
  /** Inline alert payload — at minimum `{ matched_events: [...] }`. */
  sample_alert?: unknown | null;
}

/** NAN-473 — response body from `POST /api/playbooks/dry-resolve`. */
export interface DryResolveResponse {
  /** The doc with every `{{...}}` token substituted. */
  resolved_doc: string;
  /** Paths whose namespace was unknown — surface as "missing context". */
  unresolved: string[];
  /** Freeform display metadata from the snapshot the server built. */
  context_summary: {
    alert_id?: string | null;
    alert_severity?: string | null;
    rule_id?: string | null;
    rule_name?: string | null;
    source_type?: string | null;
    has_top_matched_event?: boolean;
    entity_counts?: Record<string, number>;
    snapshot?: unknown;
  };
}

/** Per-role ACL row. */
export interface PlaybookPermission {
  playbook_id: string;
  role: string;
  can_view: boolean;
  can_run: boolean;
  can_edit: boolean;
  can_publish: boolean;
  member_count?: number | null;
  created_at: string;
  updated_at: string;
}

/** Approval request on a playbook version. */
export interface PlaybookApproval {
  id: string;
  playbook_id: string;
  version: number;
  requester_id?: string | null;
  approver_id?: string | null;
  status: string;
  message?: string | null;
  response?: string | null;
  requested_at: string;
  responded_at?: string | null;
}

/** Query params for GET /api/playbooks. */
export interface ListPlaybooksQuery {
  category?: PlaybookCategory;
  status?: PlaybookStatus;
  signal?: string;
  search?: string;
  /** Sort mode — backend recognises 'recent' | 'title' | 'attached'; the UI
   *  also sorts client-side by usage/skip/az. */
  sort?: string;
  limit?: number;
  offset?: number;
  adaptive?: boolean;
}

/** Response envelope for GET /api/playbooks. */
export interface PlaybookListResponse {
  playbooks: Playbook[];
  total: number;
}

/** Body for POST /api/playbooks. Mirrors CreatePlaybookRequest in Rust. */
export interface CreatePlaybookRequest {
  title: string;
  subtitle?: string;
  category: PlaybookCategory;
  doc: string;
  match_signals?: string[];
  danger_policy?: DangerPolicy;
  review_cadence?: string;
  scope?: PlaybookScope;
  tags?: string[];
  owner_team?: string;
  status?: PlaybookStatus;
  adaptive?: boolean;
  adaptive_source?: AdaptiveSource;
  source_playbook_path?: string;
  source_repository_id?: string;
  source_linked?: boolean;
}

/** Body for PATCH /api/playbooks/:id. All fields optional. */
export interface UpdatePlaybookRequest {
  title?: string;
  subtitle?: string;
  category?: PlaybookCategory;
  doc?: string;
  match_signals?: string[];
  danger_policy?: DangerPolicy;
  review_cadence?: string;
  scope?: PlaybookScope;
  tags?: string[];
  owner_team?: string;
  status?: PlaybookStatus;
  /** Change note saved onto the new version row. */
  note?: string;
}

/** Body for POST /api/playbooks/:id/fork. */
export interface ForkPlaybookRequest {
  title?: string;
  owner_team?: string;
}

// ============================================================================
// NAN-450 — FE wiring: types for Phase 4/5/6/7 endpoints.
// ============================================================================

/** A scored playbook suggestion for a given rule (NAN-445). */
export interface PlaybookSuggestion {
  playbook: Playbook;
  score: number;
  matched_signals: string[];
  matched_by_category: boolean;
}

/** Body for POST /api/playbooks/:id/runs (NAN-445). */
export interface AttachToCaseRequest {
  case_id: string;
  version?: number;
}

/** Body for PATCH /api/playbook-runs/:id (NAN-445). */
export interface FinishRunRequest {
  outcome?: string;
  step_completion?: Record<string, unknown>;
  /** NAN-475: optional closing note from the analyst. The backend persists
   *  it under `step_completion.__run__.operator_note`. */
  note?: string;
}

/** Body for POST /api/playbooks/:id/submit-for-review (NAN-447). */
export interface SubmitForReviewRequest {
  approver_id?: string;
  message?: string;
}

/** Body for POST /api/playbook-approvals/:id/{approve,reject} (NAN-447). */
export interface ApprovalResponseRequest {
  response?: string;
}

/** Body for PUT /api/playbooks/:id/permissions/:role (NAN-447). */
export interface SetPermissionRequest {
  can_view: boolean;
  can_run: boolean;
  can_edit: boolean;
  can_publish: boolean;
  member_count?: number;
}

/** Response from GET /api/playbooks/:id/analytics (NAN-448).
 *  Replaces the synthetic `pbAnalytics()` helper. */
export interface PlaybookAnalytics {
  attached: number;
  started: number;
  finished: number;
  evd: number;
  ttr_median_min: number | null;
  hours_since_last_run: number | null;
  /** Exactly 30 daily attach counts, oldest → newest. */
  spark_30d: number[];
}
