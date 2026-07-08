// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Observability API routes (NAN-1536)
 *
 * Backs the tabbed Observability console. Two families of endpoints:
 *
 *  - Service RED aggregates — computed from `nanosiem.otel_spans` on the SEARCH
 *    service (GET /api/search/services, GET /api/search/services/{service}).
 *  - SLOs — a PG-backed model with compute-from-spans, on the MAIN api service
 *    (GET/POST/PUT/DELETE /api/observability/slos).
 *
 * Traces / Metrics reuse the existing NAN-1534 search endpoints (listTraces,
 * getTrace, listMetricNames, queryMetrics) — this module re-exposes them on the
 * `api.observability` facade so surfaces consume a single client.
 *
 * NOTE (foundation slice): the service + SLO endpoints are wired to the PINNED
 * backend contracts; backend agents implement the routes. Types here are the
 * source of truth the surface agents build against.
 */

import type {
  TimeRange,
  ListTracesRequest,
  ListTracesResponse,
  TraceResponse,
  MetricsQueryRequest,
  MetricsQueryResponse,
  MetricNamesResponse,
  MetricTimeseriesV2Request,
  MetricTimeseriesV2Response,
  MetricTagsResponse,
  MetricMonitor,
  MetricMonitorRequest,
  MetricMonitorListResponse,
} from './types';

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

/** A single time-bucketed scalar point. `t` is RFC3339, `v` the bucket value. */
export interface SeriesPoint {
  t: string;
  v: number;
}

/** A latency time-bucket carrying the three RED percentiles (milliseconds). */
export interface LatencyPoint {
  t: string;
  p50: number;
  p95: number;
  p99: number;
}

/** Service health, derived server-side from error_rate + p95 thresholds. */
export type ServiceHealth = 'good' | 'warn' | 'bad';

// ---------------------------------------------------------------------------
// GET /api/search/services
// ---------------------------------------------------------------------------

/** One row in the Services overview (RED aggregate per service_name). */
export interface ServiceSummary {
  service: string;
  request_count: number;
  /** Requests per second over the window. */
  rate_per_sec: number;
  /** Error fraction (0..1). */
  error_rate: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  health: ServiceHealth;
  /** Per-bucket request-count sparkline. */
  sparkline: SeriesPoint[];
}

export interface ServicesResponse {
  services: ServiceSummary[];
  /** Post-filter count before the page slice (NAN-1543). Older backends omit it. */
  total?: number;
  /** Whether more rows exist beyond the returned page (NAN-1543). */
  has_more?: boolean;
}

/** Sort key for the Services overview (NAN-1543). Default `rate`. */
export type ServicesSort = 'rate' | 'p95' | 'name' | 'error_rate';

/** Optional Services-overview filters + paging (NAN-1543). All default-compatible. */
export interface ServicesQuery {
  /** Case-insensitive service-name substring. */
  q?: string;
  /** Post-aggregation health filter. */
  health?: ServiceHealth;
  sort?: ServicesSort;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// GET /api/search/services/{service}
// ---------------------------------------------------------------------------

/** RED dashboards for a single service (bucketed timeseries). */
export interface ServiceRed {
  rate: SeriesPoint[];
  errors: SeriesPoint[];
  latency: LatencyPoint[];
}

/** One endpoint (span_name) breakdown row in the service detail. */
export interface ServiceEndpoint {
  span_name: string;
  request_count: number;
  error_rate: number;
  p95_ms: number;
}

/** A sampled recent/errored trace for the exemplars strip. */
export interface ServiceExemplar {
  trace_id: string;
  duration_ms: number;
  error: boolean;
  start_time: string;
  span_name: string;
}

export interface ServiceDetailResponse {
  service: string;
  red: ServiceRed;
  endpoints: ServiceEndpoint[];
  exemplars: ServiceExemplar[];
}

// ---------------------------------------------------------------------------
// SLOs — PG-backed model + compute-from-spans
// ---------------------------------------------------------------------------

export type SloKind = 'availability' | 'latency';
export type SloStatus = 'ok' | 'at_risk' | 'breaching' | 'no_data';

/** A service-level objective with its currently-computed budget figures. */
export interface Slo {
  /** typeid (e.g. `slo_<base32>`). */
  id: string;
  name: string;
  service: string;
  sli_kind: SloKind;
  /** Objective target, 0..1 (e.g. 0.999). */
  target: number;
  /** Rolling compliance/budget window in days. */
  window_days: number;
  /** Required for `latency` SLIs: the threshold a request must beat. */
  latency_threshold_ms?: number;
  /** Current SLI value over the window, 0..1. */
  current: number;
  /** Error budget remaining, as a percentage (can be negative when breaching). */
  budget_remaining_pct: number;
  /** Burn rate (multiples of the sustainable spend rate). */
  burn_rate: number;
  status: SloStatus;
}

export interface SloListResponse {
  slos: Slo[];
}

/** Create/update payload (the computed fields are server-derived, never sent). */
export interface SloInput {
  name: string;
  service: string;
  sli_kind: SloKind;
  /** 0..1. */
  target: number;
  window_days: number;
  /** Required when `sli_kind === 'latency'`. */
  latency_threshold_ms?: number;
}

// ---------------------------------------------------------------------------
// Infra (NAN-1537) — host inventory from otel_metrics
// ---------------------------------------------------------------------------

/** Host health, derived server-side from CPU/mem thresholds. */
export type HostStatus = 'good' | 'warn' | 'bad';

/** One host row in the Infrastructure waffle (latest per-metric snapshot). */
export interface InfraHost {
  host: string;
  group: string | null;
  /** CPU utilization percent (0..100), or null when unreported. */
  cpu_pct: number | null;
  /** Memory utilization percent (0..100), or null when unreported. */
  mem_pct: number | null;
  /** 1-minute load average, or null when unreported. */
  load: number | null;
  /** Network throughput in bytes/sec, or null when unreported. */
  net_bytes_per_sec: number | null;
  status: HostStatus;
}

export interface InfraHostsResponse {
  hosts: InfraHost[];
  /** Post-filter count before the page slice (NAN-1543). Older backends omit it. */
  total?: number;
  /** Whether more rows exist beyond the returned page (NAN-1543). */
  has_more?: boolean;
}

/** Optional Infra-hosts filters + paging (NAN-1543). All default-compatible. */
export interface InfraHostsQuery {
  /** Case-insensitive host-name substring. */
  q?: string;
  /** Exact `host.group` match. */
  group?: string;
  /** Exact `deployment.environment` match. */
  env?: string;
  /** Post-aggregation status filter. */
  status?: HostStatus;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// RUM (NAN-1538) — web vitals + page views/errors
// ---------------------------------------------------------------------------

/** Core Web Vitals at p75 over the window (nulls when unreported). */
export interface RumWebVitals {
  lcp_ms: number | null;
  inp_ms: number | null;
  cls: number | null;
}

/** One row in the RUM top-pages breakdown. */
export interface RumTopPage {
  page: string;
  views: number;
  lcp_ms: number | null;
}

/** A recent client-side error captured by RUM. */
export interface RumRecentError {
  message: string;
  page: string;
  /** RFC3339 timestamp. */
  ts: string;
  // NAN-1553: promoted entity overlay off the error span, for the enterprise
  // RUM→investigation pivot. Empty string when the span carried no such attr.
  user?: string;
  src_ip?: string;
  session?: string;
}

export interface RumResponse {
  web_vitals: RumWebVitals;
  page_views: number;
  page_views_series: SeriesPoint[];
  js_errors: number;
  top_pages: RumTopPage[];
  recent_errors: RumRecentError[];
}

/** Optional RUM filters (NAN-1543). All default-compatible — narrow the payload. */
export interface RumQuery {
  /** Case-insensitive URL/route substring. */
  page?: string;
  /** Exact `browser.name` match. */
  browser?: string;
  /** Exact `deployment.environment` match. */
  env?: string;
}

// ---------------------------------------------------------------------------
// Convergence cross-link (NAN-1542) — security detections on a service's hosts
// ---------------------------------------------------------------------------

/** One security detection touching a host/IP that the service runs on. */
export interface ServiceSecuritySignal {
  /** RFC3339 timestamp of the detection. */
  ts: string;
  rule_name: string;
  /** The matched entity, when it resolved to a hostname (else null). */
  src_host: string | null;
  /** The matched entity, when it parsed as an IP (else null). */
  src_ip: string | null;
  severity: string | null;
}

export interface ServiceSecuritySignalsResponse {
  /** Distinct service hosts/IPs the lookup was scoped to. */
  host_count: number;
  /** Detections in the returned sample (bounded by `limit`, == `signals.length`). */
  signal_count: number;
  /** True total matched over the window (unbounded); may exceed `signal_count`
   * when the sample is `limit`-capped. Drives "+N more in range" (O54). */
  signal_total: number;
  /** Bounded recent sample, newest-first. */
  signals: ServiceSecuritySignal[];
}

/** Window/limit options for the convergence cross-link lookup. */
export interface ServiceSecuritySignalsQuery {
  /** RFC3339 start; defaults server-side from `window_hours`. */
  start?: string;
  /** RFC3339 end; defaults server-side to now. */
  end?: string;
  /** Lookback window in hours (1..720); ignored when start+end given. */
  window_hours?: number;
  /** Max signals to sample (1..1000). */
  limit?: number;
}

// ---------------------------------------------------------------------------
// Synthetics (NAN-1538) — defs in PG, results in ClickHouse
// ---------------------------------------------------------------------------

export type SyntheticCheckType = 'http';

/** One point in a check's recent run history. */
export interface SyntheticResult {
  success: boolean;
  latency_ms: number;
  /** RFC3339 timestamp. */
  ts: string;
}

/** A synthetic check definition plus its computed run summary. */
export interface SyntheticCheck {
  /** typeid (e.g. `synth_<base32>`). */
  id: string;
  name: string;
  check_type: SyntheticCheckType;
  target_url: string;
  interval_secs: number;
  expected_status: number;
  timeout_secs: number;
  enabled: boolean;
  /** Whether the check has any recorded runs in the summary window. When
   * false, uptime/latency are null and the check renders as neutral "no data"
   * rather than a 0% "down" (O33). */
  has_runs: boolean;
  /** Uptime over the summary window, as a percentage (0..100). Null when the
   * check has no recorded runs (`has_runs === false`). */
  uptime_pct: number | null;
  /** Median latency over the summary window (ms). */
  p50_latency_ms: number | null;
  /** Last ~90 runs, oldest→newest, for the uptime bar. */
  history: SyntheticResult[];
}

export interface SyntheticChecksResponse {
  checks: SyntheticCheck[];
}

/** Create payload for a synthetic check. */
export interface SyntheticCheckInput {
  name: string;
  target_url: string;
  interval_secs: number;
  /** Defaults to 200 server-side when omitted. */
  expected_status?: number;
  /** Defaults to 10 server-side when omitted. */
  timeout_secs?: number;
}

/** Update payload — all fields optional (PATCH-style PUT). */
export interface SyntheticCheckUpdate {
  name?: string;
  target_url?: string;
  interval_secs?: number;
  expected_status?: number;
  timeout_secs?: number;
  enabled?: boolean;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class ObservabilityApi {
  constructor(
    private request: <T>(
      endpoint: string,
      options?: RequestInit,
      cacheOpts?: import('./index').CacheRequestOpts
    ) => Promise<T>,
    // The traces/metrics passthroughs delegate to the existing SearchApi so we
    // don't duplicate URL-building (and the SSE/token plumbing it owns).
    private listTracesImpl: (
      request: ListTracesRequest,
      cacheOpts?: import('./index').CacheRequestOpts
    ) => Promise<ListTracesResponse>,
    private listMetricNamesImpl: (service?: string) => Promise<MetricNamesResponse>,
    private queryMetricsImpl: (request: MetricsQueryRequest) => Promise<MetricsQueryResponse>,
    // NAN-1540: multi-series metrics (agg / group_by / filters) + tag discovery,
    // delegated to SearchApi so the obs facade stays the single client surface.
    private queryMetricsV2Impl: (
      request: MetricTimeseriesV2Request,
      cacheOpts?: import('./index').CacheRequestOpts
    ) => Promise<MetricTimeseriesV2Response>,
    private listMetricTagsImpl: (
      metricName: string,
      key?: string
    ) => Promise<MetricTagsResponse>
  ) {}

  // --- Services (RED) — search service ---

  /**
   * RED overview across all services over the window.
   *
   * `query` (NAN-1543) carries optional name-substring / health / sort / paging.
   * Omitted entirely → backend default behavior (unfiltered, default sort).
   */
  async listServices(
    timeRange: TimeRange,
    query?: ServicesQuery,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<ServicesResponse> {
    const params = new URLSearchParams({ start: timeRange.start, end: timeRange.end });
    if (query?.q) params.set('q', query.q);
    if (query?.health) params.set('health', query.health);
    if (query?.sort) params.set('sort', query.sort);
    if (query?.limit != null) params.set('limit', String(query.limit));
    if (query?.offset != null) params.set('offset', String(query.offset));
    return this.request(`/api/search/services?${params.toString()}`, undefined, cacheOpts);
  }

  /** RED dashboards + endpoint breakdown + exemplars for one service. */
  async getServiceDetail(
    service: string,
    timeRange: TimeRange,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<ServiceDetailResponse> {
    const params = new URLSearchParams({ start: timeRange.start, end: timeRange.end });
    return this.request(
      `/api/search/services/${encodeURIComponent(service)}?${params.toString()}`,
      undefined,
      cacheOpts
    );
  }

  // --- SLOs — main api service ---

  async listSlos(): Promise<SloListResponse> {
    return this.request('/api/observability/slos');
  }

  async createSlo(input: SloInput): Promise<Slo> {
    return this.request('/api/observability/slos', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async updateSlo(id: string, input: SloInput): Promise<Slo> {
    return this.request(`/api/observability/slos/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  }

  async deleteSlo(id: string): Promise<void> {
    return this.request(`/api/observability/slos/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // --- Infrastructure (NAN-1537) — search service ---

  /**
   * Latest-snapshot host inventory (CPU/mem/load/net) over the window.
   *
   * `query` (NAN-1543) carries optional host-substring / group / env / status /
   * paging. Omitted → backend default behavior (bounded top set, unfiltered).
   */
  async getInfraHosts(
    timeRange: TimeRange,
    query?: InfraHostsQuery,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<InfraHostsResponse> {
    const params = new URLSearchParams({ start: timeRange.start, end: timeRange.end });
    if (query?.q) params.set('q', query.q);
    if (query?.group) params.set('group', query.group);
    if (query?.env) params.set('env', query.env);
    if (query?.status) params.set('status', query.status);
    if (query?.limit != null) params.set('limit', String(query.limit));
    if (query?.offset != null) params.set('offset', String(query.offset));
    return this.request(`/api/search/infra/hosts?${params.toString()}`, undefined, cacheOpts);
  }

  // --- RUM (NAN-1538) — search service ---

  /**
   * Web vitals (p75) + page views/errors + top pages over the window.
   *
   * `query` (NAN-1543) carries optional page/route / browser / env filters that
   * narrow the payload. Omitted → backend default behavior (unfiltered).
   */
  async getRum(
    timeRange: TimeRange,
    query?: RumQuery,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<RumResponse> {
    const params = new URLSearchParams({ start: timeRange.start, end: timeRange.end });
    if (query?.page) params.set('page', query.page);
    if (query?.browser) params.set('browser', query.browser);
    if (query?.env) params.set('env', query.env);
    return this.request(`/api/search/rum?${params.toString()}`, undefined, cacheOpts);
  }

  // --- Convergence cross-link (NAN-1542) — main api service ---

  /**
   * Security detections touching the hosts/IPs a service runs on, over the
   * window. Backs the "Related security signals" strip on Service detail.
   * Reads `search:view`. Often returns zero — render an empty state cleanly.
   */
  async getServiceSecuritySignals(
    service: string,
    query?: ServiceSecuritySignalsQuery
  ): Promise<ServiceSecuritySignalsResponse> {
    const params = new URLSearchParams();
    if (query?.start) params.set('start', query.start);
    if (query?.end) params.set('end', query.end);
    if (query?.window_hours != null) params.set('window_hours', String(query.window_hours));
    if (query?.limit != null) params.set('limit', String(query.limit));
    const qs = params.toString();
    return this.request(
      `/api/observability/services/${encodeURIComponent(service)}/security-signals${qs ? `?${qs}` : ''}`
    );
  }

  // --- Synthetics (NAN-1538) — main api service ---

  /** List synthetic checks with their computed uptime/latency summary. */
  async listSynthetics(): Promise<SyntheticChecksResponse> {
    return this.request('/api/observability/synthetics');
  }

  async createSynthetic(input: SyntheticCheckInput): Promise<SyntheticCheck> {
    return this.request('/api/observability/synthetics', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async updateSynthetic(id: string, input: SyntheticCheckUpdate): Promise<SyntheticCheck> {
    return this.request(`/api/observability/synthetics/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  }

  async deleteSynthetic(id: string): Promise<void> {
    return this.request(`/api/observability/synthetics/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // --- Traces / Metrics passthroughs (reuse existing NAN-1534 endpoints) ---

  listTraces(
    request: ListTracesRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<ListTracesResponse> {
    return this.listTracesImpl(request, cacheOpts);
  }

  /**
   * Fetch a distributed trace by id (NAN-1721 / O36).
   *
   * Threads `cacheOpts` so the trace surfaces (Traces-tab waterfall, TracePage,
   * the `| trace` command page) can render the "cached · refresh" badge and
   * force a live refetch — the GET is Dragonfly-cached (`x-nano-cache*`) like
   * every other obs read. Goes through `this.request` directly (rather than the
   * `getTraceImpl` passthrough, which can't forward cacheOpts) so the cache
   * headers reach the `onMeta` callback; the URL/behavior is identical to the
   * SearchApi passthrough.
   */
  getTrace(
    traceId: string,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<TraceResponse> {
    return this.request(
      `/api/search/trace/${encodeURIComponent(traceId)}`,
      undefined,
      cacheOpts
    );
  }

  listMetricNames(service?: string): Promise<MetricNamesResponse> {
    return this.listMetricNamesImpl(service);
  }

  queryMetrics(request: MetricsQueryRequest): Promise<MetricsQueryResponse> {
    return this.queryMetricsImpl(request);
  }

  /** Multi-series metrics query (agg / group_by / filters) — NAN-1540. */
  queryMetricsV2(
    request: MetricTimeseriesV2Request,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<MetricTimeseriesV2Response> {
    return this.queryMetricsV2Impl(request, cacheOpts);
  }

  /** Distinct tag keys (no `key`) or values for one key — NAN-1540. */
  listMetricTags(metricName: string, key?: string): Promise<MetricTagsResponse> {
    return this.listMetricTagsImpl(metricName, key);
  }

  // --- Metric monitors — main api service (NAN-1540) ---

  /** All metric-monitor definitions (read = `search:view`). */
  async listMetricMonitors(): Promise<MetricMonitorListResponse> {
    return this.request('/api/observability/metric-monitors');
  }

  /** Create a metric monitor (mutations = `settings:system`). */
  async createMetricMonitor(input: MetricMonitorRequest): Promise<MetricMonitor> {
    return this.request('/api/observability/metric-monitors', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async updateMetricMonitor(id: string, input: MetricMonitorRequest): Promise<MetricMonitor> {
    return this.request(`/api/observability/metric-monitors/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  }

  async deleteMetricMonitor(id: string): Promise<void> {
    return this.request(`/api/observability/metric-monitors/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }
}
