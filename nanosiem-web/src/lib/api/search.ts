// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Search API routes
 * Handles search operations, saved searches, query explanations, and asset artifacts
 */

import { abortableDelay } from '../abortable-delay';
import { authenticatedFetch } from '../authenticated-fetch';
import { SessionExpiredError } from '../request-credentials';

import type {
  SearchRequest,
  SearchResponse,
  SearchJobResultPage,
  RawSqlRequest,
  TimeRange,
  SavedSearch,
  SavedSearchWithContext,
  CreateSavedSearchRequest,
  UpdateSavedSearchRequest,
  ShareSavedSearchRequest,
  CreateSharedSearchRequest,
  CreateSharedSearchResponse,
  SharedSearchResponse,
  StoreQueryExplanationRequest,
  QueryExplanationResponse,
  FieldStatsRequest,
  FieldStatsResponse,
  FieldValuesRequest,
  FieldValuesResponse,
  AssetEventsRequest,
  AssetEventsResponse,
  AssetTrueTimeRangeRequest,
  AssetTrueTimeRangeResponse,
  AssetArtifactsRequest,
  AssetArtifactsResponse,
  AssetDossierRequest,
  AssetDossierResponse,
  CloudOverviewRequest,
  CloudOverviewResponse,
  CloudDossierRequest,
  CloudDossierResponse,
  CloudEventsRequest,
  CloudEventsResponse,
  CloudUserTimelineRequest,
  CloudUserTimelineResponse,
  CloudEntityPivotRequest,
  CloudEntityPivotResponse,
  AsyncSearchResponse,
  SearchJobStatus,
  SearchStreamCallbacks,
  TraceResponse,
  MetricsQueryRequest,
  MetricsQueryResponse,
  MetricTimeseriesV2Request,
  MetricTimeseriesV2Response,
  MetricTagsResponse,
  ListTracesRequest,
  ListTracesResponse,
  MetricNamesResponse,
  RetroRequest,
  SearchHistogramRequest,
  SearchHistogramResponse,
} from './types';
import { browserTenantRuntime } from '@/lib/tenant-runtime';

import { retrySearchAuthority, type AuthorityRetryOptions } from './search-authority-retry';

/**
 * NAN-3229: tells `POST /api/search` whether this caller polls an
 * `AsyncSearchResponse`. NAN-3474: the server moves a search still running at
 * its interactive deadline to a job for every caller that does not send `0`;
 * `searchInteractive` follows the job, the atomic `search` (rows only) opts
 * out and keeps the synchronous answer.
 */
export const ACCEPT_ASYNC_HEADER = 'x-nano-accept-async';

export class SearchApi {
  constructor(
    private request: <T>(
      endpoint: string,
      options?: RequestInit,
      cacheOpts?: import('./index').CacheRequestOpts
    ) => Promise<T>,
    _getAccessToken?: () => string | null,
    private searchBaseUrl?: string
  ) {}

  // Core search endpoints
  async search(request: SearchRequest): Promise<SearchResponse> {
    return this.request('/api/search', {
      // Callers render `results` only; never hand them a job id at the deadline.
      headers: { [ACCEPT_ASYNC_HEADER]: '0' },
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * Interactive admission may escalate to an existing durable job: when the
   * query is resource-bound, or (NAN-3229, `x-nano-accept-async`) when it is
   * still running at the server's interactive deadline (45 s), so a slow
   * search never sits on a request past the 60 s edge.
   */
  async searchInteractive(
    request: Omit<SearchRequest, 'async_mode'>,
    retry?: AuthorityRetryOptions,
    // NAN-3809: a settled re-served job answers `x-nano-cache: hit` + age.
    onCacheMeta?: (meta: import('./index').CacheMeta) => void,
  ): Promise<SearchResponse | AsyncSearchResponse> {
    return retrySearchAuthority(() => this.request<SearchResponse | AsyncSearchResponse>('/api/search', {
      headers: { 'x-nano-progressive-views': '1', [ACCEPT_ASYNC_HEADER]: '1' },
      method: 'POST',
      body: JSON.stringify(request),
    }, onCacheMeta ? { onMeta: onCacheMeta } : undefined), retry);
  }

  /**
   * NAN-3093: the search's timeline alone. The Search page asks for it beside
   * a rows request sent with `skip_histogram`, so rows paint without waiting
   * for the histogram companion.
   */
  async searchHistogram(request: SearchHistogramRequest, signal?: AbortSignal): Promise<SearchHistogramResponse> {
    return this.request('/api/search/histogram', {
      method: 'POST',
      body: JSON.stringify(request),
      signal,
    });
  }

  async searchSql(request: RawSqlRequest): Promise<SearchResponse> {
    return this.request('/api/search/sql', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async explainQuery(
    query: string,
    timeRange: TimeRange,
    tableView = true,
    dataset?: import('./types').SearchDataset,
  ): Promise<{ sql: string }> {
    return this.request('/api/search/explain', {
      method: 'POST',
      // NAN-1825: send a non-logs dataset so the inspected SQL matches the
      // executed query (risk / spans / metrics). Logs stays byte-identical
      // (dataset omitted), matching the search execution path's convention.
      body: JSON.stringify({
        query,
        time_range: timeRange,
        table_view: tableView,
        ...(dataset && dataset !== 'logs' ? { dataset } : {}),
      }),
    });
  }

  // Fetch a single log by ID (for table_view mode row expansion)
  // NAN-1032: pass sourceType when known so ClickHouse can use the
  // (source_type, timestamp, ...) PK index for a tight range read — without it,
  // S3-backed historical lookups scan every source_type's marks in the time window.
  async fetchLog(id: string, timeRange?: TimeRange, sourceType?: string, signal?: AbortSignal): Promise<{ event: Record<string, unknown> | null }> {
    return this.request('/api/search/log', {
      signal,
      method: 'POST',
      body: JSON.stringify({ id, time_range: timeRange, source_type: sourceType }),
    });
  }

  // Async field stats (loaded separately from main search for better UX)
  // DEPRECATED: Use getFieldValues for on-demand per-field stats instead
  async getFieldStats(
    request: FieldStatsRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<FieldStatsResponse> {
    return this.request('/api/search/field-stats', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // On-demand field values (Kibana-style, fetched when user expands a field)
  async getSearchFieldValues(
    request: FieldValuesRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<FieldValuesResponse> {
    return this.request('/api/search/field-values', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Paginated asset events (for infinite scroll and server-side filtering)
  async getAssetEvents(
    request: AssetEventsRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<AssetEventsResponse> {
    return this.request('/api/search/asset-events', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Lazy-loaded true time range (first/last seen) for asset view
  async getAssetTrueTimeRange(
    request: AssetTrueTimeRangeRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<AssetTrueTimeRangeResponse> {
    return this.request('/api/search/asset-true-time-range', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Paginated cloud events (for infinite scroll and server-side filtering)
  async getCloudEvents(
    request: CloudEventsRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<CloudEventsResponse> {
    return this.request('/api/search/cloud-events', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Cloud user timeline (for user investigation sheet)
  async getCloudUserTimeline(
    request: CloudUserTimelineRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<CloudUserTimelineResponse> {
    return this.request('/api/search/cloud-user-timeline', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Cloud entity pivot (for entity correlation sheet)
  async getCloudEntityPivot(
    request: CloudEntityPivotRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<CloudEntityPivotResponse> {
    return this.request('/api/search/cloud-entity-pivot', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Lazy-loaded artifact summaries (hashes/domains) for asset prevalence scatter
  async getAssetArtifacts(
    request: AssetArtifactsRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<AssetArtifactsResponse> {
    return this.request('/api/search/asset-artifacts', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Asset dossier aggregates for the redesigned Asset view (NAN-393)
  async getAssetDossier(
    request: AssetDossierRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<AssetDossierResponse> {
    return this.request('/api/search/asset-dossier', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Cloud overview aggregates for the redesigned `| cloud` landing view (NAN-394)
  async getCloudOverview(
    request: CloudOverviewRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<CloudOverviewResponse> {
    return this.request('/api/search/cloud-overview', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // Cloud principal dossier aggregates for `| cloud principal=X` (NAN-395)
  async getCloudDossier(
    request: CloudDossierRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<CloudDossierResponse> {
    return this.request('/api/search/cloud-dossier', {
      method: 'POST',
      body: JSON.stringify(request),
    }, cacheOpts);
  }

  // OpenTelemetry observability (NAN-1528)

  /**
   * Fetch a distributed trace by id. The backend resolves the trace's
   * [min,max] window from otel_spans_trace_id_ts, then returns its spans
   * ordered by start_time (ready for waterfall nesting on parent_span_id).
   */
  async getTrace(traceId: string): Promise<TraceResponse> {
    // GET — the backend resolves the [min,max] window from
    // otel_spans_trace_id_ts internally, so no request body is needed.
    return this.request(`/api/search/trace/${encodeURIComponent(traceId)}`);
  }

  /**
   * Query a metric timeseries (one series of aggregated points over time).
   */
  async queryMetrics(request: MetricsQueryRequest): Promise<MetricsQueryResponse> {
    return this.request('/api/search/metrics/timeseries', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * Query a metric timeseries with aggregation / group_by / filters (NAN-1540).
   * Hits the same POST /api/search/metrics/timeseries endpoint but returns the
   * multi-series shape (`series[]`). Back-compatible: omit `agg`/`group_by` for a
   * single avg series.
   */
  async queryMetricsV2(
    request: MetricTimeseriesV2Request,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<MetricTimeseriesV2Response> {
    return this.request(
      '/api/search/metrics/timeseries',
      {
        method: 'POST',
        body: JSON.stringify(request),
      },
      cacheOpts
    );
  }

  /**
   * List distinct tag keys for a metric, or distinct values for one key
   * (NAN-1540). GET /api/search/metrics/tags?metric_name=&key=.
   */
  async listMetricTags(metricName: string, key?: string): Promise<MetricTagsResponse> {
    const params = new URLSearchParams({ metric_name: metricName });
    if (key) params.set('key', key);
    return this.request(`/api/search/metrics/tags?${params.toString()}`);
  }

  /**
   * List recent distributed traces (NAN-1534). One row per trace_id aggregated
   * from otel_spans (root service, span/error counts, root duration, start time),
   * ordered most-recent-first. The time range + optional filters are sent as
   * query params. Param names (start/end/service/errors_only/min_duration_ns)
   * match the backend `ListTracesParams` (reconciled in the verify stage).
   */
  async listTraces(
    request: ListTracesRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<ListTracesResponse> {
    const params = new URLSearchParams();
    params.set('start', request.time_range.start);
    params.set('end', request.time_range.end);
    if (request.service) params.set('service', request.service);
    if (request.errors_only) params.set('errors_only', 'true');
    if (request.min_duration_ns != null) {
      params.set('min_duration_ns', String(request.min_duration_ns));
    }
    if (request.limit != null) params.set('limit', String(request.limit));
    // Keyset pagination cursor (NAN-1539): the previous page's last start_time.
    if (request.before) params.set('before', request.before);
    return this.request(`/api/search/traces?${params.toString()}`, undefined, cacheOpts);
  }

  /**
   * List distinct metric names for the Metrics explorer dropdown (NAN-1534),
   * optionally scoped to a single service.
   */
  async listMetricNames(service?: string): Promise<MetricNamesResponse> {
    const params = new URLSearchParams();
    if (service) params.set('service', service);
    const qs = params.toString();
    return this.request(`/api/search/metrics/names${qs ? `?${qs}` : ''}`);
  }

  // IOC retro-hunt (NAN-1580)

  /**
   * Run an IOC retro-hunt against the value-sorted observables projection.
   * The initial `/api/search` response is only a marker carrying the parsed
   * retro request (`_retro_*` fields); this endpoint returns the actual
   * summary / campaign-list / pivot-rollup payload shaped by `axis`.
   * Campaign + pivot tables paginate via `offset`/`limit` (+ `has_more`);
   * the summary is single-shot.
   */
  async getRetro(
    request: RetroRequest,
    cacheOpts?: import('./index').CacheRequestOpts
  ): Promise<import('./types').RetroResultResponse> {
    return this.request(
      '/api/search/retro',
      {
        method: 'POST',
        body: JSON.stringify(request),
      },
      cacheOpts
    );
  }

  // Saved searches
  async listSavedSearches(): Promise<SavedSearchWithContext[]> {
    return this.request('/api/search/saved');
  }

  async listSharedSearches(): Promise<SavedSearchWithContext[]> {
    return this.request('/api/search/saved/shared');
  }

  async listMySavedSearches(): Promise<SavedSearchWithContext[]> {
    return this.request('/api/search/saved/mine');
  }

  async createSavedSearch(request: CreateSavedSearchRequest): Promise<SavedSearch> {
    return this.request('/api/search/saved', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getSavedSearch(id: string): Promise<SavedSearchWithContext> {
    return this.request(`/api/search/saved/${id}`);
  }

  async updateSavedSearch(id: string, request: UpdateSavedSearchRequest): Promise<SavedSearch> {
    return this.request(`/api/search/saved/${id}`, {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async deleteSavedSearch(id: string): Promise<void> {
    return this.request(`/api/search/saved/${id}`, {
      method: 'DELETE',
    });
  }

  async shareSavedSearch(id: string, request: ShareSavedSearchRequest): Promise<SavedSearchWithContext> {
    return this.request(`/api/search/saved/${id}/share`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Shared searches (short URLs)
  async createSharedSearch(request: CreateSharedSearchRequest): Promise<CreateSharedSearchResponse> {
    return this.request('/api/search/share', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getSharedSearch(id: string): Promise<SharedSearchResponse> {
    return this.request(`/api/search/shared/${id}`);
  }

  // Query explanations (AI reasoning cache)
  async storeQueryExplanation(request: StoreQueryExplanationRequest): Promise<QueryExplanationResponse> {
    return this.request('/api/search/explanation', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getQueryExplanation(query: string): Promise<QueryExplanationResponse> {
    const params = new URLSearchParams({ q: query });
    return this.request(`/api/search/explanation?${params.toString()}`);
  }

  // Query cancellation (server-side)
  async cancelSearch(requestId: string): Promise<{ cancelled: boolean }> {
    return this.request(`/api/search/${requestId}`, {
      method: 'DELETE',
    });
  }

  // Async search methods

  /**
   * Start an async search and return immediately with a job ID.
   * Use getSearchJob() to poll for results.
   */
  async searchAsync(request: Omit<SearchRequest, 'async_mode'>, retry?: AuthorityRetryOptions, signal?: AbortSignal): Promise<AsyncSearchResponse> {
    return retrySearchAuthority(() => this.request<AsyncSearchResponse>('/api/search', {
      signal,
      method: 'POST',
      body: JSON.stringify({ ...request, async_mode: true }),
    }), signal ? { ...retry, isCancelled: () => signal.aborted || !!retry?.isCancelled?.() } : retry, ms => abortableDelay(ms, signal));
  }

  async getTreePage(request: import('./types').TreePageRequest, signal?: AbortSignal): Promise<import('./types').TreePageResponse> {
    return retrySearchAuthority(() => this.request<import('./types').TreePageResponse>('/api/search/tree-page', { method: 'POST', body: JSON.stringify(request), signal }), signal ? { isCancelled: () => signal.aborted } : undefined, ms => abortableDelay(ms, signal));
  }

  /**
   * Get the status of an async search job.
   * Returns progress while running, results when completed.
   */
  async getSearchJob(jobId: string, retry?: AuthorityRetryOptions, signal?: AbortSignal): Promise<SearchJobStatus> {
    return retrySearchAuthority(() => this.request<SearchJobStatus>(`/api/search/jobs/${jobId}`, { signal }), signal ? { ...retry, isCancelled: () => signal.aborted || !!retry?.isCancelled?.() } : retry, ms => abortableDelay(ms, signal));
  }

  async getSearchJobResultPage(jobId: string, page: number, signal?: AbortSignal): Promise<SearchJobResultPage> {
    return this.request(
      `/api/search/jobs/${encodeURIComponent(jobId)}/results/${page}`, { signal }
    );
  }

  /**
   * Cancel a running async search job.
   */
  async cancelSearchJob(jobId: string): Promise<{ cancelled: boolean }> {
    return this.request(`/api/search/jobs/${jobId}`, {
      method: 'DELETE',
    });
  }

  /**
   * List the current user's active and recent search jobs.
   */
  async listSearchJobs(): Promise<import('./types').SearchJobSummary[]> {
    return this.request('/api/search/jobs');
  }

  // Admin search job endpoints

  /**
   * List all search jobs across all users (admin only).
   */
  async listAdminSearchJobs(): Promise<import('./types').AdminSearchJobsResponse> {
    return this.request('/api/search/admin/jobs');
  }

  /**
   * Get admission control statistics (admin only).
   */
  async getAdminStats(): Promise<import('./types').AdmissionStats> {
    return this.request('/api/search/admin/stats');
  }

  /**
   * Cancel any user's search job (admin only).
   */
  async adminCancelSearchJob(jobId: string): Promise<{ cancelled: boolean }> {
    return this.request(`/api/search/admin/jobs/${jobId}`, {
      method: 'DELETE',
    });
  }

  /**
   * Execute a streaming search via Server-Sent Events.
   *
   * Returns an AbortController that can be used to cancel the search.
   * Rows arrive incrementally for non-aggregate queries; aggregate queries
   * stream progress then deliver results atomically when done.
   */
  searchStreamSSE(
    request: Omit<SearchRequest, 'async_mode'>,
    callbacks: SearchStreamCallbacks,
    opts?: { bypass?: boolean; follow?: boolean }
  ): AbortController {
    const controller = new AbortController();
    const capturedRuntime = browserTenantRuntime.current();

    const baseUrl = this.searchBaseUrl ?? '';
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream',
      // NAN-1595: refresh forces a live server recompute (bypasses Dragonfly).
      ...(opts?.bypass ? { 'x-nano-cache-bypass': '1' } : {}),
      ...(opts?.follow ? { 'x-nano-follow': 'true' } : {}),
    };
    authenticatedFetch('/api/search/stream', `${baseUrl}/api/search/stream`, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
      signal: controller.signal,
    }, () => browserTenantRuntime.assertCurrent(capturedRuntime)).then(async (response) => {
      if (!browserTenantRuntime.isCurrent(capturedRuntime)) {
        controller.abort();
        return;
      }
      if (!response.ok) {
        const errorText = await response.text();
        let errorMsg = errorText;
        let errorCode = 'HTTP_ERROR';
        let coldScan: Partial<import('./types').SearchStreamError> = {};
        try {
          const errorJson = JSON.parse(errorText);
          errorMsg = errorJson?.error?.message || errorJson?.message || errorText;
          // NAN-3644: the reader's cold-read ceiling; COLD_BUDGET_EXCEEDED is
          // the retired per-query refusal a mid-roll service may still send.
          if (errorJson?.error?.code === 'COLD_SCAN_TOO_LARGE' || errorJson?.error?.code === 'COLD_BUDGET_EXCEEDED') {
            errorCode = errorJson.error.code;
            const { reason, needed_bytes, ceiling_bytes, background_ceiling_bytes, budget_bytes, retryable } = errorJson.error;
            coldScan = { reason, needed_bytes, ceiling_bytes, background_ceiling_bytes, budget_bytes, retryable };
          }
        } catch { /* use raw text */ }
        callbacks.onError?.({ ...coldScan, code: errorCode, message: errorMsg });
        return;
      }

      // NAN-1595: surface server cache status off the stream response headers.
      const ageRaw = response.headers.get('x-nano-cache-age');
      const age = ageRaw != null ? Number(ageRaw) : NaN;
      callbacks.onCacheMeta?.({
        hit: response.headers.get('x-nano-cache') === 'hit',
        ageSecs: Number.isFinite(age) ? age : null,
      });

      const reader = response.body?.getReader();
      if (!reader) {
        callbacks.onError?.({ code: 'NO_BODY', message: 'No response body' });
        return;
      }

      const decoder = new TextDecoder();
      let buffer = '';
      let currentEventType = '';
      const MAX_BUFFER_SIZE = 50 * 1024 * 1024; // 50MB limit (large EDR queries can produce big row batches)

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!browserTenantRuntime.isCurrent(capturedRuntime)) {
          await reader.cancel();
          return;
        }

        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        // Check the *remainder* after draining complete lines — this is the
        // incomplete trailing chunk waiting for the next read, not the full payload.
        if (buffer.length > MAX_BUFFER_SIZE) {
          callbacks.onError?.({ code: 'BUFFER_OVERFLOW', message: 'SSE buffer overflow - response too large' });
          return;
        }

        for (const line of lines) {
          if (!browserTenantRuntime.isCurrent(capturedRuntime)) {
            await reader.cancel();
            return;
          }
          // SSE comment (transport keepalive). Not a follow heartbeat: the
          // handler writes it even while the follow itself is stuck (NAN-3264).
          if (line.startsWith(':')) continue;

          // Event type line
          if (line.startsWith('event: ')) {
            currentEventType = line.slice(7).trim();
            continue;
          }

          // Data line
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '') continue;

            try {
              const parsed = JSON.parse(data);

              switch (currentEventType) {
                case 'queued':
                  callbacks.onQueued?.(parsed.data ?? parsed);
                  break;
                case 'started':
                  callbacks.onStarted?.(parsed.data ?? parsed);
                  break;
                case 'heartbeat':
                  callbacks.onHeartbeat?.(parsed.data ?? parsed);
                  break;
                case 'progress':
                  callbacks.onProgress?.(parsed.data ?? parsed);
                  break;
                case 'view_update':
                  callbacks.onViewUpdate?.(parsed.data ?? parsed);
                  break;
                case 'rows':
                  callbacks.onRows?.(parsed.data ?? parsed);
                  break;
                case 'metadata':
                  callbacks.onMetadata?.(parsed.data ?? parsed);
                  break;
                case 'completed':
                  callbacks.onCompleted?.(parsed.data ?? parsed);
                  return;
                case 'error':
                  callbacks.onError?.(parsed.data ?? parsed);
                  return;
                case 'done':
                  // NAN-3244: a follow stream that ends without `completed`
                  // or `error` must still tell the caller, or the tail
                  // silently stops while the UI says it is live.
                  if (opts?.follow && !controller.signal.aborted && browserTenantRuntime.isCurrent(capturedRuntime)) {
                    callbacks.onError?.({ code: 'NETWORK_ERROR', message: 'Follow stream closed' });
                  }
                  return;
              }
            } catch (e) {
              console.error('Failed to parse SSE event:', currentEventType, e, data);
            }

            currentEventType = '';
          }
        }
      }
      if (opts?.follow && !controller.signal.aborted && browserTenantRuntime.isCurrent(capturedRuntime)) {
        callbacks.onError?.({ code: 'NETWORK_ERROR', message: 'Follow stream closed' });
      }
    }).catch((error) => {
      if (!(error instanceof SessionExpiredError) && error.name !== 'AbortError' && browserTenantRuntime.isCurrent(capturedRuntime)) {
        callbacks.onError?.({ code: 'NETWORK_ERROR', message: error.message });
      }
    });

    return controller;
  }
}
