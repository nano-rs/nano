// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Search API routes
 * Handles search operations, saved searches, query explanations, and asset artifacts
 */

import type {
  SearchRequest,
  SearchResponse,
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
  RetroResponse,
} from './types';

export class SearchApi {
  constructor(
    private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    private getAccessToken?: () => string | null,
    private searchBaseUrl?: string
  ) {}

  // Core search endpoints
  async search(request: SearchRequest): Promise<SearchResponse> {
    return this.request('/api/search', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async searchSql(request: RawSqlRequest): Promise<SearchResponse> {
    return this.request('/api/search/sql', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async explainQuery(query: string, timeRange: TimeRange, tableView = true): Promise<{ sql: string }> {
    return this.request('/api/search/explain', {
      method: 'POST',
      body: JSON.stringify({ query, time_range: timeRange, table_view: tableView }),
    });
  }

  // Fetch a single log by ID (for table_view mode row expansion)
  // NAN-1032: pass sourceType when known so ClickHouse can use the
  // (source_type, timestamp, ...) PK index for a tight range read — without it,
  // S3-backed historical lookups scan every source_type's marks in the time window.
  async fetchLog(id: string, timeRange?: TimeRange, sourceType?: string): Promise<{ event: Record<string, unknown> | null }> {
    return this.request('/api/search/log', {
      method: 'POST',
      body: JSON.stringify({ id, time_range: timeRange, source_type: sourceType }),
    });
  }

  // Async field stats (loaded separately from main search for better UX)
  // DEPRECATED: Use getFieldValues for on-demand per-field stats instead
  async getFieldStats(request: FieldStatsRequest): Promise<FieldStatsResponse> {
    return this.request('/api/search/field-stats', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // On-demand field values (Kibana-style, fetched when user expands a field)
  async getSearchFieldValues(request: FieldValuesRequest): Promise<FieldValuesResponse> {
    return this.request('/api/search/field-values', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Paginated asset events (for infinite scroll and server-side filtering)
  async getAssetEvents(request: AssetEventsRequest): Promise<AssetEventsResponse> {
    return this.request('/api/search/asset-events', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Lazy-loaded true time range (first/last seen) for asset view
  async getAssetTrueTimeRange(request: AssetTrueTimeRangeRequest): Promise<AssetTrueTimeRangeResponse> {
    return this.request('/api/search/asset-true-time-range', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Paginated cloud events (for infinite scroll and server-side filtering)
  async getCloudEvents(request: CloudEventsRequest): Promise<CloudEventsResponse> {
    return this.request('/api/search/cloud-events', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Cloud user timeline (for user investigation sheet)
  async getCloudUserTimeline(request: CloudUserTimelineRequest): Promise<CloudUserTimelineResponse> {
    return this.request('/api/search/cloud-user-timeline', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Cloud entity pivot (for entity correlation sheet)
  async getCloudEntityPivot(request: CloudEntityPivotRequest): Promise<CloudEntityPivotResponse> {
    return this.request('/api/search/cloud-entity-pivot', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Lazy-loaded artifact summaries (hashes/domains) for asset prevalence scatter
  async getAssetArtifacts(request: AssetArtifactsRequest): Promise<AssetArtifactsResponse> {
    return this.request('/api/search/asset-artifacts', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Asset dossier aggregates for the redesigned Asset view (NAN-393)
  async getAssetDossier(request: AssetDossierRequest): Promise<AssetDossierResponse> {
    return this.request('/api/search/asset-dossier', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Cloud overview aggregates for the redesigned `| cloud` landing view (NAN-394)
  async getCloudOverview(request: CloudOverviewRequest): Promise<CloudOverviewResponse> {
    return this.request('/api/search/cloud-overview', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Cloud principal dossier aggregates for `| cloud principal=X` (NAN-395)
  async getCloudDossier(request: CloudDossierRequest): Promise<CloudDossierResponse> {
    return this.request('/api/search/cloud-dossier', {
      method: 'POST',
      body: JSON.stringify(request),
    });
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
    request: MetricTimeseriesV2Request
  ): Promise<MetricTimeseriesV2Response> {
    return this.request('/api/search/metrics/timeseries', {
      method: 'POST',
      body: JSON.stringify(request),
    });
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
  async listTraces(request: ListTracesRequest): Promise<ListTracesResponse> {
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
    return this.request(`/api/search/traces?${params.toString()}`);
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
  async getRetro(request: RetroRequest): Promise<RetroResponse> {
    return this.request('/api/search/retro', {
      method: 'POST',
      body: JSON.stringify(request),
    });
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
  async searchAsync(request: Omit<SearchRequest, 'async_mode'>): Promise<AsyncSearchResponse> {
    return this.request('/api/search', {
      method: 'POST',
      body: JSON.stringify({ ...request, async_mode: true }),
    });
  }

  /**
   * Get the status of an async search job.
   * Returns progress while running, results when completed.
   */
  async getSearchJob(jobId: string): Promise<SearchJobStatus> {
    return this.request(`/api/search/jobs/${jobId}`);
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
    callbacks: SearchStreamCallbacks
  ): AbortController {
    const controller = new AbortController();

    const token = this.getAccessToken?.();
    const baseUrl = this.searchBaseUrl ?? '';
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    fetch(`${baseUrl}/api/search/stream`, {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
      signal: controller.signal,
    }).then(async (response) => {
      if (!response.ok) {
        const errorText = await response.text();
        let errorMsg = errorText;
        try {
          const errorJson = JSON.parse(errorText);
          errorMsg = errorJson?.error?.message || errorJson?.message || errorText;
        } catch { /* use raw text */ }
        callbacks.onError?.({ code: 'HTTP_ERROR', message: errorMsg });
        return;
      }

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
          // SSE comment (keepalive)
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
                case 'progress':
                  callbacks.onProgress?.(parsed.data ?? parsed);
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
                  return;
              }
            } catch (e) {
              console.error('Failed to parse SSE event:', currentEventType, e, data);
            }

            currentEventType = '';
          }
        }
      }
    }).catch((error) => {
      if (error.name !== 'AbortError') {
        callbacks.onError?.({ code: 'NETWORK_ERROR', message: error.message });
      }
    });

    return controller;
  }
}
