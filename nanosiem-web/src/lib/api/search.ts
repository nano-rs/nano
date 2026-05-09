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
  async fetchLog(id: string, timeRange?: TimeRange): Promise<{ event: Record<string, unknown> | null }> {
    return this.request('/api/search/log', {
      method: 'POST',
      body: JSON.stringify({ id, time_range: timeRange }),
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
