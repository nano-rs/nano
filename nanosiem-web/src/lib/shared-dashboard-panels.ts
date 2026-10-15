// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Dashboard panel execution for shared-lake tenants (NAN-2361).
 *
 * In hosted shared deployments the browser runs panels through the
 * exact `POST /api/search` contract the Search page uses, including the
 * durable-job escalation the search service may answer with (`job_id`
 * instead of rows), which is polled to completion here.
 *
 * NAN-2771: nanosiem-api now also admits `POST /api/dashboards/panel/query`
 * for shared tenants (tenant-pinned lake view, per-tenant in-flight cap), so
 * the desktop client and any caller that misses the shared scope still get
 * panels. This browser path is unchanged and does not depend on it.
 *
 * Only nPL (`piped`) panels are supported: `/api/search/sql` stays closed for
 * shared tenants.
 */
import type { PanelQueryRequest, PanelQueryResponse, SearchJobStatus, SearchRequest, SearchResponse, TimeRange } from './api/types';

/** Same hard row cap as the dedicated panel executor (DSH40). */
export const SHARED_PANEL_ROW_LIMIT = 10_000;
export const SHARED_PANEL_POLL_INTERVAL_MS = 750;
export const SHARED_PANEL_POLL_TIMEOUT_MS = 120_000;

export type SharedPanelRequester = <T>(endpoint: string, options?: RequestInit) => Promise<T>;

interface DurableResultPage {
  rows: Record<string, unknown>[];
  total_rows: number;
}

export function sharedPanelSearchRequest(request: PanelQueryRequest): SearchRequest {
  return {
    query: request.query,
    time_range: request.time_range as TimeRange,
    limit: SHARED_PANEL_ROW_LIMIT,
    skip_histogram: true,
    skip_field_stats: true,
    use_cache: !request.bypass_cache,
    table_view: false,
    priority: 'interactive',
  };
}

export function panelResponseFromSearch(response: SearchResponse): PanelQueryResponse {
  const shown = response.results.length;
  return {
    results: response.results,
    total_count: response.total_count,
    execution_time_ms: response.execution_time_ms,
    column_order: response.column_order,
    truncated: shown === SHARED_PANEL_ROW_LIMIT && response.total_count > shown,
    cached: false,
  };
}

function isAsyncAnswer(value: unknown): value is { job_id: string } {
  return !!value && typeof value === 'object' && typeof (value as { job_id?: unknown }).job_id === 'string';
}

/**
 * Execute one panel through the search service and resolve a durable-job
 * escalation. `sleep` is injectable for tests.
 */
export async function runSharedPanelQuery(
  request: PanelQueryRequest,
  requester: SharedPanelRequester,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now: () => number = () => Date.now(),
): Promise<PanelQueryResponse> {
  if (request.query_mode === 'sql') {
    throw new Error('Raw SQL panels are unavailable in shared tenants — rewrite this panel in nPL.');
  }
  const answer = await requester<SearchResponse | { job_id: string }>('/api/search', {
    method: 'POST',
    // NAN-3229: a slow panel comes back as a job id at the server's
    // interactive deadline (polled below) instead of a proxy 502 at 60 s.
    headers: { 'x-nano-accept-async': '1' },
    body: JSON.stringify(sharedPanelSearchRequest(request)),
  });
  if (!isAsyncAnswer(answer)) return panelResponseFromSearch(answer);

  const jobId = answer.job_id;
  const deadline = now() + SHARED_PANEL_POLL_TIMEOUT_MS;
  for (;;) {
    await sleep(SHARED_PANEL_POLL_INTERVAL_MS);
    const status = await requester<SearchJobStatus>(`/api/search/jobs/${encodeURIComponent(jobId)}`);
    if (status.status === 'completed' && status.result) return panelResponseFromSearch(status.result);
    if (status.status === 'completed' && status.durable_result) {
      const page: DurableResultPage = status.durable_result.pages === 0
        ? { rows: [], total_rows: 0 }
        : await requester<DurableResultPage>(`/api/search/jobs/${encodeURIComponent(jobId)}/results/0`);
      return panelResponseFromSearch({
        results: page.rows,
        total_count: page.total_rows,
        execution_time_ms: status.progress?.elapsed_ms ?? 0,
        fields: [],
      });
    }
    if (status.status === 'completed') return panelResponseFromSearch({ results: [], total_count: 0, execution_time_ms: 0, fields: [] });
    if (status.status === 'failed' || status.status === 'cancelled') {
      throw new Error(status.error || `Panel query ${status.status}`);
    }
    if (now() > deadline) {
      await requester(`/api/search/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE' }).catch(() => undefined);
      throw new Error('Panel query timed out waiting for the lake job');
    }
  }
}
