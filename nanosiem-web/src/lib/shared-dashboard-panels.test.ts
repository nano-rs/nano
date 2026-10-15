// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  panelResponseFromSearch,
  runSharedPanelQuery,
  sharedPanelSearchRequest,
  SHARED_PANEL_ROW_LIMIT,
} from './shared-dashboard-panels.ts';

const panel = {
  query: 'class_uid=4002 | stats count by user',
  query_mode: 'piped',
  time_range: { start: '2026-01-01T00:00:00Z', end: '2026-01-02T00:00:00Z' },
};
const noSleep = async () => undefined;

test('shared panel request is the Search page contract with the panel row cap', () => {
  const request = sharedPanelSearchRequest({ ...panel, bypass_cache: true });
  assert.equal(request.limit, SHARED_PANEL_ROW_LIMIT);
  assert.equal(request.skip_histogram, true);
  assert.equal(request.skip_field_stats, true);
  assert.equal(request.use_cache, false);
  assert.equal(request.table_view, false);
  assert.equal(sharedPanelSearchRequest(panel).use_cache, true);
});

test('truncation is flagged only when the cap is hit and more rows matched', () => {
  const rows = Array.from({ length: SHARED_PANEL_ROW_LIMIT }, (_, i) => ({ i }));
  assert.equal(panelResponseFromSearch({ results: rows, total_count: rows.length + 1, execution_time_ms: 1, fields: [] }).truncated, true);
  assert.equal(panelResponseFromSearch({ results: rows, total_count: rows.length, execution_time_ms: 1, fields: [] }).truncated, false);
  const response = panelResponseFromSearch({ results: [{ a: 1 }], total_count: 1, execution_time_ms: 3, fields: [], column_order: ['a'] });
  assert.deepEqual(response.column_order, ['a']);
  assert.equal(response.cached, false);
});

test('the panel search opts in to deadline escalation (NAN-3229)', async () => {
  const options: (RequestInit | undefined)[] = [];
  const requester = async <T,>(_endpoint: string, init?: RequestInit): Promise<T> => {
    options.push(init);
    return { results: [], total_count: 0, execution_time_ms: 1, fields: [] } as T;
  };
  await runSharedPanelQuery(panel, requester, noSleep);
  assert.deepEqual(options[0]?.headers, { 'x-nano-accept-async': '1' });
});

test('a synchronous answer maps straight through', async () => {
  const calls: string[] = [];
  const requester = async <T,>(endpoint: string): Promise<T> => {
    calls.push(endpoint);
    return { results: [{ user: 'ada', count: 2 }], total_count: 1, execution_time_ms: 5, fields: [] } as T;
  };
  const response = await runSharedPanelQuery(panel, requester, noSleep);
  assert.deepEqual(calls, ['/api/search']);
  assert.equal(response.total_count, 1);
});

test('a durable-job escalation is polled to its result page', async () => {
  const calls: string[] = [];
  let polls = 0;
  const requester = async <T,>(endpoint: string): Promise<T> => {
    calls.push(endpoint);
    if (endpoint === '/api/search') return { job_id: 'job-1', status: 'queued' } as T;
    if (endpoint === '/api/search/jobs/job-1') {
      polls += 1;
      return (polls < 2
        ? { job_id: 'job-1', status: 'running' }
        : { job_id: 'job-1', status: 'completed', durable_result: { rows: 1, pages: 1, page_rows: 1 }, progress: { elapsed_ms: 40 } }) as T;
    }
    if (endpoint === '/api/search/jobs/job-1/results/0') return { rows: [{ user: 'ada' }], total_rows: 1 } as T;
    throw new Error(`unexpected ${endpoint}`);
  };
  const response = await runSharedPanelQuery(panel, requester, noSleep);
  assert.equal(response.results.length, 1);
  assert.equal(response.execution_time_ms, 40);
  assert.deepEqual(calls, ['/api/search', '/api/search/jobs/job-1', '/api/search/jobs/job-1', '/api/search/jobs/job-1/results/0']);
});

test('failed jobs, SQL panels and timeouts surface as errors', async () => {
  const failed = async <T,>(endpoint: string): Promise<T> =>
    (endpoint === '/api/search' ? { job_id: 'j', status: 'queued' } : { job_id: 'j', status: 'failed', error: 'lake worker unavailable' }) as T;
  await assert.rejects(runSharedPanelQuery(panel, failed, noSleep), /lake worker unavailable/);
  await assert.rejects(runSharedPanelQuery({ ...panel, query_mode: 'sql' }, failed, noSleep), /Raw SQL panels are unavailable/);
  const cancelled: string[] = [];
  const stuck = async <T,>(endpoint: string, options?: RequestInit): Promise<T> => {
    if (options?.method === 'DELETE') cancelled.push(endpoint);
    return (endpoint === '/api/search' ? { job_id: 'j', status: 'queued' } : { job_id: 'j', status: 'running' }) as T;
  };
  let clock = 0;
  await assert.rejects(runSharedPanelQuery(panel, stuck, noSleep, () => (clock += 100_000)), /timed out/);
  assert.deepEqual(cancelled, ['/api/search/jobs/j']);
});

test('DashboardsApi routes shared-tenant panels through the search service', () => {
  const source = readFileSync(new URL('./api/dashboards.ts', import.meta.url), 'utf8');
  const branch = source.split('async panelQuery(')[1]?.split('async exportDashboard(')[0];
  assert(branch);
  assert.match(branch, /scope\.kind === 'enterprise_shared'/);
  assert.match(branch, /runSharedPanelQuery\(request, this\.request\)/);
  assert.match(branch, /'\/api\/dashboards\/panel\/query'/);
});
