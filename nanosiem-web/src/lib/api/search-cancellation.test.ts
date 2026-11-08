// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it, vi } from 'vitest';
import { SearchApi } from './search';

const fetchMock = vi.hoisted(() => vi.fn());
vi.mock('../authenticated-fetch.ts', () => ({ authenticatedFetch: fetchMock }));

const range = { start: '2026-09-30T00:00:00Z', end: '2026-09-30T01:00:00Z' };
const initOf = (request: ReturnType<typeof vi.fn>, call = 0) =>
  (request.mock.calls[call] as unknown as [string, RequestInit])[1];
const endpointOf = (request: ReturnType<typeof vi.fn>, call = 0) =>
  (request.mock.calls[call] as unknown as [string, RequestInit])[0];

it('opts the Search page interactive call in to progressive views (NAN-3077)', async () => {
  const request = vi.fn(async () => ({ results: [] }));
  const search = new SearchApi(request as never);
  await search.searchInteractive({ query: '* | tree', time_range: range } as never);
  expect(endpointOf(request)).toBe('/api/search');
  expect(initOf(request).headers).toEqual({ 'x-nano-progressive-views': '1' });
  await search.searchInteractive({ query: '* | tree', time_range: range } as never, { acceptAsync: true });
  expect(initOf(request, 1).headers).toEqual({ 'x-nano-progressive-views': '1', 'x-nano-accept-async': '1' });
});

it('keeps the shared atomic search free of the progressive header', async () => {
  const request = vi.fn(async () => ({ results: [] }));
  const search = new SearchApi(request as never);
  await search.search({ query: '* | tree', time_range: range } as never);
  const headers = initOf(request).headers as Record<string, string> | undefined;
  expect(headers?.['x-nano-progressive-views']).toBeUndefined();
});

it('passes interactive, log, async-job and tree-page AbortSignals to the transport', async () => {
  const request = vi.fn(async () => ({}));
  const search = new SearchApi(request as never);
  const controller = new AbortController();
  await search.searchInteractive({ query: 'x', time_range: range } as never, { signal: controller.signal });
  await search.fetchLog('id', undefined, undefined, controller.signal);
  await search.searchAsync({ query: 'x', time_range: range } as never, controller.signal);
  await search.getTreePage({ job_id: 'job', parent_path: [0], offset: 25, limit: 25 }, controller.signal);
  expect(request.mock.calls.map((_, i) => initOf(request, i).signal)).toEqual(Array(4).fill(controller.signal));
  expect(endpointOf(request, 3)).toBe('/api/search/tree-page');
  expect(JSON.parse(initOf(request, 3).body as string)).toEqual({ job_id: 'job', parent_path: [0], offset: 25, limit: 25 });
});

it('delivers per-hop view_update events from the SSE stream (NAN-3077)', async () => {
  const marker = { _display_type: 'lateral', _lateral_graph: { nodes: [], edges: [] } };
  const body = [
    'event: view_update',
    `data: ${JSON.stringify({ event: 'view_update', data: { view: 'lateral', rows: [marker], completed_hops: 1, complete: false } })}`,
    '',
    'event: completed',
    `data: ${JSON.stringify({ event: 'completed', data: { total_rows_delivered: 1 } })}`,
    '',
    '',
  ].join('\n');
  fetchMock.mockResolvedValue(new Response(body, { status: 200 }));
  const search = new SearchApi(vi.fn() as never);
  const onViewUpdate = vi.fn();
  const done = new Promise<void>((resolve) => {
    search.searchStreamSSE({ query: 'h | lateral', time_range: range } as never, { onViewUpdate, onCompleted: () => resolve() });
  });
  await done;
  expect(onViewUpdate).toHaveBeenCalledExactlyOnceWith({ view: 'lateral', rows: [marker], completed_hops: 1, complete: false });
});
