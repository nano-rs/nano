// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SearchApi } from '@/lib/api/search';
import type { AsyncSearchResponse, SearchResponse } from '@/lib/api/types';
import { startInteractiveSearch } from './interactive-search';

const request = {
  query: '(actor.user.name="jsmith" OR user.name="jsmith")',
  time_range: { start: '2026-09-21T14:20:00Z', end: '2026-09-21T15:20:00Z' },
  limit: 100, offset: 0, request_id: 'request-one', dataset: 'logs' as const,
  skip_field_stats: true, skip_histogram: false, table_view: true,
};
const rows = (offset: number, count: number) => Array.from({ length: count }, (_, i) => ({ uid: offset + i }));
const inline: SearchResponse = { results: rows(0, 100), total_count: 996, execution_time_ms: 736, fields: [] };
function fixture() {
  const api = {
    searchInteractive: vi.fn<(...args: Parameters<SearchApi['searchInteractive']>) => Promise<SearchResponse | AsyncSearchResponse>>().mockResolvedValue(inline),
    cancelSearch: vi.fn().mockResolvedValue({ cancelled: true }),
    cancelSearchJob: vi.fn().mockResolvedValue({ cancelled: true }),
    getSearchJob: vi.fn().mockResolvedValue({ job_id: 'escalated', status: 'completed',
      durable_result: { rows: 100, pages: 2, page_rows: 50, has_more: true } }),
    getSearchJobResultPage: vi.fn(async (_job: string, page: number) => ({
      page, pages: 2, total_rows: 100, row_offset: page * 50, rows: rows(page * 50, 50),
    })),
  };
  const controller = new AbortController();
  const current = { value: true };
  const onStatus = vi.fn();
  const start = (offset = 0) => startInteractiveSearch(api, { ...request, offset }, 500,
    controller.signal, () => current.value, { isCancelled: () => controller.signal.aborted || !current.value }, onStatus);
  return { api, controller, current, onStatus, start };
}
afterEach(() => vi.useRealTimers());

describe('hosted-shared interactive admission', () => {
  it('returns rows and metadata for normal rendering without a job or artifact', async () => {
    const { start, api } = fixture();
    const admitted = await start();
    expect(admitted.response).toBe(inline);
    expect(admitted.pager).toBeUndefined();
    expect(api.searchInteractive).toHaveBeenCalledExactlyOnceWith(request, expect.any(Object));
    expect(api.getSearchJob).not.toHaveBeenCalled();
    expect(api.getSearchJobResultPage).not.toHaveBeenCalled();
  });

  it('adopts the escalated job once and caches its artifact pages without resubmission', async () => {
    vi.useFakeTimers();
    const { start, api } = fixture();
    api.searchInteractive.mockResolvedValueOnce({ job_id: 'escalated', status: 'queued' });
    const { pager } = await start();
    const first = pager!.read(0, 50);
    await vi.advanceTimersByTimeAsync(150);
    expect(await first).toEqual(rows(0, 50));
    expect(await pager!.read(50, 50)).toEqual(rows(50, 50));
    expect(await pager!.read(0, 100)).toEqual(rows(0, 100));
    expect(api.searchInteractive).toHaveBeenCalledOnce();
    expect(api.getSearchJob).toHaveBeenCalledExactlyOnceWith('escalated', expect.any(Object));
    expect(api.getSearchJobResultPage.mock.calls).toEqual([['escalated', 0], ['escalated', 1]]);
    api.searchInteractive.mockResolvedValueOnce({ ...inline, results: rows(100, 500) });
    expect(await pager!.read(100, 50)).toEqual(rows(100, 50));
    expect(api.searchInteractive.mock.calls[1][0]).toMatchObject({ offset: 100, limit: 500, skip_histogram: true });
    expect(api.getSearchJob).toHaveBeenCalledOnce();
  });

  it('NAN-3809: a re-served settled job reports the cache hit and pages its result like an escalation', async () => {
    vi.useFakeTimers();
    const { api, controller, current, onStatus } = fixture();
    api.searchInteractive.mockImplementationOnce(async (_body, _retry, onCacheMeta) => {
      onCacheMeta?.({ hit: true, ageSecs: 240 });
      return { job_id: 'settled', status: 'completed' };
    });
    api.getSearchJob.mockResolvedValue({ job_id: 'settled', status: 'completed',
      durable_result: { rows: 100, pages: 2, page_rows: 50, has_more: false } });
    const onCacheMeta = vi.fn();
    const { pager } = await startInteractiveSearch(api, { ...request, use_cache: true }, 500, controller.signal,
      () => current.value, { isCancelled: () => controller.signal.aborted || !current.value }, onStatus, onCacheMeta);
    expect(onCacheMeta).toHaveBeenCalledExactlyOnceWith({ hit: true, ageSecs: 240 });
    // Infinite scroll reads the stored result pages in order; nothing re-runs.
    const first = pager!.read(0, 50);
    await vi.advanceTimersByTimeAsync(150);
    expect(await first).toEqual(rows(0, 50));
    expect(await pager!.read(50, 50)).toEqual(rows(50, 50));
    expect(api.getSearchJobResultPage.mock.calls).toEqual([['settled', 0], ['settled', 1]]);
    expect(api.searchInteractive).toHaveBeenCalledOnce();
    expect(pager!.totalCount).toBe(100);
    expect(pager!.hasMore(100)).toBe(false);
  });

  it('adopts an escalation on a later interactive page at its original offset', async () => {
    vi.useFakeTimers();
    const { start, api } = fixture();
    api.searchInteractive.mockResolvedValueOnce({ job_id: 'escalated', status: 'queued' });
    const { pager } = await start(200);
    const first = pager!.read(200, 100);
    await vi.advanceTimersByTimeAsync(150);
    expect(await first).toEqual(rows(0, 100));
    api.searchInteractive.mockResolvedValueOnce({ ...inline, results: rows(300, 25) });
    expect(await pager!.read(300, 100)).toEqual(rows(300, 25));
    expect(pager!.hasMore(325)).toBe(false);
    expect(api.searchInteractive.mock.calls.map(([body]) => [body.offset, body.limit])).toEqual([[200, 100], [300, 500]]);
  });

  it.each(['rows', 'job'] as const)('cancels the captured interactive request and discards late %s after abort', async result => {
    const { start, api, controller } = fixture();
    let resolve!: (value: SearchResponse | AsyncSearchResponse) => void;
    api.searchInteractive.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
    const pending = start();
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    resolve(result === 'rows' ? inline : { job_id: 'late-job', status: 'queued' });
    await rejected;
    expect(api.cancelSearch).toHaveBeenCalledExactlyOnceWith('request-one');
    expect(api.getSearchJob).not.toHaveBeenCalled();
    if (result === 'job') expect(api.cancelSearchJob).toHaveBeenCalledExactlyOnceWith('late-job');
    else expect(api.cancelSearchJob).not.toHaveBeenCalled();
  });

  it('cancels a late escalated job after supersession', async () => {
    const { start, api, current } = fixture();
    let resolve!: (value: AsyncSearchResponse) => void;
    api.searchInteractive.mockImplementationOnce(() => new Promise(done => { resolve = done; }));
    const pending = start();
    current.value = false;
    resolve({ job_id: 'old-job', status: 'queued' });
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(api.cancelSearchJob).toHaveBeenCalledExactlyOnceWith('old-job');
  });

  it('cancels the escalated job while polling and never fetches its artifact', async () => {
    vi.useFakeTimers();
    const { start, api, controller, onStatus } = fixture();
    api.searchInteractive.mockResolvedValueOnce({ job_id: 'escalated', status: 'queued' });
    const { pager } = await start();
    const pending = pager!.read(0, 50);
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    await rejected;
    expect(api.cancelSearchJob).toHaveBeenCalledExactlyOnceWith('escalated');
    expect(api.getSearchJobResultPage).not.toHaveBeenCalled();
    expect(onStatus).not.toHaveBeenCalled();
  });

  it('sends no async_mode and retries only authority-unavailable admission', async () => {
    vi.useFakeTimers();
    const transport = vi.fn().mockRejectedValueOnce({ status: 503, code: 'search_authority_unavailable' }).mockResolvedValue(inline);
    const api = new SearchApi(transport);
    const retry = { onUnavailable: vi.fn(), onRecovered: vi.fn() };
    const pending = api.searchInteractive(request, retry);
    await vi.advanceTimersByTimeAsync(2000);
    expect(await pending).toBe(inline);
    expect(transport).toHaveBeenCalledTimes(2);
    for (const [endpoint, options] of transport.mock.calls) {
      expect(endpoint).toBe('/api/search');
      expect(JSON.parse(options.body)).toEqual(request);
      expect(JSON.parse(options.body)).not.toHaveProperty('async_mode');
    }
    expect(retry.onUnavailable).toHaveBeenCalledOnce();
    expect(retry.onRecovered).toHaveBeenCalledOnce();
  });
});
