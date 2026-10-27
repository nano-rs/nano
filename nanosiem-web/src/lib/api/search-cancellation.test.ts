// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it, vi } from 'vitest';
import { SearchApi, SearchMovedToJobError } from './search';
it('passes log, status and artifact AbortSignals to the transport', async () => {
  const request = vi.fn(async () => ({}));
  const search = new SearchApi(request as never);
  const controller = new AbortController();
  await search.fetchLog('id', undefined, undefined, controller.signal);
  await search.getSearchJob('job', undefined, controller.signal);
  await search.getSearchJobResultPage('job', 0, controller.signal);
  expect(request.mock.calls.map(call => (call as unknown as [string, RequestInit])[1].signal)).toEqual([controller.signal, controller.signal, controller.signal]);
});
it('does not retry status transport after cancellation', async () => {
  const controller = new AbortController();
  controller.abort();
  const request = vi.fn();
  const search = new SearchApi(request);
  await expect(search.getSearchJob('job', undefined, controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
  expect(request).not.toHaveBeenCalled();
});
it('opts the interactive search in to deadline escalation (NAN-3229)', async () => {
  const request = vi.fn(async () => ({ job_id: 'escalated', status: 'queued' }));
  const search = new SearchApi(request as never);
  await expect(search.searchInteractive({ query: 'error', time_range: { start: 'a', end: 'b' } } as never)).resolves.toEqual({ job_id: 'escalated', status: 'queued' });
  const init = (request.mock.calls[0] as unknown as [string, RequestInit])[1];
  expect(init.headers).toEqual({ 'x-nano-progressive-views': '1', 'x-nano-accept-async': '1' });
});
it('keeps the atomic search synchronous now the deadline applies by default (NAN-3474)', async () => {
  const request = vi.fn(async () => ({ results: [] }));
  const search = new SearchApi(request as never);
  await search.search({ query: 'error', time_range: { start: 'a', end: 'b' } } as never);
  const init = (request.mock.calls[0] as unknown as [string, RequestInit])[1];
  expect(init.headers).toEqual({ 'x-nano-accept-async': '0' });
});
it('fails loudly instead of rendering a job id as an empty result (NAN-4593)', async () => {
  const request = vi.fn(async () => ({ job_id: 'shed', status: 'queued' }));
  const search = new SearchApi(request as never);
  await expect(search.search({ query: 'error', time_range: { start: 'a', end: 'b' } } as never))
    .rejects.toBeInstanceOf(SearchMovedToJobError);
});
it('still returns a genuinely empty synchronous result (NAN-4593)', async () => {
  const request = vi.fn(async () => ({ results: [], total_count: 0 }));
  const search = new SearchApi(request as never);
  await expect(search.search({ query: 'error', time_range: { start: 'a', end: 'b' } } as never))
    .resolves.toEqual({ results: [], total_count: 0 });
});
