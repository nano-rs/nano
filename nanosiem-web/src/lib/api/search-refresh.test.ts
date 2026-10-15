// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { SearchApi } from './search.ts';
import { setAccessToken } from '../auth-token.ts';
import { sessionCredentials } from '../session-credentials.ts';

const request = { query: '*', time_range: { start: '2026-09-19T00:00:00Z', end: '2026-09-19T01:00:00Z' } };
const search = new SearchApi(async () => { throw new Error('unused JSON transport'); });

test('SSE reconnects with the refreshed bearer and delivers completion', { timeout: 2000 }, async t => {
  setAccessToken('sse-old', 900);
  let refreshes = 0;
  sessionCredentials.configure(() => sessionCredentials.runRefresh(async () => {
    refreshes++;
    setAccessToken('sse-new', 900);
    return true;
  }), null);
  const credentials: string[] = [];
  t.mock.method(globalThis, 'fetch', async (_url: string, options: RequestInit) => {
    const credential = new Headers(options.headers).get('Authorization')!;
    credentials.push(credential);
    assert.equal(options.credentials, 'omit');
    return credential === 'Bearer sse-old'
      ? new Response('{}', { status: 401 })
      : new Response('event: completed\ndata: {"total_rows_delivered":2}\n\n');
  });
  const completed = await new Promise<{ total_rows_delivered: number }>((resolve, reject) => {
    search.searchStreamSSE(request, { onCompleted: resolve, onError: reject });
  });
  assert.equal(completed.total_rows_delivered, 2);
  assert.deepEqual(credentials, ['Bearer sse-old', 'Bearer sse-new']);
  assert.equal(refreshes, 1);
});

test('SSE session failure uses the single auth prompt without a stream error toast', { timeout: 2000 }, async t => {
  setAccessToken('sse-failed', 900);
  let prompts = 0;
  let streamErrors = 0;
  sessionCredentials.configure(() => sessionCredentials.runRefresh(async () => false), () => { prompts++; });
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('{}', { status: 401 }));
  search.searchStreamSSE(request, { onError: () => { streamErrors++; } });
  // Drain the fetch / refresh / stream rejection microtasks.
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(prompts, 1);
  assert.equal(streamErrors, 0);
  assert.equal(fetch.mock.callCount(), 1);
});

test('follow option sends the lean follow header', { timeout: 2000 }, async t => {
  setAccessToken('sse-follow', 900);
  sessionCredentials.configure(() => Promise.resolve(false), null);
  const fetch = t.mock.method(globalThis, 'fetch', async (_url: string, options: RequestInit) => {
    assert.equal(new Headers(options.headers).get('x-nano-follow'), 'true');
    return new Response('event: completed\ndata: {"total_rows_delivered":0}\n\n');
  });
  await new Promise<void>((resolve, reject) => {
    search.searchStreamSSE(request, { onCompleted: () => resolve(), onError: reject }, { follow: true });
  });
  assert.equal(fetch.mock.callCount(), 1);
});

for (const streamed of [false, true]) {
  test(`cold ceiling ${streamed ? 'SSE' : 'HTTP 422'} keeps actionable code and performs one request`, { timeout: 2000 }, async t => {
    setAccessToken('budget-test', 900);
    sessionCredentials.configure(() => Promise.resolve(false), null);
    const error = { code: 'COLD_SCAN_TOO_LARGE', message: 'This search would read ~14.8 GB of uncached data in one pass, more than the ~9.6 GB this tenant\'s reader can stage at once, so it is too large to run interactively. Narrow the time range or add a filter so each pass reads less.', reason: 'cold_scan_too_large', needed_bytes: 14_800_000_000, ceiling_bytes: 9_600_000_000, background_ceiling_bytes: 9_600_000_000, retryable: false };
    const fetch = t.mock.method(globalThis, 'fetch', async () => streamed
      ? new Response(`event: error\ndata: ${JSON.stringify({ event: 'error', data: error })}\n\n`)
      : new Response(JSON.stringify({ error }), { status: 422 }));
    const result = await new Promise<import('./types').SearchStreamError>(resolve => {
      search.searchStreamSSE(request, { onError: resolve });
    });
    assert.equal(result.code, 'COLD_SCAN_TOO_LARGE');
    assert.equal(result.needed_bytes, error.needed_bytes);
    assert.equal(result.ceiling_bytes, error.ceiling_bytes);
    assert.equal(result.background_ceiling_bytes, error.background_ceiling_bytes);
    assert.equal(result.retryable, false);
    assert.equal(result.reason, 'cold_scan_too_large');
    assert.equal(result.message, error.message);
    assert.equal(fetch.mock.callCount(), 1);
  });
}

// NAN-3644: a cold read is never an error. Its progress arrives as `progress`
// events (phase cold_scan) and the search completes.
test('cold-scan progress events reach onProgress and the search completes', { timeout: 2000 }, async t => {
  setAccessToken('cold-progress-test', 900);
  sessionCredentials.configure(() => Promise.resolve(false), null);
  const queued = { phase: 'cold_scan', cold_bytes_read: 0, cold_bytes_total: 0, queued: true, rows_scanned: 0, rows_total: 0, percent: 0, elapsed_ms: 1000 };
  const scanning = { ...queued, queued: false, cold_bytes_read: 1_000_000_000, cold_bytes_total: 2_200_000_000, percent: 45, elapsed_ms: 2000 };
  t.mock.method(globalThis, 'fetch', async () => new Response(
    [queued, scanning].map(data => `event: progress\ndata: ${JSON.stringify({ event: 'progress', data })}\n\n`).join('')
      + 'event: completed\ndata: {"total_rows_delivered":0}\n\n'));
  const seen: import('./types').SearchJobProgress[] = [];
  await new Promise<void>((resolve, reject) => {
    search.searchStreamSSE(request, { onProgress: p => seen.push(p), onCompleted: () => resolve(), onError: reject });
  });
  assert.deepEqual(seen.map(p => [p.phase, p.queued, p.cold_bytes_read, p.cold_bytes_total]),
    [['cold_scan', true, 0, 0], ['cold_scan', false, 1_000_000_000, 2_200_000_000]]);
});
