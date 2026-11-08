// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />
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
    return credential === 'Bearer sse-old'
      ? new Response('{}', { status: 401 })
      : new Response('event: completed\ndata: {"total_rows_delivered":2}\n\n');
  });
  const completed = await new Promise<{ total_rows_delivered: number }>((resolve, reject) => {
    search.searchStreamSSE(request as never, {
      onCompleted: resolve as never,
      onError: reject,
    });
  });
  assert.equal(completed.total_rows_delivered, 2);
  assert.deepEqual(credentials, ['Bearer sse-old', 'Bearer sse-new']);
  assert.equal(refreshes, 1);
});

test('SSE session failure uses the single auth prompt without a stream error', { timeout: 2000 }, async t => {
  setAccessToken('sse-failed', 900);
  let prompts = 0;
  let streamErrors = 0;
  sessionCredentials.configure(() => sessionCredentials.runRefresh(async () => false), () => { prompts++; });
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('{}', { status: 401 }));
  search.searchStreamSSE(request as never, { onError: () => { streamErrors++; } });
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(prompts, 1);
  assert.equal(streamErrors, 0);
  assert.equal(fetch.mock.callCount(), 1);
});
