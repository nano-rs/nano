// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  LOCK_CONTENTION_MAX_RETRIES,
  RESOURCE_LOCK_CONTENTION,
  lockContentionDelayMs,
  withLockContentionRetry,
} from './lock-contention-retry.ts';

const contention = () => new Response(JSON.stringify({ error: { code: RESOURCE_LOCK_CONTENTION, message: 'deferred' } }),
  { status: 503, headers: { 'Retry-After': '1', 'Content-Type': 'application/json' } });
const ok = () => new Response('[]', { status: 200 });

test('a read deferred by lock contention is retried with backoff and jitter until it succeeds', async () => {
  let calls = 0;
  const waits: number[] = [];
  const response = await withLockContentionRetry('GET', async () => (++calls < 3 ? contention() : ok()), null,
    async ms => { waits.push(ms); }, () => 0.5);
  assert.equal(response.status, 200);
  assert.equal(calls, 3);
  // Retry-After (1 s) plus half of the 500 ms / 1 s exponential caps.
  assert.deepEqual(waits, [1250, 1500]);
});

test('the lowercase string error shape (enterprise handlers) is recognized too', async () => {
  let calls = 0;
  const lower = () => new Response(JSON.stringify({ error: 'resource_lock_contention' }), { status: 503 });
  const response = await withLockContentionRetry('GET', async () => (++calls < 2 ? lower() : ok()), null, async () => {});
  assert.equal(response.status, 200);
  assert.equal(calls, 2);
});

test('retries are bounded and the last 503 reaches the caller', async () => {
  let calls = 0;
  const response = await withLockContentionRetry(undefined, async () => { calls++; return contention(); }, null, async () => {});
  assert.equal(response.status, 503);
  assert.equal(calls, LOCK_CONTENTION_MAX_RETRIES + 1);
});

test('writes and other failures are never retried', async () => {
  for (const [method, make] of [
    ['POST', contention],
    ['GET', () => new Response(JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE' } }), { status: 503 })],
    ['GET', () => new Response(JSON.stringify({ error: { code: 'FORBIDDEN' } }), { status: 403 })],
  ] as const) {
    let calls = 0;
    const response = await withLockContentionRetry(method, async () => { calls++; return make(); }, null, async () => {});
    assert.equal(calls, 1, `${method} ${response.status}`);
  }
});

test('jitter spreads concurrent retries and an abort stops the wait', async () => {
  assert.notEqual(lockContentionDelayMs(1, '1', () => 0), lockContentionDelayMs(1, '1', () => 0.99));
  assert.ok(lockContentionDelayMs(10, null, () => 1) <= 4_000);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(withLockContentionRetry('GET', async () => contention(), controller.signal), { name: 'AbortError' });
});
