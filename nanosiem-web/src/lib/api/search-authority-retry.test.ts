// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { retrySearchAuthority, AUTHORITY_UNAVAILABLE } from './search-authority-retry.ts';

const unavailable = { status: 503, code: AUTHORITY_UNAVAILABLE };

test('job polling survives authority outages with notice, backoff and recovery', async () => {
  let calls = 0;
  let notices = 0;
  let recovered = 0;
  const waits: number[] = [];
  const completed = { status: 'completed', result: { results: [1] } };
  const result = await retrySearchAuthority(async () => {
    if (++calls < 4) throw unavailable;
    return completed;
  }, {
    isCancelled: () => false,
    onUnavailable: () => notices++,
    onRecovered: () => recovered++,
  }, async ms => { waits.push(ms); });
  assert.equal(result, completed);
  assert.deepEqual(waits, [2000, 4000, 8000]);
  assert.equal(notices, 3);
  assert.equal(recovered, 1);
});

test('initial POST retries the same operation after typed 503', async () => {
  let calls = 0;
  const result = await retrySearchAuthority(async () => {
    if (++calls === 1) throw unavailable;
    return { job_id: 'job-1' };
  }, {}, async () => {});
  assert.equal(result.job_id, 'job-1');
  assert.equal(calls, 2);
});

test('real 403 and unrelated failures terminate without retry or transient notice', async () => {
  for (const error of [{ status: 403, code: 'FORBIDDEN' }, { status: 503, code: 'OTHER' }, { status: 422, code: 'COLD_SCAN_TOO_LARGE', retryable: false }]) {
    let calls = 0;
    await assert.rejects(retrySearchAuthority(async () => { calls++; throw error; }, {
      onUnavailable: () => assert.fail('not a transient authority failure'),
    }, async () => assert.fail('must not retry')), e => e === error);
    assert.equal(calls, 1);
  }
});

test('stop during backoff prevents another request; delay is capped', async () => {
  let cancelled = false;
  let calls = 0;
  const waits: number[] = [];
  await assert.rejects(retrySearchAuthority(async () => { calls++; throw unavailable; }, {
    isCancelled: () => cancelled,
  }, async ms => {
    waits.push(ms);
    if (waits.length === 7) cancelled = true;
  }), { name: 'AbortError' });
  assert.equal(calls, 7);
  assert.deepEqual(waits, [2000, 4000, 8000, 16000, 30000, 30000, 30000]);
});
