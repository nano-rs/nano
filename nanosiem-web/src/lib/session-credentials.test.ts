// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { SessionCredentials } from './session-credentials.ts';
import { requestCredentials, SessionExpiredError } from './request-credentials.ts';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}

test('requests queue during scheduled refresh and each sends once with fresh bearer', async () => {
  let token: string | null = 'old';
  const gate = new SessionCredentials(() => token);
  const refresh = deferred<boolean>();
  const pending = gate.runRefresh(async () => {
    await refresh.promise;
    token = 'new';
    return true;
  });
  const sent: string[] = [];
  const requests = Array.from({ length: 20 }, async () => {
    const credential = await gate.credential();
    assert.equal(requestCredentials('/api/search', { Authorization: `Bearer ${credential}` }), 'omit');
    sent.push(credential);
  });
  await Promise.resolve();
  assert.equal(sent.length, 0);
  refresh.resolve(true);
  await Promise.all([pending, ...requests]);
  assert.deepEqual(sent, Array(20).fill('new'));
});

test('refresh failure rejects the queue with one typed error and exactly one prompt', async () => {
  let prompts = 0;
  let refreshes = 0;
  let token: string | null = null;
  const gate = new SessionCredentials(() => token);
  gate.configure(() => gate.runRefresh(async () => { refreshes++; return false; }), () => { prompts++; });
  const results = await Promise.allSettled(Array.from({ length: 20 }, () => gate.credential()));
  const errors = results.map(result => {
    assert.equal(result.status, 'rejected');
    if (result.status !== 'rejected') throw new Error('unexpected success');
    assert.ok(result.reason instanceof SessionExpiredError);
    return result.reason;
  });
  assert.equal(new Set(errors).size, 1);
  assert.equal(prompts, 1);
  assert.equal(refreshes, 1);
  await assert.rejects(gate.credential(), SessionExpiredError);
  assert.equal(refreshes, 1);
  token = 'signed-in-again';
  assert.equal(await gate.credential(), token);
});

test('a late 401 reuses an already refreshed credential without another rotation', async () => {
  const gate = new SessionCredentials(() => 'new');
  gate.configure(async () => { throw new Error('must not refresh'); }, null);
  assert.equal(await gate.credential('old'), 'new');
});

test('empty and malformed credentials never send a protected request', async () => {
  let sent = 0;
  for (const headers of [{}, { Authorization: '' }, { Authorization: 'Bearer ' }] as HeadersInit[]) {
    await assert.rejects(async () => {
      requestCredentials('/api/auth/tenant-bootstrap', headers);
      sent++;
    }, SessionExpiredError);
  }
  assert.equal(sent, 0);
  assert.equal(requestCredentials('/api/auth/refresh', {}), 'include');
  assert.equal(requestCredentials('/api/auth/login', {}), 'include');
});
