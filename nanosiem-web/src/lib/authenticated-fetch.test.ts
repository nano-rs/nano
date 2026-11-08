// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />
import assert from 'node:assert/strict';
import test from 'node:test';
import { allowsAnonymousRequest, authenticatedFetch } from './authenticated-fetch.ts';
import { clearAccessToken, setAccessToken } from './auth-token.ts';
import { sessionCredentials, SessionExpiredError } from './session-credentials.ts';

const url = 'https://example.test/api/search';

test('JSON and SSE requests wait for refresh, then fetch exactly once each', async t => {
  setAccessToken('old', 900);
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const refreshing = sessionCredentials.runRefresh(async () => {
    await blocked;
    setAccessToken('new', 900);
    return true;
  });
  const sent: string[] = [];
  t.mock.method(globalThis, 'fetch', async (_url: string, options: RequestInit) => {
    sent.push(new Headers(options.headers).get('Authorization')!);
    return new Response('{}');
  });
  const requests = ['/api/dashboards', '/api/search/stream', '/api/cases/events']
    .map(endpoint => authenticatedFetch(endpoint, url));
  await Promise.resolve();
  assert.equal(sent.length, 0);
  release();
  await Promise.all([refreshing, ...requests]);
  assert.deepEqual(sent, ['Bearer new', 'Bearer new', 'Bearer new']);
});

test('concurrent 401s rotate once and replay JSON and SSE once', async t => {
  setAccessToken('rejected', 900);
  let refreshes = 0;
  sessionCredentials.configure(() => sessionCredentials.runRefresh(async () => {
    refreshes++;
    setAccessToken('replacement', 900);
    return true;
  }), null);
  const sent: string[] = [];
  t.mock.method(globalThis, 'fetch', async (_url: string, options: RequestInit) => {
    const credential = new Headers(options.headers).get('Authorization')!;
    sent.push(credential);
    return credential === 'Bearer rejected'
      ? new Response('{}', { status: 401 })
      : new Response('event: completed\ndata: {}\n\n');
  });
  await Promise.all([
    authenticatedFetch('/api/search', url),
    authenticatedFetch('/api/search/stream', url),
  ]);
  assert.equal(refreshes, 1);
  assert.deepEqual(sent, ['Bearer rejected', 'Bearer rejected', 'Bearer replacement', 'Bearer replacement']);
});

test('refresh failure gives one prompt and zero unauthenticated fetches', async t => {
  clearAccessToken();
  let prompts = 0;
  sessionCredentials.configure(() => sessionCredentials.runRefresh(async () => false), () => { prompts++; });
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not send'); });
  await Promise.all(Array.from({ length: 10 }, () => assert.rejects(authenticatedFetch('/api/search', url), SessionExpiredError)));
  assert.equal(prompts, 1);
  assert.equal(fetch.mock.callCount(), 0);
});

test('a second 401 expires once, while a non-auth retry error stays a normal response', async t => {
  setAccessToken('login', 900);
  let prompts = 0;
  sessionCredentials.configure(() => sessionCredentials.runRefresh(async () => {
    setAccessToken('retry', 900);
    return true;
  }), () => { prompts++; });
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('{}', { status: 401 }));
  await assert.rejects(authenticatedFetch('/api/search', url), SessionExpiredError);
  assert.equal(prompts, 1);
  assert.equal(fetch.mock.callCount(), 2);
  setAccessToken('another-login', 900);
  fetch.mock.mockImplementationOnce(async () => new Response('{}', { status: 401 }));
  fetch.mock.mockImplementationOnce(async () => new Response('{}', { status: 503 }));
  assert.equal((await authenticatedFetch('/api/search', url)).status, 503);
  assert.equal(prompts, 1);
});

test('a 401 from an anonymous auth route (wrong password) never refreshes or expires', async t => {
  clearAccessToken();
  let refreshes = 0;
  let prompts = 0;
  sessionCredentials.configure(async () => { refreshes++; return true; }, () => { prompts++; });
  t.mock.method(globalThis, 'fetch', async () => new Response('{}', { status: 401 }));
  const response = await authenticatedFetch('/api/auth/login', 'https://example.test/api/auth/login');
  assert.equal(response.status, 401);
  assert.equal(refreshes, 0);
  assert.equal(prompts, 0);
});

test('cancelled requests do not send after waiting for refresh', async t => {
  setAccessToken('cancel-login', 900);
  const controller = new AbortController();
  controller.abort();
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('{}'));
  await assert.rejects(authenticatedFetch('/api/search', url, { signal: controller.signal }), { name: 'AbortError' });
  assert.equal(fetch.mock.callCount(), 0);
});

test('only authentication and bootstrap routes are anonymous', () => {
  for (const endpoint of ['/api/auth/login', '/api/auth/refresh', '/api/auth/oidc/providers',
    '/api/auth/oidc/okta/callback', '/api/setup/status', '/api/capabilities', '/api/search/shared/abc']) {
    assert.ok(allowsAnonymousRequest(endpoint), endpoint);
  }
  for (const endpoint of ['/api/auth/me', '/api/auth/password', '/api/auth/mfa/status', '/api/search',
    '/api/search/history', '/api/rules', '/api/auth/loginx']) {
    assert.ok(!allowsAnonymousRequest(endpoint), endpoint);
  }
});
