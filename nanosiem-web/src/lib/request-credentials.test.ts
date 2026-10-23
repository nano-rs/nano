// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { requestCredentials } from './request-credentials.ts';

test('bearer reads, writes, and downloads exclude ambient cookies', () => {
  for (const endpoint of ['/api/auth/me', '/api/search/jobs', '/api/search/jobs/id/results/0']) {
    assert.equal(requestCredentials(endpoint, { Authorization: 'Bearer test' }), 'omit');
  }
});
test('header matching is case insensitive and supports every HeadersInit shape', () => {
  assert.equal(requestCredentials('/api/auth/me', new Headers({ authorization: 'Bearer test' })), 'omit');
  assert.equal(requestCredentials('/api/auth/me', [['authorization', 'Bearer test']]), 'omit');
});
test('login, MFA, and refresh preserve cookie installation and rotation', () => {
  // NAN-4152: the shared demo claim installs the same session cookies as a login.
  for (const endpoint of ['/api/auth/login', '/api/auth/mfa/verify', '/api/auth/refresh', '/api/auth/shared/demo/claim']) {
    assert.equal(requestCredentials(endpoint, {}), 'include');
  }
});
test('dedicated logout retains its existing cookie behavior', () => {
  assert.equal(requestCredentials('/api/auth/logout', { Authorization: 'Bearer test' }), 'include');
});
test('shared logout uses only the tab bearer and cannot mutate a sibling cookie', () => {
  assert.equal(requestCredentials('/api/auth/logout', { Authorization: 'Bearer tenant-a' }, true), 'omit');
  assert.throws(() => requestCredentials('/api/auth/logout', {}, true), /requires the tab bearer/);
});
test('tenant bootstrap and streaming search use the credential-gated transport', () => {
  const bootstrap = readFileSync(new URL('../contexts/CapabilitiesProvider.tsx', import.meta.url), 'utf8');
  assert.match(bootstrap, /authenticatedFetch\(\s*'\/api\/auth\/tenant-bootstrap'/);
  const search = readFileSync(new URL('./api/search.ts', import.meta.url), 'utf8');
  assert.match(search, /authenticatedFetch\('\/api\/search\/stream'/);
});
test('MITRE catalog and rule-version raw fetches never present two credentials (NAN-2361)', () => {
  const mitre = readFileSync(new URL('../hooks/useMitreData.ts', import.meta.url), 'utf8');
  assert.match(mitre, /credentials: requestCredentials\(path, headers\)/);
  assert.doesNotMatch(mitre, /credentials: 'include'/);
  const editor = readFileSync(new URL('../pages/RuleEditorRedesign.tsx', import.meta.url), 'utf8');
  assert.match(editor, /credentials: requestCredentials\(`\/api\/rules\/\$\{id\}\/versions`, headers\)/);
});
