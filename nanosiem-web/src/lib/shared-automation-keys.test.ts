// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  apiKeyCreatedFromShared,
  apiKeyListFromShared,
  apiKeySummaryFromShared,
  isSharedKeyScope,
  sharedCreateRequest,
  sharedKeyStatus,
  sharedUpdateRequest,
  SharedApiKeyUnsupportedError,
  type SharedAutomationKeySummary,
} from './shared-automation-keys.ts';

const NOW = Date.parse('2026-09-16T12:00:00Z');

/** Exactly what `TenantAutomationKeySummary` serializes (camelCase). */
const wire: SharedAutomationKeySummary = {
  id: '0199a2d4-1111-7000-8000-000000000001',
  name: 'ci-robot',
  description: null,
  keyPrefix: 'nan_tak_0199a2d4',
  permissions: ['search:execute', 'alerts:view'],
  rateLimitPerMinute: 120,
  status: 'active',
  keyRevision: 3,
  expiresAt: '2026-12-01T00:00:00Z',
  lastUsedAt: null,
  createdAt: '2026-09-01T00:00:00Z',
  revokedAt: null,
};

test('list maps the camelCase registry onto the page contract (the black-screen case)', () => {
  const list = apiKeyListFromShared({ apiKeys: [wire], total: 1 }, NOW);
  assert.equal(list.total, 1);
  assert.equal(list.api_keys.length, 1);
  const key = list.api_keys[0];
  assert.equal(key.key_prefix, 'nan_tak_0199a2d4');
  assert.equal(key.rate_limit, 120);
  assert.equal(key.enabled, true);
  assert.equal(key.status, 'active');
  assert.equal(key.expires_at, '2026-12-01T00:00:00Z');
  assert.equal(key.last_used_at, undefined, 'null becomes absent like the dedicated shape');
  assert.equal(key.description, undefined);
  assert.equal(key.created_at, '2026-09-01T00:00:00Z');
  assert.equal(key.key_revision, 3);
  assert.deepEqual(key.permissions, ['search:execute', 'alerts:view']);
  // `ApiKeysView` does `keysRes.api_keys.find(...)`: never undefined.
  assert.ok(Array.isArray(list.api_keys));
});

test('a malformed or empty list never crashes the page', () => {
  assert.deepEqual(apiKeyListFromShared({ apiKeys: [], total: 0 }), { api_keys: [], total: 0 });
  assert.deepEqual(apiKeyListFromShared({} as never), { api_keys: [], total: 0 });
});

test('lifecycle: revoked is terminal, expiry is derived, enabled follows revocation only', () => {
  assert.equal(sharedKeyStatus(wire, NOW), 'active');
  assert.equal(sharedKeyStatus({ status: 'active', expiresAt: '2026-09-16T11:59:59Z' }, NOW), 'expired');
  assert.equal(sharedKeyStatus({ status: 'active', expiresAt: null }, NOW), 'active');
  assert.equal(sharedKeyStatus({ status: 'revoked', expiresAt: '2030-01-01T00:00:00Z' }, NOW), 'revoked');

  const revoked = apiKeySummaryFromShared({ ...wire, status: 'revoked', revokedAt: '2026-09-10T00:00:00Z' }, NOW);
  assert.equal(revoked.enabled, false);
  assert.equal(revoked.status, 'revoked');
  assert.equal(revoked.revoked_at, '2026-09-10T00:00:00Z');

  const expired = apiKeySummaryFromShared({ ...wire, expiresAt: '2026-09-01T00:00:00Z' }, NOW);
  assert.equal(expired.status, 'expired');
  assert.equal(expired.enabled, true, 'an expired key is still editable / revocable, so it is not "revoked"');
});

test('create and rotate expose the secret once under the dedicated `key` field', () => {
  const created = apiKeyCreatedFromShared({ ...wire, secret: 'nan_tak_0199a2d4…_s3cr3t' });
  assert.deepEqual(created, {
    id: wire.id,
    key: 'nan_tak_0199a2d4…_s3cr3t',
    name: 'ci-robot',
    created_at: '2026-09-01T00:00:00Z',
  });
  assert.equal('secret' in created, false);
});

test('create request is camelCase and carries no unknown snake_case field (deny_unknown_fields)', () => {
  const body = sharedCreateRequest({
    name: 'ci-robot',
    description: 'deploys',
    permissions: ['search:execute'],
    expires_at: '2026-12-01T00:00:00Z',
    rate_limit: 60,
  });
  assert.deepEqual(body, {
    name: 'ci-robot',
    description: 'deploys',
    permissions: ['search:execute'],
    rateLimitPerMinute: 60,
    expiresAt: '2026-12-01T00:00:00Z',
  });
  const minimal = sharedCreateRequest({ name: 'x', permissions: ['a:b'], description: undefined, rate_limit: undefined });
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(minimal))).sort(), ['name', 'permissions']);
  for (const key of Object.keys(body)) assert.ok(!key.includes('_'), `${key} is not camelCase`);
});

test('update request keeps the tri-state contract: omitted stays omitted, null clears', () => {
  const body = sharedUpdateRequest({ name: 'renamed', description: null, permissions: ['a:b'] });
  assert.deepEqual(body, { name: 'renamed', description: null, permissions: ['a:b'] });
  assert.equal('expiresAt' in body, false);
  assert.equal('rateLimitPerMinute' in body, false);
  assert.deepEqual(sharedUpdateRequest({ rate_limit: null, expires_at: '2027-01-01T00:00:00Z' }), {
    rateLimitPerMinute: null,
    expiresAt: '2027-01-01T00:00:00Z',
  });
  assert.deepEqual(sharedUpdateRequest({}), {});
});

test('dedicated-only lifecycle verbs fail with a typed reason instead of a 503', () => {
  const error = new SharedApiKeyUnsupportedError('enable');
  assert.equal(error.name, 'SharedApiKeyUnsupportedError');
  assert.equal(error.verb, 'enable');
  assert.match(error.message, /cannot be re-enabled/);
  assert.match(new SharedApiKeyUnsupportedError('disable').message, /Revoke/);
});

test('scope filter drops the wildcard and ambient platform permissions the registry rejects', () => {
  for (const ok of ['search:execute', 'alerts:view', 'apikeys:view', 'melod:query']) assert.equal(isSharedKeyScope(ok), true, ok);
  for (const bad of ['*', 'operator:all', 'support:grant', 'tenants:list', '', 'Search:Execute', 'a b']) {
    assert.equal(isSharedKeyScope(bad), false, bad);
  }
});
