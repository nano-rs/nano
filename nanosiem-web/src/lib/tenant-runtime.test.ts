// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  StaleTenantRuntimeError,
  TenantRuntimeAuthority,
  TenantRuntimeError,
  authenticatedRuntimeScope,
  refreshForCapturedRuntime,
  tenantQueryKey,
  tenantModuleCacheKey,
  tenantStorageKey,
} from './tenant-runtime.ts';

const TENANT_A = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', slug: 'tenant-a' };
const TENANT_B = { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', slug: 'tenant-b' };

test('a delayed tenant A response is discarded after activation of tenant B', async () => {
  const runtime = new TenantRuntimeAuthority();
  const tenantA = runtime.activate({
    kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_A,
  });
  let resolve!: (value: string) => void;
  const response = new Promise<string>((done) => { resolve = done; });
  const guarded = runtime.guard(tenantA, response);

  runtime.activate({ kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_B });
  resolve('tenant-a-data');

  await assert.rejects(guarded, StaleTenantRuntimeError);
});

test('a tenant switch during refresh prevents the original request retry', async () => {
  const runtime = new TenantRuntimeAuthority();
  const tenantA = runtime.activate({
    kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_A,
  });
  let retries = 0;

  await assert.rejects(
    async () => {
      const refreshed = await refreshForCapturedRuntime(runtime, tenantA, async () => {
        runtime.activate({
          kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_B,
        });
        return true;
      });
      if (refreshed) retries += 1;
    },
    StaleTenantRuntimeError,
  );
  assert.equal(retries, 0);
});

test('SSE callbacks and module cache keys are fenced by tenant epoch', () => {
  const runtime = new TenantRuntimeAuthority();
  const tenantA = runtime.activate({
    kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_A,
  });
  const cacheA = tenantModuleCacheKey(tenantA, 'autocomplete:schema');
  let callbacks = 0;
  assert.equal(runtime.runIfCurrent(tenantA, () => { callbacks += 1; }), true);

  const tenantB = runtime.activate({
    kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_B,
  });
  assert.equal(runtime.runIfCurrent(tenantA, () => { callbacks += 1; }), false);
  assert.equal(callbacks, 1);
  assert.notEqual(cacheA, tenantModuleCacheKey(tenantB, 'autocomplete:schema'));
});

test('identical product query and storage keys cannot collide across tenants', () => {
  const a = { kind: 'enterprise_shared' as const, userId: 'u', tenant: TENANT_A };
  const b = { kind: 'enterprise_shared' as const, userId: 'u', tenant: TENANT_B };
  assert.notDeepEqual(tenantQueryKey(a, ['alerts', 42]), tenantQueryKey(b, ['alerts', 42]));
  assert.notEqual(tenantStorageKey(a, 'saved-view'), tenantStorageKey(b, 'saved-view'));

  const dedicated = { kind: 'dedicated' as const, userId: 'u' };
  const original = ['alerts', 42] as const;
  assert.equal(tenantQueryKey(dedicated, original), original);
  assert.equal(tenantStorageKey(dedicated, 'saved-view'), 'saved-view');
});

test('same-browser dedicated users cannot share module search caches', () => {
  const runtime = new TenantRuntimeAuthority();
  const userA = runtime.activate({ kind: 'dedicated', userId: 'user-a' });
  const userB = runtime.activate({ kind: 'dedicated', userId: 'user-b' });
  assert.notEqual(
    tenantModuleCacheKey(userA, 'search-results'),
    tenantModuleCacheKey(userB, 'search-results'),
  );
});

test('logout advances the epoch and invalidates the authenticated runtime', () => {
  const runtime = new TenantRuntimeAuthority();
  const authenticated = runtime.activate({
    kind: 'enterprise_shared', userId: 'user-1', tenant: TENANT_A,
  });
  const loggedOut = runtime.activate({ kind: 'anonymous' });
  assert.ok(loggedOut.epoch > authenticated.epoch);
  assert.throws(() => runtime.assertCurrent(authenticated), StaleTenantRuntimeError);
});

test('enterprise_shared authentication without an exact active tenant fails closed', () => {
  assert.throws(
    () => authenticatedRuntimeScope({
      userId: 'user-1', deploymentMode: 'enterprise_shared', activeTenant: undefined,
    }),
    TenantRuntimeError,
  );
  assert.throws(
    () => authenticatedRuntimeScope({
      userId: 'user-1', deploymentMode: 'enterprise_shared',
      activeTenant: { id: 'not-a-uuid', slug: 'tenant-a' },
    }),
    TenantRuntimeError,
  );
});

test('server deployment mode is structurally required and dedicated modes stay tenantless', () => {
  assert.deepEqual(
    authenticatedRuntimeScope({ userId: 'u', roles: [], deploymentMode: 'managed' }),
    { kind: 'dedicated', userId: 'u' },
  );
  assert.throws(() => authenticatedRuntimeScope({
    userId: 'u', roles: [], deploymentMode: 'managed', activeTenant: TENANT_A,
  }), TenantRuntimeError);
});
