// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  acceptEnterpriseSharedMembership,
  SharedMembershipAcceptanceBrowserError,
} from './enterprise-shared-membership-acceptance.ts';
import { TenantRuntimeAuthority } from './tenant-runtime.ts';

const USER = '018f6f72-84b6-7a10-9f11-7ab36f022001';
const TENANT_A = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'tenant-a' };
const TENANT_B = { tenantId: '018f6f72-84b6-7a10-9f11-7ab36f02200b', slug: 'tenant-b' };
const MEMBERSHIP = '018f6f72-84b6-7a10-9f11-7ab36f02200c';
const KEY = '018f6f72-84b6-7a10-9f11-7ab36f02200d';
const TOKEN = 'acceptance_0123456789abcdefghijklmnopqrstuvwxyz_ABC';
const BEARER = 'tab.bearer.jwt';
const PATH = '/t/tenant-a/auth/shared/memberships/accept';

function success(overrides: Record<string, unknown> = {}) {
  return {
    deploymentMode: 'enterprise_shared',
    sourceTenantId: TENANT_A.id,
    targetTenant: TENANT_B,
    targetMembershipId: MEMBERSHIP,
    planCode: 'hobby',
    planRevision: 1,
    assignmentRevision: 1,
    authorityRevision: 9,
    idempotentReplay: false,
    ...overrides,
  };
}

function runtime(): TenantRuntimeAuthority {
  const runtime = new TenantRuntimeAuthority();
  runtime.activate({ kind: 'enterprise_shared', userId: USER, tenant: TENANT_A });
  return runtime;
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

test('authenticated A accepts exact B without persisting token or switching runtime', async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const replacements: string[] = [];
  const authority = runtime();
  const before = authority.current();
  const result = await acceptEnterpriseSharedMembership(`#${TOKEN}`, {
    runtime: authority,
    replaceUrl: (path) => replacements.push(path),
    randomUuid: () => KEY,
    bearer: () => BEARER,
    acceptancePath: PATH,
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(input), init });
      return json(success());
    }) as typeof globalThis.fetch,
  });

  assert.deepEqual(replacements, [PATH], 'the tenant prefix survives the fragment scrub');
  assert.deepEqual(result, {
    targetTenantId: TENANT_B.tenantId,
    targetTenantSlug: 'tenant-b',
    targetLogin: '/t/tenant-b/login',
  });
  assert.equal(authority.current(), before);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, '/api/auth/shared/memberships/accept');
  // NAN-3788: the tab bearer, never the per-tenant access cookie.
  assert.equal(requests[0].init?.credentials, 'omit');
  assert.equal(new Headers(requests[0].init?.headers).get('Authorization'), `Bearer ${BEARER}`);
  assert.deepEqual(JSON.parse(String(requests[0].init?.body)), {
    invitation_token: TOKEN,
    idempotency_key: KEY,
  });
});

test('one network retry reuses the same idempotency key and response errors never retry', async () => {
  const bodies: string[] = [];
  let attempts = 0;
  await acceptEnterpriseSharedMembership(`#${TOKEN}`, {
    runtime: runtime(),
    replaceUrl: () => {},
    randomUuid: () => KEY,
    bearer: () => BEARER,
    acceptancePath: PATH,
    fetch: (async (_input: string | URL | Request, init?: RequestInit) => {
      attempts += 1;
      bodies.push(String(init?.body));
      if (attempts === 1) throw new Error('lost response');
      return json(success({ idempotentReplay: true }));
    }) as typeof globalThis.fetch,
  });
  assert.equal(attempts, 2);
  assert.equal(bodies[0], bodies[1]);

  let rejectedCalls = 0;
  await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, {
    runtime: runtime(),
    replaceUrl: () => {},
    randomUuid: () => KEY,
    bearer: () => BEARER,
    acceptancePath: PATH,
    fetch: (async () => {
      rejectedCalls += 1;
      return json({ error: 'membership_acceptance_failed' }, 401);
    }) as typeof globalThis.fetch,
  }), SharedMembershipAcceptanceBrowserError);
  assert.equal(rejectedCalls, 1);
});

test('anonymous, malformed, stale, cross-tenant and credential-shaped results fail closed', async () => {
  let calls = 0;
  const anonymous = new TenantRuntimeAuthority();
  await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, {
    runtime: anonymous,
    replaceUrl: () => {},
    randomUuid: () => KEY,
    bearer: () => BEARER,
    acceptancePath: PATH,
    fetch: (async () => { calls += 1; return json(success()); }) as typeof globalThis.fetch,
  }), SharedMembershipAcceptanceBrowserError);
  await assert.rejects(acceptEnterpriseSharedMembership('?invitation=leak', {
    runtime: runtime(),
    replaceUrl: () => {},
    randomUuid: () => KEY,
    bearer: () => BEARER,
    acceptancePath: PATH,
    fetch: (async () => { calls += 1; return json(success()); }) as typeof globalThis.fetch,
  }), SharedMembershipAcceptanceBrowserError);
  assert.equal(calls, 0);

  for (const response of [
    success({ sourceTenantId: TENANT_B.tenantId }),
    success({ targetTenant: { ...TENANT_B, tenantId: TENANT_A.id } }),
    { ...success(), accessToken: 'forbidden' },
  ]) {
    await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, {
      runtime: runtime(),
      replaceUrl: () => {},
      randomUuid: () => KEY,
      bearer: () => BEARER,
      acceptancePath: PATH,
      fetch: (async () => json(response)) as typeof globalThis.fetch,
    }), SharedMembershipAcceptanceBrowserError);
  }

  const stale = runtime();
  await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, {
    runtime: stale,
    replaceUrl: () => {},
    randomUuid: () => KEY,
    bearer: () => BEARER,
    acceptancePath: PATH,
    fetch: (async () => {
      const response = json(success());
      stale.activate({ kind: 'enterprise_shared', userId: USER, tenant: {
        id: '018f6f72-84b6-7a10-9f11-7ab36f02200e', slug: 'tenant-c',
      } });
      return response;
    }) as typeof globalThis.fetch,
  }), SharedMembershipAcceptanceBrowserError);
});

test('browser contract has no storage, cookie, query-token, or credential API', async () => {
  const source = await readFile(fileURLToPath(new URL(
    './enterprise-shared-membership-acceptance.ts', import.meta.url,
  )), 'utf8');
  assert.doesNotMatch(source, /localStorage|sessionStorage|document\.cookie/);
  assert.doesNotMatch(source, /accessToken|refreshToken|setAccessToken/);
  assert.match(source, /replaceUrl\(dependencies\.acceptancePath\)/);
  assert.match(source, /credentials: 'omit'/);
  assert.doesNotMatch(source, /credentials: 'include'/);
  assert.doesNotMatch(source, /URLSearchParams|location\.search/);
});
