// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  acceptanceStep,
  clearInvitation,
  invitationTokenFromFragment,
  readInvitation,
  stashInvitation,
  tenantAcceptancePath,
  type ContinuationStorage,
} from './membership-acceptance-continuation.ts';
import { acceptEnterpriseSharedMembership } from './enterprise-shared-membership-acceptance.ts';
import { tenantContinuationBody, tenantSlugForAuthContinuation } from './tenant-auth-shell.ts';
import { TenantRuntimeAuthority } from './tenant-runtime.ts';

const USER = '018f6f72-84b6-7a10-9f11-7ab36f022001';
const SOURCE = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'tenant-a' };
const TARGET = { tenantId: '018f6f72-84b6-7a10-9f11-7ab36f02200b', slug: 'acme' };
const MEMBERSHIP = '018f6f72-84b6-7a10-9f11-7ab36f02200c';
const KEY = '018f6f72-84b6-7a10-9f11-7ab36f02200d';
const TOKEN = 'acceptance_0123456789abcdefghijklmnopqrstuvwxyz_ABC';

function memoryStorage(): ContinuationStorage & { size(): number } {
  const map = new Map<string, string>();
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => { map.set(key, value); },
    removeItem: (key) => { map.delete(key); },
    size: () => map.size,
  };
}

test('fresh load of the bare link: a signed-in user of another tenant can accept (NAN-3788)', async () => {
  const tab = memoryStorage();

  // 1. A partner admin opens `https://app.example.com/auth/shared/memberships/accept#<token>`.
  // Before the fix the page asked AuthContext for a session here; the refresh
  // carried no tenant slug, the pooled host refuses that, and the page always
  // showed "Invitation unavailable" without ever POSTing.
  const bare = '/auth/shared/memberships/accept';
  assert.equal(tenantSlugForAuthContinuation(bare), undefined);
  assert.deepEqual(tenantContinuationBody(tenantSlugForAuthContinuation(bare)), {}, 'refresh body has no tenant: refused');
  const fromLink = invitationTokenFromFragment(`#${TOKEN}`);
  assert.equal(fromLink, TOKEN);
  stashInvitation(tab, fromLink!);
  assert.equal(
    acceptanceStep({ pathname: bare, hasInvitation: true, isLoading: true, isAuthenticated: false }),
    'choose-tenant',
    'without a tenant prefix the page asks for the organization instead of waiting on a session it cannot get',
  );

  // 2. The user names the tenant they sign in to; a full load under its prefix.
  const scoped = tenantAcceptancePath(' Tenant-A ');
  assert.equal(scoped, '/t/tenant-a/auth/shared/memberships/accept');
  assert.equal(tenantSlugForAuthContinuation(scoped), 'tenant-a');
  assert.deepEqual(tenantContinuationBody(tenantSlugForAuthContinuation(scoped)), { tenant_slug: 'tenant-a' },
    'AuthContext now refreshes with the tenant selector');

  // 3. Not signed in there yet: sign in (login returns to the page). The token
  // survived the reloads in this tab only.
  assert.equal(acceptanceStep({ pathname: scoped, hasInvitation: readInvitation(tab) !== null, isLoading: false, isAuthenticated: false }), 'sign-in');
  assert.equal(readInvitation(tab), TOKEN);

  // 4. Signed in (fresh): accept with the tab bearer.
  assert.equal(acceptanceStep({ pathname: scoped, hasInvitation: true, isLoading: false, isAuthenticated: true }), 'accept');
  const runtime = new TenantRuntimeAuthority();
  runtime.activate({ kind: 'enterprise_shared', userId: USER, tenant: SOURCE });
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const replaced: string[] = [];
  const result = await acceptEnterpriseSharedMembership(`#${readInvitation(tab)}`, {
    runtime,
    replaceUrl: (path) => replaced.push(path),
    randomUuid: () => KEY,
    bearer: () => 'tab.bearer.jwt',
    acceptancePath: scoped,
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(input), init });
      return new Response(JSON.stringify({
        deploymentMode: 'enterprise_shared',
        sourceTenantId: SOURCE.id,
        targetTenant: TARGET,
        targetMembershipId: MEMBERSHIP,
        planCode: 'hobby',
        planRevision: 1,
        assignmentRevision: 1,
        authorityRevision: 3,
        idempotentReplay: false,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof globalThis.fetch,
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, '/api/auth/shared/memberships/accept');
  assert.equal(requests[0].init?.credentials, 'omit');
  assert.equal(new Headers(requests[0].init?.headers).get('Authorization'), 'Bearer tab.bearer.jwt');
  assert.deepEqual(JSON.parse(String(requests[0].init?.body)), { invitation_token: TOKEN, idempotency_key: KEY });
  assert.deepEqual(replaced, [scoped]);
  assert.deepEqual(result, { targetTenantId: TARGET.tenantId, targetTenantSlug: 'acme', targetLogin: '/t/acme/login' });

  // 5. The token is forgotten once accepted.
  clearInvitation(tab);
  assert.equal(tab.size(), 0);
  assert.equal(acceptanceStep({ pathname: scoped, hasInvitation: readInvitation(tab) !== null, isLoading: false, isAuthenticated: true }), 'missing');
});

test('no POST without a tab bearer or outside the acceptance path', async () => {
  const runtime = new TenantRuntimeAuthority();
  runtime.activate({ kind: 'enterprise_shared', userId: USER, tenant: SOURCE });
  let calls = 0;
  const base = {
    runtime,
    replaceUrl: () => {},
    randomUuid: () => KEY,
    fetch: (async () => { calls += 1; return new Response('{}'); }) as typeof globalThis.fetch,
  };
  await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, { ...base, bearer: () => null, acceptancePath: '/t/tenant-a/auth/shared/memberships/accept' }));
  await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, { ...base, bearer: () => 'x', acceptancePath: '/t/tenant-a/search' }));
  await assert.rejects(acceptEnterpriseSharedMembership(`#${TOKEN}`, { ...base, bearer: () => 'x', acceptancePath: '/t/%2e%2e/auth/shared/memberships/accept' }));
  assert.equal(calls, 0);
});

test('the tab continuation keeps only a well-formed token, briefly', () => {
  const tab = memoryStorage();
  assert.equal(invitationTokenFromFragment(''), null);
  assert.equal(invitationTokenFromFragment('#short'), null);
  assert.equal(invitationTokenFromFragment(`?${TOKEN}`), null);
  stashInvitation(tab, 'not a token');
  assert.equal(tab.size(), 0);

  stashInvitation(tab, TOKEN, 1_000);
  assert.equal(readInvitation(tab, 1_000 + 29 * 60 * 1000), TOKEN);
  assert.equal(readInvitation(tab, 1_000 + 31 * 60 * 1000), null, 'expired entries are dropped');
  assert.equal(tab.size(), 0);

  tab.setItem('nano.membership-acceptance', '{not json');
  assert.equal(readInvitation(tab), null);

  assert.throws(() => tenantAcceptancePath('../acme'));
  assert.throws(() => tenantAcceptancePath('ACME%2F'));
  assert.equal(acceptanceStep({ pathname: '/t/a/auth/shared/memberships/accept', hasInvitation: true, isLoading: true, isAuthenticated: false }), 'loading');
});
