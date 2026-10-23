// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-4152: `/t/demo/...` serves the tenant whose real slug is
// `lean-internal-20261004b`. Every server-visible auth value built under the
// alias must be identical to the canonical path's; navigation stays on the
// alias; with no alias every helper behaves exactly as before.

import assert from 'node:assert/strict';
import test from 'node:test';
import { AuthApi } from './api/auth.ts';
import {
  completeEnterpriseSharedOidc,
  startEnterpriseSharedOidcLogin,
  type SharedOidcBrowserDependencies,
} from './enterprise-shared-oidc.ts';
import { cookieSlotForScope } from './refresh-coordinator.ts';
import {
  TenantAuthContractError,
  currentTenantPathAlias,
  initTenantPathAlias,
  loginRequestBody,
  resolveTenantPathAlias,
  setTenantPathAlias,
  swaggerUiPath,
  tenantBasename,
  tenantContinuationBody,
  tenantLoginPath,
  tenantMfaSetupPath,
  tenantSearchPath,
  tenantShellPath,
  tenantSlugForAuthContinuation,
  tenantSlugFromLoginPath,
  tenantSlugFromMfaSetupPath,
  tenantSlugFromScopedPath,
  tenantSlugFromSearchPath,
  tenantSlugFromShellPath,
  tenantSlugFromSocPath,
  tenantSocPath,
  verifyServerAuthIdentity,
} from './tenant-auth-shell.ts';
import { TENANT_COMPONENT_CODES } from './tenant-capabilities.ts';
import { TenantRuntimeAuthority } from './tenant-runtime.ts';

const ALIAS = 'demo';
const CANONICAL = 'lean-internal-20261004b';
const TENANT = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: CANONICAL };
const USER_ID = '018f6f72-84b6-7a10-9f11-7ab36f022001';

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
}

function withAlias<T>(fn: () => T): T {
  setTenantPathAlias({ pathSegment: ALIAS, canonicalSlug: CANONICAL });
  try {
    return fn();
  } finally {
    setTenantPathAlias(null);
  }
}

async function withAliasAsync<T>(fn: () => Promise<T>): Promise<T> {
  setTenantPathAlias({ pathSegment: ALIAS, canonicalSlug: CANONICAL });
  try {
    return await fn();
  } finally {
    setTenantPathAlias(null);
  }
}

/** Every server-visible auth value the SPA derives from a browser path. */
async function authValues(prefix: string) {
  const mfaBodies: unknown[] = [];
  const api = new AuthApi(async <T>(_endpoint: string, options?: RequestInit) => {
    mfaBodies.push(JSON.parse(String(options?.body)));
    return {} as T;
  });
  const mfaSlug = tenantSlugFromMfaSetupPath(`${prefix}/mfa-setup`);
  await api.setupMfa('challenge-token', mfaSlug);
  await api.verifyMfaSetup('123456', 'challenge-token', mfaSlug);
  await api.verifyMfaChallenge('challenge-token', '123456', tenantSlugFromLoginPath(`${prefix}/login`));
  const routeSlug = tenantSlugForAuthContinuation(`${prefix}/alerts/abc`);
  const anonymous = new TenantRuntimeAuthority().current().scope;
  return {
    login: loginRequestBody('a@example.test', 'pw', tenantSlugFromLoginPath(`${prefix}/login`)),
    refresh: tenantContinuationBody(routeSlug),
    cookieSlot: cookieSlotForScope(anonymous, routeSlug),
    mfa: mfaBodies,
    shell: tenantSlugFromShellPath(prefix),
    search: tenantSlugFromSearchPath(`${prefix}/search`),
    soc: tenantSlugFromSocPath(`${prefix}/rules`),
    scoped: tenantSlugFromScopedPath(`${prefix}/dashboards/x`),
    swagger: swaggerUiPath(`${prefix}/settings`),
  };
}

test('auth values under the alias are deep-equal to the canonical path', async () => {
  const canonical = await withAliasAsync(() => authValues(`/t/${CANONICAL}`));
  const aliased = await withAliasAsync(() => authValues(`/t/${ALIAS}`));
  assert.deepEqual(aliased, canonical);
  assert.deepEqual(aliased.login, { email: 'a@example.test', password: 'pw', tenant_slug: CANONICAL });
  assert.deepEqual(aliased.refresh, { tenant_slug: CANONICAL });
  assert.equal(aliased.cookieSlot, `tenant:${CANONICAL}`);
  for (const body of aliased.mfa) assert.equal((body as { tenant_slug: string }).tenant_slug, CANONICAL);
  assert.equal(aliased.swagger, `/t/${CANONICAL}/swagger-ui/`, 'the server routes API docs by the real slug');
  // The identity check compares the server's tenant with the canonical slug.
  withAlias(() => {
    const verified = verifyServerAuthIdentity(
      { id: USER_ID, roles: [], deployment_mode: 'enterprise_shared', active_tenant: TENANT },
      tenantSlugFromLoginPath(`/t/${ALIAS}/login`),
    );
    assert.equal(verified.activeTenant?.slug, CANONICAL);
  });
});

test('basename keeps the raw segment and builders stay on the alias', () => {
  withAlias(() => {
    assert.equal(tenantBasename(`/t/${ALIAS}/alerts`), `/t/${ALIAS}`);
    assert.equal(tenantBasename(`/t/${CANONICAL}/alerts`), `/t/${CANONICAL}`);
    assert.equal(tenantLoginPath(CANONICAL), `/t/${ALIAS}/login`);
    assert.equal(tenantShellPath(CANONICAL), `/t/${ALIAS}`);
    assert.equal(tenantSearchPath(CANONICAL), `/t/${ALIAS}/search`);
    assert.equal(tenantMfaSetupPath(CANONICAL), `/t/${ALIAS}/mfa-setup`);
    assert.equal(tenantSocPath(CANONICAL, 'alerts', 'abc'), `/t/${ALIAS}/alerts/abc`);
    // Another tenant is untouched.
    assert.equal(tenantLoginPath('tenant-b'), '/t/tenant-b/login');
  });
});

test('with no alias every helper behaves as before', () => {
  setTenantPathAlias(null);
  assert.equal(currentTenantPathAlias(), null);
  assert.equal(tenantSlugFromLoginPath('/t/demo/login'), 'demo');
  assert.equal(tenantSlugForAuthContinuation('/t/demo/alerts'), 'demo');
  assert.equal(tenantBasename('/t/demo/alerts'), '/t/demo');
  assert.equal(tenantLoginPath(CANONICAL), `/t/${CANONICAL}/login`);
  assert.equal(tenantShellPath('demo'), '/t/demo');
  assert.equal(tenantBasename('/t/Demo/alerts'), undefined);
  assert.equal(tenantBasename('/settings'), undefined);
  assert.throws(() => tenantSlugFromLoginPath('/t/de%2Fmo/login'), TenantAuthContractError);
});

test('an unknown segment never maps to another tenant', () => {
  withAlias(() => {
    for (const segment of ['tenant-b', 'demo2', 'dem', 'lean-internal-20261004c']) {
      assert.equal(tenantSlugForAuthContinuation(`/t/${segment}/alerts`), segment);
      assert.equal(tenantSlugFromLoginPath(`/t/${segment}/login`), segment);
    }
    // Non-canonical lookalikes of the alias still refuse instead of resolving.
    for (const path of ['/t/Demo/login', '/t/demo%20/login', '/t/d%65mo/login']) {
      assert.throws(() => tenantSlugFromLoginPath(path), TenantAuthContractError, path);
    }
  });
  assert.throws(() => setTenantPathAlias({ pathSegment: 'demo', canonicalSlug: 'demo' }), TenantAuthContractError);
  assert.throws(() => setTenantPathAlias({ pathSegment: 'Demo', canonicalSlug: CANONICAL }), TenantAuthContractError);
  assert.equal(currentTenantPathAlias(), null);
});

function recordingFetch(response: () => Response | Promise<Response>) {
  const urls: string[] = [];
  const fetch = (async (url: string | URL | Request) => {
    urls.push(String(url));
    return response();
  }) as typeof globalThis.fetch;
  return { fetch, urls };
}

test('boot resolution: only /t/ paths, exact canonical answers, anything else is no alias', async () => {
  const ok = recordingFetch(() => json({ canonical_slug: CANONICAL }));
  assert.deepEqual(await resolveTenantPathAlias('/t/demo/alerts', ok.fetch), { pathSegment: ALIAS, canonicalSlug: CANONICAL });
  assert.deepEqual(ok.urls, ['/api/auth/shared/tenant-path-alias/demo']);

  const off = recordingFetch(() => json({ canonical_slug: CANONICAL }));
  for (const path of ['/', '/login', '/auth/shared/oidc/callback', '/t/', '/t/Demo/alerts', '/t/de%2Fmo/x']) {
    assert.equal(await resolveTenantPathAlias(path, off.fetch), null, path);
  }
  assert.deepEqual(off.urls, [], 'non-tenant or non-canonical paths never fetch');

  for (const [name, respond] of [
    ['404', () => json({ error: 'not_found' }, 404)],
    ['503', () => json({ error: 'unavailable' }, 503)],
    ['network', () => { throw new TypeError('offline'); }],
    ['html fallback', () => new Response('<!doctype html>', { status: 200, headers: { 'Content-Type': 'text/html' } })],
    ['non-canonical slug', () => json({ canonical_slug: 'Lean-Internal' })],
    ['trailing hyphen', () => json({ canonical_slug: 'lean-' })],
    ['self-map', () => json({ canonical_slug: ALIAS })],
    ['extra field', () => json({ canonical_slug: CANONICAL, tenant_id: TENANT.id })],
    ['array', () => json([CANONICAL])],
    ['number', () => json({ canonical_slug: 7 })],
  ] as const) {
    assert.equal(await resolveTenantPathAlias('/t/demo/login', recordingFetch(respond).fetch), null, name);
  }

  await initTenantPathAlias('/t/demo/login', recordingFetch(() => json({ canonical_slug: 'x/y' })).fetch);
  assert.equal(currentTenantPathAlias(), null, 'a rejected answer installs nothing');
  await initTenantPathAlias('/t/demo/login', ok.fetch);
  assert.deepEqual(currentTenantPathAlias(), { pathSegment: ALIAS, canonicalSlug: CANONICAL });
  setTenantPathAlias(null);
});

// ---- OIDC: start body identical, callback returns to the alias ------------

class MemoryStorage {
  readonly values = new Map<string, string>();
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  setItem(key: string, value: string): void { this.values.set(key, value); }
  removeItem(key: string): void { this.values.delete(key); }
}

function oidcHarness(responses: Response[]) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(url), init });
    const response = responses.shift();
    if (!response) throw new Error('unexpected fetch');
    return response;
  }) as typeof globalThis.fetch;
  const deps: SharedOidcBrowserDependencies = {
    fetch,
    sessionStorage: new MemoryStorage(),
    runtime: new TenantRuntimeAuthority(),
    replaceUrl: () => undefined,
  };
  return { deps, requests };
}

const entry = {
  url: 'https://idp.example/authorize?state=opaque',
  deploymentMode: 'enterprise_shared',
  tenant: { tenantId: TENANT.id, slug: CANONICAL },
  providerSlug: 'entra-workforce',
  authorityRevision: 4,
};
const callback = {
  user: { id: USER_ID, email: 'a@example.test', name: 'A', roles: ['analyst'], permissions: ['search:execute'] },
  tenant_id: TENANT.id, tenant_slug: CANONICAL, authority_revision: 4, assignment_revision: 7,
};
const me = {
  id: USER_ID, email: 'a@example.test', name: 'A', roles: ['analyst'], permissions: ['search:execute'],
  is_api_key: false, preferred_query_mode: null, landing_page: null,
  deployment_mode: 'enterprise_shared', active_tenant: TENANT,
};
const bootstrap = {
  edition: 'enterprise', version: '0.1.0', deploymentMode: 'enterprise_shared', tenant: TENANT,
  identity: { userId: USER_ID, roles: ['analyst'], permissions: ['search:execute'], authorizationRevision: 4 },
  plan: { code: 'hobby', revision: 2, assignmentRevision: 7 },
  limits: { ha_enabled: true, retention_days: 365 }, haEnabled: true,
  components: Object.fromEntries(TENANT_COMPONENT_CODES.map((c) => [c, { enabled: true, configuration: {} }])),
  featureFlags: { revision: 2, flags: {
    parser_cell_canary: false, r2_archive_cache_read: false, soc_ai_long_hunts: false, oidc_group_role_reconciliation: false,
  } },
};
const refreshed = { access_token: 'tab-bearer-0123456789abcdef', refresh_token: 'x', expires_in: 900 };

async function oidcRoundTrip(loginPath: string, aliasAnswer: Response | null) {
  const responses = [json(entry), json(callback), json(refreshed), json(me), json(bootstrap)];
  if (aliasAnswer) responses.push(aliasAnswer);
  const harness = oidcHarness(responses);
  // The login page passes the slug parsed from its own path.
  await startEnterpriseSharedOidcLogin(tenantSlugFromLoginPath(loginPath), 'entra-workforce', harness.deps, '/alerts');
  // The callback page lives outside /t/: no alias is installed there.
  setTenantPathAlias(null);
  const result = await completeEnterpriseSharedOidc(new URLSearchParams({ code: 'c', state: 's' }), harness.deps);
  return { result, requests: harness.requests };
}

test('OIDC bodies under the alias equal the canonical ones; the user returns to the alias', async () => {
  setTenantPathAlias({ pathSegment: ALIAS, canonicalSlug: CANONICAL });
  const aliased = await oidcRoundTrip(`/t/${ALIAS}/login`, json({ canonical_slug: CANONICAL }));
  // A page on the canonical path never has the alias installed.
  setTenantPathAlias(null);
  const canonical = await oidcRoundTrip(`/t/${CANONICAL}/login`, null);

  const bodies = (r: typeof aliased) => r.requests.filter((q) => q.url.startsWith('/api/auth/') && !q.url.includes('tenant-path-alias'))
    .map((q) => ({ url: q.url, body: q.init?.body === undefined ? undefined : JSON.parse(String(q.init.body)) }));
  assert.deepEqual(bodies(aliased), bodies(canonical));
  assert.deepEqual(bodies(aliased)[0].body, { tenant_slug: CANONICAL, provider_slug: 'entra-workforce' });
  assert.equal(aliased.result.destination, `/t/${ALIAS}/alerts`);
  assert.equal(aliased.requests.at(-1)?.url, '/api/auth/shared/tenant-path-alias/demo');
  // Entered canonically: stays canonical.
  assert.equal(canonical.result.destination, `/t/${CANONICAL}/alerts`);
});

test('OIDC callback never returns to an alias that now names another tenant', async () => {
  setTenantPathAlias({ pathSegment: ALIAS, canonicalSlug: CANONICAL });
  const moved = await oidcRoundTrip(`/t/${ALIAS}/login`, json({ canonical_slug: 'tenant-b' }));
  assert.equal(moved.result.destination, `/t/${CANONICAL}/alerts`);
  setTenantPathAlias({ pathSegment: ALIAS, canonicalSlug: CANONICAL });
  const gone = await oidcRoundTrip(`/t/${ALIAS}/login`, json({ error: 'not_found' }, 404));
  assert.equal(gone.result.destination, `/t/${CANONICAL}/alerts`);
  // Without an alias the flow is exactly as before: no alias lookup at all.
  setTenantPathAlias(null);
  const plain = await oidcRoundTrip(`/t/${CANONICAL}/login`, null);
  assert.equal(plain.result.destination, `/t/${CANONICAL}/alerts`);
  assert.ok(!plain.requests.some((q) => q.url.includes('tenant-path-alias')));
});

test('boot resolution is bounded and sends no credentials', async () => {
  let seen: RequestInit | undefined;
  const fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    seen = init;
    return json({ canonical_slug: CANONICAL });
  }) as typeof globalThis.fetch;
  await resolveTenantPathAlias('/t/demo', fetch);
  assert.equal(seen?.credentials, 'omit');
  assert.ok(seen?.signal instanceof AbortSignal, 'a hung lookup must not block the first render');
});
