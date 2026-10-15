// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  beginEnterpriseSharedOidc,
  completeEnterpriseSharedOidc,
  discoverEnterpriseSharedLoginMethods,
  discoverEnterpriseSharedOidcProviders,
  enterpriseSharedOidcContract,
  SharedOidcBrowserError,
  startEnterpriseSharedOidcLogin,
  type SharedOidcBrowserDependencies,
} from './enterprise-shared-oidc.ts';
import { TENANT_COMPONENT_CODES } from './tenant-capabilities.ts';
import { TenantRuntimeAuthority } from './tenant-runtime.ts';

const USER_ID = '018f6f72-84b6-7a10-9f11-7ab36f022001';
const TENANT_A = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'tenant-a' };
const TENANT_B = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200b', slug: 'tenant-b' };
const ENTRY_TOKEN = 'entry_0123456789abcdefghijklmnopqrstuvwxyz_ABCDEFG';

class MemoryStorage {
  readonly values = new Map<string, string>();
  readonly writes: Array<[string, string]> = [];

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
    this.writes.push([key, value]);
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function user(tenant = TENANT_A) {
  return {
    id: USER_ID,
    email: 'analyst@example.test',
    name: 'Analyst',
    roles: ['analyst'],
    permissions: ['search:execute'],
    is_api_key: false,
    preferred_query_mode: null,
    landing_page: null,
    deployment_mode: 'enterprise_shared',
    active_tenant: tenant,
  };
}

function bootstrap(tenant = TENANT_A, assignmentRevision = 7) {
  return {
    edition: 'enterprise',
    version: '0.1.0',
    deploymentMode: 'enterprise_shared',
    tenant,
    identity: {
      userId: USER_ID,
      roles: ['analyst'],
      permissions: ['search:execute'],
      authorizationRevision: 4,
    },
    plan: { code: 'hobby', revision: 2, assignmentRevision },
    limits: { ha_enabled: true, retention_days: 365 },
    haEnabled: true,
    components: Object.fromEntries(TENANT_COMPONENT_CODES.map((component) => [
      component,
      { enabled: true, configuration: {} },
    ])),
    featureFlags: {
      revision: 2,
      flags: {
        parser_cell_canary: false,
        r2_archive_cache_read: false,
        soc_ai_long_hunts: false,
        oidc_group_role_reconciliation: false,
      },
    },
  };
}

function callback(tenant = TENANT_A, assignmentRevision = 7) {
  return {
    user: {
      id: USER_ID,
      email: 'analyst@example.test',
      name: 'Analyst',
      roles: ['analyst'],
      permissions: ['search:execute'],
    },
    tenant_id: tenant.id,
    tenant_slug: tenant.slug,
    authority_revision: 4,
    assignment_revision: assignmentRevision,
  };
}

function entry(tenant = TENANT_A, authorityRevision = 4) {
  return {
    url: 'https://idp.example/authorize?state=opaque-server-state',
    deploymentMode: 'enterprise_shared',
    tenant: { tenantId: tenant.id, slug: tenant.slug },
    providerSlug: 'entra-workforce',
    authorityRevision,
  };
}

interface RecordedRequest {
  url: string;
  init?: RequestInit;
}

function dependencies(responses: Response[]) {
  const requests: RecordedRequest[] = [];
  const storage = new MemoryStorage();
  const runtime = new TenantRuntimeAuthority();
  const replacements: string[] = [];
  const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(url), init });
    const response = responses.shift();
    if (!response) throw new Error('unexpected fetch');
    return response;
  }) as typeof globalThis.fetch;
  const deps: SharedOidcBrowserDependencies = {
    fetch,
    sessionStorage: storage,
    runtime,
    replaceUrl: (path) => replacements.push(path),
  };
  return { deps, requests, storage, runtime, replacements };
}

async function begin(deps: SharedOidcBrowserDependencies): Promise<void> {
  const url = await beginEnterpriseSharedOidc(`#${ENTRY_TOKEN}`, deps);
  assert.match(url, /^https:\/\/idp\.example\/authorize/);
}

test('repeat login discovers minimal tenant labels and starts the same exact callback contract', async () => {
  const harness = dependencies([
    json({ providers: [{ slug: 'entra-workforce', name: 'Company SSO' }] }),
    json(entry()),
    json(callback()),
    json(user()),
    json(bootstrap()),
  ]);
  const providers = await discoverEnterpriseSharedOidcProviders('tenant-a', harness.deps);
  assert.deepEqual(providers, [{ slug: 'entra-workforce', name: 'Company SSO' }]);
  const authorizeUrl = await startEnterpriseSharedOidcLogin(
    'tenant-a',
    'entra-workforce',
    harness.deps,
  );
  assert.match(authorizeUrl, /^https:\/\/idp\.example\/authorize/);
  const result = await completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'repeat-code', state: 'repeat-state' }),
    harness.deps,
  );
  assert.equal(result.destination, '/t/tenant-a');
  assert.deepEqual(JSON.parse(String(harness.requests[0].init?.body)), {
    tenant_slug: 'tenant-a',
  });
  assert.deepEqual(JSON.parse(String(harness.requests[1].init?.body)), {
    tenant_slug: 'tenant-a',
    provider_slug: 'entra-workforce',
  });
  assert.equal(harness.requests[0].url, '/api/auth/shared/oidc/providers');
  assert.equal(harness.requests[1].url, '/api/auth/shared/oidc/start');
  assert.equal(harness.requests[0].init?.credentials, 'include');
  assert.equal(harness.requests[1].init?.credentials, 'include');
});

test('the uniform 401 from provider discovery means "no SSO", not a failure', async () => {
  // Anti-enumeration: the server answers 401 for an unknown tenant and for a
  // known tenant with no provider alike. The login page must treat it as an
  // empty provider list (local credentials only) — no error state, no retry.
  const harness = dependencies([
    json({ error: 'unauthorized', message: 'Tenant or provider unavailable' }, 401),
  ]);
  const methods = await discoverEnterpriseSharedLoginMethods('tenant-a', harness.deps);
  assert.deepEqual(methods, { providers: [], localPasswordEnabled: true });
  assert.equal(harness.requests.length, 1);
  assert.equal(harness.storage.values.size, 0);

  // Any other non-OK status is still a hard failure.
  const broken = dependencies([json({ error: 'unavailable' }, 503)]);
  await assert.rejects(
    discoverEnterpriseSharedOidcProviders('tenant-a', broken.deps),
    SharedOidcBrowserError,
  );
});

test('tenant login discovery carries the password sign-in flag and defaults it to enabled', async () => {
  const ssoOnly = dependencies([
    json({ providers: [{ slug: 'entra-workforce', name: 'Company SSO' }], localPasswordEnabled: false }),
  ]);
  assert.deepEqual(await discoverEnterpriseSharedLoginMethods('tenant-a', ssoOnly.deps), {
    providers: [{ slug: 'entra-workforce', name: 'Company SSO' }],
    localPasswordEnabled: false,
  });
  const legacy = dependencies([json({ providers: [{ slug: 'entra-workforce', name: 'Company SSO' }] })]);
  assert.equal((await discoverEnterpriseSharedLoginMethods('tenant-a', legacy.deps)).localPasswordEnabled, true);
  const wrongType = dependencies([
    json({ providers: [{ slug: 'entra-workforce', name: 'Company SSO' }], localPasswordEnabled: 'no' }),
  ]);
  await assert.rejects(discoverEnterpriseSharedLoginMethods('tenant-a', wrongType.deps), SharedOidcBrowserError);
  const extra = dependencies([
    json({ providers: [{ slug: 'entra-workforce', name: 'Company SSO' }], localPasswordEnabled: false, issuer: 'x' }),
  ]);
  await assert.rejects(discoverEnterpriseSharedLoginMethods('tenant-a', extra.deps), SharedOidcBrowserError);
});

test('repeat login rejects malicious selectors and credential-bearing discovery without persistence', async () => {
  const malformed = dependencies([]);
  await assert.rejects(
    discoverEnterpriseSharedOidcProviders('../tenant-a', malformed.deps),
    SharedOidcBrowserError,
  );
  await assert.rejects(
    startEnterpriseSharedOidcLogin('tenant-a', 'provider/other', malformed.deps),
    SharedOidcBrowserError,
  );
  assert.equal(malformed.requests.length, 0);
  assert.equal(malformed.storage.values.size, 0);

  const leaked = dependencies([
    json({ providers: [{ slug: 'entra-workforce', name: 'Company SSO', issuer: 'secret' }] }),
  ]);
  await assert.rejects(
    discoverEnterpriseSharedOidcProviders('tenant-a', leaked.deps),
    SharedOidcBrowserError,
  );
  assert.equal(leaked.storage.values.size, 0);

  const mismatch = dependencies([json(entry(TENANT_B))]);
  await assert.rejects(
    startEnterpriseSharedOidcLogin('tenant-a', 'entra-workforce', mismatch.deps),
    SharedOidcBrowserError,
  );
  assert.equal(mismatch.storage.values.size, 0);
});

test('shared success posts only code/state, relies on cookies, and proves exact tenant bootstrap', async () => {
  const harness = dependencies([
    json(entry()),
    json(callback()),
    json(user()),
    json(bootstrap()),
  ]);
  await begin(harness.deps);

  const result = await completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'one-time-code', state: 'opaque-server-state' }),
    harness.deps,
  );

  assert.equal(result.destination, '/t/tenant-a');
  assert.equal(result.tenant.tenant.id, TENANT_A.id);
  assert.deepEqual(harness.replacements, [
    '/auth/shared/oidc/entry',
    '/auth/shared/oidc/callback',
  ]);
  assert.equal(harness.storage.getItem(enterpriseSharedOidcContract.pendingStorageKey), null);

  assert.equal(
    harness.requests[0].url,
    '/api/auth/shared/oidc/entry',
  );
  assert.deepEqual(JSON.parse(String(harness.requests[0].init?.body)), {
    entry_token: ENTRY_TOKEN,
  });
  assert.equal(harness.requests[0].init?.method, 'POST');
  assert.equal(harness.requests[0].init?.credentials, 'include');
  assert.equal(harness.requests[1].url, '/api/auth/shared/oidc/callback');
  assert.deepEqual(JSON.parse(String(harness.requests[1].init?.body)), {
    code: 'one-time-code',
    state: 'opaque-server-state',
  });
  assert.equal(harness.requests[2].url, '/api/auth/me');
  assert.equal(harness.requests[3].url, '/api/auth/tenant-bootstrap');
  for (const request of harness.requests) {
    assert.equal(request.init?.headers instanceof Headers, false);
    assert.equal(JSON.stringify(request).includes('Authorization'), false);
  }

  const browserWrites = JSON.stringify(harness.storage.writes);
  assert.equal(browserWrites.includes('one-time-code'), false);
  assert.equal(browserWrites.includes('opaque-server-state'), false);
  assert.equal(browserWrites.includes(ENTRY_TOKEN), false);
  assert.doesNotMatch(browserWrites, /access.?token|refresh.?token|bearer/i);
});

test('callback replay and IdP errors clear pending intent without another exchange', async () => {
  const replay = dependencies([
    json(entry()),
    json(callback()),
    json(user()),
    json(bootstrap()),
  ]);
  await begin(replay.deps);
  await completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'code', state: 'opaque' }),
    replay.deps,
  );
  await assert.rejects(
    completeEnterpriseSharedOidc(
      new URLSearchParams({ code: 'code', state: 'opaque' }),
      replay.deps,
    ),
    SharedOidcBrowserError,
  );
  assert.equal(replay.requests.length, 4);

  const providerError = dependencies([
    json(entry()),
  ]);
  await begin(providerError.deps);
  await assert.rejects(
    completeEnterpriseSharedOidc(
      new URLSearchParams({ error: 'access_denied', error_description: 'tenant-a exists' }),
      providerError.deps,
    ),
    { message: 'Single sign-on failed. Please try again.' },
  );
  assert.equal(providerError.requests.length, 1);
  assert.equal(providerError.storage.values.size, 0);
});

test('malicious fragments never reach the entry endpoint and response authority is exact', async () => {
  for (const fragment of [
    '', '#', '#../tenant-b', '#token=secret', '#abc%2fadmin', '#with.dot',
  ]) {
    const harness = dependencies([]);
    await assert.rejects(
      beginEnterpriseSharedOidc(fragment, harness.deps),
      SharedOidcBrowserError,
    );
    assert.equal(harness.requests.length, 0);
    assert.deepEqual(harness.replacements, ['/auth/shared/oidc/entry']);
  }

  for (const response of [
    { ...entry(), deploymentMode: 'managed' },
    { ...entry(), tenant: { tenantId: TENANT_A.id, slug: '../tenant-b' } },
    { ...entry(), providerSlug: '%2fadmin' },
    { ...entry(), url: 'javascript:alert(1)' },
    { ...entry(), refreshToken: 'must-not-exist' },
  ]) {
    const harness = dependencies([json(response)]);
    await assert.rejects(beginEnterpriseSharedOidc(`#${ENTRY_TOKEN}`, harness.deps));
    assert.equal(harness.storage.values.size, 0);
  }
});

test('wrong tenant, assignment revision, and stale tenant runtime fail closed', async () => {
  for (const responses of [
    [callback(TENANT_B), user(TENANT_B), bootstrap(TENANT_B)],
    [callback(TENANT_A, 8), user(), bootstrap(TENANT_A, 7)],
  ]) {
    const harness = dependencies([
      json(entry()),
      ...responses.map((response) => json(response)),
    ]);
    await begin(harness.deps);
    await assert.rejects(completeEnterpriseSharedOidc(
      new URLSearchParams({ code: 'code', state: 'opaque' }),
      harness.deps,
    ), SharedOidcBrowserError);
    assert.equal(harness.storage.values.size, 0);
  }

  const stale = dependencies([
    json(entry()),
    json(callback()),
    json(user()),
    json(bootstrap()),
  ]);
  await begin(stale.deps);
  const originalFetch = stale.deps.fetch;
  let calls = 0;
  stale.deps.fetch = (async (...args: Parameters<typeof globalThis.fetch>) => {
    const response = await originalFetch(...args);
    calls += 1;
    if (calls === 3) {
      stale.runtime.activate({ kind: 'enterprise_shared', userId: USER_ID, tenant: TENANT_B });
    }
    return response;
  }) as typeof globalThis.fetch;
  await assert.rejects(completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'code', state: 'opaque' }),
    stale.deps,
  ), SharedOidcBrowserError);
});

test('token-shaped callback fields are rejected and never persisted', async () => {
  const harness = dependencies([
    json(entry()),
    json({ ...callback(), access_token: 'must-not-reach-js' }),
  ]);
  await begin(harness.deps);
  await assert.rejects(completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'code', state: 'opaque' }),
    harness.deps,
  ), SharedOidcBrowserError);
  assert.equal(JSON.stringify(harness.storage.writes).includes('must-not-reach-js'), false);
  assert.equal(harness.storage.values.size, 0);
});

test('successful callback HTTP marks the cookie mutation before later proof can fail', async () => {
  const harness = dependencies([
    json(entry()),
    json({ malformed: true }),
  ]);
  let mutations = 0;
  harness.deps.onCookieMutation = () => { mutations += 1; };
  await begin(harness.deps);
  await assert.rejects(completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'code', state: 'opaque' }),
    harness.deps,
  ), SharedOidcBrowserError);
  assert.equal(mutations, 1);

  const rejected = dependencies([
    json(entry()),
    json({ error: 'rejected' }, 401),
  ]);
  rejected.deps.onCookieMutation = () => { mutations += 1; };
  await begin(rejected.deps);
  await assert.rejects(completeEnterpriseSharedOidc(
    new URLSearchParams({ code: 'code', state: 'opaque' }),
    rejected.deps,
  ), SharedOidcBrowserError);
  assert.equal(mutations, 1, 'a rejected exchange must not claim a cookie replacement');
});

test('dedicated login stays unchanged while shared tenant login uses only the tenant-local adapter', async () => {
  const here = fileURLToPath(new URL('.', import.meta.url));
  const [app, login, auth, sharedPage] = await Promise.all([
    readFile(new URL('../App.tsx', `file://${here}`), 'utf8'),
    readFile(new URL('../pages/Login.tsx', `file://${here}`), 'utf8'),
    readFile(new URL('../contexts/AuthContext.tsx', `file://${here}`), 'utf8'),
    readFile(new URL('../pages/EnterpriseSharedOidc.tsx', `file://${here}`), 'utf8'),
  ]);

  // /login is one route; outside a tenant basename it renders the dedicated
  // <Login />, under one it renders <Login tenantSlug=…> off the browser path.
  assert.match(app, /path="\/login" element=\{<LoginRoute \/>\}/);
  assert.match(app, /function LoginRoute\(\)[\s\S]*?if \(!raw\.startsWith\('\/t\/'\)\) return <Login \/>;/);
  assert.match(app, /path="\/auth\/callback\/:provider" element=\{<AuthCallback \/>\}/);
  assert.match(app, /path="\/auth\/shared\/oidc\/entry"/);
  assert.match(app, /path="\/auth\/shared\/oidc\/callback"/);
  assert.match(login, /const ssoEnabled = tenantSlug !== undefined \|\| capabilities\.sso;/);
  assert.match(login, /tenantSlug === undefined\s*\? fetch\(`\$\{API_BASE_URL\}\/api\/auth\/oidc\/providers`/);
  assert.match(login, /discoverEnterpriseSharedLoginMethods\(tenantSlug, sharedOidcDependencies\(\)\)/);
  // NAN-2361 wave 8: on a tenant URL the password flag comes from the same
  // discovery call; the dedicated `/api/auth/methods` fetch is not used.
  assert.match(login, /if \(tenantSlug !== undefined\) return;\s*let cancelled = false;\s*fetch\(`\$\{API_BASE_URL\}\/api\/auth\/methods`\)/);
  assert.doesNotMatch(login, /if \(tenantSlug !== undefined\) \{\s*setLocalPasswordEnabled\(true\);/);
  assert.match(login, /startEnterpriseSharedOidcLogin\(/);
  assert.match(login, /window\.location\.assign\(authorizeUrl\)/);
  assert.match(auth, /`\/api\/auth\/oidc\/\$\{providerSlug\}\/authorize/);
  assert.doesNotMatch(auth, /`\/api\/auth\/shared\/oidc/);
  assert.ok(
    (auth.match(/withBrowserCookieMutationLock/g) ?? []).length >= 4,
    'password, MFA, dedicated OIDC, and logout must share the origin cookie lock',
  );
  const sharedAcceptance = auth.slice(
    auth.indexOf('const acceptSharedOidcSession'),
    auth.indexOf('const isDemoUser'),
  );
  assert.match(sharedAcceptance, /const nextState = authenticatedState/);
  assert.match(sharedAcceptance, /broadcastSessionReplacement\(\s*refreshScopeKey\(nextState\.tenantRuntime\.scope\),\s*authenticatedCookieSlot\(nextState\),\s*\)/);
  assert.match(sharedPage, /withBrowserCookieMutationLock\(async \(\) =>/);
  assert.match(sharedPage, /\{ requireCoordination: true \}/);
  assert.match(sharedPage, /onCookieMutation/);
  assert.match(sharedPage, /await dependencies\.fetch\('\/api\/auth\/logout'/);
  assert.match(sharedPage, /discardFailedSharedOidcSession\(\)/);
  assert.match(sharedPage, /broadcastSessionInvalidation\('enterprise-shared-oidc-callback-failed', ALL_COOKIE_SLOTS\)/);
  assert.match(sharedPage, /window\.history\.replaceState/);
  assert.match(sharedPage, /window\.location\.hash/);
  assert.doesNotMatch(sharedPage, /localStorage|setAccessToken|getAccessToken/);
});
