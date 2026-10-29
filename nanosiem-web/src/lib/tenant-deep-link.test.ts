// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolveTenantlessDeepLink } from './tenant-deep-link';
import { rememberActiveTenant } from './tenant-auth-shell';
import { coordinateBrowserRefresh } from './refresh-coordinator';

vi.mock('./refresh-coordinator', async (original) => ({
  ...await original<typeof import('./refresh-coordinator')>(),
  coordinateBrowserRefresh: vi.fn(async (operation: () => Promise<unknown>) => operation()),
}));

const tenant = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', slug: 'acme' };
const user = { id: 'user-1', roles: [], is_api_key: false, deployment_mode: 'enterprise_shared', active_tenant: tenant };
const location = { pathname: '/ingestion/log-sources/wizard', search: '?source=okta', hash: '#issue' };
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

function sessionFetch(identity: unknown = user) {
  return vi.fn<typeof fetch>()
    .mockResolvedValueOnce(response({ deployment_mode: 'enterprise_shared' }))
    .mockResolvedValueOnce(response({ access_token: 'test-access', expires_in: 900 }))
    .mockResolvedValueOnce(response(identity));
}

afterEach(() => { window.localStorage.clear(); vi.clearAllMocks(); });

describe('production boot tenant-less redirect', () => {
  it('main waits for verification and navigates only to the verified target', () => {
    const main = readFileSync('src/main.tsx', 'utf8');
    expect(main).toContain('resolveTenantlessDeepLink(window.location).then(');
    expect(main).toContain('window.location.replace(tenantlessRedirect)');
  });

  it('checks the selected session before returning a tenant-scoped destination', async () => {
    rememberActiveTenant('acme');
    const fetch = sessionFetch();
    expect(await resolveTenantlessDeepLink(location, fetch)).toBe('/t/acme/ingestion/log-sources/wizard?source=okta#issue');
    expect(fetch.mock.calls[1]).toEqual(['/api/auth/refresh', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', redirect: 'error', body: JSON.stringify({ tenant_slug: 'acme' }),
    })]);
    expect(fetch.mock.calls[2]).toEqual(['/api/auth/me', expect.objectContaining({
      credentials: 'omit', redirect: 'error', headers: { Authorization: 'Bearer test-access' },
    })]);
    expect(coordinateBrowserRefresh).toHaveBeenCalledWith(expect.any(Function), {
      requireCoordination: true, scopeKey: 'enterprise_shared_slug:acme', cookieSlot: 'tenant:acme',
    });
  });

  it.each(['managed', 'self-hosted', 'demo'])('a stale hint never redirects a %s deployment or refreshes its cookies', async (mode) => {
    rememberActiveTenant('acme');
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response({ deployment_mode: mode }));
    expect(await resolveTenantlessDeepLink(location, fetch)).toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    { ...user, active_tenant: { ...tenant, slug: 'other' } },
    { ...user, active_tenant: null },
    { ...user, active_tenant: { ...tenant, id: 'invalid' } },
    { ...user, deployment_mode: 'managed' },
    { ...user, is_api_key: true },
    {}, null,
  ])('refuses a hint without an exact live session tenant: %j', async (identity) => {
    rememberActiveTenant('acme');
    expect(await resolveTenantlessDeepLink(location, sessionFetch(identity))).toBeUndefined();
  });

  it.each([401, 403, 503])('does not navigate after a failed refresh (%i)', async (status) => {
    rememberActiveTenant('acme');
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(response({ deployment_mode: 'enterprise_shared' }))
      .mockResolvedValueOnce(response({}, status));
    expect(await resolveTenantlessDeepLink(location, fetch)).toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('does not navigate after a revoked membership or unreadable identity', async () => {
    rememberActiveTenant('acme');
    for (const finalResponse of [response({}, 403), new Response('not json')]) {
      const fetch = sessionFetch().mockReset()
        .mockResolvedValueOnce(response({ deployment_mode: 'enterprise_shared' }))
        .mockResolvedValueOnce(response({ access_token: 'test-access', expires_in: 900 }))
        .mockResolvedValueOnce(finalResponse);
      expect(await resolveTenantlessDeepLink(location, fetch)).toBeUndefined();
    }
  });

  it('does not fetch for a missing hint, public path, or a tenant-escaping path', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(await resolveTenantlessDeepLink(location, fetch)).toBeUndefined();
    rememberActiveTenant('acme');
    for (const pathname of ['/login', '/auth/shared/activate', '/api', '/scripts/a.js', '/../other/search', '/%2e%2e/other/search']) {
      expect(await resolveTenantlessDeepLink({ ...location, pathname }, fetch)).toBeUndefined();
    }
    expect(fetch).not.toHaveBeenCalled();
  });
});
