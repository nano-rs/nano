// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3905 hosted SSO admin wire contract. The settings page lists providers
 * from `/api/settings/oidc`, which names them by `oidc_<base32>` TypeID; the
 * hosted mutations must go to the step-up admin API
 * (`/api/auth/shared/oidc/admin/providers/{uuid}…`) — never to the dedicated
 * `/api/settings/oidc/{id}/…` family, and never with the TypeID the hosted
 * route fence used to refuse with 404 `route_not_available`.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { clearAccessToken, setAccessToken } from '@/lib/auth-token';
import {
  adminProviderId,
  sharedCreateOidcProvider,
  sharedDeleteOidcProvider,
  sharedSetOidcProviderEnabled,
  sharedUpdateOidcProvider,
} from '@/lib/shared-oidc-admin';
import type { OidcProviderSummary } from '@/lib/api/types';

const UUID = '018f6f72-84b6-7a10-9f11-7ab36f0220ff';
// Same vector as nanosiem-core typeid::encode("oidc", UUID).
const TYPEID = 'oidc_01hxqq515pf889y4btpdqg487z';

const ROW: OidcProviderSummary = {
  id: TYPEID,
  name: 'Google',
  slug: 'google',
  issuer: 'https://accounts.google.com',
  enabled: false,
  scopes: ['openid', 'email', 'profile'],
  created_at: '2026-10-15T00:00:00Z',
  updated_at: '2026-10-15T00:00:00Z',
};

function adminProvider(enabled: boolean) {
  return {
    id: UUID, name: 'Google', slug: 'google', issuer: 'https://accounts.google.com', clientId: 'client',
    scopes: ['openid'], groupClaim: null, enabled, revision: 2, secretRevision: 1, discoveryValidated: true,
  };
}

let calls: Array<{ method: string; path: string }> = [];

beforeEach(() => {
  calls = [];
  setAccessToken('tab-bearer-0123456789', 900);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const path = new URL(String(input), 'https://us.nano.test').pathname;
    const method = (init.method ?? 'GET').toUpperCase();
    calls.push({ method, path });
    const enabled = path.endsWith('/enable');
    const body = method === 'GET'
      ? { providers: [adminProvider(false)] }
      : { provider: adminProvider(enabled), revision: 2 };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearAccessToken();
});

it('decodes the settings TypeID to the admin UUID and passes UUIDs through', () => {
  expect(adminProviderId(TYPEID)).toBe(UUID);
  expect(adminProviderId(UUID.toUpperCase())).toBe(UUID);
  for (const bad of ['rule_01hxqq515pf889y4btpdqg487z', 'oidc_81hxqq515pf889y4btpdqg487z', 'oidc_short', '../x', '']) {
    expect(() => adminProviderId(bad), bad).toThrow();
  }
});

it('hosted enable / disable / update / rotate / delete use the shared admin paths with the UUID', async () => {
  await sharedSetOidcProviderEnabled(ROW, true);
  await sharedSetOidcProviderEnabled({ ...ROW, enabled: true }, false);
  await sharedUpdateOidcProvider(ROW, undefined, { name: 'Google Workspace', client_secret: 'new-secret', enabled: true });
  await sharedDeleteOidcProvider(TYPEID);
  await sharedCreateOidcProvider({
    name: 'Google', slug: 'google', issuer: 'https://accounts.google.com', client_id: 'client', client_secret: 'secret',
  });

  const base = '/api/auth/shared/oidc/admin/providers';
  expect(calls).toEqual([
    { method: 'POST', path: `${base}/${UUID}/enable` },
    { method: 'POST', path: `${base}/${UUID}/disable` },
    { method: 'GET', path: base }, // client_id lookup (settings read never returns it)
    { method: 'PUT', path: `${base}/${UUID}` },
    { method: 'POST', path: `${base}/${UUID}/rotate-secret` },
    { method: 'POST', path: `${base}/${UUID}/enable` },
    { method: 'DELETE', path: `${base}/${UUID}` },
    { method: 'POST', path: base },
  ]);
  for (const { path } of calls) {
    expect(path).not.toContain('/api/settings/oidc');
    expect(path).not.toContain('oidc_');
  }
});

it('carries group policy and credential removal through the MFA admin update', async () => {
  const policy = { mapped_groups_only: true, mappings: [{ idp_group: 'security', role_ids: [UUID], group_ids: [] }], verified_domains: ['example.com'] };
  await sharedUpdateOidcProvider(ROW, 'client', { access_policy: policy, clear_google_service_account: true });
  const update = vi.mocked(fetch).mock.calls.find(([, init]) => init?.method === 'PUT');
  expect(update).toBeDefined();
  const body = JSON.parse(String(update![1]!.body));
  expect(body.access_policy).toEqual(policy);
  expect(body.clear_google_service_account).toBe(true);
  expect(body).not.toHaveProperty('mfa_code');
  expect(body).not.toHaveProperty('google_service_account');
});
