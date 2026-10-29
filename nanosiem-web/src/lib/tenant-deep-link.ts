// SPDX-License-Identifier: AGPL-3.0-or-later

import { accessOnlyRefreshResult, coordinateBrowserRefresh, tenantCookieSlot } from './refresh-coordinator';
import {
  isTenantlessProductPath,
  rememberedActiveTenant,
  tenantlessDeepLinkRedirect,
  verifyServerAuthIdentity,
  type ServerAuthIdentity,
} from './tenant-auth-shell';

/** Validate a tenant-less bookmark before main.tsx navigates, using existing auth APIs. */
export async function resolveTenantlessDeepLink(
  location: { pathname: string; search: string; hash: string },
  fetchImpl: typeof globalThis.fetch = globalThis.fetch,
): Promise<string | undefined> {
  const slug = rememberedActiveTenant();
  if (!slug) return undefined;
  if (!isTenantlessProductPath(location)) return undefined;
  const request = async (path: string, options: RequestInit = {}): Promise<unknown> => {
    const response = await fetchImpl(path, {
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
      ...options,
    });
    if (!response.ok) throw new Error('Tenant deep-link session verification failed');
    return response.json();
  };
  try {
    // A stale hint must never turn a dedicated session into a tenant login.
    const capabilities = await request('/api/capabilities') as { deployment_mode?: unknown } | null;
    if (capabilities?.deployment_mode !== 'enterprise_shared') return undefined;
    // Keep the existing explicit selector and cross-tab cookie rotation contract.
    // No server-side tenant inference or credential persistence is introduced.
    const refreshed = await coordinateBrowserRefresh(async () => {
      const result = await request('/api/auth/refresh', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_slug: slug }),
      }) as { access_token: string; expires_in: number };
      return accessOnlyRefreshResult(result);
    }, {
      requireCoordination: true,
      scopeKey: `enterprise_shared_slug:${slug}`,
      cookieSlot: tenantCookieSlot(slug),
    });
    if (typeof refreshed.access_token !== 'string' || !refreshed.access_token) return undefined;
    const user = await request('/api/auth/me', {
      headers: { Authorization: `Bearer ${refreshed.access_token}` },
    }) as ServerAuthIdentity & { is_api_key?: boolean };
    if (user.is_api_key !== false) return undefined;
    const verified = verifyServerAuthIdentity(user, slug);
    return tenantlessDeepLinkRedirect(location, slug, verified.activeTenant ? [verified.activeTenant] : []);
  } catch {
    // Revoked membership, expired session, malformed replies and outages stay put.
    return undefined;
  }
}
