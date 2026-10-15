// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3905: a hosted tenant's login (`/t/<slug>/login`) discovers providers
 * and starts SSO only through the shared tenant-local OIDC contract
 * (`/api/auth/shared/oidc/providers` → `/start`, fixed callback
 * `/auth/shared/oidc/callback`). It must never fall back to the dedicated
 * `/api/auth/oidc/{slug}/authorize` family, which is closed on hosted tenants.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

const auth = vi.hoisted(() => ({
  state: {
    login: vi.fn(),
    loginWithOidc: vi.fn(),
    isAuthenticated: false,
    isLoading: false,
    error: null as string | null,
    clearError: vi.fn(),
    mfaPending: false,
    mfaSetupPending: false,
    challengeToken: null as string | null,
    verifyMfa: vi.fn(),
    cancelMfa: vi.fn(),
    user: null,
    pendingTenantSlug: null,
  },
}));

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => auth.state }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { sso: false } }),
}));
vi.stubGlobal('__APP_VERSION__', '0.0.0-test');

import { Login } from './Login';

const TENANT = { tenantId: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'ops' };
let calls: Array<{ path: string; body: unknown; credentials: RequestCredentials | undefined }> = [];

beforeEach(() => {
  calls = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const path = new URL(String(input), 'https://us.nano.test').pathname;
    calls.push({ path, body: init.body ? JSON.parse(String(init.body)) : null, credentials: init.credentials });
    if (path === '/api/auth/shared/oidc/providers') {
      return Response.json({ providers: [{ slug: 'google', name: 'Google' }], localPasswordEnabled: true });
    }
    if (path === '/api/auth/shared/oidc/start') {
      return Response.json({
        url: 'https://accounts.google.com/o/oauth2/v2/auth?state=opaque',
        deploymentMode: 'enterprise_shared',
        tenant: TENANT,
        providerSlug: 'google',
        authorityRevision: 1,
      });
    }
    return Response.json({ error: 'route_not_available' }, { status: 404 });
  }));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

it('hosted tenant login discovers and starts SSO through the shared OIDC path only', async () => {
  render(
    <MemoryRouter>
      <Login tenantSlug="ops" />
    </MemoryRouter>,
  );
  const [button] = await screen.findAllByLabelText('Continue with Google');
  await act(async () => {
    fireEvent.click(button);
  });

  expect(auth.state.loginWithOidc).not.toHaveBeenCalled();
  expect(calls.map((c) => c.path)).toEqual([
    '/api/auth/shared/oidc/providers',
    '/api/auth/shared/oidc/start',
  ]);
  expect(calls[0].body).toEqual({ tenant_slug: 'ops' });
  expect(calls[1].body).toEqual({ tenant_slug: 'ops', provider_slug: 'google' });
  for (const { path } of calls) {
    expect(path).not.toMatch(/^\/api\/auth\/oidc\//);
  }
});
