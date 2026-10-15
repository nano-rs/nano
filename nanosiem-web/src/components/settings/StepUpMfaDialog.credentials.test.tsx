// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3905: the hosted SSO step-up must present exactly ONE credential.
 *
 * The browser holds sessions for two hosted tenants on the pooled origin
 * (`access_token__<d>` cookie per tenant). The fake server below applies the
 * shared-tenant extractor's rule (bearer + X-API-Key + access-token cookies
 * the request would carry must total exactly one, else 401 "Provide exactly
 * one authentication credential"). The real AuthProvider, ApiClient,
 * step-up dialog and shared OIDC admin adapter run against it: create is
 * refused for stale MFA, the dialog re-proves TOTP, and the retried create
 * succeeds.
 */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';

import { AuthProvider, useAuth, type User } from '@/contexts/AuthContext';
import { useStepUpMfa } from '@/components/settings/StepUpMfaDialog';
import { sharedCreateOidcProvider } from '@/lib/shared-oidc-admin';

const TENANT = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'ops' };
const INITIAL_BEARER = 'initial-bearer-0123456789';
const STEPPED_BEARER = 'stepped-bearer-0123456789';
const CODE = '123456';

const USER = {
  id: '018f6f72-84b6-7a10-9f11-7ab36f022001',
  email: 'dan@example.test',
  name: 'Dan',
  roles: ['admin'],
  permissions: ['*'],
  deployment_mode: 'enterprise_shared',
  active_tenant: TENANT,
} as unknown as User;

interface Seen {
  path: string;
  method: string;
  credentials: number;
  authorization: string | null;
  cookieMode: RequestCredentials | undefined;
}

let seen: Seen[] = [];
let validBearers = new Set<string>();
let mfaFresh = false;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** Access-token cookies the browser would attach for this request. */
function ambientAccessCookies(mode: RequestCredentials | undefined): number {
  if (mode === 'omit') return 0;
  return document.cookie
    .split(';')
    .map((c) => c.trim().split('=')[0])
    .filter((name) => name === 'access_token' || name.startsWith('access_token__')).length;
}

async function fakeServer(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const url = new URL(String(input), 'https://us.nano.test');
  const headers = new Headers(init.headers);
  const authorization = headers.get('Authorization');
  const credentials = (authorization ? 1 : 0)
    + (headers.has('X-API-Key') ? 1 : 0)
    + ambientAccessCookies(init.credentials);
  const method = (init.method ?? 'GET').toUpperCase();
  seen.push({ path: url.pathname, method, credentials, authorization, cookieMode: init.credentials });

  // Authentication requires exactly one credential.
  if (credentials !== 1) {
    return json({ error: 'unauthorized', message: 'Provide exactly one authentication credential' }, 401);
  }
  const bearer = authorization?.replace(/^Bearer /, '') ?? '';
  if (!validBearers.has(bearer)) return json({ error: 'unauthorized', message: 'Invalid token' }, 401);

  if (url.pathname === '/api/auth/me') return json(USER);
  if (url.pathname === '/api/auth/shared/mfa/step-up' && method === 'POST') {
    const body = JSON.parse(String(init.body)) as { code: string };
    if (body.code !== CODE) return json({ error: 'invalid_mfa_code', message: 'Invalid MFA code' }, 401);
    mfaFresh = true;
    validBearers = new Set([STEPPED_BEARER]); // the previous access token is revoked
    return json({
      user: USER,
      tokens: { access_token: STEPPED_BEARER, refresh_token: 'not-read-by-js', expires_in: 900 },
    });
  }
  if (url.pathname === '/api/auth/shared/oidc/admin/providers' && method === 'POST') {
    if (!mfaFresh) {
      return json({ error: 'oidc_provider_admin_denied', message: 'OIDC provider administration is unavailable' }, 403);
    }
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    return json({
      provider: {
        id: '018f6f72-84b6-7a10-9f11-7ab36f0220ff',
        name: body.name,
        slug: body.slug,
        issuer: body.issuer,
        clientId: body.client_id,
        scopes: body.scopes,
        groupClaim: null,
        enabled: true,
        revision: 1,
        secretRevision: 1,
        discoveryValidated: true,
      },
      revision: 1,
    });
  }
  return json({ error: 'route_not_available', message: 'This endpoint is not available for hosted tenants' }, 404);
}

function Harness() {
  const { acceptSharedOidcSession, isAuthenticated } = useAuth();
  const { run, dialog } = useStepUpMfa();
  const [result, setResult] = useState<string>('idle');
  return (
    <>
      <button
        type="button"
        onClick={() => void acceptSharedOidcSession(USER, TENANT.slug, { accessToken: INITIAL_BEARER, expiresIn: 900 })}
      >
        adopt
      </button>
      <span data-testid="authed">{String(isAuthenticated)}</span>
      <button
        type="button"
        onClick={() => {
          void run(() => sharedCreateOidcProvider({
            name: 'Google',
            slug: 'google',
            issuer: 'https://accounts.google.com',
            client_id: 'client',
            client_secret: 'secret',
          }))
            .then((p) => setResult(`created:${p.slug}`))
            .catch((e: unknown) => setResult(`failed:${e instanceof Error ? e.message : String(e)}`));
        }}
      >
        create
      </button>
      <span data-testid="result">{result}</span>
      {dialog}
    </>
  );
}

beforeEach(() => {
  seen = [];
  mfaFresh = false;
  validBearers = new Set([INITIAL_BEARER]);
  // The SSO callback route skips the cold-start cookie refresh; the session is
  // adopted explicitly below, exactly as the shared callback page does.
  window.history.replaceState(null, '', '/auth/shared/oidc/callback');
  // Two hosted tenants signed in on the same pooled origin.
  document.cookie = 'access_token__aaaaaaaaaaaaaaaa=tenant-a-access; path=/';
  document.cookie = 'access_token__bbbbbbbbbbbbbbbb=tenant-b-access; path=/';
  vi.stubGlobal('fetch', vi.fn(fakeServer));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  document.cookie = 'access_token__aaaaaaaaaaaaaaaa=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
  document.cookie = 'access_token__bbbbbbbbbbbbbbbb=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

it('step-up with two tenant cookies sends exactly one credential and the OIDC create then succeeds', async () => {
  expect(ambientAccessCookies('include')).toBe(2);
  render(<AuthProvider><Harness /></AuthProvider>);

  fireEvent.click(screen.getByText('adopt'));
  await waitFor(() => expect(screen.getByTestId('authed').textContent).toBe('true'));

  fireEvent.click(screen.getByText('create'));
  const input = await screen.findByPlaceholderText('000000');
  fireEvent.change(input, { target: { value: CODE } });
  await act(async () => {
    fireEvent.click(screen.getByText('Verify'));
  });

  await waitFor(() => expect(screen.getByTestId('result').textContent).toBe('created:google'));

  const stepUp = seen.filter((r) => r.path === '/api/auth/shared/mfa/step-up');
  expect(stepUp).toHaveLength(1);
  expect(stepUp[0]).toMatchObject({
    credentials: 1,
    authorization: `Bearer ${INITIAL_BEARER}`,
    cookieMode: 'omit',
  });

  const creates = seen.filter((r) => r.path === '/api/auth/shared/oidc/admin/providers');
  expect(creates.map((r) => r.authorization)).toEqual([
    `Bearer ${INITIAL_BEARER}`, // refused: stale MFA -> prompt
    `Bearer ${STEPPED_BEARER}`, // retried with the stepped-up bearer
  ]);

  // Every request presented exactly one credential: nothing was refused by
  // the extractor.
  for (const request of seen) {
    expect(request, `${request.method} ${request.path}`).toMatchObject({ credentials: 1 });
  }
});

it('a wrong code keeps the dialog open without a credential refusal', async () => {
  render(<AuthProvider><Harness /></AuthProvider>);
  fireEvent.click(screen.getByText('adopt'));
  await waitFor(() => expect(screen.getByTestId('authed').textContent).toBe('true'));

  fireEvent.click(screen.getByText('create'));
  fireEvent.change(await screen.findByPlaceholderText('000000'), { target: { value: '000000' } });
  await act(async () => {
    fireEvent.click(screen.getByText('Verify'));
  });
  await screen.findByText('Invalid MFA code');
  expect(screen.queryByText(/exactly one authentication credential/)).toBeNull();
});
