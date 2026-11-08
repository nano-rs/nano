// SPDX-License-Identifier: AGPL-3.0-or-later
import { getAccessToken } from './auth-token.ts';
import { sessionCredentials } from './session-credentials.ts';

/** Only authentication / bootstrap routes may be sent without a bearer.
 * Keep this explicit: `/api/auth/*` also contains protected routes
 * (`/api/auth/me`, `/api/auth/password`, `/api/auth/mfa/status`, ...). */
export function allowsAnonymousRequest(endpoint: string): boolean {
  const path = endpoint.split('?')[0];
  return /^\/api\/auth\/(login|refresh|logout|methods|password\/reset-request|password\/reset|mfa\/(verify|setup|verify-setup|challenge))$/.test(path)
    || /^\/api\/auth\/oidc\/(providers|[^/]+\/(authorize|callback))$/.test(path)
    || /^\/api\/(capabilities|setup(?:\/.*)?|demo\/session(?:\/[^/]+\/claim)?)$/.test(path)
    || /^\/api\/search\/shared\/[^/]+$/.test(path);
}

/** NAN-2453: a protected request is never sent unauthenticated. It waits for
 * an in-flight refresh, carries the current bearer, and on 401 replays once
 * with the replacement; a second 401 expires the session once for the tab.
 * `assertCurrent` runs after every asynchronous boundary so a caller can
 * abandon a request whose context changed while it waited. */
export async function authenticatedFetch(
  endpoint: string,
  url: string,
  options: RequestInit = {},
  assertCurrent: () => void = () => {},
): Promise<Response> {
  const anonymous = allowsAnonymousRequest(endpoint);
  const token = anonymous ? getAccessToken() : await sessionCredentials.credential();
  const send = (credential: string | null) => {
    assertCurrent();
    options.signal?.throwIfAborted();
    const headers = new Headers(options.headers);
    if (credential) headers.set('Authorization', `Bearer ${credential}`);
    return fetch(url, { ...options, headers, credentials: 'include' });
  };
  let response = await send(token);
  assertCurrent();
  if (response.status === 401 && !anonymous) {
    await response.body?.cancel();
    const fresh = await sessionCredentials.credential(token ?? undefined);
    response = await send(fresh);
    assertCurrent();
    if (response.status === 401) {
      await response.body?.cancel();
      throw sessionCredentials.expire();
    }
  }
  return response;
}
