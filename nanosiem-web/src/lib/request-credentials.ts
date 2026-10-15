// SPDX-License-Identifier: AGPL-3.0-or-later

export class SessionExpiredError extends Error {
  readonly code = 'SESSION_EXPIRED';
  constructor() {
    super('Session expired — sign in again');
    this.name = 'SessionExpiredError';
  }
}

/** Only authentication/bootstrap routes may intentionally use cookies without
 * a bearer. Keep this explicit: /auth also contains protected tenant APIs.
 * The shared MFA step-up is NOT here (NAN-3905): it is a tenant-session
 * call and must carry the bearer; cookie-only it presents every tenant's
 * access-token cookie on the pooled host and is refused. */
export function allowsAnonymousRequest(endpoint: string): boolean {
  const path = endpoint.split('?')[0];
  return /^\/api\/auth\/(login|refresh|logout|methods|password\/reset-request|password\/reset|mfa\/(verify|setup|verify-setup|challenge))$/.test(path)
    || /^\/api\/auth\/(shared\/)?oidc\/(providers|[^/]+\/(authorize|callback))$/.test(path)
    || /^\/api\/(capabilities|setup(?:\/.*)?|demo\/session(?:\/[^/]+\/claim)?)$/.test(path)
    || /^\/api\/search\/shared\/[^/]+$/.test(path);
}

/** Bearer requests must not also present the origin's access-token cookie.
 * Shared logout revokes the authenticated tenant namespace on the server.
 * Omitting cookies also ignores Set-Cookie, preserving another tab's newer
 * session. The old refresh cookie is unusable after durable revocation.
 * Dedicated logout retains its existing cookie-clearing behavior.
 */
export function requestCredentials(endpoint: string, headers: HeadersInit, sharedSession = false): RequestCredentials {
  if (endpoint === '/api/auth/logout') {
    if (!sharedSession) return 'include';
    if (!new Headers(headers).has('Authorization')) throw new Error('Shared logout requires the tab bearer');
    return 'omit';
  }
  const authorization = new Headers(headers).get('Authorization');
  if (authorization && /^Bearer\s+\S+$/i.test(authorization)) return 'omit';
  if (!allowsAnonymousRequest(endpoint)) throw new SessionExpiredError();
  return 'include';
}
