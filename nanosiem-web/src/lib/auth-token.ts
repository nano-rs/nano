// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * In-memory access token store.
 *
 * The access token is held in a module-scoped variable — never persisted to
 * localStorage or sessionStorage. On page reload the AuthContext performs a
 * silent refresh via the HttpOnly refresh-token cookie to obtain a new access
 * token, so the SPA recovers transparently.
 *
 * This module is intentionally framework-agnostic so it can be imported from
 * both React code (AuthContext) and non-React code (ApiClient, hooks).
 */

let accessToken: string | null = null;
let expiresAt: number = 0;

const DEMO_SESSION_KEY = 'nano_demo_session';

/** Store a new access token with its TTL (seconds). */
export function setAccessToken(token: string, expiresInSeconds: number): void {
  accessToken = token;
  expiresAt = Date.now() + expiresInSeconds * 1000;
}

/** Return the current access token, or null if absent/expired. */
export function getAccessToken(): string | null {
  if (!accessToken) return null;
  if (Date.now() >= expiresAt) {
    accessToken = null;
    return null;
  }
  return accessToken;
}

/** Clear the in-memory access token (logout / auth failure). */
export function clearAccessToken(): void {
  accessToken = null;
  expiresAt = 0;
  try { localStorage.removeItem(DEMO_SESSION_KEY); } catch { /* noop */ }
}

// -- Demo session persistence (localStorage) --
// Demo users don't have HttpOnly refresh cookies, so we persist their
// session in localStorage to survive page reloads, tab closes, and
// browser restarts for the full 72h session lifetime.

interface DemoSessionData {
  accessToken: string;
  refreshToken: string;
  /** Session expiry (72h from creation). Used to clear localStorage when session is truly over. */
  sessionExpiresAt: number;
  user: unknown;
}

const DEMO_SESSION_TTL_MS = 72 * 60 * 60 * 1000; // 72 hours

/** Persist a demo session so it survives page reloads and tab closes. */
export function persistDemoSession(token: string, refreshToken: string, _expiresInSeconds: number, user: unknown): void {
  try {
    // Preserve the original session expiry if resuming, otherwise set 72h from now
    const existing = localStorage.getItem(DEMO_SESSION_KEY);
    const sessionExpiresAt = existing
      ? (JSON.parse(existing) as DemoSessionData).sessionExpiresAt || (Date.now() + DEMO_SESSION_TTL_MS)
      : Date.now() + DEMO_SESSION_TTL_MS;

    const data: DemoSessionData = {
      accessToken: token,
      refreshToken,
      sessionExpiresAt,
      user,
    };
    localStorage.setItem(DEMO_SESSION_KEY, JSON.stringify(data));
  } catch { /* noop — localStorage may be unavailable */ }
}

/** Restore a demo session from localStorage. Returns null if session expired or missing. */
export function restoreDemoSession(): { accessToken: string; refreshToken: string; user: unknown } | null {
  try {
    const raw = localStorage.getItem(DEMO_SESSION_KEY);
    if (!raw) return null;
    const data: DemoSessionData = JSON.parse(raw);
    if (Date.now() >= (data.sessionExpiresAt || 0)) {
      localStorage.removeItem(DEMO_SESSION_KEY);
      return null;
    }
    return { accessToken: data.accessToken, refreshToken: data.refreshToken, user: data.user };
  } catch {
    return null;
  }
}

/** Get the demo refresh token from localStorage for token refresh requests. */
export function getDemoRefreshToken(): string | null {
  try {
    const raw = localStorage.getItem(DEMO_SESSION_KEY);
    if (!raw) return null;
    const data: DemoSessionData = JSON.parse(raw);
    return data.refreshToken || null;
  } catch {
    return null;
  }
}
