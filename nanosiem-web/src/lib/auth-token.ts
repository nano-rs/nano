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
// NAN-5729: who the in-memory token belongs to, and a generation bumped
// synchronously whenever that owner changes (user switch, logout). Async
// work started under one session compares the generation after each await,
// so there is no window between installing user B's token and React
// re-rendering with user B in which it would act with B's token.
let tokenOwnerId: string | null = null;
let sessionGeneration = 0;

/** Called synchronously, before React re-renders, when the token's user changes. */
export type AuthSessionChangeListener = (previousOwnerId: string | null, nextOwnerId: string | null) => void;
const sessionListeners = new Set<AuthSessionChangeListener>();

/** Subscribe to token-owner changes; returns the unsubscribe function. */
export function onAuthSessionChange(listener: AuthSessionChangeListener): () => void {
  sessionListeners.add(listener);
  return () => { sessionListeners.delete(listener); };
}

function changeOwner(next: string | null): void {
  const previous = tokenOwnerId;
  tokenOwnerId = next;
  sessionGeneration += 1;
  sessionListeners.forEach(listener => {
    try { listener(previous, next); } catch (err) { console.error('auth session listener failed', err); }
  });
}

const DEMO_SESSION_KEY = 'nano_demo_session';

/** Store a new access token with its TTL (seconds) for the given user. */
export function setAccessToken(token: string, expiresInSeconds: number, ownerId: string): void {
  accessToken = token;
  expiresAt = Date.now() + expiresInSeconds * 1000;
  if (ownerId !== tokenOwnerId) changeOwner(ownerId);
}

/** Bumped whenever the token's user changes or the token is cleared. */
export function getAuthSessionGeneration(): number {
  return sessionGeneration;
}

/**
 * Snapshot the current auth session; the returned check is false once the
 * token's user changed or was cleared. Async UI work checks it after each
 * await so it never continues with another user's token.
 */
export function authSessionGuard(): () => boolean {
  const generation = sessionGeneration;
  return () => sessionGeneration === generation;
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
  if (tokenOwnerId !== null) changeOwner(null);
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
