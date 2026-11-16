// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Session-presence cookie (NAN-5483).
 *
 * The refresh token is an HttpOnly cookie, invisible to JS, so on page load
 * the SPA could not tell a returning user from a visitor who never signed in.
 * It always probed `POST /api/auth/refresh`, which answers 400 `missing_token`
 * for the latter — logged in red by the browser on every signed-out load.
 *
 * The API now sets `nano_session=1` (not HttpOnly, no secret) alongside every
 * refresh cookie it issues or rotates, with the same lifetime, and clears it
 * whenever it clears the refresh cookie. Its absence means there is nothing to
 * refresh, so the page-load probe can be skipped.
 *
 * The cookie is only observable when the API shares the page's origin. With a
 * cross-origin `VITE_API_URL` it lives on the API host's cookie jar, so we keep
 * probing there (old behaviour) rather than signing everyone out.
 */

export const SESSION_PRESENCE_COOKIE = 'nano_session';

function readCookieJar(): string {
  try {
    return typeof document === 'undefined' ? '' : document.cookie;
  } catch {
    return '';
  }
}

/** True when the API sets cookies this page can read via `document.cookie`. */
export function canObserveSessionPresence(
  apiBaseUrl: string = import.meta.env.VITE_API_URL ?? '',
): boolean {
  if (!apiBaseUrl) return true;
  try {
    return new URL(apiBaseUrl, window.location.href).origin === window.location.origin;
  } catch {
    return false;
  }
}

export function hasSessionPresenceCookie(): boolean {
  return readCookieJar()
    .split(';')
    .some((part) => {
      const [name, value] = part.trim().split('=');
      return name === SESSION_PRESENCE_COOKIE && !!value;
    });
}

/**
 * Whether the page-load silent refresh is worth sending. False only when we
 * can see the cookie jar and it says no refresh cookie was ever issued (or it
 * was cleared / expired).
 */
export function shouldProbeSilentRefresh(apiBaseUrl?: string): boolean {
  return !canObserveSessionPresence(apiBaseUrl) || hasSessionPresenceCookie();
}

/**
 * Drop the presence cookie locally. Used on logout so a failed logout request
 * (e.g. expired access token) still lands the next load on the login page
 * without a probe. The server-side clear remains the authority.
 */
export function clearSessionPresenceCookie(): void {
  try {
    if (typeof document === 'undefined') return;
    const secure = window.location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = `${SESSION_PRESENCE_COOKIE}=; SameSite=Strict; Path=/; Max-Age=0${secure}`;
  } catch {
    // cookie access blocked — nothing to clear
  }
}
