// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Single-use grants for running a search on arrival (NAN-5235).
 *
 * A Search URL alone never runs a query: anyone can link a signed-in analyst
 * to `/search?q=…&run=…`. In-app callers that want the query to run on
 * arrival grant it first. The grant is stored in this origin's localStorage
 * (so it also reaches a tab opened with `noopener`), bound to the exact query
 * text, expires after two minutes, and is consumed by the first Search page
 * that reads it. Another site cannot write this origin's storage, so it cannot
 * mint a grant. A `run` value without a matching grant (including the legacy
 * `run=true`) only loads the query and asks the user to run it.
 */

import { safeRandomUUID } from '@/lib/uuid';

const PREFIX = 'nano:search-auto-run:';
export const SEARCH_AUTO_RUN_TTL_MS = 2 * 60 * 1000;
const TOKEN_RE = /^[A-Za-z0-9-]{16,64}$/;

interface Grant {
  q: string;
  exp: number;
}

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.localStorage : null;
  } catch {
    return null;
  }
}

function read(store: Storage, token: string): Grant | null {
  try {
    const raw = store.getItem(PREFIX + token);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Grant>;
    return typeof parsed.q === 'string' && typeof parsed.exp === 'number'
      ? { q: parsed.q, exp: parsed.exp }
      : null;
  } catch {
    return null;
  }
}

function sweep(store: Storage, now: number): void {
  try {
    for (let i = store.length - 1; i >= 0; i--) {
      const key = store.key(i);
      if (!key?.startsWith(PREFIX)) continue;
      const grant = read(store, key.slice(PREFIX.length));
      if (!grant || grant.exp <= now) store.removeItem(key);
    }
  } catch {
    // Best effort.
  }
}

/**
 * Grant one auto-run of `query` and return the token for the `run` param.
 * Without storage the token simply never validates: the query then loads
 * with a Run prompt instead of running.
 */
export function grantSearchAutoRun(query: string, now: number = Date.now()): string {
  const token = safeRandomUUID();
  const store = storage();
  if (store) {
    sweep(store, now);
    try {
      store.setItem(PREFIX + token, JSON.stringify({ q: query, exp: now + SEARCH_AUTO_RUN_TTL_MS }));
    } catch {
      // Quota or privacy mode: fall back to the prompt.
    }
  }
  return token;
}

/** Whether `token` is a live grant for exactly `query` (does not consume it). */
export function isSearchAutoRunGranted(
  token: string | null | undefined,
  query: string,
  now: number = Date.now(),
): boolean {
  if (!token || !TOKEN_RE.test(token)) return false;
  const store = storage();
  if (!store) return false;
  const grant = read(store, token);
  return !!grant && grant.exp > now && grant.q === query;
}

/** Remove a grant so it cannot run a second time. */
export function consumeSearchAutoRun(token: string | null | undefined): void {
  if (!token || !TOKEN_RE.test(token)) return;
  try {
    storage()?.removeItem(PREFIX + token);
  } catch {
    // Best effort.
  }
}

/**
 * Append a granted `run` param to a Search URL (query string or `#` fragment
 * form). The grant is bound to the URL's own `q`.
 */
export function withSearchAutoRun(url: string): string {
  const hashAt = url.indexOf('#');
  const queryAt = url.indexOf('?');
  const useHash = hashAt >= 0;
  const head = useHash ? url.slice(0, hashAt) : queryAt >= 0 ? url.slice(0, queryAt) : url;
  const tail = useHash ? url.slice(hashAt + 1) : queryAt >= 0 ? url.slice(queryAt + 1) : '';
  const params = new URLSearchParams(tail);
  params.set('run', grantSearchAutoRun(params.get('q') ?? ''));
  return `${head}${useHash ? '#' : '?'}${params.toString()}`;
}

/**
 * For URLs built ahead of a click (e.g. a link computed at render time) that
 * mark their intent with `run=true`: swap the marker for a real grant at the
 * moment of navigation. Other URLs are returned unchanged.
 */
export function resolveSearchAutoRun(url: string): string {
  const hashAt = url.indexOf('#');
  const queryAt = url.indexOf('?');
  const tail = hashAt >= 0 ? url.slice(hashAt + 1) : queryAt >= 0 ? url.slice(queryAt + 1) : '';
  return new URLSearchParams(tail).get('run') === 'true' ? withSearchAutoRun(url) : url;
}

const TAB_RUNS_KEY = 'nano:search-tab-runs';
const TAB_RUNS_MAX = 50;

function tabStore(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

function tabRuns(store: Storage): string[] {
  try {
    const parsed = JSON.parse(store.getItem(TAB_RUNS_KEY) ?? '[]');
    return Array.isArray(parsed) ? parsed.filter((q): q is string => typeof q === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * Record that this browser tab ran `query`, so reloading or navigating back
 * to it may run it again without a prompt. Session storage is per tab and per
 * origin: another site cannot add to it, and a newly opened tab starts empty.
 */
export function rememberTabSearch(query: string): void {
  const store = tabStore();
  if (!store || !query.trim()) return;
  const runs = [query, ...tabRuns(store).filter((q) => q !== query)].slice(0, TAB_RUNS_MAX);
  try {
    store.setItem(TAB_RUNS_KEY, JSON.stringify(runs));
  } catch {
    // Best effort.
  }
}

/** Whether this tab already ran exactly `query`. */
export function tabAlreadyRan(query: string): boolean {
  const store = tabStore();
  return !!store && tabRuns(store).includes(query);
}

/**
 * Router state for a navigation that finishes an arrival from outside the app
 * (the return to the original URL after sign-in). Search treats it like a
 * landing entry: a URL query there is loaded, not run.
 */
export const OUTSIDE_ARRIVAL_STATE = { nanoOutsideArrival: true } as const;

/** Whether a router location is an arrival from outside the app. */
export function isOutsideArrival(location: { key: string; state: unknown }): boolean {
  if (location.key === 'default') return true;
  const state = location.state as { nanoOutsideArrival?: unknown } | null;
  return !!state && state.nanoOutsideArrival === true;
}
