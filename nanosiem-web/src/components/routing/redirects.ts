// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5850: client-side redirects that keep the query string. An old route
 * stays registered forever and lands on its new home in one hop.
 */

/** `keep`: the incoming query (and hash) rides along; `drop`: only the target's own query. */
export type RedirectQuery = 'keep' | 'drop';

export interface LegacyRedirect {
  from: string;
  to: string;
  query: RedirectQuery;
}

/**
 * The URL a redirect lands on. With `keep`, incoming params are kept and the
 * target's own params win over them (`/hunts/suppressions?tab=x&q=y` lands on
 * `/hunts/knowledge?tab=suppressions&q=y`). The hash is kept with the query.
 */
export function redirectTarget(to: string, search: string, hash: string, query: RedirectQuery): string {
  const [path, own = ''] = to.split('?');
  const params = new URLSearchParams(own);
  if (query === 'keep') {
    for (const [k, v] of new URLSearchParams(search)) if (!params.has(k)) params.append(k, v);
  }
  const qs = params.toString();
  return `${path}${qs ? `?${qs}` : ''}${query === 'keep' ? hash : ''}`;
}

/**
 * NAN-5850 PR A: the Hunts IA moves (design section 3). `/hunts/profile`
 * is not here: its page turns into the redirect in PR C, once the coverage
 * Telemetry tab that replaces it exists.
 */
export const LEGACY_HUNT_REDIRECTS: readonly LegacyRedirect[] = [
  { from: '/hunts/memory', to: '/hunts/knowledge', query: 'keep' },
  { from: '/hunts/suppressions', to: '/hunts/knowledge?tab=suppressions', query: 'keep' },
  { from: '/hunts/rulings', to: '/hunts/leads/decisions', query: 'keep' },
  { from: '/hunts/runners', to: '/settings/hunts', query: 'drop' },
  { from: '/hunts/rule-ideas', to: '/rules/ideas', query: 'keep' },
];
