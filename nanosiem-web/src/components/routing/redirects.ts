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
 * NAN-5859: fill `:name` segments in a redirect target from the matched
 * route's params (`/hunts/campaigns/:id` lands on `/hunts/actors/:id`). Each
 * value is URI-encoded; a param the route did not match is left as is.
 */
export function fillParams(to: string, params: Readonly<Record<string, string | undefined>>): string {
  return to.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (whole, name: string) => {
    const v = params[name];
    return v == null ? whole : encodeURIComponent(v);
  });
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
  // NAN-5859: Campaigns became Actors. The API keeps /api/hunts/campaigns;
  // only the pages move. Unassigned candidates are part of the review queue.
  { from: '/hunts/campaigns', to: '/hunts/actors', query: 'keep' },
  { from: '/hunts/campaigns/candidates', to: '/hunts/actors/review?kind=unassigned', query: 'keep' },
  { from: '/hunts/campaigns/:id', to: '/hunts/actors/:id', query: 'keep' },
];
