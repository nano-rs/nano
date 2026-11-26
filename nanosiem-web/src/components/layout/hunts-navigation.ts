// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5844 / NAN-5850: route ownership for the Hunts rail group. The group
 * itself (Hunts, Findings, Escalations, Actors, Knowledge) is declared in
 * AppLayout.tsx and gated on the enterprise `hunts` capability; this module
 * only knows which paths each entry owns.
 *
 * The old "Hunt settings" pages moved (NAN-5850): Runners and the charter to
 * Settings > Hunting, Rule ideas to Detections, Memory became Knowledge,
 * Rulings became the Decisions tab of Findings. Their old routes redirect, so
 * they only appear here for the one render before the redirect lands.
 */

/** Rail href -> the paths it owns besides itself (redirect-only legacy routes). */
const OWNED_PATHS: Record<string, readonly string[]> = {
  '/hunts/leads': ['/hunts/leads', '/hunts/rulings'],
  '/hunts/escalations': ['/hunts/escalations'],
  // NAN-5859: Campaigns became Actors; the old paths redirect.
  '/hunts/actors': ['/hunts/actors', '/hunts/campaigns'],
  '/hunts/knowledge': ['/hunts/knowledge', '/hunts/memory', '/hunts/suppressions'],
};

/** Paths owned by a section entry, so Hunts (the library) does not light for them. */
const HUNT_SECTION_PATHS = [...Object.values(OWNED_PATHS).flat(), '/hunts/runners', '/hunts/rule-ideas'];

/** `pathname` is `prefix` or below it. */
export function isUnder(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(prefix + '/');
}

/**
 * Whether the Hunts rail entry at `href` owns `pathname`: a hunt's detail page
 * (/hunts/:id) and Profile belong to Hunts, finding and actor detail pages
 * to their lists, Decisions to Findings.
 */
export function isHuntsNavItemActive(pathname: string, href: string): boolean {
  if (href === '/hunts') {
    return isUnder(pathname, '/hunts') && !HUNT_SECTION_PATHS.some((p) => isUnder(pathname, p));
  }
  const owned = OWNED_PATHS[href];
  if (owned) return owned.some((p) => isUnder(pathname, p));
  return isUnder(pathname, href);
}
