// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5738: SIEM Health findings that stay visible while their condition
 * holds. The server refuses a suppression for one
 * (`finding_signature::NON_SUPPRESSIBLE_TITLES`); the page never hides one
 * or offers to suppress it.
 */
export const NON_SUPPRESSIBLE_FINDING_TITLES: readonly string[] = [
  'SOAR installed packs failed signed catalog verification',
];

const normalize = (title: string) => title.trim().replace(/\s+/g, ' ').toLowerCase();

/** False for a finding that must stay visible while its condition holds. */
export function isSuppressibleFinding(title: string): boolean {
  const t = normalize(title);
  return !NON_SUPPRESSIBLE_FINDING_TITLES.some((n) => normalize(n) === t);
}
