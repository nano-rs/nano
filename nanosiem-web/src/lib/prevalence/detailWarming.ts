// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3210: lean (enterprise-shared) tenants build artifact detail in product
 * state on demand; the expanded explorer row polls at this cadence, up to this
 * many times, while the detail answers `availability.reason = 'warming'`.
 */
// NAN-3766: the publisher hands over a first (newest-slice) answer within
// about 1.5 s of picking the demand up, so the first poll comes after 1 s,
// then backs off: 1, 2, 4, 8, 10, 10, 10, 10 s (about one minute in all).
export const DETAIL_WARMING_POLL_MS = 1_000;
export const DETAIL_WARMING_MAX_POLLS = 8;

/** Back off while a tenant publisher builds; stop after roughly one minute. */
export function detailWarmingDelay(polls: number): number {
  return Math.min(DETAIL_WARMING_POLL_MS * 2 ** polls, 10_000);
}
