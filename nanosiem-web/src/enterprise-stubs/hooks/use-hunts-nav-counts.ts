// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub: hunts are enterprise-only and the Hunts rail group is
// capability-gated off, so there is never a count to show.

export type HuntsNavCounts = Partial<Record<string, string>>;

export function useHuntsNavCounts(fetch: boolean): HuntsNavCounts {
  void fetch;
  return {};
}
