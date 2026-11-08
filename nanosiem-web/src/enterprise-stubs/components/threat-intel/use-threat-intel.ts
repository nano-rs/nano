// SPDX-License-Identifier: AGPL-3.0-or-later
// Open-edition stub: threat-intel lookups are enterprise-only (NAN-4931).

export function useThreatIntelEnabled(): boolean {
  return false;
}

export function useIndicatorSetsEnabled(): boolean {
  return false;
}

export function useEnrichEnabled(): boolean {
  return false;
}

/** No provider list in the open edition; the Marketplace counts zero. */
export function useThreatIntelProviders(): { data: { providers: unknown[] } | undefined } {
  return { data: undefined };
}
