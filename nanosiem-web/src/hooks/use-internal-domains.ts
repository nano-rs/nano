// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3226: the internal DNS suffixes from Settings > Risk, unioned with the
// built-ins. Consumers (rarity timeline, quick pivot, notebook @ioc) use it to
// keep internal hostnames out of "domain" handling. Degrades to the built-in
// list when the request fails (no permission, open edition, older backend).

import { useContext, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { CapabilitiesContext } from '@/hooks/use-capabilities';
import { effectiveInternalSuffixes } from '@/lib/internal-domains';

/** Query key for `GET /api/settings/internal-domains`. */
export const INTERNAL_DOMAINS_QUERY_KEY = ['internal-domains'] as const;

/** The setting changes rarely; refetch at most every 10 minutes. */
const INTERNAL_DOMAINS_STALE_MS = 10 * 60_000;

/**
 * Effective internal suffixes: built-ins plus the saved list. Always returns
 * at least the built-ins (while loading, on error, when `enabled` is false, or
 * on the open edition, which has no endpoint: the setting lives with the
 * enterprise risk surface).
 */
export function useInternalDomains(enabled = true): string[] {
  // Read the context directly: outside a CapabilitiesProvider (tests, isolated
  // renders) default to trying the endpoint; a 404 still yields the built-ins.
  const riskSurface = useContext(CapabilitiesContext)?.capabilities.risk ?? true;
  const query = useQuery({
    queryKey: INTERNAL_DOMAINS_QUERY_KEY,
    queryFn: () => api.internalDomains.get(),
    enabled: enabled && riskSurface,
    retry: false,
    staleTime: INTERNAL_DOMAINS_STALE_MS,
  });
  const saved = query.data?.suffixes;
  return useMemo(() => effectiveInternalSuffixes(saved ?? []), [saved]);
}
