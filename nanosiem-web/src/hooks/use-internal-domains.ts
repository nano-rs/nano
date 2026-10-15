// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3226: the tenant's internal DNS suffixes, unioned with the built-ins.
// Consumers (rarity timeline, case intake, quick pivot, notebook @ioc) use it
// to keep internal hostnames out of "domain" handling. Degrades to the
// built-in list when the request fails (no permission, older backend).

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { effectiveInternalSuffixes } from '@/lib/internal-domains';

/** Query key for `GET /api/settings/internal-domains`, scoped to the tenant runtime. */
export function internalDomainsQueryKey() {
  return ['internal-domains', browserTenantRuntime.current().key] as const;
}

/** The setting changes rarely; refetch at most every 10 minutes. */
const INTERNAL_DOMAINS_STALE_MS = 10 * 60_000;

/**
 * Effective internal suffixes: built-ins plus the tenant list. Always returns
 * at least the built-ins (while loading, on error, or when `enabled` is false).
 */
export function useInternalDomains(enabled = true): string[] {
  const query = useQuery({
    queryKey: internalDomainsQueryKey(),
    queryFn: () => api.internalDomains.get(),
    enabled,
    retry: false,
    staleTime: INTERNAL_DOMAINS_STALE_MS,
  });
  const tenant = query.data?.suffixes;
  return useMemo(() => effectiveInternalSuffixes(tenant ?? []), [tenant]);
}
