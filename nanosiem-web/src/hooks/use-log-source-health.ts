// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3207: React Query hooks for per-log-source health series (volume vs the
 * seasonal expected band, plus per-segment series). Both endpoints are
 * tenant-scoped and need `log_sources:view`.
 */

import { useQuery } from '@tanstack/react-query';

import { api } from '@/lib/api';
import type { LogSourceHealthSeries } from '@/lib/api';

const REFRESH_MS = 60_000;

/** One retry for transient failures; a 404 (route absent / source not visible) is final. */
function retryOnce(failures: number, err: unknown): boolean {
  const status = (err as { status?: number } | null)?.status;
  return status !== 404 && status !== 403 && failures < 1;
}

export const logSourceHealthKeys = {
  all: (hours: number) => ['log-source-health-series', 'all', hours] as const,
  one: (id: string, hours: number) => ['log-source-health-series', id, hours] as const,
};

/** Every visible source. */
export function useLogSourcesHealthSeries(hours = 24, enabled = true) {
  return useQuery<LogSourceHealthSeries[]>({
    queryKey: logSourceHealthKeys.all(hours),
    queryFn: () => api.getHealthSeries(hours),
    refetchInterval: REFRESH_MS,
    retry: retryOnce,
    enabled,
  });
}

/** One source (the endpoint answers a one-element array). */
export function useLogSourceHealthSeries(id: string | undefined, hours = 24) {
  return useQuery<LogSourceHealthSeries | null>({
    queryKey: logSourceHealthKeys.one(id ?? '', hours),
    queryFn: async () => (await api.getLogSourceHealthSeries(id as string, hours))[0] ?? null,
    refetchInterval: REFRESH_MS,
    retry: retryOnce,
    enabled: !!id,
  });
}
