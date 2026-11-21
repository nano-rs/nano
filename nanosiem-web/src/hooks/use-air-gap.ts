// SPDX-License-Identifier: AGPL-3.0-or-later

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export const DEPLOYMENT_FLAGS_QUERY_KEY = ['system', 'deployment'] as const;

export interface DeploymentFlagsState {
  /** `undefined` until the flags load (or while the read is failing). */
  airGap: boolean | undefined;
  managed: boolean | undefined;
}

/**
 * NAN-5724: the deployment's air-gap and managed flags from
 * `GET /api/system/deployment`, which any signed-in user may read. Pages that
 * open without `settings:view` used to read them from `/api/system/config`
 * and drew a 403. The flags are fixed for the life of the process, so a
 * successful read is cached for the session; a failed one is retried and
 * refetched on window focus.
 */
export function useDeploymentFlags(): DeploymentFlagsState {
  const { data } = useQuery({
    queryKey: DEPLOYMENT_FLAGS_QUERY_KEY,
    queryFn: () => api.getDeploymentFlags(),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 2,
  });
  return { airGap: data?.air_gap, managed: data?.managed };
}

/**
 * Should egress controls (Git connect / sync, live sync) be withheld? Fails
 * CLOSED: until the flag is known to be false, the page offers the offline
 * bundle import instead. The server refuses Git create/sync on an air-gapped
 * install regardless (`refuse_git_egress_when_air_gapped`).
 */
export function useAirGap(): boolean {
  return useDeploymentFlags().airGap !== false;
}
