// SPDX-License-Identifier: AGPL-3.0-or-later

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { TenantParserRollout } from '@/lib/api/types';
import { LATEST_LIVE_ROLLOUT_QUERY_KEY, LOG_SOURCE_ROLLOUTS_QUERY_KEY, rolloutPollInterval } from '@/lib/parser-rollout';

const HISTORY_LIMIT = 10;

/**
 * The latest parser rollouts of one log source, newest first. Shared by the
 * rollout panel and the log source header (one cache entry, one poll).
 */
export function useLogSourceRollouts(logSourceId: string, enabled = true) {
  return useQuery({
    queryKey: LOG_SOURCE_ROLLOUTS_QUERY_KEY(logSourceId),
    queryFn: () => api.listLogSourceRollouts(logSourceId, HISTORY_LIMIT),
    enabled,
    refetchInterval: (q) => (q.state.data && q.state.data.length ? rolloutPollInterval(q.state.data[0]) : false),
  });
}

/**
 * NAN-3298: the tenant's newest `live` rollout (any source). Every bundle
 * builds from the tenant's active versions, so this tells whether a source's
 * newest version reached ingest through a later roll. Keyed on the source's
 * newest rollout id + state, so it refetches whenever that rollout moves.
 */
export function useLatestLiveRollout(latest: TenantParserRollout | undefined, enabled = true) {
  return useQuery({
    queryKey: LATEST_LIVE_ROLLOUT_QUERY_KEY(latest?.id, latest?.state),
    queryFn: async () => (await api.listParserRollouts({ states: ['live'], limit: 1 }))[0] ?? null,
    // A live newest rollout is its own answer; nothing to look up.
    enabled: enabled && !!latest && latest.state !== 'live',
  });
}
