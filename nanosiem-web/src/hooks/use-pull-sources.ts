// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * React Query hooks for cloud pull sources (NAN-3596). Keys are scoped to the
 * active tenant and user, like the hosted collectors (NAN-3572).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { api, ApiClientError } from '@/lib/api';
import { PULL_SOURCES_NOT_ENABLED, type CreatePullSourceRequest, type PullSource, type UpdatePullSourceRequest } from '@/lib/api/pull-sources';

export function usePullSourcesKey() {
  const { user } = useAuth();
  return ['pull-sources', user?.active_tenant?.id, user?.id] as const;
}

/**
 * The tenant is not admitted to cloud pull (409 `pull_sources_not_enabled`),
 * or the API does not serve the surface yet (404). Both render as a quiet
 * empty state, never as an error.
 */
export function isPullNotEnabled(error: unknown): boolean {
  return error instanceof ApiClientError && (error.code === PULL_SOURCES_NOT_ENABLED || error.status === 404);
}

/**
 * The tenant's pull sources. With `poll`, a non-empty list refetches every
 * 30 s while the document is visible; failures are not retried.
 */
export function usePullSources({ enabled = true, poll = false }: { enabled?: boolean; poll?: boolean } = {}) {
  const queryKey = usePullSourcesKey();
  return useQuery({
    queryKey,
    queryFn: () => api.pullSources.list(),
    enabled,
    retry: false,
    refetchInterval: (query: { state: { status: string; data?: PullSource[] } }) =>
      poll && query.state.status === 'success' && (query.state.data?.length ?? 0) > 0 ? 30000 : false,
    refetchIntervalInBackground: false,
  });
}

export function usePullSourceAwsSetup({ enabled = true }: { enabled?: boolean } = {}) {
  const queryKey = usePullSourcesKey();
  return useQuery({
    queryKey: [...queryKey, 'setup', 'aws'],
    queryFn: () => api.pullSources.getAwsSetup(),
    enabled,
    retry: false,
    staleTime: 5 * 60 * 1000,
  });
}

/**
 * GCP setup (NAN-3598). With a (client-validated) subscription the gcloud and
 * verify commands come back filled in; without one they carry placeholders.
 */
export function usePullSourceGcpSetup({ enabled = true, subscription }: { enabled?: boolean; subscription?: string } = {}) {
  const queryKey = usePullSourcesKey();
  return useQuery({
    queryKey: [...queryKey, 'setup', 'gcp', subscription ?? null],
    queryFn: () => api.pullSources.getGcpSetup(subscription),
    enabled,
    retry: false,
    staleTime: 5 * 60 * 1000,
  });
}

/** Azure setup (NAN-3604): the federated identity credential + role commands. */
export function usePullSourceAzureSetup({ enabled = true }: { enabled?: boolean } = {}) {
  const queryKey = usePullSourcesKey();
  return useQuery({
    queryKey: [...queryKey, 'setup', 'azure'],
    queryFn: () => api.pullSources.getAzureSetup(),
    enabled,
    retry: false,
    staleTime: 5 * 60 * 1000,
  });
}

export function useCreatePullSource() {
  const queryKey = usePullSourcesKey();
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: CreatePullSourceRequest) => api.pullSources.create(body),
    onSettled: () => client.invalidateQueries({ queryKey, exact: true }),
  });
}

export type PullSourceAction = 'pause' | 'resume' | 'retry' | 'delete';

export function usePullSourceAction() {
  const queryKey = usePullSourcesKey();
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: PullSourceAction }): Promise<PullSource | void> =>
      action === 'pause' ? api.pullSources.pause(id)
        : action === 'resume' ? api.pullSources.resume(id)
          : action === 'retry' ? api.pullSources.retry(id)
            : api.pullSources.remove(id),
    onSettled: () => {
      void client.invalidateQueries({ queryKey, exact: true });
      // NAN-3661: the Log Source Delivery panel and list indicator read pull state from the lane inputs.
      void client.invalidateQueries({ queryKey: ['pipe-inputs'] });
    },
  });
}

/** NAN-3729: rotate a source's credential in place (it re-verifies). */
export function useUpdatePullSourceCredential() {
  const queryKey = usePullSourcesKey();
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: UpdatePullSourceRequest }) => api.pullSources.update(id, body),
    onSettled: () => {
      void client.invalidateQueries({ queryKey, exact: true });
      void client.invalidateQueries({ queryKey: ['pipe-inputs'] });
    },
  });
}
