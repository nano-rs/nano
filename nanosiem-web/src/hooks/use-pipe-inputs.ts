// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3621: React Query hooks for the inputs that feed a Pipe lane (push
 * credentials, cloud pull sources, connector feeds). Keys are scoped to the
 * active tenant runtime, like the rest of the Pipelines workspace.
 */

import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import { pipeEndpointMissing } from '@/lib/api/pipelines';

/** A backend older than the SPA (404) answers no data rather than an error. */
const quietMissing = <T,>(load: () => Promise<T>) => async (): Promise<T | null> => {
  try {
    return await load();
  } catch (error) {
    if (pipeEndpointMissing(error)) return null;
    throw error;
  }
};

export function usePipeLaneInputs(sourceId: string | undefined, { enabled = true }: { enabled?: boolean } = {}) {
  const { tenantRuntime } = useAuth();
  return useQuery({
    queryKey: ['pipe-inputs', tenantRuntime.key, sourceId],
    queryFn: ({ signal }) => quietMissing(() => api.pipelines.inputs(sourceId!, signal))(),
    enabled: enabled && !!sourceId,
    retry: false,
    staleTime: 30_000,
  });
}

export function usePipeInputSummary({ enabled = true }: { enabled?: boolean } = {}) {
  const { tenantRuntime } = useAuth();
  return useQuery({
    queryKey: ['pipe-inputs', tenantRuntime.key, 'summary'],
    queryFn: ({ signal }) => quietMissing(() => api.pipelines.inputSummary(signal))(),
    enabled,
    retry: false,
    staleTime: 30_000,
  });
}
