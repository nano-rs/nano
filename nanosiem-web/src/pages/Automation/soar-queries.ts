// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 — React Query hooks for the Automation workspace. Every hook takes
 * `enabled`, which callers derive from the SOAR gate, so a disabled tenant
 * issues no SOAR request beyond the settings read.
 *
 * Polling is bounded: lists refresh every 15s only while work is in flight,
 * a non-terminal run detail every 5s. No push/stream contract exists.
 */
import { useQueries, useQuery, type QueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { SoarApprovalStatus, SoarRun, SoarRunDetail, SoarRuns } from '@/lib/api/soar';
import { isTerminal } from './soar-model';

export const RUNS_PAGE = 100;
export const APPROVALS_PAGE = 100;

export const soarKeys = {
  all: (tenant: string) => ['soar', tenant] as const,
  catalog: (tenant: string) => ['soar', tenant, 'catalog'] as const,
  connections: (tenant: string) => ['soar', tenant, 'connections'] as const,
  flows: (tenant: string) => ['soar', tenant, 'flows'] as const,
  flow: (tenant: string, id: string) => ['soar', tenant, 'flow', id] as const,
  runs: (tenant: string, caseId?: string) => ['soar', tenant, 'runs', caseId ?? null] as const,
  runsWindow: (tenant: string, start: number | null, ms: number) => ['soar', tenant, 'runs-window', start, ms] as const,
  run: (tenant: string, id: string) => ['soar', tenant, 'run', id] as const,
  runVolume: (tenant: string) => ['soar', tenant, 'runs', 'volume'] as const,
  flowStats: (tenant: string) => ['soar', tenant, 'flows', 'stats'] as const,
  approvals: (tenant: string, status: SoarApprovalStatus) => ['soar', tenant, 'approvals', status] as const,
  approval: (tenant: string, id: string) => ['soar', tenant, 'approval', id] as const,
};

function inFlight(data: SoarRuns | undefined): boolean {
  return !!data?.runs.some((r) => !isTerminal(r.status));
}

export function useCatalog(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.catalog(tenant),
    queryFn: () => api.soar.getCatalog(),
    enabled,
    staleTime: 60_000,
  });
}

/** Connections are hidden from demo principals by the server fence. */
export function useConnections(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.connections(tenant),
    queryFn: () => api.soar.getConnections(),
    enabled,
    staleTime: 30_000,
  });
}

export function useFlows(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.flows(tenant),
    queryFn: () => api.soar.getFlows(),
    enabled,
    staleTime: 15_000,
  });
}

/** NAN-4544: per-flow 24h run counts from the server (one GROUP BY). */
export function useFlowStats(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.flowStats(tenant),
    queryFn: () => api.soar.getFlowStats(),
    enabled,
    staleTime: 60_000,
  });
}

export function useFlow(tenant: string, id: string, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.flow(tenant, id),
    queryFn: () => api.soar.getFlow(id),
    enabled,
  });
}

export function useRuns(tenant: string, enabled: boolean, caseId?: string) {
  return useQuery({
    queryKey: soarKeys.runs(tenant, caseId),
    queryFn: () => api.soar.getRuns({ limit: RUNS_PAGE, case_id: caseId }),
    enabled,
    staleTime: 5_000,
    refetchInterval: (query) => (inFlight(query.state.data) ? 15_000 : false),
  });
}

/** NAN-4556: the runs of one histogram bucket, fetched from the server (not the loaded page). */
export function useWindowRuns(tenant: string, enabled: boolean, start: number | null, ms: number) {
  return useQuery({
    queryKey: soarKeys.runsWindow(tenant, start, ms),
    queryFn: () => api.soar.getRuns({
      limit: RUNS_PAGE,
      created_after: new Date(start as number).toISOString(),
      created_before: new Date((start as number) + ms).toISOString(),
    }),
    enabled: enabled && start != null,
    staleTime: 5_000,
  });
}

/** NAN-4556: full 24h run volume (30-minute buckets) for the Runs histogram. */
export function useRunVolume(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.runVolume(tenant),
    queryFn: () => api.soar.getRunVolume({ hours: 24, bucket_minutes: 30 }),
    enabled,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}

export function useRun(tenant: string, id: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.run(tenant, id ?? ''),
    queryFn: () => api.soar.getRun(id!, { steps_limit: 50, approvals_limit: 50 }),
    enabled: enabled && !!id,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !isTerminal(status) ? 5_000 : false;
    },
  });
}

/** Unknown-outcome probes: how many failed/canceled runs to open for step status. */
export const AMBIGUOUS_PROBE = 10;

/**
 * "Ambiguous" lives on steps, not runs. Open the details of the most recent
 * failed / canceled / timed-out runs (bounded) so the header chips and the
 * status strip can show unknown outcomes. Shares the run-detail cache.
 */
export function useRunDetails(tenant: string, runs: SoarRun[], enabled: boolean): Map<string, SoarRunDetail> {
  const ids = runs
    .filter((r) => r.status === 'failed' || r.status === 'canceled' || r.status === 'timed_out')
    .slice(0, AMBIGUOUS_PROBE)
    .map((r) => r.id);
  const results = useQueries({
    queries: ids.map((id) => ({
      queryKey: soarKeys.run(tenant, id),
      queryFn: () => api.soar.getRun(id, { steps_limit: 50, approvals_limit: 50 }),
      enabled,
      staleTime: 60_000,
    })),
  });
  const out = new Map<string, SoarRunDetail>();
  results.forEach((r, i) => { if (r.data) out.set(ids[i], r.data); });
  return out;
}

/** Approvals are hidden from demo principals by the server fence. */
export function useApprovals(tenant: string, status: SoarApprovalStatus, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.approvals(tenant, status),
    queryFn: () => api.soar.getApprovals({ status, limit: APPROVALS_PAGE }),
    enabled,
    staleTime: 15_000,
    refetchInterval: status === 'pending' ? 30_000 : false,
  });
}

export function useApproval(tenant: string, id: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: soarKeys.approval(tenant, id ?? ''),
    queryFn: () => api.soar.getApproval(id!),
    enabled: enabled && !!id,
  });
}

/** After any effect: refresh everything SOAR for this tenant. */
export function invalidateSoar(client: QueryClient, tenant: string) {
  return client.invalidateQueries({ queryKey: soarKeys.all(tenant) });
}

export function errorStatus(error: unknown): number | undefined {
  const status = (error as { status?: unknown } | null)?.status;
  return typeof status === 'number' ? status : undefined;
}

/** Sanitized, actionable copy for an effect failure. Never echoes payloads. */
export function effectErrorMessage(error: unknown, fallback: string): string {
  switch (errorStatus(error)) {
    case 400:
      return error instanceof Error && error.message ? error.message : 'The request was rejected as invalid.';
    case 403:
      return 'You do not have permission for this action, or your session is not an interactive one.';
    case 404:
      return 'This item is no longer available to you.';
    case 409:
      return 'It changed since you loaded it. The view has been refreshed; review it and try again.';
    case 503:
      return 'SOAR is temporarily unavailable. Try again in a moment.';
    default:
      return fallback;
  }
}
