// SPDX-License-Identifier: AGPL-3.0-or-later

/** React Query hooks for the ATT&CK catalog and coverage data. */

import { useQuery } from '@tanstack/react-query';

import type { CoverageFilters, MitreCoverageResponse } from '@/components/mitre/types';
import { useAuth } from '@/contexts/AuthContext';
import { getAccessToken } from '@/lib/auth-token';
import { mitreAuthScope, mitreQueryKeys, normalizeMitreFilter } from './mitre-query-keys';

interface MitreTactic {
  id: string;
  name: string;
  short_name: string;
  description?: string;
  url?: string;
}

interface MitreTechnique {
  id: string;
  name: string;
  description?: string;
  url?: string;
  is_subtechnique: boolean;
  parent_id?: string;
  tactic_ids: string[];
  deprecated: boolean;
}

/** Durable state of the latest ATT&CK catalog sync attempt (mirrors the API). */
export interface MitreSyncState {
  status: string;
  release_version?: string | null;
  source_url?: string | null;
  source_sha256?: string | null;
  tactic_count?: number | null;
  technique_count?: number | null;
  last_started_at?: string | null;
  last_completed_at?: string | null;
  last_success_at?: string | null;
  last_error?: string | null;
  consecutive_failures: number;
  next_retry_at?: string | null;
}

interface MitreDataResponse {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
  last_sync?: {
    last_sync_at: string;
    version?: string;
    technique_count: number;
    tactic_count: number;
  };
  /** Populated on the boot/seed window so callers can distinguish an empty
   *  catalog that is still syncing from a genuine no-data state. */
  sync_state?: MitreSyncState | null;
}

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

function authHeaders(): HeadersInit {
  const token = getAccessToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function fetchJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(authHeaders());
  new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error(`MITRE request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

function errorMessage(error: unknown): string | null {
  return error instanceof Error ? error.message : error ? 'Failed to load MITRE data' : null;
}

export function useMitreData() {
  const { user, isAuthenticated, isLoading: authLoading } = useAuth();
  const authScope = mitreAuthScope(user?.id, getAccessToken());
  const query = useQuery({
    queryKey: mitreQueryKeys.catalog(authScope),
    queryFn: ({ signal }) => fetchJson<MitreDataResponse>('/api/mitre', { signal }),
    enabled: isAuthenticated && !authLoading,
  });

  return {
    data: query.data ?? null,
    loading: authLoading || (isAuthenticated && query.isPending),
    error: errorMessage(query.error),
  };
}

// Convert MITRE data to autocomplete options format
export function tacticsToOptions(tactics: MitreTactic[]) {
  return tactics.map((tactic) => ({
    value: tactic.id,
    label: `${tactic.id} - ${tactic.name}`,
    description: tactic.description?.substring(0, 100) || '',
  }));
}

export function techniquesToOptions(techniques: MitreTechnique[]) {
  return techniques.map((technique) => ({
    value: technique.id,
    label: `${technique.id} - ${technique.name}`,
    description: technique.description?.substring(0, 100) || '',
  }));
}

export function useMitreCoverage(filters: CoverageFilters) {
  const { user, isAuthenticated, isLoading: authLoading } = useAuth();
  const authScope = mitreAuthScope(user?.id, getAccessToken());
  const severities = normalizeMitreFilter(filters.severity);
  const modes = normalizeMitreFilter(filters.mode);
  const severityKey = severities.join(',');
  const modeKey = modes.join(',');

  const query = useQuery({
    queryKey: mitreQueryKeys.coverage(authScope, severityKey, modeKey),
    queryFn: ({ signal }) => {
      const params = new URLSearchParams();
      if (severityKey) params.set('severity', severityKey);
      if (modeKey) params.set('mode', modeKey);
      const queryString = params.toString();
      return fetchJson<MitreCoverageResponse>(
        `/api/mitre/coverage${queryString ? `?${queryString}` : ''}`,
        { signal },
      );
    },
    enabled: isAuthenticated && !authLoading,
  });

  return {
    data: query.data ?? null,
    loading: authLoading || (isAuthenticated && query.isPending),
    error: errorMessage(query.error),
  };
}

/**
 * A rule mapping a catalog sync could not resolve (NAN-1918). `repaired_at`
 * is set once a later sync managed to migrate it onto the current catalog.
 */
export interface MitreQuarantinedMapping {
  id: number;
  rule_id: string;
  rule_name: string | null;
  original_tactics: string[];
  original_techniques: string[];
  reason: string;
  quarantined_at: string;
  repaired_at: string | null;
  repaired_tactics: string[] | null;
  repaired_techniques: string[] | null;
}

interface MitreQuarantineResponse {
  mappings: MitreQuarantinedMapping[];
  unrepaired_count: number;
}

/**
 * Rules whose ATT&CK mapping a catalog sync dropped.
 *
 * Coverage is computed from live mappings, so a rule that lost its mapping
 * silently stops counting — and the percentage goes *up*. Surfacing this
 * alongside the coverage figure is the point.
 */
export function useMitreQuarantine() {
  const { user, isAuthenticated, isLoading: authLoading } = useAuth();
  const authScope = mitreAuthScope(user?.id, getAccessToken());
  const query = useQuery({
    queryKey: mitreQueryKeys.quarantine(authScope),
    queryFn: ({ signal }) =>
      fetchJson<MitreQuarantineResponse>('/api/mitre/quarantine', { signal }),
    enabled: isAuthenticated && !authLoading,
  });

  return {
    mappings: query.data?.mappings ?? [],
    unrepairedCount: query.data?.unrepaired_count ?? 0,
    loading: authLoading || (isAuthenticated && query.isPending),
    error: errorMessage(query.error),
  };
}
