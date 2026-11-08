// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * useSchemaFieldMap — the active deployment's profile-aware field map
 * (NAN-4903). Reads the schema discriminator from `GET /api/schema/fields`
 * (shared React Query cache key with `useSchemaEntityMap`, fetched once per
 * session) and returns the bound helpers from `@/lib/schema-fields`.
 *
 * The frontend never guesses the tenant's schema. Until the API answers — or
 * while it is failing — the map is `unresolved`: callers must not build a query
 * from it. Buttons disable on `unresolved`; click handlers wrap themselves in
 * `guard(fn)`, which refuses with an error toast (and kicks a refetch) instead
 * of running. A failed fetch keeps retrying in the background.
 */

import { useCallback, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { toast } from '@/hooks/use-toast';
import {
  UNRESOLVED_SCHEMA_PROFILE,
  schemaFieldMap,
  toSchemaProfile,
  type SchemaFieldMap,
} from '@/lib/schema-fields';

export const SCHEMA_FIELDS_QUERY_KEY = ['schema-fields'] as const;

/** Retry cadence while `/api/schema/fields` is failing. */
const ERROR_REFETCH_MS = 10_000;

export interface SchemaFieldMapState extends SchemaFieldMap {
  /** The profile is known; queries may be built. */
  ready: boolean;
  /** Not known yet (loading) or unavailable (error): build no queries. */
  unresolved: boolean;
  /** The last fetch failed; a retry is scheduled. */
  error: boolean;
  /** Why actions are disabled, for a title/tooltip; null once ready. */
  unresolvedReason: string | null;
  /** Refetch the profile now. */
  retry: () => void;
  /**
   * Wrap a query-producing action. While unresolved it shows an error toast,
   * triggers a refetch, and does NOT run `fn`.
   */
  guard: <A extends unknown[]>(fn: (...args: A) => void) => (...args: A) => void;
}

export const SCHEMA_PROFILE_LOADING_REASON = 'Loading the schema profile…';
export const SCHEMA_PROFILE_ERROR_REASON = 'Schema profile unavailable. Retrying…';

export function useSchemaFieldMap(): SchemaFieldMapState {
  const { data, isError, refetch } = useQuery({
    queryKey: SCHEMA_FIELDS_QUERY_KEY,
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
    refetchInterval: (query) => (query.state.status === 'error' ? ERROR_REFETCH_MS : false),
  });
  const resolved = toSchemaProfile(data?.schema);
  const ready = resolved !== null;
  const error = !ready && isError;
  const unresolvedReason = ready ? null : error ? SCHEMA_PROFILE_ERROR_REASON : SCHEMA_PROFILE_LOADING_REASON;

  const retry = useCallback(() => {
    void refetch();
  }, [refetch]);

  const guard = useCallback(
    <A extends unknown[]>(fn: (...args: A) => void) =>
      (...args: A) => {
        if (ready) {
          fn(...args);
          return;
        }
        toast({
          title: 'Schema profile not loaded',
          description: `${unresolvedReason} The action was not run, so no query was built against a guessed schema.`,
          variant: 'destructive',
        });
        retry();
      },
    [ready, unresolvedReason, retry],
  );

  return useMemo(
    () => ({
      ...schemaFieldMap(resolved ?? UNRESOLVED_SCHEMA_PROFILE),
      ready,
      unresolved: !ready,
      error,
      unresolvedReason,
      retry,
      guard,
    }),
    [resolved, ready, error, unresolvedReason, retry, guard],
  );
}
