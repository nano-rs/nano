// SPDX-License-Identifier: AGPL-3.0-or-later

// useTelemetryAvailability (NAN-2361) — does telemetry back the Observability
// console on this deployment? See components/observability/TelemetryUnavailable.

import { useQuery } from '@tanstack/react-query';

import { api } from '@/lib/api';
import type { TelemetryAvailability } from '@/lib/api/observability';
import { useCapabilities } from '@/hooks/use-capabilities';

export interface TelemetryAvailabilityState {
  /** True while the shared-tenant verdict is still loading. */
  loading: boolean;
  /** The verdict; undefined on dedicated deployments (nothing to ask). */
  telemetry?: TelemetryAvailability;
  /** Convenience: data tabs must render the empty state. */
  unavailable: boolean;
}

/**
 * Ask once per session whether telemetry backs the console. Only a shared-lake
 * tenant (`tenantPlan` present) asks — the route is not mounted elsewhere. A
 * failed ask fails open to the legacy behavior (tabs call their routes), so a
 * transient control-plane error cannot hide a working deployment.
 */
export function useTelemetryAvailability(): TelemetryAvailabilityState {
  const { tenantPlan } = useCapabilities();
  const shared = !!tenantPlan;
  const { data, isLoading } = useQuery({
    queryKey: ['observability-telemetry-availability'],
    queryFn: () => api.observability.getTelemetryAvailability(),
    enabled: shared,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  return {
    loading: shared && isLoading,
    telemetry: data,
    unavailable: shared && data?.available === false,
  };
}
