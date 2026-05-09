// SPDX-License-Identifier: AGPL-3.0-or-later

import { type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { API_BASE_URL } from '@/lib/api/utils';
import {
  CapabilitiesContext,
  type CapabilitiesContextValue,
} from '@/hooks/use-capabilities';

// Enterprise-everywhere fallback used when the fetch hasn't resolved or
// errored. Preserves the existing single-bundle behavior — better to render
// a feature the API doesn't have (the request 404s, same as today) than to
// hide enterprise nav from a real enterprise user during a transient outage.
const FALLBACK_CAPABILITIES: CapabilitiesContextValue = {
  edition: 'enterprise',
  version: 'unknown',
  capabilities: {
    cases: true,
    notebooks: true,
    risk: true,
    melod: true,
    customEnrichment: true,
    agentEnrichment: true,
    aiTuning: true,
    playbooks: true,
    incidents: true,
    siemHealth: true,
    sso: true,
  },
};

async function fetchCapabilities(): Promise<CapabilitiesContextValue> {
  const response = await fetch(`${API_BASE_URL}/api/capabilities`);
  if (!response.ok) {
    throw new Error(`Failed to fetch capabilities: ${response.status}`);
  }
  const body = (await response.json()) as CapabilitiesContextValue;
  if (body.edition !== 'open' && body.edition !== 'enterprise') {
    throw new Error(`Unexpected build edition: ${body.edition}`);
  }
  return body;
}

export function CapabilitiesProvider({ children }: { children: ReactNode }) {
  // staleTime/gcTime infinity: build edition is static for the session.
  // While the fetch is in flight we render with FALLBACK_CAPABILITIES so the
  // login + setup + onboarding flows aren't blocked on a no-auth GET. Open
  // users may briefly see enterprise nav before items disappear — acceptable
  // because the route gates use the same flag and the bundle-level exclusion
  // (Phase 5.10+) makes this code load-bearing only on staging.
  const { data } = useQuery({
    queryKey: ['capabilities'],
    queryFn: fetchCapabilities,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
  });

  return (
    <CapabilitiesContext.Provider value={data ?? FALLBACK_CAPABILITIES}>
      {children}
    </CapabilitiesContext.Provider>
  );
}
