// SPDX-License-Identifier: AGPL-3.0-or-later

import { type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { API_BASE_URL } from '@/lib/api/utils';
import {
  CapabilitiesContext,
  type CapabilitiesContextValue,
} from '@/hooks/use-capabilities';

// Fallback used when the fetch hasn't resolved or has errored.
//
// Runtime admission can change without a browser reload (online renewal or a
// C05 import). Until the public endpoint answers, fail closed for every
// licensed-only surface even in an enterprise bundle. Core SIEM Health stays
// available in both editions.

const FALLBACK_CAPABILITIES: CapabilitiesContextValue = {
  edition: __EDITION__,
  version: 'unknown',
  fallback: true,
  capabilities: {
    cases: false,
    notebooks: false,
    risk: false,
    melod: false,
    customEnrichment: false,
    agentEnrichment: false,
    aiTuning: false,
    playbooks: false,
    incidents: false,
    // Core in both editions (NAN-2357) — an open bundle that falls back to
    // false would hide the nav and breadcrumb for a page it genuinely has.
    siemHealth: true,
    sso: false,
    observabilityConvergence: false,
    iocLists: false,
    soar: false,
    threatIntel: false,
    agentLane: false,
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
  // Older APIs did not publish these flags. Absence is fail-closed because
  // bundle edition alone says nothing about current license admission.
  if (typeof body.capabilities?.soar !== 'boolean') {
    body.capabilities = { ...body.capabilities, soar: false };
  }
  // Same for `threatIntel` (NAN-4931): an older API answers without it.
  if (typeof body.capabilities?.threatIntel !== 'boolean') {
    body.capabilities = { ...body.capabilities, threatIntel: false };
  }
  return body;
}

export function CapabilitiesProvider({ children }: { children: ReactNode }) {
  // Admission is live, so refetch in the background and on focus. This hides
  // licensed navigation shortly after hard stop and restores it after renewal
  // without disturbing open/core pages.
  const { data } = useQuery({
    queryKey: ['capabilities'],
    queryFn: fetchCapabilities,
    staleTime: 30_000,
    gcTime: Infinity,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
    retry: 1,
  });

  return (
    <CapabilitiesContext.Provider value={data ?? FALLBACK_CAPABILITIES}>
      {children}
    </CapabilitiesContext.Provider>
  );
}
