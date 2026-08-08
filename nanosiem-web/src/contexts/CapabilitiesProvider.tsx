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
// It is EDITION-AWARE (NAN-2356). The old fallback claimed every capability
// unconditionally, on the reasoning that rendering a feature the API lacks just
// 404s. That reasoning does not hold inside an OPEN bundle: there,
// `@/enterprise/*` resolves to stubs that render nothing, so an optimistic
// `melod: true` makes callers mount a null component instead of their working
// core path. The result is the exact dead affordance this issue fixes —
// briefly on every load, and permanently if `/api/capabilities` fails (the
// query retries once, then `data` stays undefined forever).
//
// The bundle already knows what it is: `__EDITION__` is baked in at build time
// by vite.config.ts. An open bundle can never have enterprise surfaces, so
// false is not a guess — it is the only correct answer. The enterprise bundle
// keeps the optimistic fallback so a real enterprise user doesn't lose nav
// during a transient outage. Runtime data still overrides either.
const ENTERPRISE_BUNDLE = __EDITION__ === 'enterprise';

const FALLBACK_CAPABILITIES: CapabilitiesContextValue = {
  edition: __EDITION__,
  version: 'unknown',
  capabilities: {
    cases: ENTERPRISE_BUNDLE,
    notebooks: ENTERPRISE_BUNDLE,
    risk: ENTERPRISE_BUNDLE,
    melod: ENTERPRISE_BUNDLE,
    customEnrichment: ENTERPRISE_BUNDLE,
    agentEnrichment: ENTERPRISE_BUNDLE,
    aiTuning: ENTERPRISE_BUNDLE,
    playbooks: ENTERPRISE_BUNDLE,
    incidents: ENTERPRISE_BUNDLE,
    // Core in both editions (NAN-2357) — an open bundle that falls back to
    // false would hide the nav and breadcrumb for a page it genuinely has.
    siemHealth: true,
    sso: ENTERPRISE_BUNDLE,
    observabilityConvergence: ENTERPRISE_BUNDLE,
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
