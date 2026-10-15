// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useLocation } from 'react-router-dom';
import { API_BASE_URL } from '@/lib/api/utils';
import { useAuth } from '@/contexts/AuthContext';
import { authenticatedFetch } from '@/lib/authenticated-fetch';
import { browserTenantRuntime, type TenantRuntimeSnapshot } from '@/lib/tenant-runtime';
import {
  acceptTenantBootstrapAuthorityRevisions,
  parseTenantAiAvailability,
  tenantAiCapabilities,
  tenantBootstrapCacheKey,
  TENANT_AI_UNAVAILABLE,
  validateTenantCapabilitySnapshot,
  type ExpectedTenantCapabilityIdentity,
  type TenantAiAvailability,
  type TenantBootstrapAuthorityRevisions,
  type TenantCapabilitySnapshot,
} from '@/lib/tenant-capabilities';
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
  // NAN-3844: until the API answers, the install's ingest mode is unknown;
  // Vector-dependent controls render disabled rather than assuming Vector.
  ingestMode: 'unknown',
  capabilities: {
    search: true,
    cases: ENTERPRISE_BUNDLE,
    notebooks: ENTERPRISE_BUNDLE,
    risk: ENTERPRISE_BUNDLE,
    melod: ENTERPRISE_BUNDLE,
    queryCorrection: ENTERPRISE_BUNDLE,
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
    // NAN-3467: `/api/ioc-lists` is mounted only on the hosted-shared tenant
    // substrate, never by a dedicated build of either edition.
    iocLists: false,
  },
};

const SHARED_FAIL_CLOSED_CAPABILITIES: CapabilitiesContextValue = {
  edition: 'enterprise',
  version: 'unknown',
  capabilities: {
    search: false,
    cases: false,
    notebooks: false,
    risk: false,
    melod: false,
    queryCorrection: false,
    customEnrichment: false,
    agentEnrichment: false,
    aiTuning: false,
    playbooks: false,
    incidents: false,
    siemHealth: false,
    sso: false,
    observabilityConvergence: false,
    iocLists: false,
  },
};

async function fetchCapabilities(): Promise<CapabilitiesContextValue> {
  const response = await authenticatedFetch('/api/capabilities', `${API_BASE_URL}/api/capabilities`);
  if (!response.ok) {
    throw new Error(`Failed to fetch capabilities: ${response.status}`);
  }
  const body = (await response.json()) as CapabilitiesContextValue;
  if (body.edition !== 'open' && body.edition !== 'enterprise') {
    throw new Error(`Unexpected build edition: ${body.edition}`);
  }
  // NAN-3844: an older API omits ingestMode; it predates `--tenzir`, so Vector.
  return { ...body, ingestMode: body.ingestMode === 'tenzir_only' ? 'tenzir_only' : 'vector' };
}

/**
 * NAN-2361 wave 8: the platform provider half of tenant AI. Read alongside
 * the plan so `capabilities.melod` / `queryCorrection` / `aiTuning` are false
 * while no platform AI provider is enabled, instead of every page learning it
 * from a 409 (the Search page fired `POST /api/melod/correct-query` after each
 * failed search on the live lake). An unreadable probe is deny-all; the next
 * poll retries it.
 */
const AI_AVAILABILITY_TTL_MS = 60_000;
let aiAvailabilityCache: { runtimeKey: string; at: number; value: TenantAiAvailability } | undefined;

async function fetchTenantAiAvailability(
  capturedRuntime: TenantRuntimeSnapshot,
): Promise<TenantAiAvailability> {
  // The plan is polled every 15 s for revocation; provider state changes on
  // a platform timescale, so one probe per minute per runtime is enough.
  const cached = aiAvailabilityCache;
  if (cached && cached.runtimeKey === capturedRuntime.key && Date.now() - cached.at < AI_AVAILABILITY_TTL_MS) {
    return cached.value;
  }
  let value = TENANT_AI_UNAVAILABLE;
  try {
    const response = await authenticatedFetch(
      '/api/settings/ai-availability', `${API_BASE_URL}/api/settings/ai-availability`, {},
      () => browserTenantRuntime.assertCurrent(capturedRuntime),
    );
    browserTenantRuntime.assertCurrent(capturedRuntime);
    if (response.ok) value = parseTenantAiAvailability(await response.json());
  } catch {
    value = TENANT_AI_UNAVAILABLE;
  }
  aiAvailabilityCache = { runtimeKey: capturedRuntime.key, at: Date.now(), value };
  return value;
}

async function fetchTenantCapabilities(
  capturedRuntime: TenantRuntimeSnapshot,
  expected: ExpectedTenantCapabilityIdentity,
  previousRevisions: TenantBootstrapAuthorityRevisions | undefined,
): Promise<CapabilitiesContextValue> {
  if (capturedRuntime.scope.kind !== 'enterprise_shared') {
    throw new Error('Tenant capability fetch requires an enterprise_shared runtime');
  }
  const response = await authenticatedFetch(
    '/api/auth/tenant-bootstrap', `${API_BASE_URL}/api/auth/tenant-bootstrap`, {},
    () => browserTenantRuntime.assertCurrent(capturedRuntime),
  );
  if (!response.ok) {
    throw new Error(`Failed to fetch tenant capabilities: ${response.status}`);
  }
  const body: unknown = await response.json();
  browserTenantRuntime.assertCurrent(capturedRuntime);
  const tenantPlan = validateTenantCapabilitySnapshot(body, expected);
  acceptTenantBootstrapAuthorityRevisions(previousRevisions, {
    authorization: tenantPlan.identity.authorizationRevision,
    planAssignment: tenantPlan.plan.assignmentRevision,
    featureFlags: tenantPlan.featureFlags.revision,
  });
  browserTenantRuntime.assertCurrent(capturedRuntime);
  const ai = tenantAiCapabilities(tenantPlan, await fetchTenantAiAvailability(capturedRuntime));

  return {
    edition: tenantPlan.edition,
    version: tenantPlan.version,
    tenantPlan,
    // Existing navigation and route components consume these names. In shared
    // mode the tenant's plan is the entitlement authority (NAN-2361): every
    // product area is served on the tenant substrate, so each capability maps
    // to its plan component instead of being hard-wired off. The API's fence
    // still enforces the plan per request; this only decides what the shell
    // shows.
    capabilities: {
      search: tenantPlan.components.search.enabled,
      cases: tenantPlan.components.cases.enabled,
      notebooks: tenantPlan.components.notebooks.enabled,
      risk: tenantPlan.components.risk.enabled,
      // The three AI flags also require an enabled platform provider (see
      // fetchTenantAiAvailability); a plan grant alone cannot serve a job.
      melod: ai.melod,
      queryCorrection: ai.queryCorrection,
      customEnrichment: tenantPlan.components.custom_enrichment.enabled,
      agentEnrichment: tenantPlan.components.agent_enrichment.enabled,
      aiTuning: ai.aiTuning,
      playbooks: tenantPlan.components.playbooks.enabled,
      incidents: tenantPlan.components.incidents.enabled,
      siemHealth: tenantPlan.components.siem_health.enabled,
      sso: tenantPlan.components.sso.enabled,
      observabilityConvergence: tenantPlan.components.observability_convergence.enabled,
      // NAN-3467: always mounted in shared mode; `enrichments:view` gates it.
      iocLists: true,
    },
  };
}

export function CapabilitiesProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { user, isAuthenticated, isLoading, tenantRuntime } = useAuth();
  const tenantAuthShell = location.pathname.startsWith('/t/');
  const shared = user?.deployment_mode === 'enterprise_shared'
    && tenantRuntime.scope.kind === 'enterprise_shared';
  // Runtime keys already include the exact tenant+member+epoch. The three
  // server revisions prevent an older in-flight response from replacing a
  // newer auth, plan, or rollout snapshot inside that runtime.
  const activeBootstrapKeys = useRef(new Map<string, string>());
  const acceptedBootstraps = useRef(new Map<string, TenantCapabilitySnapshot>());
  useEffect(() => {
    const currentRuntimeKey = shared ? tenantRuntime.key : undefined;
    for (const [runtimeKey, bootstrapKey] of activeBootstrapKeys.current) {
      if (runtimeKey !== currentRuntimeKey) {
        activeBootstrapKeys.current.delete(runtimeKey);
        acceptedBootstraps.current.delete(bootstrapKey);
      }
    }
  }, [shared, tenantRuntime.key]);
  // The public build edition is static. Shared plans are deliberately polled:
  // PostgreSQL assignment/membership changes must revoke UI affordances within
  // a bounded window, and any failed refresh switches to the deny-all value.
  const { data, error } = useQuery({
    queryKey: shared
      ? ['tenant-capabilities', tenantRuntime.key]
      : ['capabilities'],
    queryFn: async () => {
      if (!shared || !user || tenantRuntime.scope.kind !== 'enterprise_shared') {
        return fetchCapabilities();
      }
      const runtimeKey = tenantRuntime.key;
      const previousCacheKey = activeBootstrapKeys.current.get(runtimeKey);
      const previous = previousCacheKey
        ? acceptedBootstraps.current.get(previousCacheKey)
        : undefined;
      const result = await fetchTenantCapabilities(tenantRuntime, {
        userId: user.id,
        tenant: tenantRuntime.scope.tenant,
        roles: user.roles,
        permissions: user.permissions,
      }, previous ? {
        authorization: previous.identity.authorizationRevision,
        planAssignment: previous.plan.assignmentRevision,
        featureFlags: previous.featureFlags.revision,
      } : undefined);
      if (!result.tenantPlan) {
        throw new Error('Tenant capability response omitted the plan snapshot');
      }
      const nextCacheKey = JSON.stringify(tenantBootstrapCacheKey(result.tenantPlan));
      if (previousCacheKey && previousCacheKey !== nextCacheKey) {
        acceptedBootstraps.current.delete(previousCacheKey);
      }
      acceptedBootstraps.current.set(nextCacheKey, result.tenantPlan);
      activeBootstrapKeys.current.set(runtimeKey, nextCacheKey);
      return result;
    },
    staleTime: shared ? 0 : Infinity,
    gcTime: shared ? 30_000 : Infinity,
    refetchInterval: shared ? 15_000 : false,
    refetchOnWindowFocus: shared,
    retry: shared ? 0 : 1,
    // Never call the public build-wide route while the shared tenant identity
    // is loading, and never make the tenant route's unauthenticated login shell
    // depend on an authenticated endpoint.
    enabled: !isLoading && (shared ? isAuthenticated : !tenantAuthShell),
  });

  const value = shared
    ? (error === null && data?.tenantPlan ? data : SHARED_FAIL_CLOSED_CAPABILITIES)
    : (data ?? (error === null
      ? FALLBACK_CAPABILITIES
      // A failed fetch must not lock Vector surfaces for good; the API's
      // 409 still guards a Tenzir-only install.
      : { ...FALLBACK_CAPABILITIES, ingestMode: 'vector' }));

  return (
    <CapabilitiesContext.Provider value={value}>
      {children}
    </CapabilitiesContext.Provider>
  );
}
