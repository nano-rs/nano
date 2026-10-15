// SPDX-License-Identifier: AGPL-3.0-or-later
import { useContext } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { ThreatIntelProvider } from '@/lib/api/threat-intel';
import { CapabilitiesContext } from '@/hooks/use-capabilities';

/** External threat-intel lookups exist on hosted-shared tenants (the only ones with a
    `tenantPlan` snapshot) whose plan includes agent enrichment and whose
    member holds `enrichments:view`; `/api/threat-intel/*` is not mounted
    elsewhere. Reads the context without throwing, so the Enrich affordances
    can sit in components rendered outside the provider (tests, embeds). */
export function useThreatIntelEnabled(): boolean {
  const ctx = useContext(CapabilitiesContext);
  const plan = ctx?.tenantPlan;
  if (!plan || !ctx.capabilities.agentEnrichment) return false;
  const perms = plan.identity.permissions;
  return perms.includes('*') || perms.includes('enrichments:view');
}

/** The tenant's own indicator sets (IOC feeds and lists) are searchable by
    hosted-shared members with `enrichments:view` and `search:execute` (the
    lookup runs on the tenant's attested search runtime). NAN-3881. */
export function useIndicatorSetsEnabled(): boolean {
  const ctx = useContext(CapabilitiesContext);
  const perms = ctx?.tenantPlan?.identity.permissions;
  if (!perms) return false;
  return perms.includes('*') || (perms.includes('enrichments:view') && perms.includes('search:execute'));
}

/** The Enrich sheet: it always searches the tenant's own indicator sets
    when the member may, and adds external providers where the tenant has
    the agent-enrichment add-on (NAN-3881). */
export function useEnrichEnabled(): boolean {
  const sets = useIndicatorSetsEnabled();
  const external = useThreatIntelEnabled();
  return sets || external;
}

/** Query key root. The QueryClient is already per tenant runtime
    (TenantRuntimeBoundary), so a tenant switch starts from an empty cache;
    the member id keeps a re-login under another member separate too. */
export function useThreatIntelKey(): readonly unknown[] {
  const ctx = useContext(CapabilitiesContext);
  return ['threat-intel', ctx?.tenantPlan?.identity.userId] as const;
}

/** The tenant's provider list (shared query; disabled where lookups don't exist). */
export function useThreatIntelProviders() {
  const enabled = useThreatIntelEnabled();
  const key = useThreatIntelKey();
  return useQuery({
    queryKey: [...key, 'providers'],
    queryFn: () => api.threatIntel.listProviders(),
    enabled,
    retry: false,
  });
}

export function matchesProvider(p: ThreatIntelProvider, query: string): boolean {
  const q = query.trim().toLowerCase();
  return !q || p.name.toLowerCase().includes(q) || p.provider.includes(q) || 'threat intel'.includes(q);
}
