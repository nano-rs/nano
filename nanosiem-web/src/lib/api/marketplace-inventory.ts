// SPDX-License-Identifier: AGPL-3.0-or-later
/** Phase 7's authoritative tenant status; browser return parameters never populate it. */
export interface MarketplaceEntitlement {
  feed_id: string;
  tier: string;
  grant_revision: number;
  revision: number;
  state: string;
  enabled: boolean;
  expires_at: string | null;
}

export function entitlementLabel(status: MarketplaceEntitlement, now = Date.now()): string {
  if (status.state === 'revoked') return 'Revoked';
  if (status.state === 'expired' || (status.expires_at !== null && Date.parse(status.expires_at) <= now)) return 'Expired';
  if (status.state === 'pending') return 'Payment pending';
  if (status.state !== 'active') return 'Status unavailable';
  return status.enabled ? 'Purchased · Enabled' : 'Purchased · Disabled';
}

export interface InventoryCommon {
  id: string;
  name: string;
  enabled: boolean;
  revision: number | null;
  effective_health: string;
  last_sync: string | null;
  next_refresh: string | null;
  reason: string | null;
  execution_stage: string;
  capabilities: string[];
  can_toggle: boolean;
  can_edit: boolean;
}
export type InventoryItem = InventoryCommon & (
  | { kind: 'baseline'; grant_revision: number | null; feed_revision: number | null }
  | { kind: 'premium'; grant_revision: number | null; feed_revision: number | null; entitled: boolean }
  | { kind: 'custom'; tenant_id: string; author: string; connector: string; repo_commit: string | null; artifact_id: string | null; artifact_sha256: string | null; repository_id: string | null }
);
export function inventoryAction(item: InventoryItem): string {
  if (item.kind === 'baseline') return 'Included · On';
  if (item.kind === 'premium' && !item.entitled) return 'Purchase';
  return item.enabled ? 'Disable' : 'Enable';
}
export function inventoryRouteId(slug: string): string {
  const aliases: Record<string, string> = { 'ipinfo-lite': 'ipinfo_lite', tor: 'tor_exit_nodes', 'tor-exit-nodes': 'tor_exit_nodes' };
  return aliases[slug] ?? slug;
}
export function inventoryReason(item: InventoryItem): string {
  const reasons: Record<string, string> = {
    stale: 'Feed is stale; new evidence is marked with its freshness.',
    missing: 'No usable snapshot is available.', unavailable: 'Provider is not available.',
    unentitled: 'No active entitlement.', expired: 'The snapshot or entitlement has expired.',
    revoked: 'Access has been revoked.', disabled: 'Disabled for this tenant.',
    agent_enrichment_not_provisioned: 'Agent execution is not provisioned for this tenant.', not_synced: 'No successful sync has been recorded.',
    connector_execution_not_provisioned: 'This connector has no tenant execution runtime assigned.',
    sync_failed: 'The last sync failed.', not_deployed: 'No active artifact matches this provider revision.',
  };
  return item.reason ? (reasons[item.reason] ?? 'Provider status is unknown.') : 'Healthy';
}

export function customInventoryRedirect(id: string, shared: boolean, search: string): string | null {
  return shared && !new URLSearchParams(search).has('edit')
    ? `/marketplace?item=${encodeURIComponent(`custom:${id}`)}` : null;
}

export interface CheckoutResponse {
  intent: { purchase_key: string; sku: string; origin: 'signup' | 'later'; created_at: string };
  redirect_url: string;
}

