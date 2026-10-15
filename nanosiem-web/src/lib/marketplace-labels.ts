// SPDX-License-Identifier: AGPL-3.0-or-later
// User copy for Marketplace / enrichment enum values (NAN-3762). The API keeps
// its wire values; these maps are display-only. A value the UI does not know
// never renders raw: it falls back to a neutral label.

/**
 * Where an enrichment runs, from the API's `execution_stage`. There is no
 * search-time stage.
 */
const EXECUTION_STAGE_LABELS: Record<string, string> = {
  bronze_ingest: 'Built in · at ingest',
  agent_on_demand: 'On demand · pivt',
  tenant_scheduled_publication: 'Scheduled refresh',
};

export function executionStageLabel(stage: string | null | undefined): string {
  return own(EXECUTION_STAGE_LABELS, stage) ?? 'Enrichment';
}

/** `pull` collector delivery: the vendor API the customer connected, never HEC. */
export function collectorDeliveryLabel(entry: { slug: string; name: string; origin?: string | null }): string {
  const named = (value: string | null | undefined) => {
    const v = value?.trim();
    return v && !/\bhec\b/i.test(v) ? v : '';
  };
  return `Pull · ${named(entry.origin) || named(entry.name) || 'vendor API'}`;
}

/** Hosted feed ingest-credential state (`credential`). */
const FEED_CREDENTIAL_LABELS: Record<string, string> = {
  ready: 'ready',
  pending: 'pending',
  not_required: 'not required',
  waiting_for_enrollment: 'waiting for enrollment',
};

export function feedCredentialLabel(state: string | null | undefined): string {
  return own(FEED_CREDENTIAL_LABELS, state) ?? (state ? humanizeEnum(state) : 'unknown');
}

/** Parser rollout state of a feed's log source (`rollout_state`). */
const ROLLOUT_STATE_LABELS: Record<string, string> = {
  live: 'live', pending: 'pending', building: 'building', validated: 'validated',
  rolling: 'rolling out', failed: 'failed', cancelled: 'cancelled', superseded: 'superseded',
};

export function rolloutStateLabel(state: string | null | undefined): string {
  return state ? own(ROLLOUT_STATE_LABELS, state) ?? humanizeEnum(state) : 'pending';
}

/** Last run status of a hosted feed (`last_status`). */
export function feedRunStatusLabel(status: string | null | undefined): string {
  return status ? humanizeEnum(status) : 'pending';
}

/** Effective health of an inventory item. */
export function inventoryHealthLabel(health: string): string {
  return humanizeEnum(health);
}

/** Capabilities / categories / enrichment types: known copy, else words. */
const CAPABILITY_LABELS: Record<string, string> = {
  ip: 'IP', ip_geo: 'IP geo', ip_asn: 'IP ASN', asn: 'ASN', geo: 'geo', geoip: 'GeoIP',
  ioc: 'IOC', threat_intel: 'threat intel', ip_reputation: 'IP reputation',
  domain_reputation: 'domain reputation', hash_reputation: 'hash reputation',
  tor_exit_nodes: 'Tor exit nodes', identity: 'identity', vulnerability: 'vulnerability',
};

export function capabilityLabel(value: string): string {
  return own(CAPABILITY_LABELS, value) ?? humanizeEnum(value);
}

/** Own-property lookup: `__proto__` / `toString` are not labels. */
function own(map: Record<string, string>, key: string | null | undefined): string | undefined {
  return key && Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

/** Last resort for an enum value: `snake_case`/`kebab-case` → spaced words. */
export function humanizeEnum(value: string): string {
  const words = value.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  return words || 'unknown';
}
