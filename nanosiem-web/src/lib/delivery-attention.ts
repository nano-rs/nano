// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4941 (main's NAN-3661, re-backed for the ClickHouse product): which
 * deliveries into a log source need attention, for the Log Sources list badge.
 *
 * Main read `attention` from the hosted `/api/log-sources/pipe-inputs`. Here a
 * source is fed by the source configuration it is dispatched from (cloud pull,
 * Kafka) and by connector pull feeds on its lane, so the attention is derived
 * from APIs this product serves:
 *
 * - pull: the dispatching config is gone (failed), enabled but not deployed
 *   (blocked: events wait in the queue), or disabled (paused);
 * - push: the same, when the dispatching config is a push listener (HTTP,
 *   Vector, OTLP). A `splunk_hec` config is only a routing profile over the
 *   platform-managed HEC listener (always on, routes by sourcetype), so its
 *   enabled/deployed flags never stop delivery and raise no attention
 *   (NAN-5318);
 * - connector: a feed on the lane whose last run did not succeed (failed), or
 *   that is paused.
 *
 * Reasons are fixed codes or statuses, never a stored free-text error.
 */

import type { LogSource, SourceConfiguration } from '@/lib/api/types';
import type { ConnectorFeed } from '@/lib/api/connector-feeds';
import { isListenerConfigType } from '@/lib/ingestion-paths';

export type DeliveryAttentionLevel = 'failed' | 'blocked' | 'paused';

export interface DeliveryAttention {
  kind: 'pull' | 'push' | 'connector';
  id: string;
  name: string;
  level: DeliveryAttentionLevel;
  reason: string;
}

type DispatchConfig = Pick<SourceConfiguration, 'id' | 'name' | 'enabled' | 'deployed'> &
  Partial<Pick<SourceConfiguration, 'config_type'>>;

/**
 * The shared HEC listener is platform-managed and always on; a `splunk_hec`
 * source configuration only adds routing on top of it, so disabling or not
 * deploying it never stops HEC delivery (NAN-5318).
 */
export function isPlatformHecProfile(config: { config_type?: string }): boolean {
  return config.config_type === 'splunk_hec';
}

/** The dispatching config's attention, else null. `undefined` config = not loaded yet. */
export function pullAttention(
  configId: string,
  config: DispatchConfig | null | undefined,
): DeliveryAttention | null {
  if (config === undefined) return null;
  if (config === null) return { kind: 'pull', id: configId, name: configId, level: 'failed', reason: 'source configuration missing' };
  if (isPlatformHecProfile(config)) return null;
  const kind = config.config_type && isListenerConfigType(config.config_type) ? 'push' : 'pull';
  if (!config.enabled) return { kind, id: config.id, name: config.name, level: 'paused', reason: 'disabled' };
  if (!config.deployed) return { kind, id: config.id, name: config.name, level: 'blocked', reason: 'not deployed' };
  return null;
}

/** A connector feed's attention, else null (healthy, running or not yet run). */
export function connectorAttention(
  feed: Pick<ConnectorFeed, 'id' | 'name' | 'enabled' | 'last_status'>,
): DeliveryAttention | null {
  if (!feed.enabled) return { kind: 'connector', id: feed.id, name: feed.name, level: 'paused', reason: 'paused' };
  if (feed.last_status && feed.last_status !== 'success') {
    return { kind: 'connector', id: feed.id, name: feed.name, level: 'failed', reason: feed.last_status };
  }
  return null;
}

/** Attention per log source id, from the sources, the configs list (when readable) and the feeds (when readable). */
export function deliveryAttentionBySource(
  sources: Pick<LogSource, 'id' | 'source_type' | 'match_values' | 'dispatch_source_config_id'>[],
  configs: DispatchConfig[] | undefined,
  feeds: Pick<ConnectorFeed, 'id' | 'name' | 'enabled' | 'last_status' | 'source_type'>[] | undefined,
): Map<string, DeliveryAttention[]> {
  const configById = configs ? new Map(configs.map((c) => [c.id, c])) : null;
  const out = new Map<string, DeliveryAttention[]>();
  for (const ls of sources) {
    const items: DeliveryAttention[] = [];
    if (ls.dispatch_source_config_id && configById) {
      const a = pullAttention(ls.dispatch_source_config_id, configById.get(ls.dispatch_source_config_id) ?? null);
      if (a) items.push(a);
    }
    const lanes = new Set([...(ls.match_values ?? []), ls.source_type].filter(Boolean));
    for (const feed of feeds ?? []) {
      if (!lanes.has(feed.source_type)) continue;
      const a = connectorAttention(feed);
      if (a) items.push(a);
    }
    if (items.length) out.set(ls.id, items);
  }
  return out;
}

const LEVEL_RANK: Record<string, number> = { failed: 3, blocked: 2, paused: 1 };

/** The worst level among `items`, or null. */
export function worstAttention(items: readonly { level: string }[]): DeliveryAttentionLevel | null {
  let worst: DeliveryAttentionLevel | null = null;
  for (const item of items) {
    const rank = LEVEL_RANK[item.level] ?? 0;
    if (rank > 0 && (!worst || rank > LEVEL_RANK[worst])) worst = item.level as DeliveryAttentionLevel;
  }
  return worst;
}

/** One tooltip line per item: `pull · CloudTrail prod: blocked (not deployed)`. */
export function attentionSummary(items: readonly DeliveryAttention[]): string[] {
  return items.map((i) => `${i.kind} · ${i.name}: ${i.level}${i.reason && i.reason !== i.level ? ` (${i.reason})` : ''}`);
}
