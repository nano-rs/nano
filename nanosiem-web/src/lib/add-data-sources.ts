// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The "Add source" source list (main's NAN-2593 module, re-backed for the
 * ClickHouse product by NAN-4922).
 *
 * On main this joined the hosted tenant's enrolled route templates to the
 * registry. Here a source is a log source with a push route key: an ingest
 * token bound to it (NAN-4907) decides the source of every event it sends,
 * over HEC, HTTP JSON or OTLP. There is no enrollment step, so every source
 * is issuable as soon as it exists (a draft receives events unparsed).
 */

import type { LogSource } from '@/lib/api/types';
import type { LogSourceConnectStatus } from '@/lib/api/log-source-connect';

/** React Query keys (no secrets are ever cached under them). */
export const INGEST_ENDPOINT_QUERY_KEY = ['log-sources', 'ingest-endpoint'] as const;

/** Log Sources → Credentials (the per-source ingest tokens). */
export const INGEST_CREDENTIALS_PATH = '/ingestion/log-sources/credentials';

/** The Add source flow, and its `?source=<slug>` preselect (NAN-2946). */
export const ADD_DATA_PATH = '/ingestion/log-sources/new';
export const ADD_DATA_SOURCE_PARAM = 'source';

/** Building the parser of an existing source edits it; other arrivals create a source. */
export function sourceOnboardingPermission(search: string): 'log_sources:edit' | 'log_sources:create' {
  const params = new URLSearchParams(search);
  return params.get('stage') === 'parse' && !!params.get('source_id')
    ? 'log_sources:edit' : 'log_sources:create';
}

/** Route keys no token can be issued for: what unattributed traffic falls back to. */
const UNATTRIBUTED_SLUGS = new Set(['unknown', 'default']);

/** nano's own audit lane takes no user-issued tokens. */
export function isPlatformOnlySource(slug: string): boolean {
  return slug === 'audit';
}

/**
 * Add source, optionally with one source preselected: the flow opens on the
 * Connect step for that source.
 */
export function addDataLink(slug?: string | null): string {
  const s = slug?.trim();
  return s && issuableSlugs([s]).length === 1 ? `${ADD_DATA_PATH}?${ADD_DATA_SOURCE_PARAM}=${encodeURIComponent(s)}` : ADD_DATA_PATH;
}

/** The slugs a token can be issued for. */
export function issuableSlugs(slugs: readonly string[] | undefined): string[] {
  return (slugs ?? []).filter((s) => !!s && !UNATTRIBUTED_SLUGS.has(s) && !isPlatformOnlySource(s));
}

/** Protocols one ingest token authenticates (HEC, HTTP JSON, OTLP/HTTP). */
export type DirectProtocol = 'hec' | 'nano_https' | 'otlp_http';
export const DIRECT_PROTOCOLS: DirectProtocol[] = ['hec', 'nano_https', 'otlp_http'];

export const PROTOCOL_LABEL: Record<string, string> = {
  hec: 'HEC',
  nano_https: 'HTTP JSON',
  otlp_http: 'OTLP/HTTP',
};

export interface AddDataSource {
  /** The route key every event of a bound token carries. */
  slug: string;
  protocols: DirectProtocol[];
  /** Always true here: a source receives as soon as it exists. Kept for main's shape. */
  enrolled: boolean;
  logSource?: Pick<LogSource, 'id' | 'name' | 'vendor' | 'product' | 'lifecycle_status' | 'deployed'>;
  events24h?: number;
  lastEventAt?: string | null;
}

/**
 * Sources a token can be issued for: log sources whose connect status says
 * they take pushed events, keyed by route key. A source without a status row
 * (the status read failed) falls back to its first match value. Sorted by
 * name.
 */
export function addDataSources(
  logSources: LogSource[] | undefined,
  statuses: LogSourceConnectStatus[] | undefined,
): AddDataSource[] {
  const byId = new Map((statuses ?? []).map((s) => [s.source_id, s]));
  const bySlug = new Map<string, AddDataSource>();
  for (const ls of logSources ?? []) {
    const status = byId.get(ls.id);
    if (status && !status.push_capable) continue;
    const slug = status?.route_key ?? ls.match_values?.[0] ?? '';
    if (issuableSlugs([slug]).length === 0 || bySlug.has(slug)) continue;
    bySlug.set(slug, {
      slug,
      protocols: [...DIRECT_PROTOCOLS],
      enrolled: true,
      logSource: {
        id: ls.id, name: ls.name, vendor: ls.vendor, product: ls.product,
        lifecycle_status: ls.lifecycle_status, deployed: ls.deployed,
      },
      events24h: status?.events_24h,
      lastEventAt: status?.last_seen ?? null,
    });
  }
  return [...bySlug.values()].sort((a, b) => (a.logSource?.name ?? a.slug).localeCompare(b.logSource?.name ?? b.slug));
}

/**
 * The source a `?source=` deep link preselects: the matching entry, or null
 * (unknown slug, reserved key, or the list is not loaded yet).
 */
export function preselectedAddDataSource(
  sources: readonly AddDataSource[],
  requested: string | null | undefined,
): AddDataSource | null {
  const slug = requested?.trim();
  if (!slug || issuableSlugs([slug]).length === 0) return null;
  return sources.find((s) => s.slug === slug) ?? null;
}

/** Protocols offered for a source: every token takes all three. */
export function protocolsFor(source: AddDataSource | undefined): DirectProtocol[] {
  if (!source) return [];
  return source.protocols.length > 0 ? source.protocols : [...DIRECT_PROTOCOLS];
}

/** A default token name: `<slug>-<protocol>` (the server caps names at 128). */
export function defaultCredentialLabel(slug: string, protocol: string): string {
  return `${slug}-${protocol.replace(/_/g, '-')}`.slice(0, 120);
}
