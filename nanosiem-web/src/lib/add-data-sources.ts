// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The hosted-shared "Add data" source list (NAN-2593, design §3.2).
 *
 * A credential is issued against a slug the tenant's parser cell accepts: a
 * route template the platform enrolled from the tenant's parser bundle. The
 * ingest endpoint lists those templates with the tenant's credentials (label
 * `route template: <slug>`, 9000601/9001125). They are joined here, by slug,
 * to the registry entries in `GET /api/log-sources` for names and 24h counts.
 * Registry entries whose slug is not enrolled yet (a custom parser still
 * rolling out, NAN-2607) are listed too: a credential can be requested for
 * them at once and is issued when the roll enrolls the slug.
 */

import type { LogSource, TenantIngestCredential, TenantIngestEndpoint, TenantIngestSource } from '@/lib/api/types';

export const ROUTE_TEMPLATE_LABEL_PREFIX = 'route template: ';

/** React Query keys (no secrets are ever cached under them). */
export const INGEST_ENDPOINT_QUERY_KEY = ['log-sources', 'ingest-endpoint'] as const;
export const INGEST_CREDENTIALS_QUERY_KEY = ['log-sources', 'ingest-credentials'] as const;
export const SENDER_TEMPLATES_QUERY_KEY = ['log-sources', 'sender-templates'] as const;
export function sourceWritersQueryKey(target: { logSourceId?: string; sourceSlug?: string }) {
  return ['log-sources', 'source-writers', target.logSourceId ?? null, target.sourceSlug ?? null] as const;
}

/** Log Sources → Credentials with the revoke dialog open for one credential (NAN-2597). */
export function revokeLink(credentialId: string): string {
  return `/ingestion/log-sources/credentials?revoke=${encodeURIComponent(credentialId)}`;
}

/** The Add data wizard, and its `?source=<slug>` preselect (NAN-2946). */
export const ADD_DATA_PATH = '/ingestion/log-sources/wizard';
export const ADD_DATA_SOURCE_PARAM = 'source';

/**
 * Add data, optionally with one source preselected: the wizard opens on the
 * Issue step for that source (direct arrival).
 */
export function addDataLink(slug?: string | null): string {
  const s = slug?.trim();
  return s ? `${ADD_DATA_PATH}?${ADD_DATA_SOURCE_PARAM}=${encodeURIComponent(s)}` : ADD_DATA_PATH;
}

/**
 * Lake labels no source credential can be issued for: `unknown` / `default`
 * are what collector and conventional traffic fall back to (Unattributed).
 */
const UNATTRIBUTED_SLUGS = new Set(['unknown', 'default']);

/** The slugs of a registry entry a source credential can be issued for. */
export function issuableSlugs(slugs: readonly string[] | undefined): string[] {
  return (slugs ?? []).filter((s) => !!s && !UNATTRIBUTED_SLUGS.has(s));
}

/**
 * The source a `?source=` deep link preselects: the matching Add data entry,
 * or null (unknown slug, Unattributed label, or the list is not loaded yet).
 */
export function preselectedAddDataSource(
  sources: readonly AddDataSource[],
  requested: string | null | undefined,
): AddDataSource | null {
  const slug = requested?.trim();
  if (!slug || UNATTRIBUTED_SLUGS.has(slug)) return null;
  return sources.find((s) => s.slug === slug) ?? null;
}

/** Unread sealed tokens expire 10 minutes after issuance (9001640). */
const REVEAL_WINDOW_MS = 10 * 60 * 1000;

/** Protocols a source credential can carry (`kind = source`). */
export type DirectProtocol = 'hec' | 'nano_https' | 'otlp_http';
export const DIRECT_PROTOCOLS: DirectProtocol[] = ['hec', 'nano_https', 'otlp_http'];

export const PROTOCOL_LABEL: Record<string, string> = {
  hec: 'HEC',
  nano_https: 'HTTPS JSON',
  otlp_http: 'OTLP/HTTP',
};

export interface AddDataSource {
  slug: string;
  /** Protocols enrolled for the slug (route templates); empty when not enrolled yet. */
  protocols: DirectProtocol[];
  enrolled: boolean;
  /** The registry entry answering for this slug, when there is one. */
  logSource?: Pick<LogSource, 'id' | 'name' | 'vendor' | 'product' | 'lifecycle_status' | 'deployed'>;
  events24h?: number;
  lastEventAt?: string | null;
}

function isDirectProtocol(p: string): p is DirectProtocol {
  return (DIRECT_PROTOCOLS as string[]).includes(p);
}

export function isRouteTemplate(source: Pick<TenantIngestSource, 'label'>): boolean {
  return source.label.startsWith(ROUTE_TEMPLATE_LABEL_PREFIX);
}

function registrySlugs(ls: LogSource): string[] {
  const slugs = ls.ingest?.source_slugs?.length ? ls.ingest.source_slugs : ls.match_values ?? [];
  return slugs.filter((s) => !!s);
}

/**
 * Enrolled slugs (active route templates) joined to registry entries, then
 * registry entries that are not enrolled yet. Sorted: enrolled first, by slug.
 */
export function addDataSources(
  endpoint: Pick<TenantIngestEndpoint, 'sources'> | undefined,
  logSources: LogSource[] | undefined,
): AddDataSource[] {
  const bySlug = new Map<string, AddDataSource>();
  for (const row of endpoint?.sources ?? []) {
    if (!isRouteTemplate(row)) continue;
    if (row.route_state !== 'active' || !isDirectProtocol(row.protocol)) continue;
    const entry = bySlug.get(row.source_slug) ?? { slug: row.source_slug, protocols: [], enrolled: true };
    if (!entry.protocols.includes(row.protocol)) entry.protocols.push(row.protocol);
    bySlug.set(row.source_slug, entry);
  }
  for (const ls of logSources ?? []) {
    if (ls.lifecycle_status === 'draft') continue;
    for (const slug of registrySlugs(ls)) {
      const entry = bySlug.get(slug) ?? { slug, protocols: [], enrolled: false };
      if (!entry.logSource) {
        entry.logSource = {
          id: ls.id, name: ls.name, vendor: ls.vendor, product: ls.product,
          lifecycle_status: ls.lifecycle_status, deployed: ls.deployed,
        };
        entry.events24h = ls.ingest?.events_last_24h;
        entry.lastEventAt = ls.ingest?.last_event_at ?? null;
      }
      bySlug.set(slug, entry);
    }
  }
  for (const entry of bySlug.values()) entry.protocols.sort((a, b) => DIRECT_PROTOCOLS.indexOf(a) - DIRECT_PROTOCOLS.indexOf(b));
  return [...bySlug.values()].sort((a, b) => Number(b.enrolled) - Number(a.enrolled) || a.slug.localeCompare(b.slug));
}

/**
 * Protocols offered for a source. An enrolled slug offers exactly its route
 * templates. A slug still rolling out offers HEC and HTTPS JSON (the
 * protocols a custom parser is enrolled with); OTLP slugs are fixed by path.
 */
export function protocolsFor(source: AddDataSource | undefined): DirectProtocol[] {
  if (!source) return [];
  if (source.protocols.length > 0) return source.protocols;
  return ['hec', 'nano_https'];
}

/** A default credential label: `<slug>-<protocol>`, which the server accepts as-is. */
export function defaultCredentialLabel(slug: string, protocol: string): string {
  return `${slug}-${protocol.replace(/_/g, '-')}`.slice(0, 120);
}

/** Issued-but-never-revealed after the reveal window: the token is lost and should be revoked. */
export function tokenLost(c: Pick<TenantIngestCredential, 'state' | 'request_id' | 'revealed_at' | 'created_at'>, now = Date.now()): boolean {
  return c.state === 'active' && !!c.request_id && !c.revealed_at && now - new Date(c.created_at).getTime() > REVEAL_WINDOW_MS;
}
