// SPDX-License-Identifier: AGPL-3.0-or-later
// Pull collector catalog + feed state for the Marketplace (NAN-4946). Main's
// hosted pull broker (NAN-3572 / NAN-3590) is re-backed on this deployment's
// connector pull feeds (NAN-4914): every bundled connector spec is one card,
// and its installations are the connector feeds bound to that spec.
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { ConnectorFeed, ConnectorSpecInfo } from '@/lib/api/connector-feeds';

export const CONNECTOR_FEEDS_KEY = ['connectorFeeds'] as const;
export const CONNECTOR_SPECS_KEY = ['connectorSpecs'] as const;

export interface CollectorRow { spec: ConnectorSpecInfo; feeds: ConnectorFeed[] }

const IDENTITY = /^(okta|google_workspace|gws|entra|azure_ad|onelogin|jumpcloud|duo)/;

/** Marketplace group a collector belongs to. Unknown vendors fall into "Other integrations". */
export function collectorSection(spec: ConnectorSpecInfo): 'identity' | 'other' {
  return IDENTITY.test(spec.name) || spec.credential_provider === 'okta' ? 'identity' : 'other';
}

/** Identity directory feeds (users and groups, `kind: identity`) rather than event logs. */
export function isDirectoryCollector(spec: ConnectorSpecInfo): boolean {
  return spec.kind === 'identity';
}

/** What this caller may do with one connector, mirroring the server's checks
 *  in handlers/connector_feeds.rs: identity connectors also need
 *  `enrichments:configure`; binding a credential needs `credentials:use`,
 *  entering a new one also `credentials:create`. */
export interface CollectorPermissions {
  /** Install with an existing credential (or one that needs none). */
  installExisting: boolean;
  /** Install entering a new credential inline. */
  installNew: boolean;
  /** Enable / disable and adopt a spec update. */
  toggle: boolean;
  remove: boolean;
  rotate: boolean;
}

export function collectorPermissions(spec: ConnectorSpecInfo, has: (perm: string) => boolean): CollectorPermissions {
  const identityOk = spec.kind !== 'identity' || has('enrichments:configure');
  const needsCredential = spec.credential_fields.length > 0;
  const base = identityOk && has('log_sources:create') && has('log_sources:deploy');
  return {
    installExisting: base && (!needsCredential || has('credentials:use')),
    installNew: base && needsCredential && has('credentials:use') && has('credentials:create'),
    toggle: identityOk && has('log_sources:edit') && has('log_sources:deploy'),
    remove: identityOk && has('log_sources:delete'),
    rotate: has('credentials:rotate'),
  };
}

export function collectorMatches(spec: ConnectorSpecInfo, query: string): boolean {
  const q = query.toLowerCase().trim();
  return !q || `${spec.display_name} ${spec.name} ${spec.source_type} ${spec.credential_provider}`.toLowerCase().includes(q);
}

export interface CollectorState { installed: boolean; enabled: boolean; health: string }

export function collectorState(feeds: ConnectorFeed[], status: { isError: boolean; isPending: boolean }): CollectorState {
  const installed = feeds.length > 0;
  const live = feeds.filter(f => f.enabled);
  const enabled = live.length > 0;
  const health = status.isError ? 'status unavailable'
    : status.isPending ? 'checking'
    : !installed ? 'not installed'
    : !enabled ? 'disabled'
    : live.some(f => f.last_error || (f.last_status && f.last_status !== 'success')) ? 'error'
    : live.some(f => f.running) ? 'running'
    : live.every(f => f.last_success_at) ? 'healthy'
    : 'pending';
  return { installed, enabled, health };
}

/**
 * Connector specs + feeds. `pollFeeds` gates the 30 s refresh: when collectors
 * are not on screen nothing is polled.
 */
export function useConnectorCollectors({ pollFeeds }: { pollFeeds: boolean }) {
  const { hasAllPermissions } = useAuth();
  const canView = hasAllPermissions(['log_sources:view']);
  const specs = useQuery({ queryKey: CONNECTOR_SPECS_KEY, queryFn: () => api.connectorFeeds.listSpecs(), enabled: canView, retry: false, staleTime: 5 * 60_000 });
  const feeds = useQuery({
    queryKey: CONNECTOR_FEEDS_KEY,
    queryFn: () => api.connectorFeeds.list(),
    enabled: canView,
    retry: false,
    refetchInterval: query => pollFeeds && (query.state.data?.length ?? 0) > 0 ? 30_000 : false,
    refetchIntervalInBackground: false,
  });
  const rows: CollectorRow[] = canView
    ? (specs.data ?? []).map(spec => ({ spec, feeds: (feeds.data ?? []).filter(f => f.connector === spec.name) }))
    : [];
  return {
    rows,
    canView,
    feedStatus: { isError: feeds.isError, isPending: feeds.isPending },
    isError: canView && specs.isError,
    isRefetching: canView && (specs.isFetching || feeds.isFetching),
    refetch: () => { void specs.refetch(); void feeds.refetch(); },
    permissionsFor: (spec: ConnectorSpecInfo) => collectorPermissions(spec, perm => hasAllPermissions([perm])),
  };
}
