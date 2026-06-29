// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import type {
  CloudOverviewAccount,
  CloudOverviewAnomaly,
  CloudOverviewPrincipal,
  CloudOverviewResponse,
  TimeRange,
} from '@/lib/api/types';
import { CachedNotice } from '@/components/search/CachedNotice';
import { useReportPhase2Status } from '@/components/search/footer-reporter';
import { useIsLiveRun } from '@/components/search/live-run-context';
import { CloudOverviewTopStrip } from './CloudOverviewTopStrip';
import { CloudOverviewHeader } from './CloudOverviewHeader';
import { AccountsGrid } from './AccountsGrid';
import { RiskyPrincipals } from './RiskyPrincipals';
import { CrossAccountTimeline } from './CrossAccountTimeline';
import { AnomalyFeed } from './AnomalyFeed';
import { ServiceHealth } from './ServiceHealth';
import { TopChanges } from './TopChanges';

interface CloudOverviewViewProps {
  /** The time window the initial `| cloud` query was evaluated over */
  timeRange?: TimeRange;
  /** The executed query string to echo in the header (e.g. "| cloud") */
  query?: string;
  /** Current visible-fields count (for the Fields restore pill, when collapsed) */
  fieldsCount?: number;
  /** Callback to expand the collapsed Fields panel */
  onExpandFields?: () => void;
  /** Callback to add a field=value pivot to the running query */
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  /**
   * Replace the full query and re-run. Used for command-level rewrites
   * (e.g. appending `principal="..."` to the `| cloud` command to pivot
   * from the overview into the principal dossier). When omitted, principal
   * picks fall back to `onAddToQuery('user', ...)`.
   */
  onSetQuery?: (query: string) => void;
}

export function CloudOverviewView({
  timeRange,
  query,
  fieldsCount,
  onExpandFields,
  onAddToQuery,
  onSetQuery,
}: CloudOverviewViewProps) {
  const request = useMemo(() => {
    if (!timeRange) return null;
    return {
      provider: null,
      account: null,
      time_range: timeRange,
    };
  }, [timeRange]);

  // Primary overview fetch (NAN-1595). Owned locally (rather than via the
  // useCloudOverview hook) so we can capture the server cache status via
  // `onMeta` and force a live re-fetch with `bypass` from the header notice.
  const [overview, setOverview] = useState<CloudOverviewResponse | null>(null);
  const [loading, setLoading] = useState(!!request);
  const [error, setError] = useState<Error | null>(null);
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // NAN-1595: sequence guard so a slow older request can't overwrite newer
  // data / badge / loading state (or setState after unmount).
  const reqSeq = useRef(0);
  const fetchOverview = useCallback(
    // NAN-1602: `bypass` controls the cache; `asRefresh` controls the UI. They
    // usually match (the refresh button), but a live INITIAL load bypasses the
    // cache while still showing the loading state (asRefresh=false).
    async (bypass: boolean, asRefresh: boolean = bypass) => {
      // Bump first so even a no-request call invalidates any older in-flight response.
      const seq = ++reqSeq.current;
      if (!request) {
        setLoading(false);
        setRefreshing(false);
        setCacheMeta(null);
        return;
      }
      if (asRefresh) setRefreshing(true);
      else {
        setLoading(true);
        setCacheMeta(null); // clear stale badge while a fresh load runs
      }
      setError(null);
      try {
        const result = await api.getCloudOverview(request, {
          onMeta: (m) => { if (seq === reqSeq.current) setCacheMeta(m); },
          bypass,
        });
        if (seq === reqSeq.current) setOverview(result);
      } catch (err) {
        if (seq === reqSeq.current) setError(err instanceof Error ? err : new Error(String(err)));
      } finally {
        if (seq === reqSeq.current) {
          if (asRefresh) setRefreshing(false);
          else setLoading(false);
        }
      }
    },
    [request]
  );

  // NAN-1602: a user-initiated search's first overview fetch is live (no
  // "cached" badge); later pivots read cache. No-op outside the search page.
  const liveOnceRef = useRef(useIsLiveRun());

  // Re-run on a fresh (non-refresh) load whenever the request changes.
  useEffect(() => {
    const bypass = liveOnceRef.current;
    liveOnceRef.current = false;
    fetchOverview(bypass, false);
  }, [fetchOverview]);

  const refresh = useCallback(() => {
    void fetchOverview(true);
  }, [fetchOverview]);

  // NAN-1600: report the real overview fetch to the search footer (spinner →
  // events_total hits · query time), replacing the marker query's "0ms".
  useReportPhase2Status({
    loading,
    settled: overview != null || error != null,
    error,
    totalCount: overview?.header.events_total,
  });

  const handlePickAccount = (account: CloudOverviewAccount) => {
    // Account scope goes through the `| cloud` command's `account=` arg so the
    // resulting overview is scoped server-side (same page, narrower data).
    const rewritten = appendCloudArg(query, { account: account.id });
    if (rewritten && onSetQuery) onSetQuery(rewritten);
    else onAddToQuery?.('cloud_account_id', account.id, false);
  };
  const handlePickPrincipal = (principal: CloudOverviewPrincipal) => {
    // Principal click pivots to the dossier — append `principal="..."` to the
    // `| cloud` command so the backend emits `_cloud_principal` and the
    // frontend dispatcher renders CloudPrincipalDossier.
    const rewritten = appendCloudArg(query, { principal: principal.id });
    if (rewritten && onSetQuery) onSetQuery(rewritten);
    else onAddToQuery?.('user', principal.id, false);
  };
  const handleOpenAnomaly = (anomaly: CloudOverviewAnomaly) => {
    if (!anomaly.principal) return;
    const rewritten = appendCloudArg(query, { principal: anomaly.principal });
    if (rewritten && onSetQuery) onSetQuery(rewritten);
    else onAddToQuery?.('user', anomaly.principal, false);
  };

  // Non-principal pivots (service, actor, target) — "leave the cloud view and
  // explore this dimension broadly". Drop the `| cloud ...` command from the
  // query and append the filter so the user sees raw events.
  const handleAddFilterLeavingCloud = (field: string, value: string) => {
    if (!field || !value || !onSetQuery) {
      onAddToQuery?.(field, value, false);
      return;
    }
    const withoutCloud = (query ?? '').replace(/\s*\|\s*cloud\b[^|]*/i, '').trim();
    const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const filter = `${field}="${escaped}"`;
    const rewritten = withoutCloud ? `${withoutCloud} ${filter}` : filter;
    onSetQuery(rewritten);
  };

  const headerQuery = query && query.trim().length > 0 ? query.trim() : '| cloud';
  const providerLabel = overview?.header.providers[0]?.id ?? 'aws';
  const windowLabel = overview?.header.window_label ?? null;

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      <CloudOverviewTopStrip
        provider={providerLabel}
        account={null}
        windowLabel={windowLabel}
        fieldsCount={fieldsCount}
        onExpandFields={onExpandFields}
      />

      <div className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">
        <div className="px-4 py-4 space-y-4 min-w-0">
          {error && (
            <div className="bg-card border border-[oklch(62%_0.18_28/0.4)] rounded-lg p-4 text-[12px] text-[oklch(72%_0.17_28)]">
              Failed to load cloud overview: {error.message}
            </div>
          )}

          {!overview && loading && (
            <div className="bg-card border border-border rounded-lg p-6 text-center text-[12px] font-mono text-muted-foreground/70">
              Loading cloud overview…
            </div>
          )}

          {overview && (
            <>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <CloudOverviewHeader data={overview.header} query={headerQuery} />
                </div>
                <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
              </div>

              <div className="grid grid-cols-[1.1fr_1fr] gap-3">
                <AccountsGrid accounts={overview.accounts} onPickAccount={handlePickAccount} />
                <RiskyPrincipals
                  principals={overview.risky_principals}
                  onPick={handlePickPrincipal}
                />
              </div>

              <CrossAccountTimeline timeline={overview.timeline} />

              <div className="grid grid-cols-[1fr_1.1fr] gap-3">
                <AnomalyFeed
                  anomalies={overview.anomalies}
                  windowLabel={overview.header.window_label}
                  onOpen={handleOpenAnomaly}
                />
                <ServiceHealth
                  services={overview.service_health}
                  onPivotService={(id) => handleAddFilterLeavingCloud('cloud_service', id)}
                />
              </div>

              <TopChanges
                changes={overview.changes}
                onPivotActor={(actor) => handleAddFilterLeavingCloud('user', actor)}
                onPivotTarget={(target) => handleAddFilterLeavingCloud('resource_name', target)}
                onPivotAccount={(acct) => handleAddFilterLeavingCloud('cloud_account_id', acct)}
              />
            </>
          )}

          <div className="h-6" />
        </div>
      </div>
    </div>
  );
}

/**
 * Rewrite the `| cloud` segment of a query to add / update `principal="..."`
 * and/or `account="..."` args. Returns null if the query doesn't contain a
 * `| cloud` command at all (caller falls back to `onAddToQuery`).
 *
 * Keeps existing args on the command (e.g. `show_mfa=true`) — we only replace
 * the specific keys passed in.
 */
export function appendCloudArg(
  query: string | undefined,
  args: { principal?: string; account?: string }
): string | null {
  if (!query) return null;
  const match = query.match(/\|\s*cloud\b([^|]*)/i);
  if (!match) return null;
  const fullMatch = match[0];
  const argsStr = match[1] ?? '';

  const existing: Record<string, string> = {};
  const kvRe = /(\w+)\s*=\s*("([^"\\]|\\.)*"|\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = kvRe.exec(argsStr)) !== null) {
    const key = m[1].toLowerCase();
    let value = m[2];
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    existing[key] = value;
  }

  if (args.principal !== undefined) existing.principal = args.principal;
  if (args.account !== undefined) existing.account = args.account;

  const parts: string[] = ['| cloud'];
  for (const [k, v] of Object.entries(existing)) {
    if (v === '' || v === undefined) continue;
    // Only quote values that aren't simple identifiers — keeps args like
    // `by=service` and `show_mfa=true` readable while making quoting
    // unambiguous for ids with `.`, `@`, `-`, etc.
    const simple = /^[A-Za-z0-9_]+$/.test(v);
    const escaped = v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    parts.push(`${k}=${simple ? escaped : `"${escaped}"`}`);
  }
  const rewritten = parts.join(' ');

  return query.replace(fullMatch, rewritten);
}
