// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import type { CloudDossierResponse, TimeRange } from '@/lib/api/types';
import { CachedNotice } from '@/components/search/CachedNotice';
import { DurableJobNotice, type DurableProductJobState } from '../DurableJobNotice';
import { waitForDurableProductArtifact } from '../durable-product-job';
import { useReportPhase2Status } from '@/components/search/footer-reporter';
import { useIsLiveRun } from '@/components/search/live-run-context';
import { CloudDossierTopStrip } from './CloudDossierTopStrip';
import { IdentityHeader } from './IdentityHeader';
import { FacetsBand } from './FacetsBand';
import { AssumeRoleChain } from './AssumeRoleChain';
import { TimelineLanes } from './TimelineLanes';
import { RegionsStrip } from './RegionsStrip';
import { AuthPosture } from './AuthPosture';
import { TopActions } from './TopActions';
import { TopResources } from './TopResources';
import { ErrorRate } from './ErrorRate';
import { Stream } from './Stream';
import { nplQuotedBody } from '@/lib/npl-quote';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';

interface CloudPrincipalDossierProps {
  principal: string;
  account?: string | null;
  provider?: string | null;
  /** The executed query, used for rewriting the `| cloud` command on pivots */
  query?: string;
  timeRange?: TimeRange;
  fieldsCount?: number;
  onExpandFields?: () => void;
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  /** Replace the full query and re-run (for command-level pivots) */
  onSetQuery?: (query: string) => void;
  initialDossier?: CloudDossierResponse | null;
  onOpenJobs?: () => void;
}

export function CloudPrincipalDossier({
  principal,
  account,
  provider,
  query,
  timeRange,
  fieldsCount,
  onExpandFields,
  onAddToQuery,
  onSetQuery,
  initialDossier,
  onOpenJobs,
}: CloudPrincipalDossierProps) {
  const { schema } = useSchemaEntityMap();
  const strictOcsf = schema === 'ocsf';
  // Facet filters live entirely client-side: clicking a chip toggles entries
  // in this state, and the dossier hook re-fetches with the new filter set so
  // every section (identity, facets, timeline, stream, …) narrows in lockstep.
  // Intentionally NOT wired to `onAddToQuery` — the outer query stays at
  // `| cloud principal=X`, while these filters scope the dossier view only.
  type FacetKey = 'services' | 'regions' | 'accounts' | 'resource_types' | 'change_types';
  const [filters, setFilters] = useState<Record<FacetKey, string[]>>({
    services: [],
    regions: [],
    accounts: [],
    resource_types: [],
    change_types: [],
  });

  const request = useMemo(() => {
    if (!timeRange || !principal) return null;
    return {
      principal,
      account: account ?? null,
      provider: provider ?? null,
      services: filters.services,
      regions: filters.regions,
      accounts: filters.accounts,
      resource_types: filters.resource_types,
      change_types: filters.change_types,
      time_range: timeRange,
    };
  }, [principal, account, provider, timeRange, filters]);

  // Primary dossier fetch (NAN-1595). Owned locally (rather than via the
  // useCloudDossier hook) so we can capture the server cache status via
  // `onMeta` and force a live re-fetch with `bypass` from the header notice.
  const [dossier, setDossier] = useState<CloudDossierResponse | null>(initialDossier ?? null);
  const [loading, setLoading] = useState(!!request && !initialDossier);
  const [error, setError] = useState<Error | null>(null);
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [durableJob, setDurableJob] = useState<DurableProductJobState | null>(null);
  const initialDossierRef = useRef(initialDossier ?? null);

  // NAN-1595: sequence guard so a slow older request can't overwrite newer
  // data / badge / loading state (or setState after unmount).
  const requestAbort = useRef<AbortController | null>(null);
  useEffect(() => () => { requestAbort.current?.abort(); ++reqSeq.current; }, []);
  const reqSeq = useRef(0);
  const fetchDossier = useCallback(
    // NAN-1602: `bypass` controls the cache; `asRefresh` controls the UI — a
    // live initial load bypasses the cache but still shows loading.
    async (bypass: boolean, asRefresh: boolean = bypass) => {
      // Bump first so even a no-request call invalidates any older in-flight response.
      requestAbort.current?.abort();
      const controller = new AbortController();
      requestAbort.current = controller;
      const signal = controller.signal;
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
        setDossier(null);
        setDurableJob(null);
        setCacheMeta(null); // clear stale badge while a fresh load runs
      }
      setError(null);
      try {
        if (!asRefresh) {
          try {
            const page = await api.getCloudDossier({ ...request, fetch: 'page' }, { bypass, signal });
            if (seq !== reqSeq.current || signal.aborted) return;
            setDossier(page);
            // Non-lake backends can return the already complete dossier.
            if (!page.bounded_preview && !page.durable_job) return;
          } catch {
            if (seq !== reqSeq.current || signal.aborted) return;
            // Preview failure must not suppress the independent exact fetch.
          }
        }
        const result = await api.getCloudDossier({ ...request, fetch: 'full' }, {
          onMeta: (m) => { if (seq === reqSeq.current) setCacheMeta(m); },
          bypass,
          signal,
        });
        if (result.durable_job) {
          const handle = result.durable_job;
          if (seq === reqSeq.current) {
            setDurableJob({ jobId: handle.job_id, status: 'queued' });
          }
          const artifact = await waitForDurableProductArtifact(
            handle.job_id,
            'cloud_dossier_v1',
            (job) => { if (seq === reqSeq.current) setDurableJob(job); },
            () => seq === reqSeq.current && !signal.aborted,
            signal,
          );
          const response = artifact.row.response;
          if (
            artifact.row.operation !== 'cloud_dossier'
            || !response
            || typeof response !== 'object'
            || !('identity' in response)
          ) {
            throw new Error('Durable Cloud dossier returned an invalid typed result artifact');
          }
          if (seq === reqSeq.current) {
            setDossier(response as CloudDossierResponse);
            setDurableJob(null);
          }
        } else if (seq === reqSeq.current) {
          setDurableJob(null);
          setDossier(result);
        }
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

  // NAN-1602: a user-initiated search's first dossier fetch is live (no "cached"
  // badge); later facet/scope changes read cache. No-op outside the search page.
  const liveOnceRef = useRef(useIsLiveRun());

  // Re-run on a fresh (non-refresh) load whenever the request changes
  // (principal / account / provider / window / facet filters).
  useEffect(() => {
    if (initialDossierRef.current) {
      setDossier(initialDossierRef.current);
      initialDossierRef.current = null;
      setLoading(false);
      return;
    }
    const bypass = liveOnceRef.current;
    liveOnceRef.current = false;
    void fetchDossier(bypass, false);
    return () => { requestAbort.current?.abort(); ++reqSeq.current; };
  }, [fetchDossier]);

  const refresh = useCallback(() => {
    void fetchDossier(true);
  }, [fetchDossier]);

  const providerLabel = dossier?.facets.provider[0]?.name ?? provider ?? 'aws';
  const eventsTotal = dossier?.error_rate.events_total ?? 0;
  const accountId = dossier?.identity.account ?? account ?? null;

  // NAN-1600: report the real dossier fetch to the search footer (spinner →
  // events_total hits · query time), replacing the marker query's "0ms".
  useReportPhase2Status({
    loading,
    settled: dossier != null || error != null,
    error,
    totalCount: dossier && !dossier.bounded_preview ? eventsTotal : undefined,
  });

  const handleFacetClick = (dim: string, value: string) => {
    const key = facetDimToFilterKey(dim);
    if (!key) return;
    setFilters((prev) => {
      const current = prev[key];
      const next = current.includes(value)
        ? current.filter((v) => v !== value)
        : [...current, value];
      return { ...prev, [key]: next };
    });
  };

  // Pivot to a different principal's dossier — rewrite the `| cloud` command
  // so the query state flips and the dispatcher re-mounts the dossier for the
  // new principal. Falls back to a filter-append when onSetQuery isn't wired.
  const handlePivotPrincipal = (id: string) => {
    if (!id || id === principal) return;
    if (query && onSetQuery) {
      const rewritten = query.replace(
        /\|\s*cloud\b([^|]*)/i,
        (_match, args: string) => {
          // Drop any existing principal= arg, keep the others (by=, show_mfa=,
          // account=, provider=, positional). The simplest way is to rebuild
          // from scratch — the parser accepts repeated args gracefully but we
          // prefer a clean single-principal command.
          const kept = args.replace(/\bprincipal\s*=\s*("([^"\\]|\\.)*"|\S+)/i, '').trim();
          const prefix = kept ? `| cloud ${kept}` : '| cloud';
          const needsQuote = !/^[A-Za-z0-9_]+$/.test(id);
          const escaped = nplQuotedBody(id);
          return `${prefix} principal=${needsQuote ? `"${escaped}"` : escaped}`;
        }
      );
      onSetQuery(rewritten);
    } else {
      onAddToQuery?.(strictOcsf ? 'actor.user.name' : 'user', id, false);
    }
  };

  // Generic filter pivot — used by non-facet sections (regions, IPs, actions,
  // resources, error codes, top-changes targets). These are "leave the dossier
  // and explore this dimension broadly" clicks, so we DROP the `| cloud ...`
  // command from the query and append the new filter to the base search.
  // Facet chips stay in the dossier (they're dossier-local filters);
  // principal pivots use `handlePivotPrincipal` instead to stay in dossier
  // mode on a different entity.
  const handleAddFilter = (field: string, value: string) => {
    if (!field || !value) return;
    const queryField = strictOcsf
      ? ({
          cloud_account_id: 'cloud.account.uid',
          cloud_region: 'cloud.region',
          cloud_service: 'api.service.name',
          src_ip: 'src_endpoint.ip',
          event_type: 'activity_name',
          action: 'activity_name',
          resource_id: 'resources.uid',
          resource_name: 'resources.name',
          user: 'actor.user.name',
        } as Record<string, string>)[field] ?? field
      : field;
    if (query && onSetQuery) {
      const withoutCloud = query.replace(/\s*\|\s*cloud\b[^|]*/i, '').trim();
      const escaped = nplQuotedBody(value);
      const filter = `${queryField}="${escaped}"`;
      const rewritten = withoutCloud ? `${withoutCloud} ${filter}` : filter;
      onSetQuery(rewritten);
    } else {
      onAddToQuery?.(queryField, value, false);
    }
  };

  const clearFilter = (key: FacetKey, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: prev[key].filter((v) => v !== value) }));
  };

  const clearAllFilters = () => {
    setFilters({
      services: [],
      regions: [],
      accounts: [],
      resource_types: [],
      change_types: [],
    });
  };

  const activeFilters: Array<{ key: FacetKey; value: string; label: string }> = [];
  for (const [key, values] of Object.entries(filters) as [FacetKey, string[]][]) {
    for (const value of values) {
      activeFilters.push({ key, value, label: filterKeyToLabel(key) });
    }
  }

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      <CloudDossierTopStrip
        provider={providerLabel}
        principal={principal}
        account={accountId}
        windowLabel={dossier?.window_label ?? null}
        fieldsCount={fieldsCount}
        onExpandFields={onExpandFields}
        lastEventLabel={dossier?.identity.last_seen?.slice(11, 19) ?? null}
      />

      {durableJob && <DurableJobNotice job={durableJob} onOpenJobs={onOpenJobs} />}

      <div className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">
        <div className="px-4 py-4 space-y-3 min-w-0">
          {error && (
            <div className="bg-card border border-[oklch(62%_0.18_28/0.4)] rounded-lg p-4 text-[12px] text-[oklch(72%_0.17_28)]">
              Failed to load cloud dossier: {error.message}
            </div>
          )}

          {!dossier && loading && (
            <div className="bg-card border border-border rounded-lg p-6 text-center text-[12px] font-mono text-muted-foreground/70">
              Loading cloud dossier for {principal}…
            </div>
          )}

          {dossier && (
            <>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  {dossier.bounded_preview ? (
                    <div className="border border-border p-3 text-[12px] font-mono">
                      <div>{principal}</div>
                      <div className="text-muted-foreground text-[10.5px]">{dossier.identity.arn ?? dossier.identity.account ?? account ?? ''}</div>
                    </div>
                  ) : <IdentityHeader
                    identity={dossier.identity}
                    risk={dossier.risk}
                    eventsTotal={eventsTotal}
                    onPivotAccount={(id) => handleAddFilter('cloud_account_id', id)}
                    onPivotIp={(ip) => handleAddFilter('src_ip', ip)}
                    onPivotAssumedRole={handlePivotPrincipal}
                  />}
                </div>
                <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={refreshing} />
              </div>

              {activeFilters.length > 0 && (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70">
                    filters
                  </span>
                  {activeFilters.map((f) => (
                    <button
                      key={`${f.key}:${f.value}`}
                      onClick={() => clearFilter(f.key, f.value)}
                      className="inline-flex items-center gap-1.5 h-6 px-2 rounded-md border border-primary/40 bg-primary/10 text-primary text-[10.5px] font-mono hover:bg-primary/15 transition-colors"
                    >
                      <span className="text-muted-foreground/70">{f.label}:</span>
                      <span className="text-foreground">{f.value}</span>
                      <X className="w-3 h-3" strokeWidth={1.5} />
                    </button>
                  ))}
                  <button
                    onClick={clearAllFilters}
                    className="text-[10px] font-mono text-muted-foreground/80 hover:text-foreground underline"
                  >
                    clear all
                  </button>
                </div>
              )}

              {dossier.bounded_preview && (
                <div role="status" className="text-[10.5px] font-mono text-muted-foreground">
                  Newest 200-event sample in the requested window, with current filters applied. {loading ? 'Window summaries loading…' : 'Window summaries unavailable.'}
                </div>
              )}
              {!dossier.bounded_preview && <>
              <FacetsBand
                facets={dossier.facets}
                eventsTotal={eventsTotal}
                onFacetClick={handleFacetClick}
                activeFilters={filters}
              />

              <div className="grid grid-cols-[1.15fr_1fr] gap-3">
                <TimelineLanes timeline={dossier.timeline} timeRange={timeRange} />
                <AssumeRoleChain
                  chain={dossier.assume_chain}
                  onPivotPrincipal={handlePivotPrincipal}
                  onPivotAction={(action) => handleAddFilter('event_type', action)}
                  onPivotTarget={(target) => handleAddFilter('resource_name', target)}
                />
              </div>

              <div className="grid grid-cols-[1.15fr_1fr] gap-3">
                <RegionsStrip
                  regions={dossier.regions}
                  identity={dossier.identity}
                  onPivotRegion={(id) => handleAddFilter('cloud_region', id)}
                  onPivotIp={(ip) => handleAddFilter('src_ip', ip)}
                />
                <ErrorRate
                  data={dossier.error_rate}
                  onPivotErrorCode={(code) => handleAddFilter('status', code)}
                />
              </div>

              <div className="grid grid-cols-[1fr_1fr] gap-3">
                <AuthPosture
                  posture={dossier.auth_posture}
                  onPivotPrincipal={handlePivotPrincipal}
                />
                <TopActions
                  actions={dossier.top_actions}
                  onPivotAction={(name) => handleAddFilter('event_type', name)}
                />
              </div>

              <TopResources
                resources={dossier.top_resources}
                onPivotResource={(arn) =>
                  handleAddFilter(arn.startsWith('arn:') ? 'resource_id' : 'resource_name', arn)
                }
              />

              </>}

              <Stream
                events={dossier.stream}
                onPivotField={(field, value) => handleAddFilter(field, value)}
              />
            </>
          )}

          <div className="h-6" />
        </div>
      </div>
    </div>
  );
}

function facetDimToFilterKey(
  dim: string
): 'services' | 'regions' | 'accounts' | 'resource_types' | 'change_types' | null {
  switch (dim) {
    case 'service':
      return 'services';
    case 'region':
      return 'regions';
    case 'account':
      return 'accounts';
    case 'resource_type':
      return 'resource_types';
    case 'change_type':
      return 'change_types';
    default:
      // `provider` scope belongs in the `| cloud provider=X` command arg, not
      // a dossier-local filter. Click falls through to a no-op for now.
      return null;
  }
}

function filterKeyToLabel(key: string): string {
  switch (key) {
    case 'services':
      return 'service';
    case 'regions':
      return 'region';
    case 'accounts':
      return 'account';
    case 'resource_types':
      return 'resource';
    case 'change_types':
      return 'change';
    default:
      return key;
  }
}
