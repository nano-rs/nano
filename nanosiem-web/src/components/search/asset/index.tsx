// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { api } from '@/lib/api';
import type { CacheMeta } from '@/lib/api';
import { useIsLiveRun } from '@/components/search/live-run-context';
import type {
  AssetDossierResponse,
  EntityContextResponse,
  TimeRange,
} from '@/lib/api/types';
import { CachedNotice } from '@/components/search/CachedNotice';
import { AssetTopStrip } from './AssetTopStrip';
import { AssetIdentityHeader } from './AssetIdentityHeader';
import { AssetActivityTimeline } from './AssetActivityTimeline';
import { AlertsCard } from './sections/AlertsCard';
import { ProcessesCard } from './sections/ProcessesCard';
import { NetworkCard } from './sections/NetworkCard';
import { AuthCard } from './sections/AuthCard';
import { FilesCard } from './sections/FilesCard';
import { DnsCard } from './sections/DnsCard';
import { AssetPrevalenceCard } from './AssetPrevalenceCard';
import { AssetStream } from './AssetStream';
import { computeBucketWindow, formatTimestampHMS, withAssetIdentity } from './helpers';
import { nplQuotedBody } from '@/lib/npl-quote';

// nPL `| where` snippets used by more than one drilldown. Keep these as
// module-level consts so future edits land in one place.
const NPL_TOP_DOMAINS = '| where query!="" | stats count by query | sort -count';
// NEW_DOMAINS mirrors the backend tile: uniqExactIf(dest_host, prevalence_dest_domain < 5).
// Don't reuse NPL_TOP_DOMAINS — that aggregates the DNS-question field, which is
// empty on the asset's network rows.
const NPL_NEW_DOMAINS =
  '| where dest_host!="" AND prevalence_dest_domain<5 | stats count by dest_host | sort -count';
const NPL_TOP_DESTINATIONS_BY_BYTES =
  '| where dest_ip!="" | stats count, sum(bytes_out) as bytes by dest_ip, dest_host | sort -bytes';
const NPL_TOP_DESTINATIONS_BY_COUNT =
  '| where dest_ip!="" | stats count by dest_ip, dest_host | sort -count';
const NPL_PROCESS_TREE = '| where process_name!="" | tree process';
const NPL_FILE_EVENTS = '| where file_action!=""';
const NPL_AUTH_INTERACTIVE =
  '| where category="authentication" AND lower(auth_type) LIKE "%interactive%"';
const NPL_AUTH_NETWORK_OR_LATERAL =
  '| where category="authentication" AND (lower(auth_type) LIKE "%network%" OR lower(auth_type) LIKE "%lateral%")';
// Timeline lane → drilldown command. AUTH/PROC/NET/FILE use `| where`; ALERT
// uses a base-search filter on source_type.
const NPL_LANE_AUTH = '| where category="authentication" OR category="authorization"';
const NPL_LANE_PROC = '| where process_name!=""';
const NPL_LANE_NET = '| where dest_ip!=""';
const NPL_LANE_FILE = '| where file_action!=""';

// ---------------------------------------------------------------------------
// Types (mirrors the shape SearchResults passes today)
// ---------------------------------------------------------------------------

interface AssetIdentityRecord {
  ip?: string | null;
  hostname?: string | null;
  mac?: string | null;
  user?: string | null;
}

interface AssetProfile {
  primary_identifier: { field: string; value: string } | null;
  identities: AssetIdentityRecord[];
  first_seen: string | null;
  last_seen: string | null;
  // NAN-1455: set by `| asset` when the requested window had no events and the
  // command re-anchored to the entity's last activity. The frontend then drives
  // the dossier/timeline/stream off this window so they match the events shown.
  reanchored?: boolean;
  effective_time_range?: { start: string; end: string } | null;
}

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

export interface AssetViewProps {
  results: SearchResult[];
  onDrilldown?: (filters: Record<string, unknown>) => void;
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  prevalenceFilter?: {
    artifacts: string[];
    filterType: 'include' | 'rare';
    timestamp?: number;
  } | null;
  timeRange?: TimeRange;
  onFetchLog?: (id: string, timestamp: Date, sourceType?: string) => Promise<Record<string, unknown> | null>;
  /** Current visible-fields count for the Fields restore pill (22 in the mockup) */
  fieldsCollapsedCount?: number;
  /** Callback to expand the Fields panel */
  onExpandFields?: () => void;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

export function AssetView({ results, timeRange, fieldsCollapsedCount, onExpandFields, onDrilldown }: AssetViewProps) {
  // Pull the asset profile out of the first result (set by `| asset` command)
  const assetProfile = useMemo<AssetProfile | null>(() => {
    if (!results.length) return null;
    const fields = results[0]?.fields;
    if (fields?._display_type === 'asset' && fields?._asset_profile) {
      return fields._asset_profile as AssetProfile;
    }
    return null;
  }, [results]);

  const primary = assetProfile?.primary_identifier;
  const identifierField = primary?.field ?? '';
  const identifierValue = primary?.value ?? '';
  const identities = useMemo(
    () => (assetProfile?.identities ?? []) as unknown as Record<string, unknown>[],
    [assetProfile]
  );

  const kind: 'host' | 'user' =
    identifierField === 'user' || identifierField === 'src_user' ? 'user' : 'host';

  // NAN-1455: when `| asset` re-anchored to the entity's last activity (the
  // requested window was empty), drive every window-scoped fetch off that
  // effective range so the dossier/timeline/stream match the events the command
  // surfaced. Otherwise use the requested window verbatim.
  const reanchored = !!assetProfile?.reanchored && !!assetProfile?.effective_time_range;
  const effectiveTimeRange = reanchored ? assetProfile!.effective_time_range! : timeRange;

  // Focus mode — persisted in localStorage, mirrors the mockup
  const [focus, setFocus] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('nano-asset-focus') === '1';
  });
  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('nano-asset-focus', focus ? '1' : '0');
    }
  }, [focus]);

  // Dossier aggregate fetch
  const dossierRequest = useMemo(() => {
    if (!identifierField || !identifierValue || !effectiveTimeRange) return null;
    return {
      identifier_field: identifierField,
      identifier_value: identifierValue,
      identities,
      time_range: effectiveTimeRange,
    };
  }, [identifierField, identifierValue, identities, effectiveTimeRange]);
  // Primary dossier fetch (NAN-1595). Driven directly off the api client (rather
  // than the useAssetDossier hook) so it can capture the server cache status via
  // `onMeta` and support a `bypass` refresh — the hook doesn't thread cacheOpts.
  const [dossier, setDossier] = useState<AssetDossierResponse | null>(null);
  const [dossierLoading, setDossierLoading] = useState(false);
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);

  // NAN-1595: sequence guard so a slow older request (incl. a refresh racing a
  // window/entity change) can't overwrite newer data/badge or setState after unmount.
  const reqSeq = useRef(0);
  const loadDossier = useCallback(
    (bypass: boolean) => {
      // Bump first so even a no-request call invalidates any older in-flight response.
      const seq = ++reqSeq.current;
      if (!dossierRequest) {
        setDossier(null);
        setCacheMeta(null);
        setDossierLoading(false);
        return;
      }
      // Fresh load clears the stale badge; refresh keeps the current data visible
      // until the live result lands.
      if (!bypass) setCacheMeta(null);
      setDossierLoading(true);
      api
        .getAssetDossier(dossierRequest, {
          onMeta: (m) => { if (seq === reqSeq.current) setCacheMeta(m); },
          bypass,
        })
        .then((resp) => {
          if (seq === reqSeq.current) setDossier(resp);
        })
        .catch(() => {
          /* dossier failures surface as the empty/loading state below */
        })
        .finally(() => {
          if (seq === reqSeq.current) setDossierLoading(false);
        });
    },
    [dossierRequest],
  );

  // NAN-1602: a user-initiated search's first dossier fetch is live (no "cached"
  // badge); later window/entity changes read cache. No-op outside the search page.
  const liveOnceRef = useRef(useIsLiveRun());

  // Reset + load whenever the request (entity / window / identities) changes.
  useEffect(() => {
    setDossier(null);
    const bypass = liveOnceRef.current;
    liveOnceRef.current = false;
    return loadDossier(bypass);
  }, [loadDossier]);

  // NAN-1595: force a live re-fetch of the dossier, bypassing the server cache.
  const refresh = useCallback(() => {
    loadDossier(true);
  }, [loadDossier]);

  // Identity-aware drilldown — see `helpers.tsx:withAssetIdentity`. Wrapped in
  // a callback so each card can route clicks through one call.
  const handleAssetDrilldown = useCallback(
    (filters: Record<string, unknown>) => {
      if (!onDrilldown) return;
      // NAN-1458: land the pivot in the window the asset view is actually showing
      // (event-centered, or re-anchored to last activity), not the picker's
      // default. Callers that already scope a window — e.g. a timeline bucket —
      // keep theirs.
      const scoped =
        effectiveTimeRange && filters._timeRangeOverride === undefined
          ? { ...filters, _timeRangeOverride: effectiveTimeRange }
          : filters;
      onDrilldown(
        withAssetIdentity(
          scoped,
          identities as { ip?: string | null; hostname?: string | null; user?: string | null }[],
          identifierField && identifierValue ? { field: identifierField, value: identifierValue } : null,
        ),
      );
    },
    [onDrilldown, identities, identifierField, identifierValue, effectiveTimeRange],
  );

  // Prevalence scatter drill — narrow the asset's events to a clicked artifact.
  // Reuses handleAssetDrilldown so the asset identity + view window ride along;
  // the hash/domain OR-expression goes through as a pre-built raw clause.
  const handleArtifactDrilldown = useCallback(
    (artifact: string, artifactType: 'hash' | 'domain') => {
      // Escape like the field=value drilldown builder — a log-derived artifact
      // with `"`/`\` must not break out of the quoted comparison.
      const esc = nplQuotedBody(artifact);
      const rawClause =
        artifactType === 'hash'
          ? `(file_hash="${esc}" OR process_hash="${esc}")`
          : `(dest_host="${esc}" OR query="${esc}" OR url_domain="${esc}")`;
      handleAssetDrilldown({ _rawClause: rawClause });
    },
    [handleAssetDrilldown],
  );

  // Investigate pivot — the plain entity filter, scoped to the asset view's
  // window (NAN-1458). Kept separate from handleAssetDrilldown so it doesn't
  // OR-expand across related identities.
  const handleInvestigate = useCallback(
    (filters: Record<string, unknown>) => {
      if (!onDrilldown) return;
      onDrilldown(
        effectiveTimeRange ? { ...filters, _timeRangeOverride: effectiveTimeRange } : filters,
      );
    },
    [onDrilldown, effectiveTimeRange],
  );

  const navigate = useNavigate();
  const handleAlertClick = useCallback(
    (alertRowId: string) => {
      navigate(`/alerts/${alertRowId}`);
    },
    [navigate],
  );

  // Map a timeline lane (auth/proc/net/file/alert) + bucket index to a
  // lane-scoped, time-narrowed drilldown. Each bucket spans
  // (timeRange / dossier.timeline.buckets) of wall-clock time; we pass the
  // bucket's [start, end] as `_timeRangeOverride` so handleDrilldown in
  // Search.tsx narrows the time picker to that window (NAN-1050).
  const handleTimelineCellClick = useCallback(
    (lane: string, bucketIdx: number) => {
      const bucketCount = dossier?.timeline.buckets;
      const bucketWindow =
        effectiveTimeRange && bucketCount && bucketCount > 0
          ? computeBucketWindow(effectiveTimeRange, bucketCount, bucketIdx)
          : undefined;
      const extras: Record<string, unknown> = bucketWindow
        ? { _timeRangeOverride: bucketWindow }
        : {};
      switch (lane) {
        case 'auth':
          handleAssetDrilldown({ ...extras, _tableCommand: NPL_LANE_AUTH });
          return;
        case 'proc':
          handleAssetDrilldown({ ...extras, _tableCommand: NPL_LANE_PROC });
          return;
        case 'net':
          handleAssetDrilldown({ ...extras, _tableCommand: NPL_LANE_NET });
          return;
        case 'file':
          handleAssetDrilldown({ ...extras, _tableCommand: NPL_LANE_FILE });
          return;
        case 'alert':
          handleAssetDrilldown({ ...extras, source_type: 'signal' });
          return;
        default:
          handleAssetDrilldown(extras);
      }
    },
    [handleAssetDrilldown, dossier?.timeline.buckets, effectiveTimeRange],
  );

  // Entity context (risk + alerts + cases) fetched in parallel from nanosiem-api
  const [entityContext, setEntityContext] = useState<EntityContextResponse | null>(null);
  useEffect(() => {
    if (!identifierField || !identifierValue) return;
    const entityType = mapFieldToEntityType(identifierField);
    const idValues: string[] = [];
    for (const id of identities) {
      const ip = (id.ip as string) ?? '';
      const hostname = (id.hostname as string) ?? '';
      const user = (id.user as string) ?? '';
      if (ip && !idValues.includes(ip)) idValues.push(ip);
      if (hostname && !idValues.includes(hostname)) idValues.push(hostname);
      if (user && !idValues.includes(user)) idValues.push(user);
    }

    api
      .getEntityContext(entityType, identifierValue, idValues.length ? idValues : undefined)
      .then(setEntityContext)
      .catch(() => {
        /* context is supplementary — fail silently */
      });
  }, [identifierField, identifierValue, identities]);

  if (!primary) {
    return (
      <div className="p-8 text-center text-[12px] text-muted-foreground/70 font-mono">
        Asset view requires an | asset command with a resolved identifier.
      </div>
    );
  }

  const kindLabel = kind === 'host' ? 'host dossier' : 'user dossier';
  const spanLabel = labelForRange(effectiveTimeRange);
  const lastObservationLabel = dossier?.identity.last_seen_in_range
    ? formatTimestampHMS(dossier.identity.last_seen_in_range)
    : undefined;
  const resolvedSourcesLabel = dossier?.identity.log_sources.length
    ? `identity resolved from ${dossier.identity.log_sources.length} sources`
    : undefined;

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
      <AssetTopStrip
        entityField={identifierField}
        entityValue={identifierValue}
        kindLabel={kindLabel}
        fieldsCount={fieldsCollapsedCount}
        onExpandFields={onExpandFields}
        focus={focus}
        onToggleFocus={() => setFocus((f) => !f)}
        resolvedSourcesLabel={resolvedSourcesLabel}
        lastObservationLabel={lastObservationLabel}
        cachedNotice={
          <CachedNotice meta={cacheMeta} onRefresh={refresh} refreshing={dossierLoading} />
        }
      />

      <div className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">
        <div className="px-4 py-4 space-y-4 min-w-0">
          {reanchored && (
            <div className="flex items-center gap-2 px-3 py-1.5 border border-amber-500/40 bg-amber-500/10 text-[11px] font-mono text-muted-foreground">
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-500" strokeWidth={1.5} />
              <span>
                <span className="text-amber-500 font-medium">No activity in the selected range</span>
                {' — showing the last 6h of activity'}
                {assetProfile?.effective_time_range
                  ? ` (ending ${formatTimestampHMS(assetProfile.effective_time_range.end)})`
                  : ''}.
              </span>
            </div>
          )}
          {!focus && (
            <>
              <AssetIdentityHeader
                kind={kind}
                entityValue={identifierValue}
                entityField={identifierField}
                onInvestigate={onDrilldown ? handleInvestigate : undefined}
                identity={
                  dossier?.identity ?? {
                    hostname: null,
                    ip: null,
                    mac: null,
                    user: null,
                    vendor_product: null,
                    first_seen_in_range: null,
                    last_seen_in_range: null,
                    log_sources: [],
                    domain: null,
                  }
                }
                risk={entityContext?.risk ?? null}
                tags={[]}
              />

              {dossier && (
                <AssetActivityTimeline
                  timeline={dossier.timeline}
                  spanLabel={spanLabel}
                  onCellClick={onDrilldown ? handleTimelineCellClick : undefined}
                />
              )}

              <div className="grid grid-cols-2 gap-3">
                <AlertsCard
                  alerts={entityContext?.alerts ?? []}
                  total={entityContext?.alert_count}
                  onAlertClick={handleAlertClick}
                  onOpenSequence={onDrilldown ? () => handleAssetDrilldown({ source_type: 'signal' }) : undefined}
                />
                {dossier && (
                  <ProcessesCard
                    processes={dossier.processes}
                    onOpenTree={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: NPL_PROCESS_TREE }) : undefined}
                  />
                )}
                {dossier && (
                  <NetworkCard
                    network={dossier.network}
                    onOpenTopDestinations={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: NPL_TOP_DESTINATIONS_BY_BYTES }) : undefined}
                    onStatClick={onDrilldown ? (key, ctx) => {
                      switch (key) {
                        case 'UNIQ_DSTS':
                          handleAssetDrilldown({ _tableCommand: NPL_TOP_DESTINATIONS_BY_COUNT });
                          return;
                        case 'NEW_DOMAINS':
                          handleAssetDrilldown({ _tableCommand: NPL_NEW_DOMAINS });
                          return;
                        case 'RARE_COUNTRY':
                          // Dossier returns enriched_dest_country_code (e.g. "CN"),
                          // not the full name in enriched_dest_country — filter the
                          // column the value came from.
                          if (ctx?.country) handleAssetDrilldown({ enriched_dest_country_code: ctx.country });
                          return;
                      }
                    } : undefined}
                  />
                )}
                {dossier && (
                  <AuthCard
                    auth={dossier.auth}
                    onOpenAll={onDrilldown ? () => handleAssetDrilldown({ category: 'authentication' }) : undefined}
                    onStatClick={onDrilldown ? (key) => {
                      switch (key) {
                        case 'SUCCESS':
                          handleAssetDrilldown({ category: 'authentication', auth_result: 'success' });
                          return;
                        case 'FAILURE':
                          handleAssetDrilldown({ category: 'authentication', auth_result: 'failure' });
                          return;
                        case 'INTERACT':
                          handleAssetDrilldown({ _tableCommand: NPL_AUTH_INTERACTIVE });
                          return;
                        case 'NETWORK':
                          handleAssetDrilldown({ _tableCommand: NPL_AUTH_NETWORK_OR_LATERAL });
                          return;
                      }
                    } : undefined}
                  />
                )}
                {dossier && (
                  <FilesCard
                    files={dossier.files}
                    onOpenAll={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: NPL_FILE_EVENTS }) : undefined}
                  />
                )}
                {dossier && (
                  <DnsCard
                    dns={dossier.dns}
                    onOpenTopDomains={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: NPL_TOP_DOMAINS }) : undefined}
                  />
                )}
              </div>
            </>
          )}

          <AssetPrevalenceCard
            identifierField={identifierField}
            identifierValue={identifierValue}
            identities={identities}
            timeRange={effectiveTimeRange}
            focus={focus}
            onArtifactClick={onDrilldown ? handleArtifactDrilldown : undefined}
          />

          <AssetStream
            identifierField={identifierField}
            identifierValue={identifierValue}
            identities={identities}
            timeRange={effectiveTimeRange}
          />

          {dossierLoading && !dossier && (
            <div className="text-[11px] text-muted-foreground/70 font-mono">
              Loading dossier…
            </div>
          )}

          <div className="h-6" />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapFieldToEntityType(field: string): string {
  const map: Record<string, string> = {
    src_ip: 'ip',
    dest_ip: 'ip',
    src_host: 'host',
    dest_host: 'host',
    user: 'user',
    src_user: 'user',
    dest_user: 'user',
  };
  return map[field] ?? field;
}

function labelForRange(tr: TimeRange | undefined): string {
  if (!tr) return 'selected range';
  const start = new Date(tr.start).getTime();
  const end = new Date(tr.end).getTime();
  const hours = Math.max(1, Math.round((end - start) / 3_600_000));
  if (hours <= 1) return 'last hour';
  if (hours < 24) return `last ${hours}h`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'last 24h';
  return `last ${days}d`;
}
