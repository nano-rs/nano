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
import { DurableJobNotice, type DurableProductJobState } from '../DurableJobNotice';
import { waitForDurableProductArtifact } from '../durable-product-job';
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
import { fetchProgressive, progressLabel } from './progressive';

// Product-view drilldowns have a frontend DTO contract, but generated search
// text must remain native to the active storage schema. The OCSF lane therefore
// emits only exact 1.9 paths; these are not compatibility aliases.
const UDM_NPL = {
  topDomains: '| where query!="" | stats count by query | sort -count',
  newDomains: '| where dest_host!="" AND prevalence_dest_domain<5 | stats count by dest_host | sort -count',
  topDestinationsByBytes: '| where dest_ip!="" | stats count, sum(bytes_out) as bytes by dest_ip, dest_host | sort -bytes',
  topDestinationsByCount: '| where dest_ip!="" | stats count by dest_ip, dest_host | sort -count',
  processTree: '| where process_name!="" | tree process',
  fileEvents: '| where file_action!=""',
  authInteractive: '| where category="authentication" AND lower(auth_type) LIKE "%interactive%"',
  authNetworkOrLateral: '| where category="authentication" AND (lower(auth_type) LIKE "%network%" OR lower(auth_type) LIKE "%lateral%")',
  laneAuth: '| where category="authentication" OR category="authorization"',
  laneProc: '| where process_name!=""',
  laneNet: '| where dest_ip!=""',
  laneFile: '| where file_action!=""',
} as const;
const OCSF_NPL = {
  topDomains: '| where query.hostname!="" | stats count by query.hostname | sort -count',
  newDomains: '| where dst_endpoint.hostname!="" | stats count by dst_endpoint.hostname | sort -count',
  topDestinationsByBytes: '| where dst_endpoint.ip!="" | stats count, sum(traffic.bytes_out) as bytes by dst_endpoint.ip, dst_endpoint.hostname | sort -bytes',
  topDestinationsByCount: '| where dst_endpoint.ip!="" | stats count by dst_endpoint.ip, dst_endpoint.hostname | sort -count',
  processTree: '| where process.name!="" | tree process',
  fileEvents: '| where class_uid=1001',
  authInteractive: '| where class_uid=3002 AND lower(auth_protocol) LIKE "%interactive%"',
  authNetworkOrLateral: '| where class_uid=3002 AND (lower(auth_protocol) LIKE "%network%" OR dst_endpoint.port IN (22,445,3389,5985,5986))',
  laneAuth: '| where class_uid=3002',
  laneProc: '| where class_uid=1007',
  laneNet: '| where class_uid=4001 OR class_uid=4003',
  laneFile: '| where class_uid=1001',
} as const;

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
  onOpenJobs?: () => void;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

export function AssetView({ results, timeRange, fieldsCollapsedCount, onExpandFields, onDrilldown, onOpenJobs }: AssetViewProps) {
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
  const durableSummary = (results[0]?.fields?._asset_durable_summary as import('@/lib/api/types').AssetEventsResponse | undefined) ?? null;
  const initialDossier = (results[0]?.fields?._asset_durable_dossier as AssetDossierResponse | undefined) ?? null;
  const isOcsf = identifierField.includes('.') || identifierField === 'device.hostname';
  const npl = isOcsf ? OCSF_NPL : UDM_NPL;

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
  const [dossier, setDossier] = useState<AssetDossierResponse | null>(initialDossier);
  const [dossierLoading, setDossierLoading] = useState(!initialDossier);
  const [cacheMeta, setCacheMeta] = useState<CacheMeta | null>(null);
  const [durableJob, setDurableJob] = useState<DurableProductJobState | null>(null);
  const [dossierError, setDossierError] = useState<string | null>(null);
  const initialDossierRef = useRef(initialDossier);

  // NAN-3094: the event stream's first page is the page's first content and
  // its only lake call at that moment. The dossier and artifact panels start
  // once it has answered, and then share one
  // server-side snapshot, so the page never has two lake reads in flight.
  const streamKey = `${identifierField}|${identifierValue}|${effectiveTimeRange?.start ?? ''}|${effectiveTimeRange?.end ?? ''}`;
  const [streamReadyKey, setStreamReadyKey] = useState<string | null>(null);
  const onStreamFirstPage = useCallback(() => setStreamReadyKey(streamKey), [streamKey]);
  const streamReady = streamReadyKey === streamKey;

  // NAN-1595: sequence guard so a slow older request (incl. a refresh racing a
  // window/entity change) can't overwrite newer data/badge or setState after unmount.
  const requestAbort = useRef<AbortController | null>(null);
  useEffect(() => () => { requestAbort.current?.abort(); ++reqSeq.current; }, []);
  const reqSeq = useRef(0);
  const loadDossier = useCallback(
    (bypass: boolean) => {
      // Bump first so even a no-request call invalidates any older in-flight response.
      requestAbort.current?.abort();
      const controller = new AbortController();
      requestAbort.current = controller;
      const signal = controller.signal;
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
      setDossierError(null);
      void (async () => {
        try {
          // NAN-3094: a lean dossier answers progressively; render each
          // partial answer and poll until it is complete.
          const resp = await fetchProgressive(
            (firstBypass) => api.getAssetDossier(dossierRequest, {
              onMeta: (m) => { if (seq === reqSeq.current) setCacheMeta(m); },
              bypass: firstBypass,
              signal,
            }),
            (partial) => {
              if (!partial.durable_job && seq === reqSeq.current) {
                setDossier(partial);
                setDossierLoading(false);
              }
            },
            () => seq === reqSeq.current && !signal.aborted,
            bypass,
            signal,
          );
          if (resp.durable_job) {
            const handle = resp.durable_job;
            if (seq === reqSeq.current) {
              setDossier(null);
              setDurableJob({ jobId: handle.job_id, status: 'queued' });
            }
            const artifact = await waitForDurableProductArtifact(
              handle.job_id,
              'asset_dossier_v1',
              (job) => { if (seq === reqSeq.current) setDurableJob(job); },
              () => seq === reqSeq.current && !signal.aborted,
              signal,
            );
            const response = artifact.row.response;
            if (
              artifact.row.operation !== 'asset_dossier'
              || !response
              || typeof response !== 'object'
              || !('identity' in response)
            ) {
              throw new Error('Durable Asset dossier returned an invalid typed result artifact');
            }
            if (seq === reqSeq.current) {
              setDossier(response as AssetDossierResponse);
              setDurableJob(null);
            }
          } else if (seq === reqSeq.current) {
            setDurableJob(null);
            setDossier(resp);
          }
        } catch (error) {
          // One panel's failure never blanks the page: the stream, artifacts
          // and header keep rendering; the dossier shows a one-line error.
          if (seq === reqSeq.current) {
            setDossierError(error instanceof Error ? error.message : String(error));
          }
        } finally {
          if (seq === reqSeq.current) setDossierLoading(false);
        }
      })();
    },
    [dossierRequest],
  );

  // NAN-1602: a user-initiated search's first dossier fetch is live (no "cached"
  // badge); later window/entity changes read cache. No-op outside the search page.
  const liveOnceRef = useRef(useIsLiveRun());

  // Reset + load whenever the request (entity / window / identities) changes,
  // once the stream's first page has painted.
  useEffect(() => {
    if (initialDossierRef.current) {
      setDossier(initialDossierRef.current);
      initialDossierRef.current = null;
      setDossierLoading(false);
      return;
    }
    setDossier(null);
    if (!streamReady) {
      setDossierLoading(true);
      return;
    }
    const bypass = liveOnceRef.current;
    liveOnceRef.current = false;
    loadDossier(bypass);
    return () => { requestAbort.current?.abort(); ++reqSeq.current; };
  }, [loadDossier, streamReady]);

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
          isOcsf,
        ),
      );
    },
    [onDrilldown, identities, identifierField, identifierValue, effectiveTimeRange, isOcsf],
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
          ? isOcsf
            ? `(file.hashes.value="${esc}" OR process.file.hashes.value="${esc}" OR actor.process.file.hashes.value="${esc}")`
            : `(file_hash="${esc}" OR process_hash="${esc}")`
          : isOcsf
            ? `(dst_endpoint.hostname="${esc}" OR query.hostname="${esc}" OR http_request.url.hostname="${esc}")`
            : `(dest_host="${esc}" OR query="${esc}" OR url_domain="${esc}")`;
      handleAssetDrilldown({ _rawClause: rawClause });
    },
    [handleAssetDrilldown, isOcsf],
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
          handleAssetDrilldown({ ...extras, _tableCommand: npl.laneAuth });
          return;
        case 'proc':
          handleAssetDrilldown({ ...extras, _tableCommand: npl.laneProc });
          return;
        case 'net':
          handleAssetDrilldown({ ...extras, _tableCommand: npl.laneNet });
          return;
        case 'file':
          handleAssetDrilldown({ ...extras, _tableCommand: npl.laneFile });
          return;
        case 'alert':
          handleAssetDrilldown({ ...extras, [isOcsf ? 'metadata.log_source' : 'source_type']: 'signal' });
          return;
        default:
          handleAssetDrilldown(extras);
      }
    },
    [handleAssetDrilldown, dossier?.timeline.buckets, effectiveTimeRange, isOcsf, npl],
  );

  // Entity context (risk + alerts + cases) fetched in parallel from nanosiem-api
  const [entityContext, setEntityContext] = useState<EntityContextResponse | null>(null);
  useEffect(() => {
    if (!identifierField || !identifierValue) return;
    const controller = new AbortController();
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
      .getEntityContext(entityType, identifierValue, idValues.length ? idValues : undefined, controller.signal)
      .then((context) => { if (!controller.signal.aborted) setEntityContext(context); })
      .catch(() => {
        /* context is supplementary — fail silently */
      });
    return () => controller.abort();
  }, [identifierField, identifierValue, identities]);

  if (!primary) {
    return (
      <div className="p-8 text-center text-[12px] text-muted-foreground/70 font-mono">
        Asset view requires an | asset command with a resolved identifier.
      </div>
    );
  }

  const kindLabel = kind === 'host' ? 'host dossier' : 'user dossier';
  const dossierProgressLabel = progressLabel(dossier?.progress, effectiveTimeRange?.start);
  // NAN-3291: while the dossier is still reading, an empty card is pending,
  // not empty (its aggregate may not have landed yet).
  const dossierPending = dossier?.progress?.complete === false && !dossierError;
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

      {durableJob && <DurableJobNotice job={durableJob} onOpenJobs={onOpenJobs} />}

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

              {/* NAN-3252: partial panels are painted as they arrive; this
                  is only a subtle marker that they are still being refined. */}
              {dossierProgressLabel && !dossierError && (
                <div
                  data-testid={dossier?.progress?.complete ? 'asset-dossier-note' : 'asset-dossier-refining'}
                  className="flex items-center gap-1.5 text-[10.5px] font-mono text-muted-foreground/70"
                >
                  {!dossier?.progress?.complete && (
                    <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/60 animate-pulse" />
                  )}
                  dossier {dossierProgressLabel}
                </div>
              )}

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
                  onOpenSequence={onDrilldown ? () => handleAssetDrilldown({ [isOcsf ? 'metadata.log_source' : 'source_type']: 'signal' }) : undefined}
                />
                {dossier && (
                  <ProcessesCard
                    pending={dossierPending}
                    processes={dossier.processes}
                    onOpenTree={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: npl.processTree }) : undefined}
                  />
                )}
                {dossier && (
                  <NetworkCard
                    pending={dossierPending}
                    network={dossier.network}
                    onOpenTopDestinations={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: npl.topDestinationsByBytes }) : undefined}
                    onStatClick={onDrilldown ? (key, ctx) => {
                      switch (key) {
                        case 'UNIQ_DSTS':
                          handleAssetDrilldown({ _tableCommand: npl.topDestinationsByCount });
                          return;
                        case 'NEW_DOMAINS':
                          handleAssetDrilldown({ _tableCommand: npl.newDomains });
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
                    pending={dossierPending}
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
                          handleAssetDrilldown({ _tableCommand: npl.authInteractive });
                          return;
                        case 'NETWORK':
                          handleAssetDrilldown({ _tableCommand: npl.authNetworkOrLateral });
                          return;
                      }
                    } : undefined}
                  />
                )}
                {dossier && (
                  <FilesCard
                    pending={dossierPending}
                    files={dossier.files}
                    onOpenAll={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: npl.fileEvents }) : undefined}
                  />
                )}
                {dossier && (
                  <DnsCard
                    pending={dossierPending}
                    dns={dossier.dns}
                    onOpenTopDomains={onDrilldown ? () => handleAssetDrilldown({ _tableCommand: npl.topDomains }) : undefined}
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
            enabled={streamReady}
            onArtifactClick={onDrilldown ? handleArtifactDrilldown : undefined}
          />

          <AssetStream
            identifierField={identifierField}
            identifierValue={identifierValue}
            identities={identities}
            timeRange={effectiveTimeRange}
            initialSummary={durableSummary}
            onFirstPage={onStreamFirstPage}
            onOpenJobs={onOpenJobs}
          />

          {dossierLoading && !dossier && !dossierError && (
            <div className="text-[11px] text-muted-foreground/70 font-mono">
              Loading dossier…
            </div>
          )}
          {/* NAN-3282: a refinement poll that fails after partial panels were
              painted (e.g. a 413 view_too_large: "narrow the time window")
              keeps the partial panels and says why refining stopped. */}
          {dossierError && (
            <div
              data-testid="asset-dossier-error"
              className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground"
            >
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-amber-500" strokeWidth={1.5} />
              <span>{dossier ? 'Dossier incomplete' : 'Dossier unavailable'}: {dossierError}</span>
              <button type="button" className="underline" onClick={refresh}>retry</button>
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
    'src_endpoint.ip': 'ip',
    'dst_endpoint.ip': 'ip',
    'src_endpoint.hostname': 'host',
    'dst_endpoint.hostname': 'host',
    'device.hostname': 'host',
    'user.name': 'user',
    'actor.user.name': 'user',
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
